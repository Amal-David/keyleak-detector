"""Full Site Scan — subdomain enumeration and multi-level page crawling.

Discovers subdomains for a domain (certificate transparency via crt.sh +
optional ``subfinder`` + DNS brute-force), crawls each host for internal links
up to a depth, then runs ``run_browser_scan()`` on every collected URL.
Findings are merged into a single report that preserves provenance — which
subdomains and pages each leak appeared on.

Scope is limited to the target's registrable domain; hard caps bound the
number of subdomains and pages. Read-only: crawl + passive scan only.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
from collections import deque
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urlparse, urlsplit

import requests
import tldextract

from .browser_scanner import run_browser_scan
from .models import Evidence, Finding, ScanReport, confidence_for_severity
from .proxy import playwright_proxy, requests_proxies
from .reporting import build_report


# Query parameter names that commonly feed OS command / code execution sinks.
DANGEROUS_PARAMS = {
    "cmd", "command", "exec", "execute", "shell", "system", "run",
    "code", "func", "function", "ping",
}
# Server-executed endpoints (vs. static assets); a dangerous param here is worse.
_SERVER_EXEC_EXT = (".aspx", ".asp", ".jsp", ".php", ".cgi", ".do", ".action")
_EXEC_FAMILY = {"cmd", "command", "exec", "execute", "shell", "system", "run"}


COMMON_SUBDOMAINS = [
    "www", "api", "app", "admin", "staging", "dev", "beta",
    "cdn", "assets", "static", "docs", "blog", "status",
    "mail", "dashboard", "portal", "auth", "login", "signup",
    "m", "mobile", "shop", "store", "pay", "billing",
    "support", "help", "community", "forum", "wiki",
    "preview", "demo", "sandbox", "test", "qa",
    "v1", "v2", "graphql", "ws", "realtime",
    "media", "images", "files", "uploads", "download",
]

# Hard caps to keep a scan bounded and polite.
MAX_SUBDOMAINS_DEFAULT = 50
MAX_PAGES_DEFAULT = 100

ProgressFn = Optional[Callable[[Dict[str, Any]], None]]


def _emit(on_progress: ProgressFn, phase: str, message: str,
          current: int = 0, total: int = 0) -> None:
    """Send a progress event to the hook (if any) and mirror to stderr."""
    print(f"[keyleak] {message}", file=sys.stderr)
    if on_progress:
        try:
            on_progress({"phase": phase, "message": message,
                         "current": current, "total": total})
        except Exception:
            pass


def registrable_domain(host: str) -> str:
    """Return the registrable domain (handles multi-label TLDs like co.uk)."""
    host = (host or "").strip().lower().split(":")[0]
    ext = tldextract.extract(host)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return host


def _resolves(host: str) -> bool:
    try:
        # AF_UNSPEC so IPv6-only hosts are also treated as live.
        socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        return True
    except (socket.gaierror, OSError):
        return False


def _crt_sh_subdomains(domain: str, timeout: int = 12, proxy: Optional[str] = None) -> List[str]:
    """Passive subdomain discovery via crt.sh certificate transparency logs.

    No external binary required. Returns names within the target domain.
    Degrades to an empty list on any network/parse failure.
    """
    found: Set[str] = set()
    try:
        resp = requests.get(
            "https://crt.sh/",
            params={"q": f"%.{domain}", "output": "json"},
            timeout=timeout,
            headers={"User-Agent": "keyleak-detector/full-site-scan"},
            proxies=requests_proxies(proxy),
        )
        resp.raise_for_status()
        entries = resp.json()
    except (requests.RequestException, json.JSONDecodeError, ValueError):
        return []

    for entry in entries:
        name_value = str(entry.get("name_value", ""))
        for raw in name_value.splitlines():
            name = raw.strip().lower().lstrip("*.")
            if not name or "@" in name:
                continue
            if name == domain or name.endswith("." + domain):
                found.add(name)
    return sorted(found)


def _subfinder_subdomains(domain: str) -> List[str]:
    """Use the optional subfinder binary if present, else empty."""
    try:
        result = subprocess.run(
            ["subfinder", "-d", domain, "-silent", "-timeout", "10"],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0 and result.stdout.strip():
            return sorted({s.strip().lower() for s in result.stdout.splitlines() if s.strip()})
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass
    return []


def _amass_subdomains(domain: str) -> List[str]:
    """Use the optional amass binary (passive mode) if present, else empty."""
    try:
        result = subprocess.run(
            ["amass", "enum", "-passive", "-norecursive", "-d", domain, "-timeout", "2"],
            capture_output=True, text=True, timeout=180,
        )
        if result.returncode == 0 and result.stdout.strip():
            out = {
                line.strip().lower()
                for line in result.stdout.splitlines()
                if line.strip()
            }
            return sorted(h for h in out if h == domain or h.endswith("." + domain))
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass
    return []


SUBFINDER_VERSION = "v2.14.0"


def _go_bin_dir() -> Optional[str]:
    """Best-effort location of the Go install bin dir (GOBIN or GOPATH/bin)."""
    for var in ("GOBIN", "GOPATH"):
        try:
            out = subprocess.run(["go", "env", var], capture_output=True,
                                 text=True, timeout=10).stdout.strip()
        except (subprocess.SubprocessError, OSError):
            continue
        if out:
            return out if var == "GOBIN" else os.path.join(out, "bin")
    return os.path.join(os.path.expanduser("~"), "go", "bin")


def _ensure_subfinder(*, auto_install: bool, on_progress: ProgressFn = None) -> bool:
    """Make subfinder available for a deep scan, installing it if needed.

    If subfinder is missing and ``auto_install`` is set (and the env var
    ``KEYLEAK_NO_AUTO_INSTALL`` is unset), try Homebrew first, then a pinned
    ``go install``. Never raises — a failed install just means discovery
    falls back to crt.sh + DNS. Returns True if subfinder is usable.
    """
    if shutil.which("subfinder"):
        return True
    no_auto_install = (os.environ.get("KEYLEAK_NO_AUTO_INSTALL", "").strip().lower()
                       in {"1", "true", "yes", "on"})
    if not auto_install or no_auto_install:
        return False

    if shutil.which("brew"):
        _emit(on_progress, "install",
              "subfinder not found — installing via Homebrew (brew install subfinder)...")
        try:
            subprocess.run(["brew", "install", "subfinder"],
                           check=True, capture_output=True, text=True, timeout=900)
        except (subprocess.SubprocessError, OSError) as exc:
            _emit(on_progress, "install", f"brew install subfinder failed: {exc}")

    if not shutil.which("subfinder") and shutil.which("go"):
        _emit(on_progress, "install",
              f"Installing subfinder via go install (pinned {SUBFINDER_VERSION})...")
        try:
            subprocess.run(
                ["go", "install",
                 f"github.com/projectdiscovery/subfinder/v2/cmd/subfinder@{SUBFINDER_VERSION}"],
                check=True, capture_output=True, text=True, timeout=900,
            )
            gobin = _go_bin_dir()
            exe_name = "subfinder.exe" if os.name == "nt" else "subfinder"
            if gobin and os.path.isfile(os.path.join(gobin, exe_name)):
                os.environ["PATH"] = gobin + os.pathsep + os.environ.get("PATH", "")
        except (subprocess.SubprocessError, OSError) as exc:
            _emit(on_progress, "install", f"go install subfinder failed: {exc}")

    ok = shutil.which("subfinder") is not None
    _emit(on_progress, "install",
          "subfinder ready." if ok else "Could not install subfinder; using crt.sh + DNS only.")
    return ok


def discover_subdomains(
    domain: str,
    *,
    max_subdomains: int = MAX_SUBDOMAINS_DEFAULT,
    offline: bool = False,
    proxy: Optional[str] = None,
    auto_install: bool = False,
    sources_out: Optional[Dict[str, Any]] = None,
    on_progress: ProgressFn = None,
) -> List[str]:
    """Discover subdomains within ``domain``, scoped and capped.

    Sources (union, in priority order): subfinder + amass (if installed) +
    crt.sh certificate transparency + DNS brute-force of common names. Each
    candidate is DNS-resolved to drop dead names, then the list is capped at
    ``max_subdomains``. With ``offline=True`` no network is used and only the
    bare domain is returned.

    If ``sources_out`` is provided, it is populated with a per-source
    breakdown: ``candidates`` (counts found per source), ``kept`` (counts of
    resolved hosts attributed to each source), and ``by_host`` (host -> source).
    """
    domain = domain.strip().lower().split(":")[0]

    if offline:
        _emit(on_progress, "subdomains", "Offline mode — skipping subdomain discovery", 1, 1)
        if sources_out is not None:
            sources_out.update({
                "candidates": {"subfinder": 0, "amass": 0, "crt.sh": 0, "dns-brute": 0},
                "kept": {"apex": 1},
                "by_host": {domain: "apex"},
            })
        return [domain]

    _ensure_subfinder(auto_install=auto_install, on_progress=on_progress)
    subfinder = set(_subfinder_subdomains(domain))
    amass = set(_amass_subdomains(domain))
    crt = set(_crt_sh_subdomains(domain, proxy=proxy))
    brute_force = {f"{sub}.{domain}" for sub in COMMON_SUBDOMAINS}
    _emit(on_progress, "subdomains",
          f"Candidates — subfinder {len(subfinder)}, amass {len(amass)}, "
          f"crt.sh {len(crt)}, dns-brute {len(brute_force)}")

    # Build the candidate list in source-priority order — bare domain, then
    # passive discovery (subfinder, amass, crt.sh), then guessed names last —
    # so a small cap never drops a real hit in favour of a brute-force guess
    # that merely sorts earlier alphabetically. Attribute each host to the
    # first (highest-priority) source that surfaced it.
    source_of: Dict[str, str] = {domain: "apex"}
    ordered: List[str] = [domain]
    seen = {domain}
    for label, bucket in (("subfinder", subfinder), ("amass", amass),
                          ("crt.sh", crt), ("dns-brute", brute_force)):
        for host in sorted(bucket):
            if host not in seen:
                seen.add(host)
                source_of[host] = label
                ordered.append(host)

    # Keep only names that actually resolve, capped at max_subdomains.
    resolved: List[str] = []
    kept_counts: Dict[str, int] = {}
    for host in ordered:
        if len(resolved) >= max_subdomains:
            break
        if _resolves(host):
            resolved.append(host)
            src = source_of.get(host, "dns-brute")
            kept_counts[src] = kept_counts.get(src, 0) + 1

    if not resolved:
        resolved = [domain]
        kept_counts = {"apex": 1}

    if sources_out is not None:
        sources_out.update({
            "candidates": {
                "subfinder": len(subfinder), "amass": len(amass),
                "crt.sh": len(crt), "dns-brute": len(brute_force),
            },
            "kept": kept_counts,
            "by_host": {h: source_of.get(h, "dns-brute") for h in resolved},
        })

    kept_summary = ", ".join(f"{k} {v}" for k, v in sorted(kept_counts.items()))
    _emit(on_progress, "subdomains",
          f"Discovered {len(resolved)} live host(s) [{kept_summary}]",
          len(resolved), len(resolved))
    return resolved


def _normalize_url(url: str) -> str:
    """Scheme + netloc + path, no fragment/query — for crawl dedup."""
    p = urlparse(url)
    path = p.path or "/"
    return f"{p.scheme}://{p.netloc}{path}".rstrip("/") or f"{p.scheme}://{p.netloc}/"


def _filter_links(
    links: List[str],
    registrable: str,
    seen: Set[str],
    remaining: int,
) -> List[str]:
    """Pure helper: keep in-scope, http(s), de-duplicated links.

    Updates ``seen`` in place with normalized URLs. Returns up to
    ``remaining`` newly discovered normalized URLs, in order.
    """
    out: List[str] = []
    if remaining <= 0:
        return out
    for link in links:
        if len(out) >= remaining:
            break
        p = urlparse(link)
        if p.scheme not in ("http", "https") or not p.netloc:
            continue
        if registrable_domain(p.netloc) != registrable:
            continue
        normalized = _normalize_url(link)
        if normalized in seen:
            continue
        seen.add(normalized)
        out.append(normalized)
    return out


def crawl_pages(
    hosts: List[str],
    *,
    depth: int = 3,
    max_pages: int = MAX_PAGES_DEFAULT,
    headless: bool = True,
    proxy: Optional[str] = None,
    collect_raw: Optional[Set[str]] = None,
    on_progress: ProgressFn = None,
) -> List[str]:
    """Breadth-first crawl across ``hosts`` up to ``depth`` link levels.

    Same-registrable-domain scope, normalized dedup, global ``max_pages`` cap.
    Falls back to host roots only when Playwright is unavailable. When
    ``collect_raw`` is given, in-scope hrefs that carry a query string are added
    to it verbatim (before normalization strips the query) so callers can scan
    them for dangerous parameters.
    """
    seen: Set[str] = set()
    roots = []
    for h in hosts:
        root = _normalize_url(f"https://{h}")
        if root not in seen:
            seen.add(root)
            roots.append(root)

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return roots[:max_pages]

    results: List[str] = []
    queue: deque = deque((r, 0) for r in roots)

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=headless, proxy=playwright_proxy(proxy))
        try:
            while queue and len(results) < max_pages:
                url, level = queue.popleft()
                results.append(url)
                if level >= depth:
                    continue
                context = None
                try:
                    context = browser.new_context(viewport={"width": 1280, "height": 1024})
                    page = context.new_page()
                    page.set_default_timeout(15000)
                    page.goto(url, wait_until="domcontentloaded")
                    links = page.evaluate(
                        "() => Array.from(document.querySelectorAll('a[href]'))"
                        ".map(a => a.href).filter(h => h.startsWith('http'))"
                    )
                except Exception:
                    continue
                finally:
                    # Always release the context, even when goto/evaluate raised,
                    # so failed hosts don't leak browser contexts during a crawl.
                    if context is not None:
                        try:
                            context.close()
                        except Exception:
                            pass
                registrable = registrable_domain(urlparse(url).netloc)
                if collect_raw is not None:
                    for link in links:
                        if "?" not in link:
                            continue
                        lp = urlparse(link)
                        if lp.scheme in ("http", "https") and lp.netloc \
                                and registrable_domain(lp.netloc) == registrable:
                            collect_raw.add(link)
                remaining = max_pages - (len(results) + len(queue))
                for nu in _filter_links(links, registrable, seen, remaining):
                    queue.append((nu, level + 1))
        finally:
            browser.close()

    _emit(on_progress, "crawl", f"Found {len(results)} page(s) to scan",
          len(results), len(results))
    return results


def _merge_findings(
    pairs: List[Tuple[Finding, str]],
) -> Tuple[List[Finding], Dict[str, List[str]]]:
    """Merge findings across pages, preserving per-finding provenance.

    ``pairs`` is a list of (finding, source_url). Keeps one Finding per
    (type, redacted_value); returns the deduped list plus a map of
    ``finding.id -> sorted list of URLs`` it was seen on.
    """
    kept: Dict[str, Finding] = {}
    urls_by_key: Dict[str, Set[str]] = {}
    for finding, url in pairs:
        key = f"{finding.type}:{finding.evidence.redacted_value}"
        if key not in kept:
            if not finding.evidence.request_url and url:
                finding.evidence.request_url = url
            kept[key] = finding
        if url:
            urls_by_key.setdefault(key, set()).add(url)

    findings = list(kept.values())
    provenance = {
        kept[key].id: sorted(urls)
        for key, urls in urls_by_key.items()
        if key in kept
    }
    return findings, provenance


def _deduplicate_findings(findings: List[Finding]) -> List[Finding]:
    """Backward-compatible dedup by (type, redacted_value)."""
    merged, _ = _merge_findings([(f, "") for f in findings])
    return merged


def _dangerous_param_findings(urls: Set[str]) -> List[Finding]:
    """Flag crawled URLs whose query string carries a command-injection-shaped
    parameter (``?cmd=``, ``?exec=``, …). Deduplicated by (host, path, params).

    These are leads: the parameter name is suggestive, not proof of a sink.
    Query *values* are never echoed (they may themselves be attacker payloads).
    """
    findings: List[Finding] = []
    seen: Set[Tuple[str, str, Tuple[str, ...]]] = set()
    for url in urls or set():
        try:
            parts = urlsplit(url)
        except ValueError:
            continue
        if not parts.query:
            continue
        params = parse_qs(parts.query, keep_blank_values=True)
        hits = tuple(sorted(p for p in params if p.lower() in DANGEROUS_PARAMS))
        if not hits:
            continue
        path = parts.path or "/"
        key = (parts.netloc, path, hits)
        if key in seen:
            continue
        seen.add(key)

        server_exec = path.lower().endswith(_SERVER_EXEC_EXT)
        exec_family = any(h.lower() in _EXEC_FAMILY for h in hits)
        severity = "high" if (server_exec and exec_family) else "medium"
        loc = f"{parts.scheme}://{parts.netloc}{path}"
        names = ", ".join(hits)
        findings.append(
            Finding(
                type="dangerous_url_parameter",
                severity=severity,
                confidence=confidence_for_severity(severity),
                detector_id="appsec.dangerous_url_param",
                source=loc,
                evidence=Evidence(
                    source=loc,
                    snippet=f"{path}?{names}=…",
                    redacted_value=names,
                    request_url=loc,
                ),
                risk_reason=(
                    f"A crawled link exposes the query parameter(s) {names} on "
                    f"{'a server-executed endpoint ' if server_exec else ''}{path} — "
                    "a common command-injection / RCE vector."
                ),
                remediation=(
                    "Treat this parameter as untrusted input: never pass it to a shell, "
                    "OS command, or eval; validate against a strict allowlist and re-test "
                    "the endpoint."
                ),
                validation_status="lead",
                category="appsec",
                references=[
                    "https://cwe.mitre.org/data/definitions/78.html",
                    "https://owasp.org/www-community/attacks/Command_Injection",
                ],
            )
        )
    return findings


def scan_site(
    domain: str,
    *,
    depth: int = 3,
    max_pages: int = MAX_PAGES_DEFAULT,
    max_subdomains: int = MAX_SUBDOMAINS_DEFAULT,
    headless: bool = True,
    baas_validate: bool = False,
    baas_prober: Optional[Any] = None,
    baas_tables: Optional[List[str]] = None,
    scan_budget_seconds: int = 30,
    launch_profile: str = "launch-gate",
    offline: bool = False,
    proxy: Optional[str] = None,
    auto_install: bool = True,
    on_progress: ProgressFn = None,
) -> ScanReport:
    """Full Site Scan: discover subdomains, crawl pages, scan each for secrets.

    Returns an aggregated ScanReport whose ``extra`` carries the scanned
    subdomains, page count, and a ``provenance`` map (finding id -> URLs).
    """
    # Normalize to the registrable domain (eTLD+1), tolerating full URLs,
    # credentials, ports, and IPv6 literals (parsed.hostname drops user/port).
    raw = domain.strip()
    parsed = urlparse(raw if "://" in raw else f"//{raw}")
    host = (parsed.hostname or raw).strip().lower()
    domain = registrable_domain(host)

    _emit(on_progress, "start", f"Starting full site scan for {domain}")

    discovery_sources: Dict[str, Any] = {}
    subdomains = discover_subdomains(
        domain, max_subdomains=max_subdomains, offline=offline,
        proxy=proxy, auto_install=auto_install,
        sources_out=discovery_sources, on_progress=on_progress,
    )
    if not subdomains:
        subdomains = [domain]

    # Subdomain-takeover check runs in parallel with the crawl/scan below. It
    # only uses ``requests`` (no Playwright), so a single worker thread safely
    # overlaps the main-thread browser work and adds almost no wall-clock time.
    takeover_pool = None
    takeover_future = None
    if not offline:
        from concurrent.futures import ThreadPoolExecutor

        from .subdomain_takeover import check_subdomain_takeovers

        _emit(on_progress, "takeover",
              f"Checking {len(subdomains)} subdomain(s) for takeover in parallel")
        takeover_pool = ThreadPoolExecutor(max_workers=1)
        takeover_future = takeover_pool.submit(
            check_subdomain_takeovers, subdomains, proxy=proxy
        )

    raw_query_urls: Set[str] = set()
    pairs: List[Tuple[Finding, str]] = []
    takeover_count = 0
    total = 0
    urls: List[str] = []
    # Everything from the crawl through the takeover join runs inside a
    # try/finally so the background takeover pool is always shut down — even if
    # crawl_pages or the per-host scan raises.
    try:
        urls = crawl_pages(
            subdomains, depth=depth, max_pages=max_pages,
            headless=headless, proxy=proxy, collect_raw=raw_query_urls,
            on_progress=on_progress,
        )

        for finding in _dangerous_param_findings(raw_query_urls):
            pairs.append((finding, finding.evidence.request_url))
        total = len(urls)
        for i, url in enumerate(urls):
            _emit(on_progress, "scan", f"Scanning [{i + 1}/{total}] {url}", i + 1, total)
            try:
                report = run_browser_scan(
                    url,
                    headless=headless,
                    baas_validate=baas_validate,
                    baas_prober=baas_prober,
                    baas_tables=baas_tables,
                    scan_budget_seconds=scan_budget_seconds,
                    proxy=proxy,
                )
                for f in report.findings:
                    pairs.append((f, url))
            except Exception as exc:
                print(f"[keyleak]   Error scanning {url}: {exc}", file=sys.stderr)
                continue

        # Join the parallel subdomain-takeover check and fold its findings in.
        if takeover_future is not None:
            try:
                takeover_findings = takeover_future.result()
            except Exception:
                takeover_findings = []
            for f in takeover_findings:
                pairs.append((f, f.source))
            takeover_count = len(takeover_findings)
            if takeover_count:
                _emit(on_progress, "takeover",
                      f"Subdomain-takeover check flagged {takeover_count} host(s)",
                      takeover_count, takeover_count)
    finally:
        if takeover_pool is not None:
            takeover_pool.shutdown(wait=False)

    findings, provenance = _merge_findings(pairs)
    _emit(on_progress, "done",
          f"Full site scan complete: {len(findings)} unique finding(s) from {total} page(s)",
          total, total)

    report = build_report(
        domain,
        findings,
        scan_mode="full-site",
        profile=launch_profile,
        packs=["leak", "appsec", "access-control", "baas"],
    )
    report.extra.update({
        "subdomains": subdomains,
        "hosts_scanned": len(subdomains),
        "pages_scanned": total,
        "scanned_urls": urls,
        "provenance": provenance,
        "subdomain_takeovers": takeover_count,
        "discovery_sources": discovery_sources,
    })
    return report
