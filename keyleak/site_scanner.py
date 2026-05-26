"""Site-wide scanner with subdomain discovery and page crawling.

Discovers subdomains for a domain, crawls each for internal links,
then runs ``run_browser_scan()`` on each collected URL. Aggregates
findings into a single report with deduplication.
"""

from __future__ import annotations

import socket
import subprocess
import sys
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse

from .browser_scanner import run_browser_scan
from .models import Finding, ScanReport
from .reporting import build_report


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


def discover_subdomains(domain: str) -> List[str]:
    """Discover subdomains using subfinder (if available) or DNS brute-force."""
    domain = domain.strip().lower()

    # Try subfinder first
    try:
        result = subprocess.run(
            ["subfinder", "-d", domain, "-silent", "-timeout", "10"],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0 and result.stdout.strip():
            subs = [s.strip() for s in result.stdout.strip().splitlines() if s.strip()]
            if subs:
                print(f"[keyleak] subfinder found {len(subs)} subdomains", file=sys.stderr)
                return sorted(set(subs))
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Fallback: DNS brute-force with common subdomains
    print(f"[keyleak] subfinder not found, trying {len(COMMON_SUBDOMAINS)} common subdomains via DNS", file=sys.stderr)
    found = []
    for sub in COMMON_SUBDOMAINS:
        hostname = f"{sub}.{domain}"
        try:
            socket.getaddrinfo(hostname, None, socket.AF_INET, socket.SOCK_STREAM)
            found.append(hostname)
        except socket.gaierror:
            continue

    # Always include the bare domain
    try:
        socket.getaddrinfo(domain, None, socket.AF_INET, socket.SOCK_STREAM)
        if domain not in found:
            found.insert(0, domain)
    except socket.gaierror:
        pass

    print(f"[keyleak] DNS resolved {len(found)} subdomains", file=sys.stderr)
    return found


def crawl_pages(
    hosts: List[str],
    *,
    depth: int = 1,
    max_pages: int = 20,
    headless: bool = True,
) -> List[str]:
    """Crawl each host for internal links up to ``depth`` levels.

    Uses Playwright to load pages and extract ``<a href>`` links.
    Returns deduplicated list of URLs to scan.
    """
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        # No Playwright — just return root URLs
        return [f"https://{h}" for h in hosts[:max_pages]]

    urls: List[str] = []
    seen: Set[str] = set()

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=headless)

        for host in hosts:
            if len(urls) >= max_pages:
                break

            root_url = f"https://{host}"
            if root_url in seen:
                continue
            seen.add(root_url)
            urls.append(root_url)

            if depth < 1:
                continue

            # Crawl for internal links
            try:
                context = browser.new_context(viewport={"width": 1280, "height": 1024})
                page = context.new_page()
                page.set_default_timeout(15000)
                page.goto(root_url, wait_until="domcontentloaded")

                links = page.evaluate("""() => {
                    const anchors = document.querySelectorAll('a[href]');
                    return Array.from(anchors).map(a => a.href).filter(h => h.startsWith('http'));
                }""")

                parsed_root = urlparse(root_url)
                base_domain = parsed_root.netloc
                # Extract registrable domain (last two labels) for same-site matching
                domain_parts = base_domain.split(".")
                if len(domain_parts) >= 2:
                    registrable = domain_parts[-2] + "." + domain_parts[-1]
                else:
                    registrable = base_domain

                for link in links:
                    if len(urls) >= max_pages:
                        break
                    parsed = urlparse(link)
                    # Only follow same-domain links
                    if not parsed.netloc.endswith(registrable):
                        continue
                    # Normalize — strip fragments and query params for dedup
                    normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                    if normalized not in seen:
                        seen.add(normalized)
                        urls.append(link)

                context.close()
            except Exception:
                continue

        browser.close()

    return urls


def scan_site(
    domain: str,
    *,
    depth: int = 1,
    max_pages: int = 20,
    headless: bool = True,
    baas_validate: bool = False,
    baas_prober: Optional[Any] = None,
    baas_tables: Optional[List[str]] = None,
    scan_budget_seconds: int = 30,
) -> ScanReport:
    """Discover subdomains, crawl pages, and scan each for secrets.

    Returns an aggregated ScanReport with deduplicated findings.
    """
    # Parse domain from URL if given
    parsed = urlparse(domain)
    if parsed.netloc:
        domain = parsed.netloc
    domain = domain.split(":")[0]  # strip port

    print(f"[keyleak] Starting site scan for {domain}", file=sys.stderr)

    # Step 1: Discover subdomains
    subdomains = discover_subdomains(domain)
    if not subdomains:
        subdomains = [domain]

    # Step 2: Crawl pages
    print(f"[keyleak] Crawling {len(subdomains)} hosts (depth={depth}, max={max_pages})", file=sys.stderr)
    urls = crawl_pages(subdomains, depth=depth, max_pages=max_pages, headless=headless)
    print(f"[keyleak] Found {len(urls)} pages to scan", file=sys.stderr)

    # Step 3: Scan each URL
    all_findings: List[Finding] = []
    for i, url in enumerate(urls):
        print(f"[keyleak] Scanning [{i+1}/{len(urls)}] {url}", file=sys.stderr)
        try:
            report = run_browser_scan(
                url,
                headless=headless,
                baas_validate=baas_validate,
                baas_prober=baas_prober,
                baas_tables=baas_tables,
                scan_budget_seconds=scan_budget_seconds,
            )
            all_findings.extend(report.findings)
        except Exception as exc:
            print(f"[keyleak]   Error scanning {url}: {exc}", file=sys.stderr)
            continue

    # Step 4: Deduplicate — same detector + same redacted value = one finding
    deduped = _deduplicate_findings(all_findings)

    print(f"[keyleak] Site scan complete: {len(deduped)} unique findings from {len(urls)} pages", file=sys.stderr)

    return build_report(
        domain,
        deduped,
        scan_mode="site",
        profile="launch-gate",
        packs=["leak", "appsec", "access-control", "baas"],
    )


def _deduplicate_findings(findings: List[Finding]) -> List[Finding]:
    """Keep one finding per (type, redacted_value) pair."""
    seen: Dict[str, Finding] = {}
    for f in findings:
        key = f"{f.type}:{f.evidence.redacted_value}"
        if key not in seen:
            seen[key] = f
    return list(seen.values())
