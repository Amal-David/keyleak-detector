"""Site-wide scanner with subdomain discovery and page crawling."""

from __future__ import annotations

import socket
import subprocess
import sys
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

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
    domain = domain.strip().lower()
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

    print(f"[keyleak] subfinder not found, trying DNS brute-force", file=sys.stderr)
    found = []
    for sub in COMMON_SUBDOMAINS:
        hostname = f"{sub}.{domain}"
        try:
            socket.getaddrinfo(hostname, None, socket.AF_INET, socket.SOCK_STREAM)
            found.append(hostname)
        except socket.gaierror:
            continue

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
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
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

            try:
                context = browser.new_context(viewport={"width": 1280, "height": 1024})
                page = context.new_page()
                page.set_default_timeout(15000)
                page.goto(root_url, wait_until="domcontentloaded")

                links = page.evaluate("""() => {
                    return Array.from(document.querySelectorAll('a[href]'))
                        .map(a => a.href)
                        .filter(h => h.startsWith('http'));
                }""")

                parsed_root = urlparse(root_url)
                root_domain = parsed_root.netloc

                for link in links:
                    if len(urls) >= max_pages:
                        break
                    parsed = urlparse(link)
                    if not parsed.netloc.endswith(root_domain.split(".")[-2] + "." + root_domain.split(".")[-1] if "." in root_domain else root_domain):
                        continue
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
    parsed = urlparse(domain)
    if parsed.netloc:
        domain = parsed.netloc
    domain = domain.split(":")[0]

    print(f"[keyleak] Starting site scan for {domain}", file=sys.stderr)

    subdomains = discover_subdomains(domain)
    if not subdomains:
        subdomains = [domain]

    print(f"[keyleak] Crawling {len(subdomains)} hosts (depth={depth}, max={max_pages})", file=sys.stderr)
    urls = crawl_pages(subdomains, depth=depth, max_pages=max_pages, headless=headless)
    print(f"[keyleak] Found {len(urls)} pages to scan", file=sys.stderr)

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
            print(f"[keyleak]   Error: {exc}", file=sys.stderr)
            continue

    seen: Dict[str, Finding] = {}
    for f in all_findings:
        key = f"{f.type}:{f.evidence.redacted_value}"
        if key not in seen:
            seen[key] = f
    deduped = list(seen.values())

    print(f"[keyleak] Site scan complete: {len(deduped)} unique findings from {len(urls)} pages", file=sys.stderr)

    return build_report(
        domain, deduped, scan_mode="site", profile="launch-gate",
        packs=["leak", "appsec", "access-control", "baas"],
    )
