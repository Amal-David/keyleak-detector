import calendar
import ipaddress
import math
import os
import shutil
import socket
import ssl
import subprocess
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import requests

try:
    import tldextract
except ImportError:  # pragma: no cover - optional dependency
    tldextract = None

DEFAULT_SCAN_BUDGET_SECONDS = int(os.getenv("SCAN_TIME_BUDGET_SECONDS", "600"))
DEFAULT_REQUEST_TIMEOUT = (3.05, 6)

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "medium",
        "recommendation": "Enable HSTS to enforce HTTPS connections.",
    },
    "Content-Security-Policy": {
        "severity": "medium",
        "recommendation": "Define a CSP to reduce XSS and data injection risks.",
    },
    "X-Frame-Options": {
        "severity": "low",
        "recommendation": "Set X-Frame-Options to prevent clickjacking.",
    },
    "X-Content-Type-Options": {
        "severity": "low",
        "recommendation": "Set X-Content-Type-Options to nosniff.",
    },
    "Referrer-Policy": {
        "severity": "low",
        "recommendation": "Set Referrer-Policy to control referrer leakage.",
    },
    "Permissions-Policy": {
        "severity": "low",
        "recommendation": "Restrict powerful browser features via Permissions-Policy.",
    },
}

EXPOSED_PATHS = [
    {
        "path": "/.env",
        "label": "Exposed .env file",
        "severity": "critical",
        "match": "=",  # simple heuristic
        "recommendation": "Remove .env files from public web roots.",
    },
    {
        "path": "/.git/HEAD",
        "label": "Exposed Git metadata (.git/HEAD)",
        "severity": "high",
        "match": "ref:",
        "recommendation": "Block access to the .git directory.",
    },
    {
        "path": "/.git/config",
        "label": "Exposed Git config (.git/config)",
        "severity": "high",
        "match": "[core]",
        "recommendation": "Block access to the .git directory.",
    },
    {
        "path": "/backup.zip",
        "label": "Exposed backup archive (backup.zip)",
        "severity": "high",
        "match": None,
        "recommendation": "Remove backup archives from public directories.",
    },
    {
        "path": "/backup.tar.gz",
        "label": "Exposed backup archive (backup.tar.gz)",
        "severity": "high",
        "match": None,
        "recommendation": "Remove backup archives from public directories.",
    },
    {
        "path": "/db.sql",
        "label": "Exposed database dump (db.sql)",
        "severity": "critical",
        "match": "CREATE TABLE",
        "recommendation": "Remove database dumps from public directories.",
    },
]

ADMIN_ENDPOINTS = [
    "/admin",
    "/administrator",
    "/login",
    "/dashboard",
    "/wp-admin",
    "/phpmyadmin",
    "/server-status",
]

OUTDATED_TECH_PATTERNS = [
    {
        "pattern": r"Apache/2\.2",
        "label": "Apache 2.2 detected",
        "severity": "high",
        "recommendation": "Upgrade Apache to a supported 2.4+ release.",
    },
    {
        "pattern": r"nginx/1\.(?:0|1[0-7])\b",
        "label": "Old Nginx version detected",
        "severity": "medium",
        "recommendation": "Upgrade Nginx to a supported release.",
    },
    {
        "pattern": r"PHP/5\.",
        "label": "PHP 5 detected",
        "severity": "high",
        "recommendation": "Upgrade PHP to a supported 8.x release.",
    },
    {
        "pattern": r"OpenSSL/1\.0\.",
        "label": "OpenSSL 1.0 detected",
        "severity": "medium",
        "recommendation": "Upgrade OpenSSL to a supported release.",
    },
    {
        "pattern": r"Microsoft-IIS/6\.",
        "label": "IIS 6 detected",
        "severity": "high",
        "recommendation": "Upgrade IIS to a supported release.",
    },
]

_TLD_EXTRACT = tldextract.TLDExtract(suffix_list_urls=()) if tldextract else None


def run_attack_vector_scan(
    target_url: str,
    time_budget_seconds: Optional[int] = None,
    proxy: Optional[str] = None,
) -> Dict[str, Any]:
    budget = time_budget_seconds or DEFAULT_SCAN_BUDGET_SECONDS
    start_time = time.monotonic()
    deadline = start_time + budget

    parsed = urlparse(target_url)
    host = parsed.hostname
    if not host:
        return {
            "status": "error",
            "error": "Invalid URL host.",
            "summary": _empty_summary(),
            "subdomains": [],
            "elapsed_seconds": 0,
            "time_budget_seconds": budget,
        }

    base_domain = _get_registrable_domain(host)
    subdomains, enum_meta = _enumerate_subdomains(
        base_domain,
        remaining_seconds=max(0, deadline - time.monotonic()),
        proxy=proxy,
    )

    hosts = _normalize_hosts({base_domain, host, *subdomains})
    results: List[Dict[str, Any]] = []
    status = "completed"
    if enum_meta.get("error"):
        status = "partial"

    session = requests.Session()
    for host_entry in hosts:
        if time.monotonic() >= deadline:
            status = "partial"
            break
        host_result = _scan_host(host_entry, session, deadline, base_domain)
        results.append(host_result)
        if host_result.get("incomplete"):
            status = "partial"

    summary = _summarize_findings(
        [finding for host_result in results for finding in host_result.get("findings", [])]
    )

    elapsed = int(time.monotonic() - start_time)
    return {
        "status": status,
        "summary": summary,
        "subdomains": results,
        "enumerator": enum_meta,
        "elapsed_seconds": elapsed,
        "time_budget_seconds": budget,
    }


def _get_registrable_domain(host: str) -> str:
    if not host or _is_ip_address(host) or host in {"localhost"}:
        return host
    if not _TLD_EXTRACT:
        return host
    extracted = _TLD_EXTRACT(host)
    if extracted.domain and extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}"
    return host


def _enumerate_subdomains(
    domain: str,
    remaining_seconds: float,
    proxy: Optional[str] = None,
) -> Tuple[List[str], Dict[str, Any]]:
    if not domain or _is_ip_address(domain) or "." not in domain:
        return [], {
            "tool": None,
            "fallback_used": False,
            "error": None,
            "note": "Subdomain enumeration skipped.",
        }

    preference = os.getenv("SUBDOMAIN_ENUMERATOR", "subfinder").lower()
    ordered_tools = ["subfinder", "amass"] if preference != "amass" else ["amass", "subfinder"]

    last_error = None
    for index, tool in enumerate(ordered_tools):
        if not shutil.which(tool):
            last_error = f"{tool} not available"
            continue
        try:
            if tool == "subfinder":
                subdomains = _run_subfinder(domain, remaining_seconds, proxy)
            else:
                subdomains = _run_amass(domain, remaining_seconds)
            return subdomains, {
                "tool": tool,
                "fallback_used": index > 0,
                "error": None,
            }
        except Exception as exc:
            last_error = str(exc)

    return [], {"tool": None, "fallback_used": False, "error": last_error or "No enumerator available."}


def _run_subfinder(domain: str, timeout_seconds: float, proxy: Optional[str]) -> List[str]:
    max_minutes = max(1, math.ceil(timeout_seconds / 60))
    cmd = ["subfinder", "-silent", "-d", domain, "-max-time", str(max_minutes)]
    if proxy:
        cmd += ["-proxy", proxy]
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=max(1, int(timeout_seconds)),
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "subfinder failed")
    return _filter_subdomains(result.stdout.splitlines(), domain)


def _run_amass(domain: str, timeout_seconds: float) -> List[str]:
    max_minutes = max(1, math.ceil(timeout_seconds / 60))
    cmd = ["amass", "enum", "--passive", "-d", domain, "-timeout", str(max_minutes)]
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=max(1, int(timeout_seconds)),
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "amass failed")
    return _filter_subdomains(result.stdout.splitlines(), domain)


def _filter_subdomains(lines: List[str], domain: str) -> List[str]:
    filtered = []
    suffix = f".{domain}"
    for line in lines:
        host = line.strip().lower().rstrip(".")
        if not host:
            continue
        if host == domain or host.endswith(suffix):
            filtered.append(host)
    return sorted(set(filtered))


def _scan_host(
    host: str,
    session: requests.Session,
    deadline: float,
    allowed_domain: str,
) -> Dict[str, Any]:
    findings: List[Dict[str, Any]] = []
    response, base_url, scheme, error = _fetch_base_url(host, session, allowed_domain)
    incomplete = False

    if not response:
        if error:
            findings.append(
                _make_finding(
                    "host_unreachable",
                    "low",
                    host,
                    f"Unable to reach {host}: {error}",
                    "Verify host availability and allow inbound scanning traffic.",
                    source="connectivity",
                    url=None,
                )
            )
        return {
            "host": host,
            "url": None,
            "findings": findings,
            "summary": _summarize_findings(findings),
            "incomplete": False,
        }

    findings.extend(_check_security_headers(response, base_url))

    if scheme == "https":
        findings.extend(_check_tls_posture(host, base_url))
    else:
        findings.append(
            _make_finding(
                "https_not_available",
                "medium",
                host,
                "HTTPS not available or failed TLS negotiation.",
                "Enable HTTPS with a valid certificate.",
                source="tls",
                url=base_url,
            )
        )

    findings.extend(_check_directory_listing(response, base_url))

    if time.monotonic() < deadline:
        findings.extend(_check_exposed_paths(base_url, session, deadline))
    else:
        incomplete = True

    if time.monotonic() < deadline:
        findings.extend(_check_admin_endpoints(base_url, session, deadline))
    else:
        incomplete = True

    findings.extend(_check_fingerprint(response, base_url))
    response.close()

    return {
        "host": host,
        "url": base_url,
        "findings": findings,
        "summary": _summarize_findings(findings),
        "incomplete": incomplete,
    }


def _fetch_base_url(
    host: str,
    session: requests.Session,
    allowed_domain: str,
) -> Tuple[Optional[requests.Response], Optional[str], Optional[str], Optional[str]]:
    last_error = None
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}/"
        try:
            response = session.get(
                url,
                timeout=DEFAULT_REQUEST_TIMEOUT,
                allow_redirects=False,
            )
            if response.is_redirect or response.is_permanent_redirect:
                location = response.headers.get("Location")
                if location:
                    redirect_url = urljoin(url, location)
                    redirect_host = urlparse(redirect_url).hostname
                    if _host_in_scope(redirect_host, allowed_domain):
                        response.close()
                        redirect_response = session.get(
                            redirect_url,
                            timeout=DEFAULT_REQUEST_TIMEOUT,
                            allow_redirects=False,
                        )
                        return redirect_response, redirect_url, scheme, None
            return response, response.url or url, scheme, None
        except requests.RequestException as exc:
            last_error = str(exc)
            continue
    return None, None, None, last_error


def _check_security_headers(response: requests.Response, base_url: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    headers = response.headers
    for header, meta in SECURITY_HEADERS.items():
        if header not in headers:
            findings.append(
                _make_finding(
                    "missing_security_header",
                    meta["severity"],
                    header,
                    f"{header} header is missing.",
                    meta["recommendation"],
                    source="headers",
                    url=base_url,
                )
            )
    return findings


def _check_tls_posture(host: str, base_url: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
        not_after = cert.get("notAfter") if cert else None
        if not_after:
            expires_at = calendar.timegm(time.strptime(not_after, "%b %d %H:%M:%S %Y %Z"))
            seconds_left = int(expires_at - time.time())
            if seconds_left < 0:
                findings.append(
                    _make_finding(
                        "tls_certificate_expired",
                        "high",
                        host,
                        "TLS certificate is expired.",
                        "Renew the TLS certificate.",
                        source="tls",
                        url=base_url,
                    )
                )
            elif seconds_left < 30 * 86400:
                findings.append(
                    _make_finding(
                        "tls_certificate_expiring",
                        "medium",
                        host,
                        "TLS certificate expires within 30 days.",
                        "Schedule certificate renewal.",
                        source="tls",
                        url=base_url,
                    )
                )
    except Exception as exc:
        findings.append(
            _make_finding(
                "tls_check_failed",
                "low",
                host,
                f"TLS check failed: {exc}",
                "Verify TLS configuration and certificate validity.",
                source="tls",
                url=base_url,
            )
        )
    return findings


def _check_directory_listing(response: requests.Response, base_url: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    content_type = response.headers.get("Content-Type", "")
    if "text/html" not in content_type.lower():
        return findings
    sample = response.text[:4096].lower()
    markers = ("index of /", "directory listing for", "directory listing")
    if any(marker in sample for marker in markers):
        findings.append(
            _make_finding(
                "directory_listing_enabled",
                "medium",
                base_url,
                "Directory listing appears to be enabled.",
                "Disable directory listing in the web server.",
                source="content",
                url=base_url,
            )
        )
    return findings


def _check_exposed_paths(
    base_url: str,
    session: requests.Session,
    deadline: float,
) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for item in EXPOSED_PATHS:
        if time.monotonic() >= deadline:
            break
        url = f"{base_url.rstrip('/')}{item['path']}"
        response = _fetch_lightweight(session, url)
        if not response:
            continue
        try:
            if response.status_code in {200, 206}:
                content_type = response.headers.get("Content-Type", "").lower()
                if "text/html" in content_type:
                    continue
                content_sample = _read_snippet(response, 2048).lower()
                match = item.get("match")
                if match and match.lower() not in content_sample:
                    continue
                findings.append(
                    _make_finding(
                        "exposed_file",
                        item["severity"],
                        item["label"],
                        f"{item['label']} detected at {item['path']}.",
                        item["recommendation"],
                        source="exposed_file",
                        url=url,
                    )
                )
        finally:
            response.close()
    return findings


def _check_admin_endpoints(
    base_url: str,
    session: requests.Session,
    deadline: float,
) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for path in ADMIN_ENDPOINTS:
        if time.monotonic() >= deadline:
            break
        url = f"{base_url.rstrip('/')}{path}"
        response = _fetch_lightweight(session, url)
        if not response:
            continue
        try:
            if response.status_code in {200, 204}:
                severity = "medium"
            elif response.status_code in {301, 302}:
                severity = "low"
            elif response.status_code in {401, 403}:
                severity = "low"
            else:
                continue
            findings.append(
                _make_finding(
                    "admin_endpoint_exposed",
                    severity,
                    path,
                    f"Admin/default endpoint responded with {response.status_code}.",
                    "Ensure admin endpoints are protected and access-controlled.",
                    source="admin_endpoint",
                    url=url,
                )
            )
        finally:
            response.close()
    return findings


def _check_fingerprint(response: requests.Response, base_url: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    headers = response.headers
    fingerprint_values = []

    for header_name in ("Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"):
        value = headers.get(header_name)
        if value:
            fingerprint_values.append(f"{header_name}: {value}")
            findings.append(
                _make_finding(
                    "technology_fingerprint",
                    "low",
                    value,
                    f"{header_name} header reveals technology details.",
                    "Avoid exposing detailed server or framework versions.",
                    source="headers",
                    url=base_url,
                )
            )

    content_sample = response.text[:50000]
    generator_match = _find_meta_generator(content_sample)
    if generator_match:
        fingerprint_values.append(f"generator={generator_match}")
        findings.append(
            _make_finding(
                "technology_fingerprint",
                "low",
                generator_match,
                "HTML generator meta tag discloses technology details.",
                "Remove or sanitize generator meta tags in production.",
                source="content",
                url=base_url,
            )
        )

    if fingerprint_values:
        findings.extend(_check_outdated_versions(" ".join(fingerprint_values), base_url))

    return findings


def _check_outdated_versions(fingerprint: str, base_url: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for pattern in OUTDATED_TECH_PATTERNS:
        if not _regex_search(pattern["pattern"], fingerprint):
            continue
        findings.append(
            _make_finding(
                "outdated_technology",
                pattern["severity"],
                pattern["label"],
                pattern["label"],
                pattern["recommendation"],
                source="fingerprint",
                url=base_url,
            )
        )
    return findings


def _find_meta_generator(content: str) -> Optional[str]:
    match = _regex_search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', content, True)
    if not match:
        return None
    return match.group(1).strip()


def _fetch_lightweight(session: requests.Session, url: str) -> Optional[requests.Response]:
    try:
        return session.get(
            url,
            timeout=DEFAULT_REQUEST_TIMEOUT,
            allow_redirects=False,
            stream=True,
        )
    except requests.RequestException:
        return None


def _read_snippet(response: requests.Response, limit: int) -> str:
    try:
        content = b""
        for chunk in response.iter_content(chunk_size=512):
            if not chunk:
                break
            content += chunk
            if len(content) >= limit:
                break
        return content.decode(errors="ignore")
    except Exception:
        return ""


def _make_finding(
    finding_type: str,
    severity: str,
    value: str,
    details: str,
    recommendation: str,
    source: str,
    url: Optional[str],
) -> Dict[str, Any]:
    return {
        "type": finding_type,
        "severity": severity,
        "value": value,
        "details": details,
        "recommendation": recommendation,
        "source": source,
        "url": url,
    }


def _summarize_findings(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    summary = _empty_summary()
    summary["total_findings"] = len(findings)
    for finding in findings:
        severity = finding.get("severity", "low")
        if severity == "critical":
            summary["critical_severity"] += 1
        elif severity == "high":
            summary["high_severity"] += 1
        elif severity == "medium":
            summary["medium_severity"] += 1
        else:
            summary["low_severity"] += 1
    return summary


def _empty_summary() -> Dict[str, int]:
    return {
        "total_findings": 0,
        "critical_severity": 0,
        "high_severity": 0,
        "medium_severity": 0,
        "low_severity": 0,
    }


def _normalize_hosts(hosts: set) -> List[str]:
    normalized = {host.strip().lower().rstrip(".") for host in hosts if host}
    return sorted(normalized)


def _host_in_scope(host: Optional[str], allowed_domain: str) -> bool:
    if not host:
        return False
    host = host.strip().lower().rstrip(".")
    if host == allowed_domain:
        return True
    return host.endswith(f".{allowed_domain}")


def _is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _regex_search(pattern: str, text: str, return_match: bool = False):
    import re

    match = re.search(pattern, text, re.IGNORECASE)
    if return_match:
        return match
    return bool(match)
