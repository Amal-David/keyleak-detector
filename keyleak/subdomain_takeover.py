"""Subdomain-takeover detection.

A subdomain that still points (via DNS/CNAME) at a third-party service which no
longer claims it can be re-registered by an attacker, who then serves content
from your domain — phishing, cookie theft, CSP bypass, etc.

We detect the most reliable, low-false-positive signal: the *fingerprint* the
abandoned provider returns for an unclaimed host (e.g. S3's "NoSuchBucket",
GitHub Pages' "There isn't a GitHub Pages site here"). Fingerprints come from the
community ``can-i-take-over-xyz`` project. No DNS library is required — we fetch
the host and match the response body — and probes run concurrently so checking
many subdomains adds little wall-clock time.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Dict, List, Optional

from .models import Evidence, Finding, confidence_for_severity
from .proxy import requests_proxies

ProgressFn = Optional[Callable[[Dict[str, Any]], None]]

# service -> response-body signatures that indicate an unclaimed/danging target.
# Conservative subset chosen for low false positives; easy to extend.
TAKEOVER_FINGERPRINTS: Dict[str, List[str]] = {
    "AWS/S3": ["The specified bucket does not exist", "NoSuchBucket"],
    "GitHub Pages": [
        "There isn't a GitHub Pages site here.",
        "For root URLs (like http://example.com/) you must provide an index.html file",
    ],
    "Heroku": ["No such app", "herokucdn.com/error-pages/no-such-app.html"],
    "Fastly": ["Fastly error: unknown domain"],
    "Shopify": ["Sorry, this shop is currently unavailable"],
    "Bitbucket": ["Repository not found"],
    "Ghost": ["The thing you were looking for is no longer here, or never was"],
    "Surge.sh": ["project not found"],
    "Tilda": ["Please renew your subscription"],
    "Pantheon": ["The gods are wise, but do not know of the site which you seek"],
    "Cargo": ["If you're moving your domain away from Cargo"],
    "Help Scout": ["No settings were found for this company"],
    "Unbounce": ["The requested URL was not found on this server"],
    "Azure": ["404 Web Site not found"],
    "Netlify": ["Not Found - Request ID"],
}

_REFERENCES = [
    "https://github.com/EdOverflow/can-i-take-over-xyz",
    "https://owasp.org/www-community/attacks/Subdomain_Takeover",
]

DEFAULT_WORKERS = 16


def _probe_host(host: str, proxy: Optional[str], timeout: int) -> Optional[Finding]:
    """Fetch ``host`` and return a Finding if its body matches a takeover
    fingerprint, else None. Network/TLS errors are treated as "no signal"."""
    import requests
    from .net_guard import guarded_request, SSRFBlocked

    proxies = requests_proxies(proxy)
    body = None
    for scheme in ("https", "http"):
        try:
            # Subdomain names are partly sourced from CT logs (attacker-seedable),
            # so the probe target is attacker-influenced: guard the host and
            # re-validate redirect hops rather than following 3xx into an
            # internal address.
            resp = guarded_request(
                "GET",
                f"{scheme}://{host}",
                timeout=timeout,
                proxies=proxies,
                headers={"User-Agent": "keyleak-detector/subdomain-takeover"},
            )
            body = resp.text or ""
            break
        except SSRFBlocked:
            return None
        except requests.RequestException:
            continue
    if not body:
        return None

    for service, signatures in TAKEOVER_FINGERPRINTS.items():
        for sig in signatures:
            if sig in body:
                loc = f"https://{host}"
                return Finding(
                    type="subdomain_takeover",
                    severity="high",
                    confidence=confidence_for_severity("high"),
                    detector_id="appsec.subdomain_takeover",
                    source=loc,
                    evidence=Evidence(
                        source=loc,
                        snippet=f"{host} returns an unclaimed-{service} fingerprint",
                        redacted_value=f"{host} -> {service}",
                        request_url=loc,
                    ),
                    risk_reason=(
                        f"{host} still resolves to {service} but the target is unclaimed "
                        f"(\"{sig}\"). An attacker can register it and serve content from your "
                        "domain — phishing, cookie/session theft, and CSP/SSO bypass."
                    ),
                    remediation=(
                        f"Remove the dangling DNS record for {host}, or re-claim the {service} "
                        "resource it points to. Audit all CNAMEs for retired services."
                    ),
                    validation_status="lead",
                    category="appsec",
                    references=list(_REFERENCES),
                )
    return None


def check_subdomain_takeovers(
    hosts: List[str],
    *,
    proxy: Optional[str] = None,
    timeout: int = 8,
    max_workers: int = DEFAULT_WORKERS,
) -> List[Finding]:
    """Probe ``hosts`` concurrently for subdomain-takeover fingerprints.

    Returns one Finding per vulnerable host. Safe to run from a background
    thread alongside the Playwright crawl (uses ``requests`` only).
    """
    findings: List[Finding] = []
    unique = [h for h in dict.fromkeys(hosts) if h]
    if not unique:
        return findings
    workers = max(1, min(max_workers, len(unique)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_probe_host, h, proxy, timeout): h for h in unique}
        for fut in as_completed(futures):
            try:
                finding = fut.result()
            except Exception:
                finding = None
            if finding is not None:
                findings.append(finding)
    findings.sort(key=lambda f: f.source)
    return findings
