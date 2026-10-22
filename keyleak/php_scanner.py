"""Ordinary-response assessment of the October 2026 PHP advisories."""

from __future__ import annotations

import re
import shlex
from urllib.parse import urlsplit

import requests

from .models import Evidence, Finding, build_coverage
from .net_guard import url_block_reason
from .proxy import requests_proxies
from .redaction import redact_url
from .reporting import build_report


PHP_REFERENCE = "https://www.php.net/archive/2026.php#2026-10-21-5"
PHP_CVES = ["CVE-2026-109618", "CVE-2026-109619"]
PHP_FIXED = {(8, 2): 35, (8, 3): 36, (8, 4): 27, (8, 5): 12}


def assess_php_headers(headers, status_code=200):
    """A banner is a lead, never proof of the origin's installed patch level."""
    versions = set()
    php_seen = False
    for name, value in headers.items():
        if name.lower() not in {"server", "x-powered-by"}:
            continue
        text = str(value)[:4096]
        php_seen |= bool(re.search(r"\bPHP\b", text, re.I))
        versions.update(re.findall(r"\bPHP/([^\s;,()]+)", text, re.I))
    result = {"status": "unknown", "version": "", "cves": PHP_CVES,
              "reason": "No unambiguous PHP patch version was advertised. PHP may still be present."}
    if not 200 <= status_code < 300:
        result["reason"] = "The response was a redirect or error; the origin PHP patch level is unknown."
        return result
    if len(versions) != 1:
        if len(versions) > 1:
            result["reason"] = "Conflicting PHP banners; verify the deployed origin runtime."
        elif php_seen:
            result["reason"] = "PHP was advertised without a complete patch version."
        return result
    version = versions.pop()
    if not re.fullmatch(r"[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}", version):
        result["reason"] = "A vendor, prerelease, or incomplete PHP version needs vendor patch verification."
        return result
    result["version"] = version
    major, minor, patch = map(int, version.split("."))
    fixed_patch = PHP_FIXED.get((major, minor))
    if fixed_patch is not None:
        result["status"] = "patched_version_reported" if patch >= fixed_patch else "potentially_affected"
    elif major < 8 or (major == 8 and minor < 2):
        result["status"] = "potentially_affected"
    if result["status"] == "potentially_affected":
        result["reason"] = "The advertised version predates the upstream fixes. Vendor backports may apply."
    elif result["status"] == "patched_version_reported":
        result["reason"] = "The banner reports an upstream patched version; this does not verify the origin or every worker."
    else:
        result["reason"] = "This PHP release branch is outside the advisory snapshot; verify with its vendor."
    return result


def scan_php_url(url: str, *, proxy=None, offline=False):
    """Fetch one supplied public URL, without cookies, redirects, or body reads."""
    if offline:
        raise ValueError("PHP URL assessment requires network access and cannot run with --offline.")
    if not isinstance(url, str) or len(url) > 2048 or any(ord(c) < 33 for c in url):
        raise ValueError("Supply an HTTP(S) URL without whitespace.")
    try:
        parsed = urlsplit(url)
        valid = (parsed.scheme in {"http", "https"} and parsed.hostname and
                 parsed.username is None and parsed.password is None and not parsed.query and
                 not parsed.fragment and parsed.port in {None, 80, 443})
    except ValueError:
        valid = False
    if not valid:
        raise ValueError("Supply an HTTP(S) URL on port 80 or 443 without credentials, query, or fragment.")
    if url_block_reason(url, allow_private=False):
        raise ValueError("The PHP checker requires a resolvable public HTTP(S) target.")
    target = redact_url(url)
    try:
        with requests.Session() as session:
            session.trust_env = False  # Do not send ambient proxy settings or .netrc credentials.
            with session.get(url, allow_redirects=False, stream=True, timeout=(5, 10),
                             proxies=requests_proxies(proxy),
                             headers={"User-Agent": "KeyLeak-PHP-Assessment/1"}) as response:
                result = assess_php_headers(response.headers, response.status_code)
    except requests.RequestException:
        result = {"status": "unknown", "version": "", "cves": PHP_CVES,
                  "reason": "The HTTP/TLS request failed; no patch status could be established."}
    potential = result["status"] == "potentially_affected"
    evidence = result["version"] or result["status"]
    report = build_report(target, [Finding(
        type=f"PHP assessment: {result['status']}", severity="high" if potential else "medium",
        confidence=0.6, detector_id="incident:php-oct2026", source=target,
        evidence=Evidence(source=target, redacted_value=evidence, snippet=evidence),
        risk_reason=result["reason"],
        remediation=("Verify the serving runtime and all workers. Apply PHP 8.2.35, 8.3.36, "
                     "8.4.27, 8.5.12 or a vendor-confirmed backport, then restart workers. "
                     "Headers cannot establish that a site is safe; no exploit probe was performed."),
        category="appsec", references=[PHP_REFERENCE], validation_status="lead",
    )], scan_mode="php-check")
    report.extra["php_assessment"] = result
    unknown = result["status"] == "unknown"
    report.extra["coverage"] = build_coverage(
        "php_response_headers", 1, 0 if unknown else 1, skipped=1 if unknown else 0,
        reasons=[result["reason"]] if unknown else [],
    )
    report.retest_command = "keyleak php-check " + shlex.quote(target) + " --authorized"
    return report
