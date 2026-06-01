"""Known-vulnerable frontend JavaScript library detection (retire.js-style).

The browser scanner reads the versions of libraries a page actually loads
(see ``__keyleak_library_scan`` in ``browser_scanner.py``). This module maps a
``(library, version)`` pair to publicly documented CVEs and builds ``appsec``
findings.

Detection is version-based, so findings are reported as ``lead``: a vulnerable
version is present, but whether the specific sink is reachable depends on how
the app uses the library. The signal is still high-value — shipping a decade-old
jQuery or an unpatched Bootstrap is a real, common exposure.

Only well-established, widely-cited CVEs for popular libraries are encoded. The
table is deliberately small and easy to extend; library/version come from the
page at runtime, CVE IDs are public, so nothing target-specific lives here.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from .models import Evidence, Finding, confidence_for_severity

Version = Tuple[int, int, int]

NVD_URL = "https://nvd.nist.gov/vuln/detail/{}"

# Severity rank for picking the worst across multiple matched rules.
_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Each library maps to a list of rules. A rule matches when the parsed version
# is >= ``introduced`` (inclusive, default 0.0.0) and < ``below`` (exclusive).
# A single version may match several rules; findings aggregate them.
VULN_TABLE: Dict[str, List[Dict[str, Any]]] = {
    "jquery": [
        {
            "below": (1, 9, 0),
            "severity": "high",
            "cves": ["CVE-2012-6708"],
            "summary": "jQuery < 1.9 cannot reliably tell a CSS selector from HTML, so $() on attacker-controlled input executes scripts (DOM XSS).",
        },
        {
            "below": (3, 0, 0),
            "severity": "high",
            "cves": ["CVE-2015-9251"],
            "summary": "jQuery < 3.0 auto-executes cross-domain AJAX responses served as text/javascript, enabling XSS.",
        },
        {
            "below": (3, 4, 0),
            "severity": "high",
            "cves": ["CVE-2019-11358"],
            "summary": "jQuery < 3.4 jQuery.extend(true, ...) is vulnerable to Object.prototype pollution.",
        },
        {
            "below": (3, 5, 0),
            "severity": "high",
            "cves": ["CVE-2020-11022", "CVE-2020-11023"],
            "summary": "jQuery < 3.5 htmlPrefilter regex can be bypassed, so .html()/.append() on untrusted HTML executes scripts (XSS).",
        },
    ],
    "bootstrap": [
        {
            "below": (3, 4, 1),
            "severity": "medium",
            "cves": ["CVE-2018-14041", "CVE-2019-8331"],
            "summary": "Bootstrap < 3.4.1 has XSS in data-target and tooltip/popover templates.",
        },
        {
            "introduced": (4, 0, 0),
            "below": (4, 1, 2),
            "severity": "medium",
            "cves": ["CVE-2018-14041"],
            "summary": "Bootstrap 4 < 4.1.2 has XSS in the scrollspy data-target attribute.",
        },
        {
            "introduced": (4, 0, 0),
            "below": (4, 3, 1),
            "severity": "medium",
            "cves": ["CVE-2019-8331"],
            "summary": "Bootstrap 4 < 4.3.1 has XSS in tooltip/popover data-template.",
        },
        {
            "introduced": (4, 0, 0),
            "below": (4, 6, 3),
            "severity": "medium",
            "cves": ["CVE-2024-6531"],
            "summary": "Bootstrap 4 (4.0.0–4.6.2) has XSS in the carousel data-slide / data-slide-to attributes.",
        },
    ],
}

# Latest safe major line per library, for remediation guidance.
_SAFE_TARGET = {"jquery": "3.7.1 or later", "bootstrap": "5.3.x or later"}


def parse_version(raw: Optional[str]) -> Optional[Version]:
    """Parse a loose version string into a (major, minor, patch) tuple.

    Tolerates a leading ``v``, pre-release/build suffixes (``3.5.0-beta``), and
    missing patch/minor (``2`` -> ``(2, 0, 0)``). Returns None when no numeric
    version can be recovered, so callers simply skip the library.
    """
    if not raw or not isinstance(raw, str):
        return None
    text = raw.strip().lstrip("vV")
    # Take the leading dotted-numeric run, ignoring any -beta/+build suffix.
    head = ""
    for ch in text:
        if ch.isdigit() or ch == ".":
            head += ch
        else:
            break
    parts = [p for p in head.split(".") if p != ""]
    if not parts:
        return None
    nums: List[int] = []
    for p in parts[:3]:
        try:
            nums.append(int(p))
        except ValueError:
            return None
    while len(nums) < 3:
        nums.append(0)
    return (nums[0], nums[1], nums[2])


def match_library_cves(name: str, version: Optional[str]) -> List[Dict[str, Any]]:
    """Return the vulnerability rules that apply to ``name``@``version``.

    Empty list when the library is unknown or the version is safe/unparseable.
    """
    rules = VULN_TABLE.get((name or "").strip().lower())
    if not rules:
        return []
    parsed = parse_version(version)
    if parsed is None:
        return []
    matched: List[Dict[str, Any]] = []
    for rule in rules:
        introduced = rule.get("introduced", (0, 0, 0))
        below = rule["below"]
        if introduced <= parsed < below:
            matched.append(rule)
    return matched


def _library_cve_findings(libraries: List[Dict[str, Any]], page_url: str) -> List[Finding]:
    """Build one ``appsec`` Finding per distinct vulnerable (library, version).

    ``libraries`` is the raw payload from ``__keyleak_library_scan``: dicts with
    ``name``, ``version``, ``source`` ('global'|'script-url'), and optional
    ``url``.
    """
    findings: List[Finding] = []
    seen: set = set()
    for lib in libraries or []:
        name = str((lib or {}).get("name") or "").strip().lower()
        version = (lib or {}).get("version")
        if not name or not version:
            continue
        key = (name, str(version))
        if key in seen:
            continue
        seen.add(key)

        matched = match_library_cves(name, version)
        if not matched:
            continue

        cves: List[str] = []
        for rule in matched:
            for cve in rule["cves"]:
                if cve not in cves:
                    cves.append(cve)
        severity = max((r["severity"] for r in matched), key=lambda s: _SEVERITY_RANK.get(s, 0))
        summary = " ".join(r["summary"] for r in matched)
        source = str(lib.get("url") or page_url or "")
        target = _SAFE_TARGET.get(name, "a current, supported release")

        findings.append(
            Finding(
                type="vulnerable_js_library",
                severity=severity,
                confidence=confidence_for_severity(severity),
                detector_id="appsec.vulnerable_js_library",
                source=source,
                evidence=Evidence(
                    source=source,
                    snippet=f"{name} {version} — {', '.join(cves)}",
                    redacted_value=f"{name} {version}",
                    request_url=page_url or "",
                ),
                risk_reason=(
                    f"{name} {version} is loaded and has known vulnerabilities ({', '.join(cves)}). {summary}"
                ),
                remediation=(
                    f"Upgrade {name} to {target} and re-test. Pin the dependency and "
                    "track advisories so vulnerable versions are not reintroduced."
                ),
                validation_status="lead",
                category="appsec",
                references=[NVD_URL.format(c) for c in cves],
            )
        )
    return findings
