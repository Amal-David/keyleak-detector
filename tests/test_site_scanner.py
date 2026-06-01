"""Tests for the Full Site Scan engine (keyleak/site_scanner.py).

All network and browser access is mocked — no real DNS, HTTP, or Playwright.
Uses unittest to match the repo's existing test style.
"""

from __future__ import annotations

import unittest
from unittest import mock

import keyleak.site_scanner as ss
from keyleak.models import Evidence, Finding, ScanReport


def _finding(value: str, type_: str = "openai_api_key", sev: str = "critical") -> Finding:
    return Finding(
        type=type_,
        severity=sev,
        confidence=0.9,
        detector_id="leak.openai_api_key",
        source="bundle",
        evidence=Evidence(source="bundle", redacted_value=value),
        risk_reason="exposed key",
        remediation="rotate it",
    )


class _FakeResp:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


class CrtShTests(unittest.TestCase):
    def test_parses_filters_and_dedups(self):
        payload = [
            {"name_value": "a.example.com\n*.b.example.com"},
            {"name_value": "example.com\nexample.com"},   # dup + apex
            {"name_value": "mail@example.com"},            # email — dropped
            {"name_value": "evil.com\nnotexample.com"},    # out of scope
        ]
        with mock.patch.object(ss.requests, "get", return_value=_FakeResp(payload)):
            out = ss._crt_sh_subdomains("example.com")
        self.assertIn("a.example.com", out)
        self.assertIn("b.example.com", out)        # leading "*." stripped
        self.assertIn("example.com", out)
        self.assertEqual(out.count("example.com"), 1)
        self.assertNotIn("evil.com", out)
        self.assertNotIn("notexample.com", out)
        self.assertFalse(any("@" in n for n in out))

    def test_degrades_on_network_error(self):
        with mock.patch.object(ss.requests, "get",
                               side_effect=ss.requests.RequestException("no net")):
            self.assertEqual(ss._crt_sh_subdomains("example.com"), [])


class DiscoverTests(unittest.TestCase):
    def test_offline_uses_no_network(self):
        def fail(*a, **k):
            raise AssertionError("network must not be touched in offline mode")
        with mock.patch.object(ss, "_crt_sh_subdomains", fail), \
             mock.patch.object(ss, "_subfinder_subdomains", fail), \
             mock.patch.object(ss, "_resolves", fail):
            self.assertEqual(ss.discover_subdomains("example.com", offline=True),
                             ["example.com"])

    def test_caps_and_requires_resolution(self):
        with mock.patch.object(ss, "_subfinder_subdomains", lambda d: []), \
             mock.patch.object(ss, "_crt_sh_subdomains",
                               lambda d, **k: [f"s{i}.example.com" for i in range(50)]), \
             mock.patch.object(ss, "_resolves", lambda h: True):
            out = ss.discover_subdomains("example.com", max_subdomains=5)
        self.assertEqual(len(out), 5)
        self.assertEqual(out[0], "example.com")     # apex leads


class FilterLinksTests(unittest.TestCase):
    def test_scope_dedup_and_normalize(self):
        seen = {"https://example.com"}
        links = [
            "https://example.com/pricing",
            "https://app.example.com/login",      # subdomain — in registrable scope
            "https://evil.com/phish",             # out of scope
            "ftp://example.com/file",             # non-http
            "https://example.com/pricing#frag",   # dup after normalize
            "https://example.com/about",
        ]
        out = ss._filter_links(links, "example.com", seen, remaining=10)
        self.assertIn("https://example.com/pricing", out)
        self.assertIn("https://app.example.com/login", out)
        self.assertIn("https://example.com/about", out)
        self.assertTrue(all("evil.com" not in u for u in out))
        self.assertTrue(all(not u.startswith("ftp") for u in out))
        self.assertEqual(sum(u == "https://example.com/pricing" for u in out), 1)

    def test_respects_remaining(self):
        out = ss._filter_links(
            ["https://example.com/a", "https://example.com/b", "https://example.com/c"],
            "example.com", set(), remaining=2,
        )
        self.assertEqual(len(out), 2)


class ScanSiteTests(unittest.TestCase):
    def test_merges_findings_with_provenance(self):
        urls = [
            "https://example.com/",
            "https://example.com/pricing",
            "https://api.example.com/",
        ]

        def fake_scan(url, **kwargs):
            if url.startswith("https://api."):
                findings = [_finding("sk-BBB", type_="stripe_secret_key")]
            else:
                findings = [_finding("sk-AAA")]
            return ScanReport(target=url, scan_mode="browser", findings=findings)

        with mock.patch.object(ss, "discover_subdomains",
                               lambda d, **k: ["example.com", "api.example.com"]), \
             mock.patch.object(ss, "crawl_pages", lambda hosts, **k: urls), \
             mock.patch.object(ss, "run_browser_scan", fake_scan):
            report = ss.scan_site("https://example.com")

        self.assertEqual(len(report.findings), 2)
        self.assertEqual(report.scan_mode, "full-site")
        self.assertEqual(report.extra["pages_scanned"], 3)
        self.assertEqual(report.extra["subdomains"], ["example.com", "api.example.com"])

        prov = report.extra["provenance"]
        shared = next(f for f in report.findings if f.evidence.redacted_value == "sk-AAA")
        self.assertEqual(sorted(prov[shared.id]),
                         ["https://example.com/", "https://example.com/pricing"])

    def test_handles_page_scan_errors(self):
        def boom(url, **kwargs):
            raise RuntimeError("playwright exploded")

        with mock.patch.object(ss, "discover_subdomains", lambda d, **k: ["example.com"]), \
             mock.patch.object(ss, "crawl_pages", lambda hosts, **k: ["https://example.com/"]), \
             mock.patch.object(ss, "run_browser_scan", boom):
            report = ss.scan_site("example.com")   # must not raise
        self.assertEqual(report.findings, [])
        self.assertEqual(report.extra["pages_scanned"], 1)


if __name__ == "__main__":
    unittest.main()
