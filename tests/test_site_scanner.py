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

    def test_proxy_is_passed_to_requests(self):
        captured = {}

        def fake_get(*a, **k):
            captured.update(k)
            return _FakeResp([])

        with mock.patch.object(ss.requests, "get", side_effect=fake_get):
            ss._crt_sh_subdomains("example.com", proxy="socks5://127.0.0.1:40000")
        self.assertEqual(
            captured["proxies"],
            {"http": "socks5://127.0.0.1:40000", "https": "socks5://127.0.0.1:40000"},
        )

    def test_no_proxy_passes_none(self):
        captured = {}

        def fake_get(*a, **k):
            captured.update(k)
            return _FakeResp([])

        with mock.patch.object(ss.requests, "get", side_effect=fake_get):
            ss._crt_sh_subdomains("example.com")
        self.assertIsNone(captured["proxies"])


class DiscoverTests(unittest.TestCase):
    def test_offline_uses_no_network_and_fills_sources(self):
        def fail(*a, **k):
            raise AssertionError("offline mode must not touch network or install")
        with mock.patch.object(ss, "_crt_sh_subdomains", fail), \
             mock.patch.object(ss, "_subfinder_subdomains", fail), \
             mock.patch.object(ss, "_amass_subdomains", fail), \
             mock.patch.object(ss, "_ensure_subfinder", fail), \
             mock.patch.object(ss, "_resolves", fail):
            sources = {}
            out = ss.discover_subdomains("example.com", offline=True, sources_out=sources)
        self.assertEqual(out, ["example.com"])
        # offline still returns a consistent discovery_sources structure
        self.assertEqual(sources["by_host"], {"example.com": "apex"})
        self.assertEqual(sources["kept"], {"apex": 1})

    def test_caps_and_requires_resolution(self):
        with mock.patch.object(ss, "_subfinder_subdomains", lambda d: []), \
             mock.patch.object(ss, "_amass_subdomains", lambda d: []), \
             mock.patch.object(ss, "_crt_sh_subdomains",
                               lambda d, **k: [f"s{i}.example.com" for i in range(50)]), \
             mock.patch.object(ss, "_resolves", lambda h: True):
            out = ss.discover_subdomains("example.com", max_subdomains=5)
        self.assertEqual(len(out), 5)
        self.assertEqual(out[0], "example.com")     # apex leads

    def test_amass_unioned_with_source_attribution(self):
        with mock.patch.object(ss, "_subfinder_subdomains", lambda d: []), \
             mock.patch.object(ss, "_amass_subdomains", lambda d: ["a.example.com"]), \
             mock.patch.object(ss, "_crt_sh_subdomains", lambda d, **k: ["b.example.com"]), \
             mock.patch.object(ss, "_resolves", lambda h: True):
            sources = {}
            out = ss.discover_subdomains("example.com", sources_out=sources)
        # amass hits are unioned alongside crt.sh
        self.assertIn("a.example.com", out)
        self.assertIn("b.example.com", out)
        # each kept host is attributed to the source that surfaced it
        self.assertEqual(sources["by_host"]["a.example.com"], "amass")
        self.assertEqual(sources["by_host"]["b.example.com"], "crt.sh")
        self.assertEqual(sources["by_host"]["example.com"], "apex")
        # per-source candidate + kept counts are reported
        self.assertEqual(sources["candidates"]["amass"], 1)
        self.assertEqual(sources["candidates"]["crt.sh"], 1)
        self.assertGreaterEqual(sources["kept"].get("amass", 0), 1)


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
            raise RuntimeError(f"playwright exploded for {url} owner jane.doe@example.com")

        with mock.patch.object(ss, "discover_subdomains", lambda d, **k: ["example.com"]), \
             mock.patch.object(
                 ss,
                 "crawl_pages",
                 lambda hosts, **k: ["https://example.com/?token=supersecretvalue-long"],
             ), \
             mock.patch.object(ss, "run_browser_scan", boom):
            report = ss.scan_site("example.com")   # must not raise
        self.assertEqual(report.findings, [])
        self.assertEqual(report.extra["pages_scanned"], 1)
        self.assertEqual(report.extra["pages_failed"], 1)
        self.assertEqual(report.extra["scan_failures"][0]["error"], "RuntimeError during page scan")
        self.assertIn("[redacted]", report.extra["scan_failures"][0]["url"])
        self.assertNotIn("supersecretvalue", report.extra["scan_failures"][0]["url"])
        self.assertNotIn("jane.doe@example.com", report.extra["scan_failures"][0]["error"])

    def test_proxy_threaded_to_crawl_and_browser_scan(self):
        seen = {}

        def fake_crawl(hosts, **k):
            seen["crawl_proxy"] = k.get("proxy")
            return ["https://example.com/"]

        def fake_scan(url, **k):
            seen["scan_proxy"] = k.get("proxy")
            return ScanReport(target=url, scan_mode="browser", findings=[])

        with mock.patch.object(ss, "discover_subdomains", lambda d, **k: ["example.com"]), \
             mock.patch.object(ss, "crawl_pages", fake_crawl), \
             mock.patch.object(ss, "run_browser_scan", fake_scan):
            ss.scan_site("example.com", proxy="warp-resolved")

        self.assertEqual(seen["crawl_proxy"], "warp-resolved")
        self.assertEqual(seen["scan_proxy"], "warp-resolved")

    def test_normalizes_url_to_registrable_domain(self):
        captured = {}

        def fake_discover(domain, **kwargs):
            captured["domain"] = domain
            return [domain]

        with mock.patch.object(ss, "discover_subdomains", fake_discover), \
             mock.patch.object(ss, "crawl_pages", lambda hosts, **k: []), \
             mock.patch.object(ss, "run_browser_scan",
                               lambda url, **k: ScanReport(target=url, scan_mode="browser", findings=[])):
            report = ss.scan_site("https://user:pass@app.example.com:8443/dashboard")

        # Credentials/port stripped, reduced to the registrable domain (eTLD+1).
        self.assertEqual(captured["domain"], "example.com")
        self.assertEqual(report.target, "example.com")


class AutoInstallTests(unittest.TestCase):
    def test_present_subfinder_skips_install(self):
        with mock.patch.object(ss.shutil, "which",
                               side_effect=lambda n: "/usr/bin/subfinder" if n == "subfinder" else None), \
             mock.patch.object(ss.subprocess, "run",
                               side_effect=AssertionError("must not install when present")):
            self.assertTrue(ss._ensure_subfinder(auto_install=True))

    def test_no_install_when_opted_out(self):
        with mock.patch.object(ss.shutil, "which", lambda n: None), \
             mock.patch.object(ss.subprocess, "run",
                               side_effect=AssertionError("must not install when opted out")):
            self.assertFalse(ss._ensure_subfinder(auto_install=False))

    def test_env_opt_out_blocks_install(self):
        with mock.patch.object(ss.shutil, "which", lambda n: None), \
             mock.patch.dict(ss.os.environ, {"KEYLEAK_NO_AUTO_INSTALL": "1"}), \
             mock.patch.object(ss.subprocess, "run",
                               side_effect=AssertionError("env opt-out must block install")):
            self.assertFalse(ss._ensure_subfinder(auto_install=True))

    def test_env_value_zero_does_not_block(self):
        # Only explicit truthy values opt out; "0"/"false" must NOT block install.
        calls = []

        def fake_run(cmd, *a, **k):
            calls.append(cmd)

            class _R:
                returncode, stdout, stderr = 0, "", ""

            return _R()

        with mock.patch.object(ss.shutil, "which",
                               lambda n: "/opt/homebrew/bin/brew" if n == "brew" else None), \
             mock.patch.dict(ss.os.environ, {"KEYLEAK_NO_AUTO_INSTALL": "0"}), \
             mock.patch.object(ss.subprocess, "run", fake_run):
            ss._ensure_subfinder(auto_install=True)
        self.assertTrue(any("brew" in c for c in calls),
                        "KEYLEAK_NO_AUTO_INSTALL=0 must not block auto-install")

    def test_discover_threads_auto_install_flag(self):
        captured = {}

        def fake_ensure(*, auto_install, on_progress=None):
            captured["auto_install"] = auto_install
            return False

        with mock.patch.object(ss, "_ensure_subfinder", fake_ensure), \
             mock.patch.object(ss, "_subfinder_subdomains", lambda d: []), \
             mock.patch.object(ss, "_amass_subdomains", lambda d: []), \
             mock.patch.object(ss, "_crt_sh_subdomains", lambda d, **k: []), \
             mock.patch.object(ss, "_resolves", lambda h: True):
            ss.discover_subdomains("example.com", auto_install=True)
        self.assertTrue(captured["auto_install"])


if __name__ == "__main__":
    unittest.main()
