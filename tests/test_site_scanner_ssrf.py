"""scan_site's target_guard must keep internal hosts out of crawl/scan/takeover."""

from __future__ import annotations

import unittest
from unittest import mock

import keyleak.site_scanner as ss
from keyleak.models import ScanReport


def _guard(host):
    return "internal" if host == "internal.example.test" else None


class SiteScannerSSRFTests(unittest.TestCase):
    def test_guard_filters_subdomains_before_crawl_and_takeover(self):
        seen = {}

        def fake_crawl(hosts, **kwargs):
            seen["crawl_hosts"] = list(hosts)
            return []

        def fake_takeover(hosts, **kwargs):
            seen["takeover_hosts"] = list(hosts)
            return []

        with mock.patch.object(ss, "discover_subdomains",
                               lambda d, **k: ["safe.example.test", "internal.example.test"]), \
             mock.patch.object(ss, "crawl_pages", fake_crawl), \
             mock.patch.object(ss, "run_browser_scan",
                               lambda u, **k: ScanReport(target=u, scan_mode="browser", findings=[])), \
             mock.patch("keyleak.subdomain_takeover.check_subdomain_takeovers", fake_takeover):
            ss.scan_site("example.test", target_guard=_guard)

        self.assertIn("safe.example.test", seen["crawl_hosts"])
        self.assertNotIn("internal.example.test", seen["crawl_hosts"])
        # The parallel takeover check must also only see the safe host.
        self.assertNotIn("internal.example.test", seen["takeover_hosts"])

    def test_no_guard_keeps_all_hosts(self):
        seen = {}
        with mock.patch.object(ss, "discover_subdomains",
                               lambda d, **k: ["a.example.test", "b.example.test"]), \
             mock.patch.object(ss, "crawl_pages",
                               lambda hosts, **k: seen.setdefault("hosts", list(hosts)) or []), \
             mock.patch.object(ss, "run_browser_scan",
                               lambda u, **k: ScanReport(target=u, scan_mode="browser", findings=[])), \
             mock.patch("keyleak.subdomain_takeover.check_subdomain_takeovers", lambda *a, **k: []):
            ss.scan_site("example.test")
        self.assertEqual(set(seen["hosts"]), {"a.example.test", "b.example.test"})


if __name__ == "__main__":
    unittest.main()
