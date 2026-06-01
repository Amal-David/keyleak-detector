"""Tests for crawl-time dangerous-URL-parameter detection (site_scanner)."""

from __future__ import annotations

import unittest
from unittest import mock

import keyleak.site_scanner as ss
from keyleak.models import ScanReport


class DangerousParamFindingTests(unittest.TestCase):
    def _by_loc(self, urls):
        return {f.source: f for f in ss._dangerous_param_findings(set(urls))}

    def test_flags_cmd_on_server_endpoint_as_high(self):
        found = self._by_loc(["https://h.example.test/Eval/QP.aspx?cmd=whoami"])
        f = found["https://h.example.test/Eval/QP.aspx"]
        self.assertEqual(f.type, "dangerous_url_parameter")
        self.assertEqual(f.detector_id, "appsec.dangerous_url_param")
        self.assertEqual(f.severity, "high")
        self.assertEqual(f.validation_status, "lead")
        self.assertEqual(f.evidence.redacted_value, "cmd")

    def test_non_exec_endpoint_is_medium(self):
        found = self._by_loc(["https://h.example.test/api?exec=ls&token=abc"])
        self.assertEqual(found["https://h.example.test/api"].severity, "medium")

    def test_ignores_benign_params(self):
        self.assertEqual(ss._dangerous_param_findings({"https://h.example.test/p?id=5"}), [])
        self.assertEqual(ss._dangerous_param_findings({"https://h.example.test/s?q=hi"}), [])

    def test_does_not_echo_param_values(self):
        # The query value (a possible payload) must not appear in the finding.
        found = self._by_loc(["https://h.example.test/x.php?command=rm%20-rf%20%2F"])
        f = found["https://h.example.test/x.php"]
        self.assertNotIn("rm", f.evidence.snippet)
        self.assertNotIn("rm", f.evidence.redacted_value)

    def test_dedupes_same_endpoint_and_params(self):
        urls = [
            "https://h.example.test/x.aspx?cmd=a",
            "https://h.example.test/x.aspx?cmd=b",  # same host/path/param
        ]
        self.assertEqual(len(ss._dangerous_param_findings(set(urls))), 1)


class ScanSiteWiringTests(unittest.TestCase):
    def test_dangerous_params_reach_the_report(self):
        def fake_crawl(hosts, **kwargs):
            collect = kwargs.get("collect_raw")
            if collect is not None:
                collect.add("https://h.example.test/Eval/QP.aspx?cmd=whoami")
            return ["https://h.example.test/"]

        with mock.patch.object(ss, "discover_subdomains", lambda d, **k: ["h.example.test"]), \
             mock.patch.object(ss, "crawl_pages", fake_crawl), \
             mock.patch.object(ss, "run_browser_scan",
                               lambda url, **k: ScanReport(target=url, scan_mode="browser", findings=[])):
            report = ss.scan_site("example.test")

        types = [f.type for f in report.findings]
        self.assertIn("dangerous_url_parameter", types)


if __name__ == "__main__":
    unittest.main()
