"""Tests for parallel subdomain-takeover detection."""

from __future__ import annotations

import unittest
from unittest import mock

import requests

import keyleak.subdomain_takeover as st
import keyleak.site_scanner as ss
from keyleak.models import ScanReport


class _Resp:
    def __init__(self, text):
        self.text = text


class ProbeHostTests(unittest.TestCase):
    # _probe_host does a local ``import requests``, so patch the real global.
    def test_flags_known_fingerprint(self):
        body = "<html><body>There isn't a GitHub Pages site here.</body></html>"
        with mock.patch("requests.get", return_value=_Resp(body)):
            finding = st._probe_host("app.example.test", None, 8)
        self.assertIsNotNone(finding)
        self.assertEqual(finding.type, "subdomain_takeover")
        self.assertEqual(finding.severity, "high")
        self.assertEqual(finding.detector_id, "appsec.subdomain_takeover")
        self.assertIn("GitHub Pages", finding.evidence.redacted_value)

    def test_benign_body_yields_nothing(self):
        with mock.patch("requests.get", return_value=_Resp("<html>Welcome to our app</html>")):
            self.assertIsNone(st._probe_host("ok.example.test", None, 8))

    def test_network_error_is_no_signal(self):
        with mock.patch("requests.get", side_effect=requests.RequestException("boom")):
            self.assertIsNone(st._probe_host("dead.example.test", None, 8))


class CheckSubdomainTakeoversTests(unittest.TestCase):
    def test_runs_over_all_hosts_and_collects(self):
        def fake_probe(host, proxy, timeout):
            from keyleak.models import Evidence, Finding
            if host == "vuln.example.test":
                return Finding(
                    type="subdomain_takeover", severity="high", confidence=0.9,
                    detector_id="appsec.subdomain_takeover", source=f"https://{host}",
                    evidence=Evidence(source=f"https://{host}", redacted_value=f"{host} -> AWS/S3"),
                    risk_reason="x", remediation="y", validation_status="lead", category="appsec",
                )
            return None

        with mock.patch.object(st, "_probe_host", side_effect=fake_probe):
            findings = st.check_subdomain_takeovers(
                ["ok.example.test", "vuln.example.test", "ok.example.test"], max_workers=4
            )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].source, "https://vuln.example.test")

    def test_empty_hosts(self):
        self.assertEqual(st.check_subdomain_takeovers([]), [])


class ScanSiteWiringTests(unittest.TestCase):
    def test_takeover_findings_reach_the_report(self):
        from keyleak.models import Evidence, Finding
        fake_finding = Finding(
            type="subdomain_takeover", severity="high", confidence=0.9,
            detector_id="appsec.subdomain_takeover", source="https://t.example.test",
            evidence=Evidence(source="https://t.example.test", redacted_value="t.example.test -> Heroku"),
            risk_reason="x", remediation="y", validation_status="lead", category="appsec",
        )
        with mock.patch.object(ss, "discover_subdomains", lambda d, **k: ["t.example.test"]), \
             mock.patch.object(ss, "crawl_pages", lambda hosts, **k: ["https://t.example.test/"]), \
             mock.patch.object(ss, "run_browser_scan",
                               lambda url, **k: ScanReport(target=url, scan_mode="browser", findings=[])), \
             mock.patch("keyleak.subdomain_takeover.check_subdomain_takeovers",
                        return_value=[fake_finding]):
            report = ss.scan_site("example.test")

        self.assertIn("subdomain_takeover", [f.type for f in report.findings])
        self.assertEqual(report.extra["subdomain_takeovers"], 1)

    def test_offline_skips_takeover(self):
        with mock.patch.object(ss, "discover_subdomains", lambda d, **k: ["x.example.test"]), \
             mock.patch.object(ss, "crawl_pages", lambda hosts, **k: []), \
             mock.patch.object(ss, "run_browser_scan",
                               lambda url, **k: ScanReport(target=url, scan_mode="browser", findings=[])), \
             mock.patch("keyleak.subdomain_takeover.check_subdomain_takeovers") as chk:
            report = ss.scan_site("example.test", offline=True)
        chk.assert_not_called()
        self.assertEqual(report.extra["subdomain_takeovers"], 0)


if __name__ == "__main__":
    unittest.main()
