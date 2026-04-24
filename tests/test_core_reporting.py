import json
import tempfile
import unittest

from keyleak.local_scanner import scan_path
from keyleak.models import Finding, Evidence
from keyleak.redaction import redact_value
from keyleak.reporting import build_report, fail_threshold_met, format_sarif
from keyleak.suppressions import apply_suppressions


class ReportingTests(unittest.TestCase):
    def test_redacts_long_values(self):
        self.assertEqual(redact_value("sk-proj-abcdefghijklmnopqrstuvwxyz"), "sk-pro...[redacted]...wxyz")

    def test_report_blocks_ship_on_high_findings(self):
        finding = Finding(
            type="openai_api_key",
            severity="critical",
            confidence=0.95,
            detector_id="test:openai_api_key",
            source="fixture",
            evidence=Evidence(source="fixture", redacted_value="sk-pro...[redacted]...wxyz"),
            risk_reason="OpenAI API key exposed.",
            remediation="Rotate the key.",
        )
        report = build_report("https://preview.example.com", [finding], scan_mode="browser")

        self.assertEqual(report.verdict["status"], "BLOCK_SHIP")
        self.assertTrue(fail_threshold_met(report, "high"))
        self.assertIn("sarif", format_sarif(report).lower())


class LocalScannerTests(unittest.TestCase):
    def test_vulnerable_fixture_produces_actionable_report(self):
        report = scan_path("fixtures/vulnerable-demo")
        finding_types = [finding.type for finding in report.findings]

        self.assertEqual(report.verdict["status"], "BLOCK_SHIP")
        self.assertIn("openai_api_key", finding_types)
        self.assertIn("database_url", finding_types)
        self.assertIn("openrouter_api_key", finding_types)
        self.assertIn("mcp_config_secret", finding_types)
        self.assertIn("graphql_introspection_hint", finding_types)
        self.assertIn("hidden_prompt_injection", finding_types)
        self.assertIn("source_map_reference", finding_types)
        openai_sources = [finding.source for finding in report.findings if finding.type == "openai_api_key"]
        self.assertFalse(any(source.endswith("app.js.map") for source in openai_sources))
        self.assertTrue(all("[redacted]" in finding.evidence.redacted_value for finding in report.findings))

    def test_baseline_suppresses_known_findings(self):
        report = scan_path("fixtures/vulnerable-demo")
        baseline = {"findings": [finding.to_dict() for finding in report.findings]}

        with tempfile.NamedTemporaryFile("w", suffix=".json") as handle:
            json.dump(baseline, handle)
            handle.flush()
            filtered = apply_suppressions(report, baseline_path=handle.name)

        self.assertEqual(filtered.verdict["status"], "SAFE_TO_SHIP")
        self.assertEqual(filtered.findings, [])


if __name__ == "__main__":
    unittest.main()
