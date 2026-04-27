import json
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path

from keyleak.cli import _scan_request_payload
from keyleak.local_scanner import scan_file, scan_path
from keyleak.detectors import DETECTORS
from keyleak.local_scanner import _is_placeholder
from keyleak.models import Finding, Evidence, ScanReport, finding_from_legacy
from keyleak.redaction import redact_value
from keyleak.reporting import build_report, fail_threshold_met, format_sarif
from keyleak.suppressions import apply_suppressions, load_suppressions


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

    def test_attack_vector_findings_contribute_to_report_summary(self):
        report = build_report(
            "https://preview.example.com",
            [],
            scan_mode="basic",
            attack_vectors={
                "subdomains": [
                    {
                        "host": "preview.example.com",
                        "url": "https://preview.example.com/admin",
                        "findings": [
                            {
                                "type": "exposed_admin",
                                "severity": "high",
                                "details": "Admin panel exposed.",
                            }
                        ],
                    }
                ]
            },
        )

        self.assertEqual(report.summary["total_findings"], 1)
        self.assertEqual(report.summary["high_severity"], 1)
        self.assertEqual(report.verdict["status"], "BLOCK_SHIP")

    def test_retest_command_quotes_local_paths(self):
        report = build_report("/tmp/my repo", [], scan_mode="local")

        self.assertEqual(report.retest_command, "keyleak local '/tmp/my repo'")

    def test_report_round_trips_server_payload(self):
        report = build_report("https://preview.example.com", [], scan_mode="basic")
        payload = report.to_dict()
        payload["generated_at"] = "2026-04-24T00:00:00+00:00"
        payload["future_enrichment"] = {"kept": True}

        restored = ScanReport.from_dict(payload)

        self.assertEqual(restored.generated_at, "2026-04-24T00:00:00+00:00")
        self.assertEqual(restored.to_dict()["future_enrichment"], {"kept": True})

    def test_legacy_finding_preserves_falsy_values(self):
        finding = finding_from_legacy(
            {
                "type": "token",
                "severity": "low",
                "source": "fixture",
                "value": None,
                "match": "real-token-value-abcdefghijklmnopqrstuvwxyz",
                "confidence": 0,
            }
        )

        self.assertEqual(finding.confidence, 0)
        self.assertEqual(finding.evidence.redacted_value, "real-t...[redacted]...wxyz")

    def test_finding_ids_include_location(self):
        first = Finding(
            type="token",
            severity="high",
            confidence=0.9,
            detector_id="test:token",
            source="fixture",
            evidence=Evidence(source="fixture", line=1, redacted_value="token"),
            risk_reason="risk",
            remediation="fix",
        )
        second = Finding(
            type="token",
            severity="high",
            confidence=0.9,
            detector_id="test:token",
            source="fixture",
            evidence=Evidence(source="fixture", line=2, redacted_value="token"),
            risk_reason="risk",
            remediation="fix",
        )

        self.assertNotEqual(first.id, second.id)


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

    def test_placeholder_filter_does_not_drop_stripe_test_keys(self):
        self.assertFalse(_is_placeholder("sk_test_4eC39HqLyjWDarjtT1zdp7dc"))
        self.assertTrue(_is_placeholder("test-placeholder-value"))

    def test_graphql_type_hint_is_not_filtered_as_short_placeholder(self):
        detector = _detector("graphql_introspection_hint")
        with tempfile.NamedTemporaryFile("w", suffix=".html") as handle:
            handle.write("query { __type(name: \"User\") { name } }")
            handle.flush()

            findings = scan_file(Path(handle.name), [detector])

        self.assertEqual([finding.type for finding in findings], ["graphql_introspection_hint"])

    def test_unknown_allowlist_prefix_fails_loudly(self):
        with tempfile.NamedTemporaryFile("w") as handle:
            handle.write("detctor:local:openai_api_key\n")
            handle.flush()

            with self.assertRaises(ValueError):
                load_suppressions(handle.name)


class DetectorTests(unittest.TestCase):
    def test_private_key_detector_matches_pkcs8(self):
        detector = _detector("private_key")
        content = "-----BEGIN PRIVATE KEY-----\nabc123\n-----END PRIVATE KEY-----"

        self.assertIsNotNone(detector.compile().search(content))

    def test_source_map_detector_is_bounded_per_reference(self):
        detector = _detector("source_map_reference")
        content = "sourceMappingURL=a.js.map\nmiddle\nsourceMappingURL=b.js.map"
        matches = [match.group(0) for match in detector.compile().finditer(content)]

        self.assertEqual(matches, ["sourceMappingURL=a.js.map", "sourceMappingURL=b.js.map"])

    def test_docker_category_selects_secret_detectors(self):
        docker_detectors = {detector.id for detector in DETECTORS if "docker" in detector.categories}

        self.assertIn("openai_api_key", docker_detectors)

    def test_mcp_config_detector_does_not_bridge_lines(self):
        detector = _detector("mcp_config_secret")
        unrelated_lines = "server configuration\nTOKEN=abcdefghijklmnopqrstuvwx1234567890"
        same_line = "mcp server token=abcdefghijklmnopqrstuvwx1234567890"

        self.assertIsNone(detector.compile().search(unrelated_lines))
        self.assertIsNotNone(detector.compile().search(same_line))


class CliTests(unittest.TestCase):
    def test_authenticated_profile_without_credentials_uses_no_auth_mode(self):
        payload = _scan_request_payload(
            Namespace(
                url="https://preview.example.com",
                profile="authenticated",
                bearer="",
                cookie="",
            )
        )

        self.assertEqual(payload["scan_mode"], "extensive")
        self.assertEqual(payload["auth_config"]["mode"], "none")

    def test_scan_payload_auth_mode_matches_supplied_credentials(self):
        payload = _scan_request_payload(
            Namespace(
                url="https://preview.example.com",
                profile="browser",
                bearer=" token ",
                cookie=" session=abc ",
            )
        )

        self.assertEqual(payload["scan_mode"], "extensive")
        self.assertEqual(payload["auth_config"]["mode"], "both")
        self.assertEqual(payload["auth_config"]["bearer_token"], "token")
        self.assertEqual(payload["auth_config"]["cookie"], "session=abc")


def _detector(detector_id):
    for detector in DETECTORS:
        if detector.id == detector_id:
            return detector
    raise AssertionError(f"missing detector {detector_id}")


if __name__ == "__main__":
    unittest.main()
