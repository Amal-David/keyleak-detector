import json
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path

from keyleak.access_control import compare_access_control_urls
from keyleak.cli import _scan_request_payload
from keyleak.extension_bundle import extension_pattern_payload, extension_patterns_js
from keyleak.local_scanner import scan_file, scan_path
from keyleak.detectors import DETECTORS, DETECTOR_PACKS, HEATMAP_ROWS, detectors_for_packs, normalize_packs
from keyleak.local_scanner import _is_placeholder
from keyleak.models import Finding, Evidence, ScanReport, finding_from_legacy
from keyleak.redaction import redact_value
from keyleak.reporting import build_report, fail_threshold_met, format_html, format_sarif
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
        self.assertEqual(report.to_dict()["profile"], "launch-gate")

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


class HtmlReportTests(unittest.TestCase):
    def test_html_report_contains_structure(self):
        findings = [
            Finding(
                type="openai_api_key",
                severity="critical",
                confidence=0.95,
                detector_id="leak:openai_api_key",
                source="fixture.js",
                evidence=Evidence(source="fixture.js", redacted_value="sk-pro...[redacted]...wxyz"),
                risk_reason="OpenAI API key exposed in client bundle.",
                remediation="Rotate the key immediately.",
                validation_status="confirmed",
                category="leak",
            ),
            Finding(
                type="database_url",
                severity="high",
                confidence=0.9,
                detector_id="leak:database_url",
                source=".env",
                evidence=Evidence(source=".env", redacted_value="postgres://...[redacted]...5432/db"),
                risk_reason="Database connection string exposed.",
                remediation="Move to environment variable and rotate credentials.",
                validation_status="lead",
                category="leak",
            ),
            Finding(
                type="wide_open_cors",
                severity="medium",
                confidence=0.7,
                detector_id="baas:wide_open_cors",
                source="response header",
                evidence=Evidence(source="response header", redacted_value="access-control-allow-origin: *"),
                risk_reason="CORS allows any origin.",
                remediation="Restrict CORS to production domain.",
                category="baas",
            ),
            Finding(
                type="select_star_overfetch",
                severity="low",
                confidence=0.55,
                detector_id="baas:select_star_overfetch",
                source="app.js",
                evidence=Evidence(source="app.js", redacted_value='.select("*")'),
                risk_reason="Fetching all columns leaks schema.",
                remediation="Use explicit column lists.",
                category="baas",
            ),
        ]
        report = build_report(
            "https://preview.example.com",
            findings,
            scan_mode="browser",
            packs=["leak", "baas"],
        )
        output = format_html(report)

        self.assertIn("<!DOCTYPE html>", output)
        self.assertIn("preview.example.com", output)
        self.assertIn("Block Ship", output)
        self.assertIn("CRITICAL", output)
        self.assertIn("openai_api_key", output)
        self.assertIn("database_url", output)
        self.assertIn("wide_open_cors", output)
        self.assertIn("select_star_overfetch", output)
        self.assertIn("confirmed", output)
        self.assertIn("leak, baas", output)
        self.assertIn("browser", output)

    def test_html_report_escapes_dynamic_content(self):
        finding = Finding(
            type="xss_test",
            severity="high",
            confidence=0.9,
            detector_id="test:xss_test",
            source="fixture",
            evidence=Evidence(source="fixture", redacted_value='<script>alert("xss")</script>'),
            risk_reason='Risk with <b>bold</b> & "quotes".',
            remediation="Sanitize <input> tags.",
        )
        report = build_report("<script>evil</script>", [finding], scan_mode="browser")
        output = format_html(report)

        # Raw angle brackets from dynamic content must be escaped
        self.assertNotIn("<script>alert", output)
        self.assertNotIn("<script>evil", output)
        self.assertIn("&lt;script&gt;alert", output)
        self.assertIn("&lt;script&gt;evil", output)

    def test_html_safe_verdict(self):
        report = build_report("https://safe.example.com", [], scan_mode="local")
        output = format_html(report)

        self.assertIn("<!DOCTYPE html>", output)
        self.assertIn("Safe to Ship", output)
        self.assertIn("safe.example.com", output)
        self.assertIn("No findings detected.", output)

    def test_html_review_verdict(self):
        finding = Finding(
            type="minor_issue",
            severity="medium",
            confidence=0.7,
            detector_id="test:minor_issue",
            source="fixture",
            evidence=Evidence(source="fixture", redacted_value="medium-value"),
            risk_reason="Needs review.",
            remediation="Review and fix.",
        )
        report = build_report("https://review.example.com", [finding], scan_mode="browser")
        output = format_html(report)

        self.assertIn("Review", output)
        self.assertIn("verdict review", output)


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
        # Wave 1.4 introduced HMAC-tagged redaction (`[redacted:abc12345]`)
        # alongside the legacy prefix/suffix form (`...[redacted]...`). Both
        # contain the literal `[redacted` substring; that's the canonical
        # redaction marker.
        self.assertTrue(all("[redacted" in finding.evidence.redacted_value for finding in report.findings))

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
    def test_heatmap_rows_have_pack_coverage(self):
        detector_types = {detector.result_type for detector in DETECTORS}
        detector_packs = {detector.pack for detector in DETECTORS}

        for heatmap_type, pack in HEATMAP_ROWS.items():
            self.assertIn(pack, DETECTOR_PACKS)
            self.assertIn(pack, detector_packs)
            self.assertIn(heatmap_type, detector_types)

    def test_detector_metadata_is_pack_aware(self):
        for detector in DETECTORS:
            self.assertIn(detector.pack, DETECTOR_PACKS)
            self.assertTrue(detector.canonical_id.startswith(f"{detector.pack}."))
            self.assertTrue(detector.result_type)
            self.assertTrue(detector.description)
            self.assertTrue(detector.remediation)
            self.assertIn(detector.validation_status, {"lead", "validated", "suppressed", "not_applicable"})

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

    def test_extension_bundle_includes_launch_gate_detectors(self):
        payload = extension_pattern_payload()
        detector_ids = {detector["id"] for detector in payload}
        detector_packs = {detector["pack"] for detector in payload}

        self.assertIn("mcp_config_secret", detector_ids)
        self.assertIn("graphql_introspection_hint", detector_ids)
        self.assertIn("hidden_prompt_injection", detector_ids)
        self.assertIn("source_map_reference", detector_ids)
        self.assertIn("openrouter_api_key", detector_ids)
        self.assertIn("sql_injection_lead", detector_ids)
        self.assertIn("xss_sink_lead", detector_ids)
        self.assertIn("idor_direct_object_lead", detector_ids)
        self.assertEqual({"leak", "appsec", "access-control", "baas"}, detector_packs)
        self.assertTrue(all("remediation" in detector for detector in payload))
        self.assertTrue(all("detector_id" in detector for detector in payload))

    def test_extension_bundle_is_generated_from_core_registry(self):
        bundle = extension_patterns_js()

        self.assertIn("Source of truth: keyleak.detectors.DETECTORS", bundle)
        self.assertIn("PATTERN_DEFINITIONS", bundle)
        self.assertIn("mcp_config_secret", bundle)
        self.assertIn("appsec.sql_injection_lead", bundle)

    def test_extension_bundle_excludes_repo_only_packs_by_default(self):
        payload = extension_pattern_payload()
        detector_ids = {detector["id"] for detector in payload}

        self.assertNotIn("n_plus_one_query_lead", detector_ids)
        self.assertNotIn("missing_test_lead", detector_ids)

    def test_profile_pack_defaults(self):
        self.assertEqual(normalize_packs(None, profile="launch-gate"), ("leak",))
        self.assertEqual(normalize_packs(None, profile="full"), tuple(DETECTOR_PACKS.keys()))
        self.assertEqual(
            normalize_packs(None, profile="launch-gate", surface="extension"),
            ("leak", "appsec", "access-control", "baas"),
        )

    def test_full_pack_local_scan_finds_heatmap_leads(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.js").write_text(
                """
const query = `SELECT * FROM users WHERE id=${userId}`;
element.innerHTML = location.hash;
const requireAuth = false;
app.get('/users/123456', handler);
// TODO add tenant ownership check
for (const user of users) { db.query("SELECT * FROM orders WHERE user_id=" + user.id); }
for (let i = 0; i <= items.length; i++) {}
const parsed = new Date(input);
test.skip("missing coverage", () => {});
debugger;
// stale documentation: old auth model
""",
                encoding="utf-8",
            )
            (root / ".env").write_text("NODE_ENV=development\nVERIFY_SSL=false\n", encoding="utf-8")

            report = scan_path(str(root), profile="full")

        finding_types = {finding.type for finding in report.findings}
        self.assertIn("sql_injection", finding_types)
        self.assertIn("xss", finding_types)
        self.assertIn("auth_bypass", finding_types)
        self.assertIn("idor", finding_types)
        self.assertIn("missing_tenant_check", finding_types)
        self.assertIn("n_plus_one_query", finding_types)
        self.assertIn("off_by_one", finding_types)
        self.assertIn("timezone_date_bug", finding_types)
        self.assertIn("env_config_bug", finding_types)
        self.assertIn("test_missing", finding_types)
        self.assertIn("dead_code", finding_types)
        self.assertIn("stale_doc", finding_types)
        self.assertIn("correctness", report.to_dict()["packs"])
        self.assertEqual(
            {finding.validation_status for finding in report.findings if finding.category != "leak"},
            {"lead"},
        )

    def test_extension_service_worker_handles_extension_page_tab_ids(self):
        source = Path("extension/service-worker.js").read_text(encoding="utf-8")

        self.assertIn("Number.isInteger(message.tabId)", source)
        self.assertNotIn("if (!tabId) return;", source)

    def test_web_ui_uses_redacted_finding_values(self):
        source = Path("static/js/main.js").read_text(encoding="utf-8")

        self.assertIn("const redactedValue", source)
        self.assertNotIn("finding.value || finding.match", source)


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
        self.assertEqual(payload["launch_profile"], "launch-gate")
        self.assertEqual(tuple(payload["packs"]), ("leak",))

    def test_scan_payload_auth_mode_matches_supplied_credentials(self):
        payload = _scan_request_payload(
            Namespace(
                url="https://preview.example.com",
                profile="browser",
                bearer=" token ",
                cookie=" session=abc ",
                launch_profile="bug-bounty",
                packs="appsec,access-control",
            )
        )

        self.assertEqual(payload["scan_mode"], "extensive")
        self.assertEqual(payload["auth_config"]["mode"], "both")
        self.assertEqual(payload["auth_config"]["bearer_token"], "token")
        self.assertEqual(payload["auth_config"]["cookie"], "session=abc")
        self.assertEqual(tuple(payload["packs"]), ("appsec", "access-control"))

    def test_scan_payload_includes_second_user_auth_when_supplied(self):
        payload = _scan_request_payload(
            Namespace(
                url="https://preview.example.com/users/123456",
                profile="authenticated",
                bearer=" user-a-token ",
                cookie="",
                bearer_b=" user-b-token ",
                cookie_b="",
                launch_profile="bug-bounty",
                packs="access-control",
            )
        )

        self.assertEqual(payload["comparison_auth_config"]["mode"], "bearer")
        self.assertEqual(payload["comparison_auth_config"]["bearer_token"], "user-b-token")


class AccessControlComparisonTests(unittest.TestCase):
    def test_two_user_comparison_validates_same_object_access(self):
        class Response:
            status_code = 200
            text = '{"id":123456,"email":"redacted@example.com"}'

        calls = []

        def fake_fetch(url, **kwargs):
            calls.append((url, kwargs["headers"].get("Authorization", "")))
            return Response()

        findings = compare_access_control_urls(
            ["https://preview.example.com/users/123456"],
            {"bearer_token": "user-a-token"},
            {"bearer_token": "user-b-token"},
            fetch=fake_fetch,
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].type, "idor")
        self.assertEqual(findings[0].category, "access-control")
        self.assertEqual(findings[0].validation_status, "validated")
        self.assertEqual(calls[0][1], "Bearer user-a-token")
        self.assertEqual(calls[1][1], "Bearer user-b-token")

    def test_two_user_comparison_ignores_rejected_second_user(self):
        class Response:
            def __init__(self, status_code):
                self.status_code = status_code
                self.text = "{}"

        statuses = [200, 403]

        def fake_fetch(_url, **_kwargs):
            return Response(statuses.pop(0))

        findings = compare_access_control_urls(
            ["https://preview.example.com/users/123456"],
            {"bearer_token": "user-a-token"},
            {"bearer_token": "user-b-token"},
            fetch=fake_fetch,
        )

        self.assertEqual(findings, [])


def _detector(detector_id):
    for detector in DETECTORS:
        if detector.id == detector_id:
            return detector
    raise AssertionError(f"missing detector {detector_id}")


if __name__ == "__main__":
    unittest.main()
