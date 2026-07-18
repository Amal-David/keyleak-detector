from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from keyleak import audit
from keyleak.audit import (
    AuditAuthorizationError,
    AuditOptions,
    classify_target,
    default_depth,
    plan_audit,
    run_audit,
)
from keyleak.cli import main
from keyleak.models import Evidence, Finding, ScanReport


def _fake_finding() -> Finding:
    return Finding(
        type="openai_api_key",
        severity="critical",
        confidence=0.95,
        detector_id="leak.openai_api_key",
        source="bundle.js",
        evidence=Evidence(
            source="bundle.js",
            snippet="Authorization: Bearer SUPERSECRET-TOKEN",
            request_url="https://example.com/?token=SUPERSECRET-TOKEN",
            redacted_value="sk-live-SUPERSECRET-TOKEN",
        ),
        risk_reason="raw secret should never persist",
        remediation="rotate",
        validation_status="lead",
        category="leak",
    )


class AuditTargetTests(unittest.TestCase):
    def test_classifies_local_archive_url_and_domain(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive_path = root / "release.tar.gz"
            archive_path.write_bytes(b"not really a tar; classification only")

            self.assertEqual(classify_target(str(root)), "local_path")
            self.assertEqual(classify_target(str(archive_path)), "archive")
            self.assertEqual(classify_target("https://preview.example.com/app"), "url")
            self.assertEqual(classify_target("example.com"), "domain")

    def test_security_audit_defaults_to_exploit_validation(self):
        self.assertEqual(default_depth("security-audit"), "exploit-validation")
        self.assertEqual(default_depth("bug-bounty"), "exploit-validation")
        self.assertEqual(default_depth("ship"), "active")

    def test_active_url_plan_is_blocked_without_authorization_and_attestation(self):
        plan = plan_audit(AuditOptions("https://preview.example.com", intent="security-audit"))
        runtime = next(phase for phase in plan["phases"] if phase["id"] == "runtime_evidence")
        self.assertEqual(runtime["status"], "blocked")
        self.assertIn("--authorized-scope", runtime["reason"])

    def test_domain_plan_selects_site_scan(self):
        plan = plan_audit(
            AuditOptions(
                "example.com",
                intent="bug-bounty",
                authorized_scope="owned domain and staging accounts",
                network_attested=True,
                include_subdomains=True,
            )
        )

        runtime = next(phase for phase in plan["phases"] if phase["id"] == "runtime_evidence")
        self.assertIn("keyleak site-scan example.com", runtime["command"])
        self.assertIn("--baas-validate", runtime["command"])
        self.assertEqual(plan["depth"], "exploit-validation")

    def test_plan_maps_red_and_blue_intent_and_marks_unattested_network_incomplete(self):
        plan = plan_audit(AuditOptions("https://preview.example.com", intent="security-audit"))

        self.assertIn("blue_team", plan["intent_mapping"])
        self.assertIn("red_team", plan["intent_mapping"])
        self.assertIn("does not fuzz or write", plan["intent_mapping"]["red_team"])
        self.assertFalse(plan["operator_attestation"]["technical_authorization_proof"])
        runtime = next(phase for phase in plan["phases"] if phase["id"] == "runtime_evidence")
        self.assertEqual(runtime["status"], "blocked")
        self.assertIn("--attest-network-scope", runtime["reason"])
        self.assertIn("Partial containment", plan["execution_constraints"]["network_scope"])

    def test_domain_plan_keeps_the_exact_host_without_expansion_opt_in(self):
        plan = plan_audit(
            AuditOptions(
                "app.example.com",
                authorized_scope="owned app host",
                network_attested=True,
            )
        )

        runtime = next(phase for phase in plan["phases"] if phase["id"] == "runtime_evidence")
        self.assertIn("browser-scan https://app.example.com", runtime["command"])
        self.assertIn("Requested single-host scope", plan["execution_constraints"]["network_scope"])

    def test_plan_and_retest_redact_url_credentials_and_query_secrets(self):
        options = AuditOptions(
            "https://operator:SUPERSECRET@example.com/app?token=SUPERSECRET",
            authorized_scope="owned preview",
            network_attested=True,
        )
        plan = plan_audit(options)

        self.assertNotIn("SUPERSECRET", json.dumps(plan))
        self.assertNotIn("SUPERSECRET", audit._audit_retest_command(options))


class AuditRunTests(unittest.TestCase):
    def test_local_audit_writes_redacted_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "repo"
            target.mkdir()
            out_dir = Path(tmp) / "audit-artifacts"

            with mock.patch.object(audit, "run_doctor", return_value=[]), \
                 mock.patch.object(
                     audit,
                     "scan_path",
                     return_value=ScanReport(str(target), "local", [_fake_finding()], extra={"packs": ["leak"]}),
                 ):
                report = run_audit(AuditOptions(str(target), out_dir=str(out_dir)))

            for name in (
                "audit-plan.json",
                "report.json",
                "findings.jsonl",
                "coverage.json",
                "evidence-ledger.json",
                "summary.md",
            ):
                self.assertTrue((out_dir / name).exists(), name)

            combined = "\n".join(path.read_text(encoding="utf-8") for path in out_dir.iterdir())
            self.assertNotIn("SUPERSECRET-TOKEN", combined)
            self.assertNotIn("sk-live-SUPERSECRET-TOKEN", combined)
            self.assertIn("[redacted]", combined)
            self.assertEqual(report.extra["artifact_dir"], str(out_dir.resolve()))

    def test_domain_audit_runs_site_scan_and_records_coverage(self):
        captured = {}

        def fake_site_scan(domain, **kwargs):
            captured.update(kwargs)
            return ScanReport(
                domain,
                "full-site",
                [],
                extra={
                    "packs": ["leak", "baas"],
                    "hosts_scanned": 1,
                    "pages_scanned": 2,
                    "pages_failed": 0,
                    "subdomains": ["example.com"],
                    "scanned_urls": ["https://example.com/", "https://example.com/users/123456"],
                    "discovery_sources": {"kept": {"apex": 1}},
                },
            )

        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(audit, "run_doctor", return_value=[]), \
                 mock.patch("keyleak.site_scanner.scan_site", side_effect=fake_site_scan):
                report = run_audit(
                    AuditOptions(
                        "example.com",
                        intent="bug-bounty",
                        authorized_scope="owned domain",
                        network_attested=True,
                        include_subdomains=True,
                        out_dir=str(Path(tmp) / "audit"),
                    )
                )

        runtime = next(phase for phase in report.extra["audit_coverage"]["phases"] if phase["id"] == "runtime_evidence")
        self.assertEqual(runtime["scanner"], "site-scan")
        self.assertEqual(runtime["pages_scanned"], 2)
        self.assertTrue(captured["baas_validate"])
        self.assertTrue(callable(captured["target_guard"]))
        self.assertFalse(captured["external_discovery"])

    def test_exact_host_domain_audit_does_not_dispatch_site_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(audit, "run_doctor", return_value=[]), \
                 mock.patch.object(audit, "url_block_reason", return_value=None), \
                 mock.patch("keyleak.browser_scanner.run_browser_scan", return_value=ScanReport("https://app.example.com", "browser", [])) as browser_scan, \
                 mock.patch("keyleak.site_scanner.scan_site") as site_scan:
                run_audit(
                    AuditOptions(
                        "app.example.com",
                        authorized_scope="owned app host",
                        network_attested=True,
                        out_dir=str(Path(tmp) / "audit"),
                    )
                )

        browser_scan.assert_called_once()
        self.assertEqual(browser_scan.call_args.args[0], "https://app.example.com")
        site_scan.assert_not_called()

    def test_local_audit_disables_self_audit_subprocesses(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "repo"
            target.mkdir()
            (target / "pyproject.toml").write_text("[tool.poetry]\nname = 'fixture'\n", encoding="utf-8")
            self_audit_report = ScanReport(str(target), "self-audit", [])
            with mock.patch.object(audit, "run_doctor", return_value=[]), \
                 mock.patch.object(audit, "scan_path", return_value=ScanReport(str(target), "local", [])), \
                 mock.patch.object(audit, "run_self_audit", return_value=self_audit_report) as self_audit:
                report = run_audit(AuditOptions(str(target), out_dir=str(Path(tmp) / "audit")))

        self_audit.assert_called_once_with(target.resolve(), allow_external_commands=False)
        self_audit_phase = next(phase for phase in report.extra["audit_coverage"]["phases"] if phase["id"] == "self_audit")
        self.assertEqual(self_audit_phase["status"], "partial")

    def test_auth_state_file_must_not_be_group_or_world_readable(self):
        with tempfile.TemporaryDirectory() as tmp:
            auth_state = Path(tmp) / "state.json"
            auth_state.write_text("{}", encoding="utf-8")
            auth_state.chmod(0o644)
            with mock.patch.object(audit, "run_doctor", return_value=[]), \
                 mock.patch.object(audit, "url_block_reason", return_value=None), \
                 mock.patch("keyleak.browser_scanner.run_browser_scan") as browser_scan:
                report = run_audit(
                    AuditOptions(
                        "https://preview.example.com",
                        authorized_scope="owned preview",
                        network_attested=True,
                        auth_state_path=str(auth_state),
                        out_dir=str(Path(tmp) / "audit"),
                    )
                )

        browser_scan.assert_not_called()
        self.assertEqual(report.extra["audit_coverage"]["status"], "incomplete")

    def test_unattested_network_audit_does_not_dispatch_browser_scan(self):
        with mock.patch("keyleak.browser_scanner.run_browser_scan") as browser_scan:
            with self.assertRaises(AuditAuthorizationError):
                run_audit(
                    AuditOptions(
                        "https://preview.example.com",
                        authorized_scope="owned preview",
                    )
                )

        browser_scan.assert_not_called()

    def test_offline_network_audit_does_not_dispatch_browser_scan(self):
        with mock.patch("keyleak.browser_scanner.run_browser_scan") as browser_scan:
            with self.assertRaises(AuditAuthorizationError):
                run_audit(
                    AuditOptions(
                        "https://preview.example.com",
                        authorized_scope="owned preview",
                        network_attested=True,
                        offline=True,
                    )
                )

        browser_scan.assert_not_called()

    def test_subdomain_audit_rejects_auth_state_before_site_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "state.json"
            state.write_text("{}", encoding="utf-8")
            state.chmod(0o600)
            with mock.patch("keyleak.site_scanner.scan_site") as site_scan:
                with self.assertRaises(AuditAuthorizationError):
                    run_audit(
                        AuditOptions(
                            "example.com",
                            authorized_scope="owned domain",
                            network_attested=True,
                            include_subdomains=True,
                            auth_state_path=str(state),
                        )
                    )

        site_scan.assert_not_called()

    def test_exploit_validation_records_unavailable_two_user_comparison(self):
        def fake_browser_scan(url, **kwargs):
            return ScanReport(url, "browser", [], extra={"packs": ["leak"]})

        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(audit, "run_doctor", return_value=[]), \
                 mock.patch.object(audit, "url_block_reason", return_value=None), \
                 mock.patch("keyleak.browser_scanner.run_browser_scan", side_effect=fake_browser_scan):
                report = run_audit(
                    AuditOptions(
                        "https://preview.example.com/users/123456",
                        intent="security-audit",
                        authorized_scope="owned preview",
                        network_attested=True,
                        out_dir=str(Path(tmp) / "audit"),
                    )
                )

        skipped = {item["id"]: item["reason"] for item in report.extra["skipped_phases"]}
        self.assertIn("access_control_two_user", skipped)
        self.assertIn("non-command-line credential handoff", skipped["access_control_two_user"])

    def test_failed_local_scan_writes_incomplete_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "repo"
            target.mkdir()
            out_dir = Path(tmp) / "audit"
            with mock.patch.object(audit, "run_doctor", return_value=[]), \
                 mock.patch.object(audit, "scan_path", side_effect=RuntimeError("token=SUPERSECRET")):
                report = run_audit(AuditOptions(str(target), out_dir=str(out_dir)))

            payload = (out_dir / "report.json").read_text(encoding="utf-8")

        local = next(phase for phase in report.extra["audit_coverage"]["phases"] if phase["id"] == "local_evidence")
        self.assertEqual(local["status"], "partial")
        self.assertEqual(report.verdict["status"], "REVIEW")
        self.assertNotIn("SUPERSECRET", payload)

    def test_report_with_audit_metadata_round_trips(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "repo"
            target.mkdir()
            with mock.patch.object(audit, "run_doctor", return_value=[]), \
                 mock.patch.object(audit, "scan_path", return_value=ScanReport(str(target), "local", [])):
                report = run_audit(AuditOptions(str(target), out_dir=str(Path(tmp) / "audit")))

            payload = report.to_dict()
            restored = ScanReport.from_dict(payload)

        self.assertIn("audit_plan", restored.to_dict())
        self.assertIn("audit_coverage", restored.to_dict())
        self.assertIn("artifact_dir", restored.to_dict())

    def test_skipped_phase_marks_audit_coverage_incomplete_in_artifacts_and_summary(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "plain-directory"
            target.mkdir()
            out_dir = Path(tmp) / "audit"
            with mock.patch.object(audit, "run_doctor", return_value=[]), \
                 mock.patch.object(audit, "scan_path", return_value=ScanReport(str(target), "local", [])):
                report = run_audit(AuditOptions(str(target), out_dir=str(out_dir)))

            coverage = report.extra["audit_coverage"]
            summary = (out_dir / "summary.md").read_text(encoding="utf-8")

        self.assertEqual(coverage["status"], "incomplete")
        self.assertIn("self_audit", coverage["incomplete_phase_ids"])
        self.assertIn("Audit coverage: `incomplete`", summary)

    def test_failed_pages_mark_runtime_phase_partial_and_audit_incomplete(self):
        fake_report = ScanReport(
            "example.com",
            "full-site",
            [],
            extra={"pages_failed": 1, "pages_scanned": 2, "scanned_urls": ["https://example.com/"]},
        )
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(audit, "run_doctor", return_value=[]), \
                 mock.patch("keyleak.site_scanner.scan_site", return_value=fake_report):
                report = run_audit(
                    AuditOptions(
                        "example.com",
                        authorized_scope="owned domain",
                        network_attested=True,
                        include_subdomains=True,
                        out_dir=str(Path(tmp) / "audit"),
                    )
                )

        runtime = next(phase for phase in report.extra["audit_coverage"]["phases"] if phase["id"] == "runtime_evidence")
        self.assertEqual(runtime["status"], "partial")
        self.assertEqual(report.extra["audit_coverage"]["status"], "incomplete")

    def test_failed_browser_scan_writes_redacted_incomplete_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "audit"
            with mock.patch.object(audit, "run_doctor", return_value=[]), \
                 mock.patch.object(audit, "url_block_reason", return_value=None), \
                 mock.patch("keyleak.browser_scanner.run_browser_scan", side_effect=RuntimeError("token=SUPERSECRET")):
                report = run_audit(
                    AuditOptions(
                        "https://preview.example.com",
                        authorized_scope="owned preview",
                        network_attested=True,
                        out_dir=str(out_dir),
                    )
                )

            payload = (out_dir / "report.json").read_text(encoding="utf-8")

        runtime = next(phase for phase in report.extra["audit_coverage"]["phases"] if phase["id"] == "runtime_evidence")
        self.assertEqual(runtime["status"], "partial")
        self.assertEqual(report.verdict["status"], "REVIEW")
        self.assertNotIn("SUPERSECRET", payload)

    def test_child_coverage_incomplete_marks_browser_phase_partial(self):
        child_report = ScanReport(
            "https://preview.example.com",
            "browser",
            [],
            extra={"coverage": {"status": "partial", "reason": "redirect target was not observed"}},
        )
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(audit, "run_doctor", return_value=[]), \
                 mock.patch.object(audit, "url_block_reason", return_value=None), \
                 mock.patch("keyleak.browser_scanner.run_browser_scan", return_value=child_report):
                report = run_audit(
                    AuditOptions(
                        "https://preview.example.com",
                        authorized_scope="owned preview",
                        network_attested=True,
                        out_dir=str(Path(tmp) / "audit"),
                    )
                )

        runtime = next(phase for phase in report.extra["audit_coverage"]["phases"] if phase["id"] == "runtime_evidence")
        self.assertEqual(runtime["status"], "partial")
        self.assertIn("child scanner reported incomplete coverage", runtime["reason"])

    def test_missing_child_coverage_marks_browser_phase_partial(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(audit, "run_doctor", return_value=[]), \
                 mock.patch.object(audit, "url_block_reason", return_value=None), \
                 mock.patch("keyleak.browser_scanner.run_browser_scan", return_value=ScanReport("https://preview.example.com", "browser", [])):
                report = run_audit(
                    AuditOptions(
                        "https://preview.example.com",
                        authorized_scope="owned preview",
                        network_attested=True,
                        out_dir=str(Path(tmp) / "audit"),
                    )
                )

        runtime = next(phase for phase in report.extra["audit_coverage"]["phases"] if phase["id"] == "runtime_evidence")
        self.assertEqual(runtime["status"], "partial")
        self.assertIn("did not expose coverage metadata", runtime["reason"])

    def test_preflight_failure_makes_audit_coverage_incomplete(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "repo"
            target.mkdir()
            failed_check = SimpleNamespace(name="keyleak-imports", status="fail", message="missing runtime dependency")
            with mock.patch.object(audit, "run_doctor", return_value=[failed_check]), \
                 mock.patch.object(audit, "scan_path", return_value=ScanReport(str(target), "local", [])):
                report = run_audit(AuditOptions(str(target), out_dir=str(Path(tmp) / "audit")))

        self.assertEqual(report.extra["audit_coverage"]["status"], "incomplete")
        self.assertEqual(report.verdict["status"], "REVIEW")
        self.assertIn("preflight", report.extra["audit_coverage"]["incomplete_phase_ids"])

    def test_baseline_suppression_is_reflected_in_artifacts(self):
        finding = _fake_finding()
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "repo"
            target.mkdir()
            baseline_path = Path(tmp) / "baseline.json"
            out_dir = Path(tmp) / "audit"
            baseline_path.write_text(
                json.dumps({"findings": [finding.to_dict()]}),
                encoding="utf-8",
            )

            with mock.patch.object(audit, "run_doctor", return_value=[]), \
                 mock.patch.object(
                     audit,
                     "scan_path",
                     return_value=ScanReport(str(target), "local", [finding], extra={"packs": ["leak"]}),
                 ):
                report = run_audit(
                    AuditOptions(
                        str(target),
                        out_dir=str(out_dir),
                        baseline_path=str(baseline_path),
                    )
                )

            artifact_payload = json.loads((out_dir / "report.json").read_text(encoding="utf-8"))
            self.assertEqual(report.findings, [])
            self.assertEqual(artifact_payload["findings"], [])
            self.assertEqual(artifact_payload["verdict"]["status"], "REVIEW")
            self.assertIn("coverage is incomplete", artifact_payload["verdict"]["reason"])

    def test_default_artifact_dir_is_absolute(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "repo"
            target.mkdir()
            old_cwd = os.getcwd()
            try:
                os.chdir(root)
                with mock.patch.object(audit, "run_doctor", return_value=[]), \
                     mock.patch.object(audit, "scan_path", return_value=ScanReport(str(target), "local", [])):
                    report = run_audit(AuditOptions(str(target)))
            finally:
                os.chdir(old_cwd)

            artifact_dir = Path(report.extra["artifact_dir"])
            self.assertTrue(artifact_dir.is_absolute())
            self.assertEqual(artifact_dir.parts[-3:-1], (".keyleak", "audits"))
            self.assertTrue((artifact_dir / "report.json").exists())


class AuditCliTests(unittest.TestCase):
    def test_cli_refuses_url_audit_without_scope(self):
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(["audit", "https://preview.example.com", "--intent", "security-audit", "--json"])

        self.assertEqual(code, 1)
        self.assertIn("--authorized-scope", stderr.getvalue())
        self.assertEqual(stdout.getvalue(), "")

    def test_cli_plan_does_not_execute_or_install(self):
        stdout = io.StringIO()
        with mock.patch.object(audit, "run_doctor") as doctor, \
             mock.patch.object(audit, "scan_path") as scan_path, \
             redirect_stdout(stdout):
            code = main(["audit", "example.com", "--plan", "--json"])

        self.assertEqual(code, 0)
        self.assertFalse(doctor.called)
        self.assertFalse(scan_path.called)
        payload = json.loads(stdout.getvalue())
        self.assertFalse(payload["bounds"]["include_subdomains"])
        runtime = next(phase for phase in payload["phases"] if phase["id"] == "runtime_evidence")
        self.assertEqual(runtime["status"], "blocked")

    def test_cli_include_subdomains_requires_explicit_opt_in(self):
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            self.assertEqual(main(["audit", "example.com", "--plan", "--include-subdomains", "--json"]), 0)

        payload = json.loads(stdout.getvalue())
        self.assertTrue(payload["bounds"]["include_subdomains"])
        runtime = next(phase for phase in payload["phases"] if phase["id"] == "runtime_evidence")
        self.assertIn("site-scan example.com", runtime["command"])

    def test_cli_plan_exposes_selected_assessment_mode(self):
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            self.assertEqual(main(["audit", ".", "--plan", "--assessment-mode", "red-team", "--json"]), 0)

        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["assessment_mode"], "red-team")
        self.assertIn("attacker-perspective", payload["assessment_focus"])

    def test_cli_plan_reflects_offline_mode_without_dispatch(self):
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            self.assertEqual(main(["--offline", "audit", "example.com", "--plan", "--json"]), 0)

        self.assertTrue(json.loads(stdout.getvalue())["bounds"]["offline"])

    def test_cli_rejects_raw_credentials_without_echoing_them(self):
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(["audit", "https://preview.example.com", "--bearer", "SUPERSECRET", "--json"])

        self.assertEqual(code, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertNotIn("SUPERSECRET", stderr.getvalue())
        self.assertIn("does not accept credentials", stderr.getvalue())

    def test_audit_bounds_are_positive_and_capped(self):
        with self.assertRaisesRegex(audit.AuditError, "max_pages must be between"):
            plan_audit(AuditOptions(".", max_pages=0))
        with self.assertRaisesRegex(audit.AuditError, "scan_budget_seconds must be between"):
            plan_audit(AuditOptions(".", scan_budget_seconds=audit.MAX_SCAN_BUDGET_SECONDS + 1))

    def test_cli_incomplete_audit_returns_nonzero_review_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "plain-directory"
            target.mkdir()
            with mock.patch.object(audit, "run_doctor", return_value=[]), \
                 mock.patch.object(audit, "scan_path", return_value=ScanReport(str(target), "local", [])):
                code = main(["audit", str(target), "--json", "--out-dir", str(Path(tmp) / "audit")])

        self.assertEqual(code, 1)


class AgentRunbookSmokeTests(unittest.TestCase):
    def test_agent_runbook_routes_security_prompts_to_audit(self):
        skill_path = Path(".claude/skills/keyleak-verify/SKILL.md")
        self.assertTrue(skill_path.exists())
        text = skill_path.read_text(encoding="utf-8")

        for phrase in ("security audit", "vulnerability detection", "pentest", "bug bounty", "is this exploitable"):
            self.assertIn(phrase, text)
        self.assertIn("keyleak audit", text)
        self.assertIn("BLOCK SHIP", text)
        self.assertIn("SAFE TO SHIP", text)


if __name__ == "__main__":
    unittest.main()
