from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
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

    def test_active_url_requires_authorized_scope(self):
        with self.assertRaises(AuditAuthorizationError):
            plan_audit(AuditOptions("https://preview.example.com", intent="security-audit"))

    def test_domain_plan_selects_site_scan(self):
        plan = plan_audit(
            AuditOptions(
                "example.com",
                intent="bug-bounty",
                authorized_scope="owned domain and staging accounts",
            )
        )

        runtime = next(phase for phase in plan["phases"] if phase["id"] == "runtime_evidence")
        self.assertIn("keyleak site-scan example.com", runtime["command"])
        self.assertIn("--baas-validate", runtime["command"])
        self.assertEqual(plan["depth"], "exploit-validation")


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
                        out_dir=str(Path(tmp) / "audit"),
                    )
                )

        runtime = next(phase for phase in report.extra["coverage"]["phases"] if phase["id"] == "runtime_evidence")
        self.assertEqual(runtime["scanner"], "site-scan")
        self.assertEqual(runtime["pages_scanned"], 2)
        self.assertTrue(captured["baas_validate"])
        self.assertTrue(callable(captured["target_guard"]))

    def test_exploit_validation_records_missing_two_user_credentials(self):
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
                        out_dir=str(Path(tmp) / "audit"),
                    )
                )

        skipped = {item["id"]: item["reason"] for item in report.extra["skipped_phases"]}
        self.assertIn("access_control_two_user", skipped)
        self.assertIn("--bearer-b", skipped["access_control_two_user"])

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
        self.assertIn("coverage", restored.to_dict())
        self.assertIn("artifact_dir", restored.to_dict())

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
            self.assertEqual(artifact_payload["verdict"]["status"], "SAFE_TO_SHIP")

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
