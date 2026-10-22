import json
import ssl
import tempfile
import unittest
from pathlib import Path

from keyleak.incident_scanner import scan_incidents


class IncidentScannerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def test_exact_pypi_match_does_not_confuse_nearby_versions_or_comments(self):
        path = self.root / "requirements.txt"
        path.write_text("# litellm==1.107.0\nlitellm==1.106.2\ncertifi==2026.10.19\n")
        self.assertEqual(len(scan_incidents(str(path)).findings), 1)
        path.write_text("litellm==1.107.0 --hash=sha256:abc\ncertifi==2026.9.1\npip==26.2.1\n")
        report = scan_incidents(str(path))
        self.assertEqual(sum(f.severity == "critical" for f in report.findings), 1)
        self.assertEqual(sum(f.detector_id == "incident:emudhra-package" for f in report.findings), 2)

    def test_toml_and_npm_lockfile_resolved_dependencies(self):
        for name in ("poetry.lock", "uv.lock"):
            (self.root / name).write_text('[[package]]\nname = "litellm"\nversion = "1.107.0"\n')
        (self.root / "package-lock.json").write_text(json.dumps({"packages": {
            "node_modules/a/node_modules/@decoopus/claude-setup": {"version": "1.0.2"},
            "node_modules/claude-desktop-setup": {"version": "1.0.0"},
            "node_modules/claude-desktop-setup-safe": {"version": "1.0.0"},
        }}))
        report = scan_incidents(str(self.root))
        self.assertEqual(sum(f.severity == "critical" for f in report.findings), 4)
        self.assertEqual(report.extra["coverage"]["completed"], 3)

    def test_npm_manifest_and_v1_lock(self):
        for name, data in [("package.json", {"devDependencies": {"claude-desktop-setup": "*"}}),
                           ("package.json", {"peerDependencies": {"claude-desktop-setup": "*"}}),
                           ("package-lock.json", {"dependencies": {"parent": {"version": "1", "dependencies": {
                               "@decoopus/claude-setup": {"version": "1"}}}}})]:
            with self.subTest(name=name):
                path = self.root / name
                path.write_text(json.dumps(data))
                self.assertEqual(sum(f.severity == "critical" for f in scan_incidents(str(path)).findings), 1)

    def test_v2_lock_duplicate_representations_produce_one_finding(self):
        path = self.root / "package-lock.json"
        path.write_text(json.dumps({"packages": {"node_modules/claude-desktop-setup": {"version": "1.0.0"}},
                                    "dependencies": {"claude-desktop-setup": {"version": "1.0.0"}}}))
        self.assertEqual(sum(f.severity == "critical" for f in scan_incidents(str(path)).findings), 1)

    def test_unresolved_pins_are_reported_without_persisting_input_secrets(self):
        path = self.root / "requirements.txt"
        secret = "private-token-do-not-report"
        path.write_text(f"litellm @ https://user:{secret}@example.com/a.whl\ncertifi>=2026.10.19\n")
        report = scan_incidents(str(path))
        self.assertEqual(sum(f.detector_id == "incident:unresolved-dependency" for f in report.findings), 2)
        self.assertNotIn(secret, str(report.to_dict()))

    def test_failures_are_visible_and_empty_scope_is_not_safe(self):
        self.assertEqual(scan_incidents(str(self.root)).extra["coverage"]["status"], "incomplete")
        for name, value in [("uv.lock", "[[broken"), ("package-lock.json", '{"packages": []}'),
                            ("requirements.txt", "-r hidden.txt"),
                            ("poetry.lock", "[package]\n"),
                            ("uv.lock", '[[package]]\nname="litellm"\nversion={}'),
                            ("package.json", '{"dependencies":{"claude-desktop-setup":{}}}')]:
            path = self.root / name
            path.write_text(value)
            with self.subTest(name=name):
                report = scan_incidents(str(path))
                self.assertEqual(report.extra["coverage"]["status"], "incomplete")
                self.assertNotEqual(report.verdict["status"], "SAFE_TO_SHIP")
        link = self.root / "alias"
        link.symlink_to(path)
        with self.assertRaises(ValueError):
            scan_incidents(str(link))
        path = self.root / "package-lock.json"
        path.write_text("{}")
        self.assertEqual(scan_incidents(str(path)).extra["coverage"]["status"], "incomplete")

    def test_npm_aliases_and_continued_hash_pins_preserve_malware_identity(self):
        manifest = self.root / "package.json"
        manifest.write_text(json.dumps({"dependencies": {"helper": "npm:claude-desktop-setup@1.0.0",
                                                         "other": "npm:@decoopus/claude-setup@1.0.2"}}))
        requirements = self.root / "requirements.txt"
        requirements.write_text("litellm==1.107.0 \\\n    --hash=sha256:abc\n")
        report = scan_incidents(str(self.root))
        self.assertEqual(sum(f.severity == "critical" for f in report.findings), 3)
        self.assertEqual(report.extra["coverage"]["status"], "complete")

    def test_railway_is_explicit_recovery_guidance_not_breach_confirmation(self):
        report = scan_incidents(str(self.root), railway=True)
        finding = next(f for f in report.findings if f.detector_id == "incident:railway-rotation")
        self.assertIn("asserted", finding.evidence.snippet)
        self.assertEqual(finding.validation_status, "lead")
        self.assertIn("revoke", finding.remediation)

    def test_invalid_pem_is_incomplete(self):
        path = self.root / "roots.pem"
        path.write_text("-----BEGIN CERTIFICATE-----\nYQ==\n-----END CERTIFICATE-----")
        report = scan_incidents(str(self.root), ca_bundle=str(path))
        self.assertEqual(report.extra["coverage"]["status"], "incomplete")

    def test_real_incident_roots_match_by_fingerprint_and_bundle_is_unchanged(self):
        bundle = Path(__file__).parent / "fixtures" / "emudhra-incident-roots.pem"
        original = bundle.read_bytes()
        self.assertEqual(scan_incidents(str(self.root), ca_bundle=str(bundle)).extra["coverage"]["status"], "incomplete")
        (self.root / "requirements.txt").write_text("certifi==2026.10.19\n")
        report = scan_incidents(str(self.root), ca_bundle=str(bundle))
        anchors = [f for f in report.findings if f.detector_id == "incident:emudhra-anchor"]
        self.assertEqual(len(anchors), 4)
        self.assertTrue(all("does not prove acceptance" in f.risk_reason for f in anchors))
        self.assertEqual(report.extra["coverage"]["status"], "complete")
        self.assertEqual(bundle.read_bytes(), original)

    def test_unrelated_certificate_is_not_an_incident_anchor(self):
        (self.root / "requirements.txt").write_text("certifi==2026.10.19\n")
        bundle = self.root / "unrelated.pem"
        cert = ssl.create_default_context().get_ca_certs(binary_form=True)[0]
        bundle.write_text(ssl.DER_cert_to_PEM_cert(cert))
        report = scan_incidents(str(self.root), ca_bundle=str(bundle))
        self.assertFalse(any(f.detector_id == "incident:emudhra-anchor" for f in report.findings))
        self.assertEqual(report.extra["coverage"]["status"], "complete")
