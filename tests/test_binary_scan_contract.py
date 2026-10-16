import contextlib
import base64
import copy
import hashlib
import hmac
import io
import json
import os
import shlex
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from keyleak.archive_scanner import scan_archive
from keyleak.chain_of_custody import build_envelope, findings_sha256, verify_envelope
from keyleak.cli import main
from keyleak.local_scanner import scan_path
from keyleak.models import Evidence
from keyleak.reporting import format_html, format_markdown, format_sarif, report_to_text


CANARY = ("AKIA" + "1234567890" + "ABCDEF").encode()


class BinaryScanContractTests(unittest.TestCase):
    def test_decoding_preserves_original_spans_and_redacted_provenance(self):
        """Recovered secrets retain outer carrier spans and transforms, never plaintext evidence."""
        variants = [("base64", base64.b64encode(CANARY)), ("hex", CANARY.hex().encode()),
                    ("percent", b"".join(("%%%02X" % c).encode() for c in CANARY)),
                    ("nested", base64.b64encode(CANARY.hex().encode()))]
        with tempfile.TemporaryDirectory() as tmp:
            for name, encoded in variants:
                with self.subTest(encoding=name):
                    path = Path(tmp) / (name + ".bin")
                    path.write_bytes(b"\x00prefix: " + encoded + b"\x00")
                    report = scan_path(str(path), scan_binaries=True)
                    self.assertEqual(len(report.findings), 1)
                    evidence = report.findings[0].evidence
                    self.assertEqual(evidence.byte_offset, len(b"\x00prefix: "))
                    self.assertEqual(evidence.byte_length, len(encoded))
                    self.assertEqual(len(evidence.extraction["transforms"]), 2 if name == "nested" else 1)
                    self.assertEqual(Evidence.from_dict(evidence.to_dict()).to_dict(), evidence.to_dict())
                    self.assertNotIn(CANARY.decode(), json.dumps(report.to_dict()))
                    self.assertEqual(report.extra["coverage"]["status"], "complete")

    def test_utf32_and_encoded_public_examples(self):
        """Wide encodings preserve byte locations without reclassifying public examples as secrets."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "app.bin"
            for encoding in ("utf-32le", "utf-32be"):
                with self.subTest(encoding=encoding):
                    path.write_bytes(("prefix:" + CANARY.decode()).encode(encoding))
                    report = scan_path(str(path), scan_binaries=True)
                    self.assertEqual(len(report.findings), 1)
                    self.assertEqual(report.findings[0].evidence.byte_offset, 28)
                    self.assertEqual(report.findings[0].evidence.extraction["encoding"], encoding)
            path.write_bytes(base64.b64encode(b"AKIAIOSFODNN7EXAMPLE"))
            self.assertEqual(scan_path(str(path), scan_binaries=True).findings, [])

    def test_decode_budget_keeps_prior_findings_and_reports_partial_work(self):
        """Resource and depth limits must remain visible without deleting earlier evidence."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "app.bin"
            path.write_bytes(CANARY + b"\x00" + base64.b64encode(CANARY))
            with patch("keyleak.binary_scanner.MAX_DECODE_WORK_BYTES", 1):
                report = scan_path(str(path), scan_binaries=True)
            self.assertEqual(len(report.findings), 1)
            self.assertEqual(report.extra["coverage"]["status"], "incomplete")
            path.write_bytes(base64.b64encode(base64.b64encode(CANARY.hex().encode())))
            report = scan_path(str(path), scan_binaries=True)
            self.assertEqual(report.extra["coverage"]["status"], "incomplete")
            self.assertIn("depth limit", " ".join(report.extra["coverage"]["reasons"]))

    def test_exports_retain_coverage_and_extraction_evidence(self):
        """Changing export format must not hide coverage gaps or expose recovered credentials."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.bin").write_bytes(base64.b64encode(CANARY))
            (root / "classes.dex").write_bytes(b"unsupported")
            report = scan_path(str(root), scan_binaries=True)
            for formatter in (format_html, format_markdown, report_to_text):
                with self.subTest(format=formatter.__name__):
                    rendered = formatter(report)
                    self.assertIn("Coverage: incomplete", rendered)
                    self.assertIn("1 unsupported", rendered)
                    self.assertIn("base64", rendered)
                    self.assertNotIn(CANARY.decode(), rendered)
            sarif = json.loads(format_sarif(report))["runs"][0]
            self.assertEqual(sarif["properties"]["coverage"]["status"], "incomplete")
            region = sarif["results"][0]["locations"][0]["physicalLocation"]["region"]
            self.assertEqual(region, {"byteOffset": 0, "byteLength": len(base64.b64encode(CANARY))})
            self.assertEqual(sarif["results"][0]["properties"]["extraction"]["transforms"][0]["encoding"], "base64")

    def test_decode_depth_limit_does_not_discard_later_runs(self):
        """A benign depth-limited branch must not hide later raw or encoded secrets."""
        benign = b"ordinary public text"
        for _ in range(3):
            benign = base64.b64encode(benign)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "app.bin"
            for later in (CANARY, base64.b64encode(CANARY)):
                with self.subTest(encoded=later != CANARY):
                    path.write_bytes(benign + b"\x00" + later)
                    report = scan_path(str(path), scan_binaries=True)
                    self.assertEqual(len(report.findings), 1)
                    self.assertEqual(report.findings[0].evidence.byte_offset, len(benign) + 1)
                    self.assertEqual(report.extra["coverage"]["status"], "incomplete")
                    self.assertEqual(report.extra["coverage"]["reasons"], ["binary decoding depth limit reached"])
                    self.assertNotIn(CANARY.decode(), json.dumps(report.to_dict()))

    def test_elf_sections_bind_file_offsets_without_confusing_virtual_addresses(self):
        """Static ELF addresses must not replace file offsets or conceal malformed section bounds."""
        header = b"\x7fELF" + bytes([2, 1, 1]) + bytes(9)
        header += struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, 0, 0, 64, 0, 64, 0, 0, 64, 2, 0)
        section = struct.pack("<IIQQQQIIQQ", 0, 1, 2, 0x401000, 192, len(CANARY), 0, 0, 1, 0)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "app.elf"
            path.write_bytes(header + bytes(64) + section + CANARY)
            report = scan_path(str(path), scan_binaries=True)
            evidence = report.findings[0].evidence
            self.assertEqual(evidence.byte_offset, 192)
            self.assertEqual(evidence.extraction["section_index"], 1)
            self.assertEqual(evidence.extraction["virtual_address"], 0x401000)
            self.assertEqual(report.extra["scan_manifest"]["artifacts"][0]["native_layout"]["status"], "parsed")
            path.write_bytes(header + bytes(64) + section[:-8] + bytes(2))
            self.assertEqual(scan_path(str(path), scan_binaries=True).extra["coverage"]["status"], "incomplete")

    def test_generated_local_retest_preserves_detection_and_exit_policy(self):
        """Replaying an unchanged artifact must preserve its detection scope and failure policy."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = root / "release with spaces.bin"
            artifact.write_bytes(CANARY)
            args = ["local", str(artifact), "--scan-binaries", "--scan-dist",
                    "--scan-node-modules", "--include", "logs", "--packs", "leak",
                    "--launch-profile", "full", "--fail-on", "critical", "--json"]
            with contextlib.redirect_stdout(io.StringIO()) as output:
                status = main(args)
            initial = json.loads(output.getvalue())
            replay = shlex.split(initial["retest_command"])[1:]
            with contextlib.redirect_stdout(io.StringIO()) as output:
                replay_status = main(replay + ["--json"])
            repeated = json.loads(output.getvalue())
        self.assertEqual(status, replay_status)
        self.assertEqual(len(initial["findings"]), 1)
        self.assertEqual(len(repeated["findings"]), 1)
        self.assertEqual(initial["scan_manifest"], repeated["scan_manifest"])
        self.assertNotIn(CANARY.decode(), json.dumps(repeated))

    def test_unsupported_binary_scope_never_reports_clean_success(self):
        """Unsupported or empty requested scope requires review even when no detector ran."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in ("classes.dex", "resource.xml", "unknown.resource"):
                with self.subTest(name=name):
                    artifact = root / name
                    artifact.write_bytes(b"\x00" + CANARY)
                    report = scan_path(str(artifact), scan_binaries=True)
                    self.assertEqual(report.verdict["status"], "REVIEW")
                    self.assertEqual(report.extra["coverage"]["status"], "incomplete")
                    self.assertEqual(report.extra["inventory"]["unsupported"], 1)
            empty = root / "empty"
            empty.mkdir()
            report = scan_path(str(empty), scan_binaries=True)
            self.assertEqual(report.verdict["status"], "REVIEW")
            self.assertIn("No eligible", " ".join(report.extra["coverage"]["reasons"]))

    def test_archive_retest_uses_original_input_and_binds_member_bytes(self):
        """Archive replay must outlive temporary extraction and identify the bytes scanned."""
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "release.zip"
            with zipfile.ZipFile(archive, "w") as output:
                output.writestr("app.bin", CANARY)
            initial = scan_archive(str(archive), scan_binaries=True, profile="full")
            report = initial["report"]
            replay = shlex.split(report["retest_command"])[1:]
            self.assertEqual(replay[:2], ["archive", str(archive.resolve())])
            with contextlib.redirect_stdout(io.StringIO()) as output:
                status = main(replay)
            repeated = json.loads(output.getvalue())
            self.assertEqual(status, 2)
            self.assertEqual(len(repeated["report"]["findings"]), 1)
            self.assertEqual(report["input_artifact"]["sha256"], hashlib.sha256(archive.read_bytes()).hexdigest())
            member = report["scan_manifest"]["artifacts"][0]
            self.assertEqual(member["source"], str(archive.resolve()) + "!/app.bin")
            self.assertEqual(member["sha256"], hashlib.sha256(CANARY).hexdigest())

    def test_envelope_binds_metadata_and_rejects_unknown_versions(self):
        """Report metadata and authentication mode must be covered by the versioned integrity check."""
        report = {"findings": [], "coverage": {"status": "incomplete"},
                  "input_artifact": {"sha256": "a" * 64}, "retest_command": "keyleak archive a.zip"}
        with patch.dict(os.environ, {"KEYLEAK_COC_KEY": "synthetic-test-key"}):
            envelope = build_envelope(report)
            self.assertEqual(envelope["version"], "2")
            self.assertTrue(verify_envelope(envelope))
            for field, replacement in (("coverage", {"status": "complete"}),
                                       ("input_artifact", {"sha256": "b" * 64}),
                                       ("retest_command", "keyleak local a.zip")):
                with self.subTest(field=field):
                    tampered = copy.deepcopy(envelope)
                    tampered["report"][field] = replacement
                    self.assertFalse(verify_envelope(tampered))
            tampered = copy.deepcopy(envelope)
            tampered["version"] = "99"
            self.assertFalse(verify_envelope(tampered))
            tampered = copy.deepcopy(envelope)
            tampered["signature_mode"] = "none"
            tampered["signature"] = ""
            self.assertFalse(verify_envelope(tampered))

    def test_shipped_v1_verification_and_required_authentication(self):
        """Legacy verification remains available while authenticated consumers reject unsigned data."""
        report = {"findings": []}
        digest = findings_sha256(report)
        self_hash = hashlib.sha256(f"|{digest}|2026-01-01|tester".encode()).hexdigest()
        envelope = {"version": "1", "envelope": "keyleak.chain_of_custody", "prev_hash": "",
                    "generated_at": "2026-01-01", "signer": "tester", "findings_sha256": digest,
                    "self_hash": self_hash, "signature_mode": "hmac-sha256", "report": report,
                    "signature": hmac.new(b"synthetic-test-key", self_hash.encode(), hashlib.sha256).hexdigest()}
        with patch.dict(os.environ, {"KEYLEAK_COC_KEY": "synthetic-test-key"}):
            self.assertTrue(verify_envelope(envelope, require_signature=True))
            unsigned = build_envelope(report, signature_mode="none")
            self.assertTrue(verify_envelope(unsigned))
            self.assertFalse(verify_envelope(unsigned, require_signature=True))
            tampered = copy.deepcopy(envelope)
            tampered["signature_mode"] = "none"
            tampered["signature"] = ""
            self.assertFalse(verify_envelope(tampered, require_signature=True))


if __name__ == "__main__":
    unittest.main()
