import json
import contextlib
import io
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from keyleak.detectors import detectors_for_packs
from keyleak.local_scanner import scan_path
from keyleak.models import Evidence, Finding, ScanReport, coverage_is_incomplete
from keyleak.reporting import format_html, format_json, format_markdown, format_sarif
from keyleak.binary_scanner import extract_printable_runs, scan_binary_bytes
from keyleak.cli import main


FIXTURE = Path(__file__).parent / "fixtures" / "binary_canary.macho"
CANARY = b"AKIA1234567890ABCDEF"
SECOND_CANARY = b"ghp_" + b"Ab3dEf8Gk2Lm5Pq9Rs1Tu4Vx6Yz0B3cD7EfG"


class BinaryScannerTests(unittest.TestCase):
    def test_extracts_ascii_and_utf16_tokens_with_absolute_byte_offsets(self):
        detectors = detectors_for_packs(["leak"])
        for encoded, start, token_bytes in (
            (b"prefix\n" + CANARY + b"\x00", len(b"prefix\n"), CANARY),
            (
                "prefix\n".encode("utf-16le") + CANARY.decode().encode("utf-16le"),
                len("prefix\n".encode("utf-16le")),
                CANARY.decode().encode("utf-16le"),
            ),
            (
                "prefix\n".encode("utf-16be") + CANARY.decode().encode("utf-16be"),
                len("prefix\n".encode("utf-16be")),
                CANARY.decode().encode("utf-16be"),
            ),
        ):
            with self.subTest(start=start, payload=encoded[:8]):
                findings = scan_binary_bytes(encoded, "artifact.bin", detectors)
                matches = [
                    item for item in findings
                    if item.detector_id == "leak.aws_access_key"
                ]
                self.assertEqual(len(matches), 1)
                finding = matches[0]
                self.assertEqual(finding.evidence.byte_offset, start)
                self.assertEqual(finding.evidence.line, 2)
                self.assertEqual(encoded[start:start + len(token_bytes)], token_bytes)
                self.assertNotIn(CANARY.decode(), finding.evidence.snippet)

    def test_local_binary_scan_is_opt_in_and_reports_payload_offset(self):
        contents = FIXTURE.read_bytes()
        expected_offset = contents.index(CANARY)

        default = scan_path(str(FIXTURE))
        self.assertFalse(any(item.detector_id == "leak.aws_access_key" for item in default.findings))

        scanned = scan_path(str(FIXTURE), scan_binaries=True, binary_source_prefix="release.zip")
        finding = next(item for item in scanned.findings if item.detector_id == "leak.aws_access_key")
        self.assertEqual(finding.source, "release.zip!/binary_canary.macho")
        self.assertEqual(finding.evidence.byte_offset, expected_offset)

    def test_directory_binary_scan_is_opt_in(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "nested" / "canary.macho"
            binary.parent.mkdir()
            binary.write_bytes(FIXTURE.read_bytes())

            default = scan_path(str(root))
            scanned = scan_path(str(root), scan_binaries=True)

        self.assertFalse(any(item.detector_id == "leak.aws_access_key" for item in default.findings))
        finding = next(
            item for item in scanned.findings
            if item.detector_id == "leak.aws_access_key"
        )
        self.assertEqual(finding.source, str(binary.resolve()))

    def test_public_example_identifier_is_not_reported(self):
        findings = scan_binary_bytes(
            b"AKIAIOSFODNN7EXAMPLE", "public-example.bin", detectors_for_packs(["leak"]),
        )
        self.assertFalse(any(item.detector_id == "leak.aws_access_key" for item in findings))

    def test_repeated_multiline_matches_keep_correct_lines(self):
        payload = b"\n".join([CANARY, CANARY, CANARY])
        findings = scan_binary_bytes(payload, "multiline.bin", detectors_for_packs(["leak"]))
        lines = [
            item.evidence.line for item in findings
            if item.detector_id == "leak.aws_access_key"
        ]
        self.assertEqual(lines, [1, 2, 3])

    def test_printable_key_crossing_old_run_boundary_is_scanned_whole(self):
        old_run_limit = 1_000_000
        prefix_length = old_run_limit - 5
        payload = b"." * prefix_length + CANARY + b"\x00"

        findings = scan_binary_bytes(payload, "large-resource.bin", detectors_for_packs(["leak"]))
        aws = next(item for item in findings if item.detector_id == "leak.aws_access_key")

        self.assertEqual(aws.evidence.byte_offset, prefix_length)
        self.assertNotIn(CANARY.decode(), aws.evidence.snippet)

    def test_public_run_extractor_enforces_binary_file_limit(self):
        with patch("keyleak.binary_scanner.MAX_BINARY_FILE_BYTES", 4):
            with self.assertRaisesRegex(ValueError, "per-file size limit"):
                list(extract_printable_runs(b"12345"))

    def test_same_line_binary_occurrences_keep_distinct_byte_offsets(self):
        payload = CANARY + b" " + SECOND_CANARY + b"\x00" + CANARY
        with patch.dict("os.environ", {"KEYLEAK_FINDING_FINGERPRINT_KEY": "binary-id-test"}):
            findings = scan_binary_bytes(payload, "same-line.bin", detectors_for_packs(["leak"]))
        aws_findings = [
            item for item in findings if item.detector_id == "leak.aws_access_key"
        ]
        github_findings = [
            item for item in findings if item.detector_id == "leak.github_pat"
        ]

        self.assertEqual([item.evidence.line for item in aws_findings], [1, 1])
        offsets = [item.evidence.byte_offset for item in aws_findings]
        self.assertEqual(offsets, [0, len(CANARY) + len(SECOND_CANARY) + 2])
        self.assertEqual(len({item.id for item in aws_findings}), 2)
        self.assertEqual(len({item.fingerprint for item in aws_findings}), 2)
        self.assertEqual(len(github_findings), 1)
        self.assertTrue(all(not item.evidence.snippet for item in findings))
        report = ScanReport("same-line.bin", "local", findings)
        outputs = (
            json.dumps([item.to_dict() for item in findings]),
            format_json(report),
            format_markdown(report),
            format_html(report),
            format_sarif(report),
        )
        for output in outputs:
            self.assertNotIn(CANARY.decode(), output)
            self.assertNotIn(SECOND_CANARY.decode(), output)
        for offset in offsets:
            self.assertEqual(payload[offset:offset + len(CANARY)], CANARY)
        round_tripped = [Finding.from_dict(item.to_dict()) for item in aws_findings]
        self.assertEqual([item.evidence.byte_offset for item in round_tripped], offsets)
        self.assertEqual([item.id for item in round_tripped], [item.id for item in aws_findings])
        self.assertEqual([item.fingerprint for item in round_tripped], [item.fingerprint for item in aws_findings])

    def test_work_limit_preserves_findings_and_marks_coverage_incomplete(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "limited.bin"
            path.write_bytes(CANARY + b"\x00" + CANARY + b"\x00")
            with patch("keyleak.binary_scanner.MAX_BINARY_SCAN_WORK_UNITS", 30):
                report = scan_path(str(path), scan_binaries=True)

        self.assertTrue(any(item.detector_id == "leak.aws_access_key" for item in report.findings))
        self.assertTrue(coverage_is_incomplete(report.extra["coverage"]))
        self.assertEqual(report.extra["coverage"]["skipped"], 1)

    def test_detector_work_limit_counts_text_times_active_detectors(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "bounded.bin"
            path.write_bytes(CANARY + b"\x00" + CANARY)
            detectors = detectors_for_packs(["leak"])
            first_run_budget = len(CANARY) * len(detectors)
            with patch(
                "keyleak.binary_scanner.MAX_BINARY_REGEX_WORK_UNITS",
                first_run_budget + 1,
            ):
                report = scan_path(str(path), packs=["leak"], scan_binaries=True)

        matches = [item for item in report.findings if item.detector_id == "leak.aws_access_key"]
        self.assertEqual(len(matches), 1)
        self.assertNotIn(CANARY.decode(), json.dumps(report.to_dict()))
        self.assertTrue(coverage_is_incomplete(report.extra["coverage"]))

    def test_finding_limit_keeps_partial_results_and_exits_incomplete(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "many-matches.bin"
            path.write_bytes(CANARY + b"\x00" + CANARY)
            output = io.StringIO()
            with patch("keyleak.binary_scanner.MAX_BINARY_FINDINGS", 1), \
                    contextlib.redirect_stdout(output):
                status = main([
                    "local", str(path), "--scan-binaries", "--json",
                    "--launch-profile", "launch-gate", "--fail-on", "critical",
                ])

        payload = json.loads(output.getvalue())
        self.assertEqual(status, 2)
        self.assertEqual(len(payload["findings"]), 1)
        self.assertTrue(coverage_is_incomplete(payload["coverage"]))
        self.assertEqual(payload["findings"][0]["evidence"]["snippet"], "")
        self.assertNotIn(CANARY.decode(), json.dumps(payload))

    def test_compiled_program_is_scanned_as_bytes_and_never_executed(self):
        compiler = shutil.which("cc") or shutil.which("clang")
        if compiler is None:
            self.skipTest("a C compiler is required for the non-execution proof")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / "canary-program"
            marker = root / "executed-marker"
            source = root / "canary.c"
            source.write_text(
                "#include <stdio.h>\n"
                f"const char canary[] = \"{CANARY.decode()}\";\n"
                "int main(void) {\n"
                f"  FILE *f = fopen({json.dumps(str(marker))}, \"w\");\n"
                "  if (f) { fputs(\"executed\", f); fclose(f); }\n"
                "  return 0;\n"
                "}\n",
                encoding="utf-8",
            )
            compiled = subprocess.run(
                [compiler, str(source), "-o", str(executable)],
                capture_output=True,
                text=True,
                check=False,
            )
            if compiled.returncode:
                self.skipTest(f"local C compiler could not build the canary: {compiled.stderr[:200]}")

            data = executable.read_bytes()
            expected_offset = data.index(CANARY)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = main([
                    "local", str(executable), "--scan-binaries", "--json", "--fail-on", "critical",
                ])
            self.assertEqual(status, 0)
            payload = json.loads(output.getvalue())
            finding = next(
                item for item in payload["findings"]
                if item["detector_id"] == "leak.aws_access_key"
            )
            self.assertEqual(finding["source"], str(executable.resolve()))
            self.assertEqual(finding["evidence"]["byte_offset"], expected_offset)
            self.assertNotIn(CANARY.decode(), json.dumps(finding))
            self.assertFalse(marker.exists())

    def test_sarif_includes_byte_offset_only_when_present(self):
        finding = Finding(
            type="credential", severity="high", confidence=0.9,
            detector_id="leak.aws_access_key", source="app.elf",
            evidence=Evidence(source="app.elf", line=1, byte_offset=37),
            risk_reason="credential found", remediation="rotate it",
        )
        report = ScanReport("app.elf", "local", [finding])
        result = json.loads(format_sarif(report))["runs"][0]["results"][0]
        self.assertEqual(result["locations"][0]["physicalLocation"]["region"]["byteOffset"], 37)

        plain = Finding(
            type="credential", severity="high", confidence=0.9,
            detector_id="leak.aws_access_key", source="app.js",
            evidence=Evidence(source="app.js", line=2),
            risk_reason="credential found", remediation="rotate it",
        )
        result = json.loads(format_sarif(ScanReport("app.js", "local", [plain])))
        region = result["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
        self.assertNotIn("byteOffset", region)


if __name__ == "__main__":
    unittest.main()
