from __future__ import annotations

import json
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest import mock

from keyleak.cli import _emit_report
from keyleak.local_scanner import scan_path
from keyleak.models import ScanReport, build_coverage, coverage_is_incomplete
from keyleak.sourcemaps import find_sourcemap_url


class LocalScannerDepthTests(unittest.TestCase):
    def test_node_modules_source_scan_is_opt_in_and_uses_worm_detector(self):
        source = """const token = process.env.NPM_TOKEN;
fetch('https://example.invalid');
fs.writeFileSync('~/.ssh/authorized_keys', token);
"""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dependency = root / "node_modules" / "evil" / "dist" / "index.js"
            dependency.parent.mkdir(parents=True)
            dependency.write_text(source, encoding="utf-8")

            default_report = scan_path(str(root))
            opted_in_report = scan_path(str(root), scan_node_modules=True)

        self.assertFalse(any(f.type == "worm_shape_capability_triad" for f in default_report.findings))
        self.assertTrue(any(f.type == "worm_shape_capability_triad" for f in opted_in_report.findings))
        self.assertEqual(opted_in_report.extra["coverage"]["status"], "complete")

    def test_root_dist_is_scanned_only_when_selected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "dist" / "bundle.js"
            output.parent.mkdir()
            output.write_text("const bundle = true;", encoding="utf-8")

            default_report = scan_path(str(root))
            selected_report = scan_path(str(root), scan_dist=True)

        self.assertEqual(default_report.extra["coverage"]["attempted"], 0)
        self.assertEqual(selected_report.extra["coverage"]["attempted"], 1)
        self.assertEqual(selected_report.extra["coverage"]["status"], "complete")

    def test_missing_declared_local_source_map_marks_coverage_incomplete(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "bundle.js").write_text(
                "const app = true;\n//# sourceMappingURL=bundle.js.map\n", encoding="utf-8"
            )
            with mock.patch(
                "keyleak.sourcemaps.find_sourcemap_url",
                wraps=find_sourcemap_url,
            ) as find_map:
                report = scan_path(str(root))

        coverage = report.extra["coverage"]
        find_map.assert_called_once()
        self.assertEqual(coverage["status"], "incomplete")
        self.assertIn("missing", coverage["reasons"][0])
        self.assertEqual(coverage["skipped"], 1)
        self.assertEqual(coverage["attempted"], coverage["completed"] + coverage["skipped"] + coverage["failed"])

    def test_declared_local_source_map_is_loaded_and_scanned(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "maps").mkdir()
            (root / "bundle.js").write_text(
                "const app = true;\n//# sourceMappingURL=maps/custom.map\n", encoding="utf-8"
            )
            (root / "maps" / "custom.map").write_text(json.dumps({
                "version": 3,
                "sources": ["src/Auth.ts"],
                "sourcesContent": ["const apiKey = 'sk-proj-abcdefghijklmnopqrstuvwxyz';"],
            }), encoding="utf-8")
            report = scan_path(str(root))

        self.assertTrue(any(
            f.type == "openai_api_key" and f.source.endswith("#src/Auth.ts")
            for f in report.findings
        ))
        self.assertEqual(report.extra["coverage"]["status"], "complete")

    def test_external_file_symlink_is_skipped_and_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            root = Path(directory)
            secret = Path(outside) / "secret.js"
            secret.write_text("const token = 'sk-proj-abcdefghijklmnopqrstuvwxyz';", encoding="utf-8")
            try:
                (root / "linked.js").symlink_to(secret)
            except OSError:
                self.skipTest("symlinks are unavailable")
            report = scan_path(str(root))

        self.assertFalse(any(f.type == "openai_api_key" for f in report.findings))
        self.assertEqual(report.extra["coverage"]["status"], "incomplete")
        self.assertIn("symlink", report.extra["coverage"]["reasons"][0])

    def test_default_excluded_node_modules_symlink_does_not_change_coverage(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            root = Path(directory)
            (Path(outside) / "index.js").write_text("const benign = true;", encoding="utf-8")
            try:
                (root / "node_modules").symlink_to(outside, target_is_directory=True)
            except OSError:
                self.skipTest("symlinks are unavailable")
            report = scan_path(str(root))

        self.assertEqual(report.extra["coverage"]["status"], "complete")

    def test_coverage_contract_and_cli_fail_closed_on_malformed_summary(self):
        complete = build_coverage("files", attempted=1, completed=1)
        incomplete = build_coverage("files", attempted=1, completed=0, skipped=1, reasons=("limit",))
        malformed = {"scope": "files", "attempted": "unknown"}
        self.assertFalse(coverage_is_incomplete(complete))
        self.assertTrue(coverage_is_incomplete(incomplete))
        self.assertTrue(coverage_is_incomplete(malformed))

        report = ScanReport(".", "local", [], extra={"coverage": malformed})
        self.assertEqual(
            _emit_report(report, Namespace(baseline="", allowlist="", no_default_suppressions=False,
                                           json=False, sarif=False, markdown=False, html=False, fail_on="critical")),
            2,
        )


if __name__ == "__main__":
    unittest.main()
