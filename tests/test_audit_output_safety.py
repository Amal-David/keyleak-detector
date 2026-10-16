"""Defensive audit-output checks using private benign filesystem fixtures."""

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from keyleak import audit
from keyleak.audit import AuditError, AuditOptions
from keyleak.models import ScanReport


class AuditOutputSafetyTests(unittest.TestCase):
    def test_managed_output_parent_links_are_rejected(self):
        """A checked-out directory link must not redirect the default report tree."""
        for link_name in (".keyleak", ".keyleak/audits"):
            with self.subTest(path=link_name), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                checkout = root / "checkout"
                checkout.mkdir()
                outside = root / "outside"
                outside.mkdir()
                link = checkout / link_name
                link.parent.mkdir(parents=True, exist_ok=True)
                link.symlink_to(outside, target_is_directory=True)
                with patch.object(audit.Path, "cwd", return_value=checkout):
                    with self.assertRaises(AuditError):
                        audit._resolve_artifact_dir(AuditOptions(str(checkout)))
                self.assertEqual(list(outside.iterdir()), [])

    def test_existing_report_links_do_not_modify_their_targets(self):
        """Atomic replacement must never truncate a linked destination file."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            destination = root / "audit"
            destination.mkdir()
            sentinel = root / "sentinel.txt"
            sentinel.write_text("keep this text")
            names = ("audit-plan.json", "report.json", "coverage.json", "evidence-ledger.json", "findings.jsonl", "summary.md")
            for name in names:
                (destination / name).symlink_to(sentinel)
            audit._write_artifacts(destination, ScanReport("fixture", "local", []))
            self.assertEqual(sentinel.read_text(), "keep this text")
            for name in names:
                self.assertFalse((destination / name).is_symlink())
                if os.name == "posix":
                    self.assertEqual((destination / name).stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads((destination / "report.json").read_text())["target"], "fixture")
            self.assertEqual(sorted(p.name for p in destination.iterdir()), sorted(names))

    def test_new_artifact_directory_is_private(self):
        """New reports should not rely on a restrictive caller umask."""
        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp) / "audit"
            audit._write_artifacts(destination, ScanReport("fixture", "local", []))
            if os.name == "posix":
                self.assertEqual(destination.stat().st_mode & 0o777, 0o700)

    def test_explicit_output_directory_link_is_rejected(self):
        """Reject a final directory link even for an explicitly selected path."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "out").symlink_to(root, target_is_directory=True)
            with self.assertRaises(AuditError):
                audit._resolve_artifact_dir(AuditOptions("fixture", out_dir=str(root / "out")))


if __name__ == "__main__":
    unittest.main()
