"""Tests for the CLI bundle wiring (keyleak bundles, --bundle)."""

import argparse
import contextlib
import io
import unittest

from keyleak.cli import _apply_bundle_selection, _print_bundles
from keyleak.bundles import REPO_ONLY_PACKS, runnable_packs, resolve_bundle


class BundleSelectionTests(unittest.TestCase):
    def test_apply_known_bundle_sets_packs(self):
        args = argparse.Namespace(bundle="secrets", packs="")
        rc = _apply_bundle_selection(args)
        self.assertEqual(rc, 0)
        self.assertEqual(args.packs, "leak")

    def test_apply_overrides_explicit_packs(self):
        args = argparse.Namespace(bundle="secrets", packs="appsec,baas")
        _apply_bundle_selection(args)
        self.assertEqual(args.packs, "leak")  # bundle wins

    def test_deep_bundle_excludes_repo_only_packs(self):
        args = argparse.Namespace(bundle="deep", packs="")
        _apply_bundle_selection(args)
        selected = set(args.packs.split(","))
        for pack in REPO_ONLY_PACKS:
            self.assertNotIn(pack, selected)
        self.assertIn("leak", selected)
        self.assertIn("baas", selected)

    def test_unknown_bundle_returns_error(self):
        args = argparse.Namespace(bundle="does-not-exist", packs="")
        self.assertEqual(_apply_bundle_selection(args), 1)

    def test_print_bundles_ok(self):
        self.assertEqual(_print_bundles(), 0)

    def test_empty_bundle_hard_fails_loud(self):
        # Audit W4: a bundle with no runnable detectors must NOT run a scan that
        # "passes" with zero findings — it hard-fails with a clear message.
        # injection has only injection/api packs (unpopulated today).
        self.assertEqual(runnable_packs(resolve_bundle("injection")), ())
        args = argparse.Namespace(bundle="injection", packs="")
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            rc = _apply_bundle_selection(args)
        self.assertEqual(rc, 1)
        self.assertIn("NO runnable detectors", err.getvalue())

    def test_probing_bundle_warns_passive_only(self):
        # A runnable probing bundle (baas) selects packs but must warn loudly that
        # its active phases are not executed by this command.
        args = argparse.Namespace(bundle="baas", packs="")
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            rc = _apply_bundle_selection(args)
        self.assertEqual(rc, 0)
        self.assertEqual(args.packs, "baas")
        out = err.getvalue()
        self.assertIn("PASSIVE detection only", out)
        self.assertIn("baas_probe", out)


if __name__ == "__main__":
    unittest.main()
