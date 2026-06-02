"""Tests for the CLI bundle wiring (keyleak bundles, --bundle)."""

import argparse
import unittest

from keyleak.cli import _apply_bundle_selection, _print_bundles
from keyleak.bundles import REPO_ONLY_PACKS


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


if __name__ == "__main__":
    unittest.main()
