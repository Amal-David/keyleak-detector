"""Tests for scan bundles (keyleak.bundles).

These pin the *contract* of bundles: what each runs, the passive/active split,
and the read-only invariant — so a change in intent fails loudly.
"""

import unittest

from keyleak.bundles import (
    BUNDLES,
    REPO_ONLY_PACKS,
    Bundle,
    ProbePolicy,
    all_known_packs,
    bundle_packs,
    resolve_bundle,
    validate_bundles,
    web_packs,
)
from keyleak.detectors import DETECTOR_PACKS


class ResolveTests(unittest.TestCase):
    def test_resolve_known_bundle(self):
        self.assertIsInstance(resolve_bundle("secrets"), Bundle)
        self.assertEqual(resolve_bundle("SECRETS").id, "secrets")  # case-insensitive

    def test_unknown_bundle_raises(self):
        with self.assertRaises(KeyError):
            resolve_bundle("does-not-exist")

    def test_bundle_packs_helper(self):
        self.assertEqual(bundle_packs("secrets"), ("leak",))


class CompositionTests(unittest.TestCase):
    def test_deep_includes_every_runtime_pack(self):
        deep = resolve_bundle("deep")
        self.assertEqual(set(deep.packs), set(web_packs()))
        # deep must cover the high-value runtime packs...
        for pack in ("leak", "baas", "access-control", "appsec"):
            self.assertIn(pack, deep.packs)
        # ...and must NOT pull in repo-only (static) packs.
        for pack in REPO_ONLY_PACKS:
            self.assertNotIn(pack, deep.packs)

    def test_web_packs_excludes_repo_only(self):
        self.assertEqual(set(web_packs()), all_known_packs() - set(REPO_ONLY_PACKS))

    def test_every_bundle_pack_is_known(self):
        known = all_known_packs()
        for bundle in BUNDLES.values():
            for pack in bundle.packs:
                self.assertIn(pack, known, f"{bundle.id} references unknown pack {pack}")

    def test_existing_packs_still_present(self):
        # guard: bundles must not silently drop a real pack from the registry
        for pack in ("leak", "baas", "access-control", "appsec"):
            self.assertIn(pack, DETECTOR_PACKS)


class PassiveActiveSplitTests(unittest.TestCase):
    def test_passive_bundles_send_no_crafted_requests(self):
        for bid in ("secrets", "quick"):
            bundle = resolve_bundle(bid)
            self.assertFalse(bundle.is_active, f"{bid} should be passive")
            self.assertFalse(bundle.probe_policy.active)
            self.assertEqual(bundle.probe_policy.max_requests, 0)

    def test_active_bundles_declare_active_policy(self):
        for bid in ("baas", "authz", "injection", "recon", "deep"):
            bundle = resolve_bundle(bid)
            self.assertTrue(bundle.is_active, f"{bid} should be active")
            self.assertTrue(bundle.probe_policy.active)
            self.assertGreater(bundle.probe_policy.max_requests, 0)


class InvariantTests(unittest.TestCase):
    def test_read_only_invariant_holds_for_all(self):
        for bundle in BUNDLES.values():
            self.assertTrue(bundle.probe_policy.read_only, f"{bundle.id} must be read-only")

    def test_validate_bundles_passes(self):
        validate_bundles()  # raises on any inconsistency

    def test_validate_rejects_write_policy(self):
        bad = Bundle("bad", "x", "x", ("leak",), ("probe",), ProbePolicy(active=True, read_only=False, max_requests=1))
        # simulate registry corruption and confirm the validator would catch it
        original = dict(BUNDLES)
        try:
            BUNDLES[bad.id] = bad
            with self.assertRaises(ValueError):
                validate_bundles()
        finally:
            BUNDLES.clear()
            BUNDLES.update(original)


if __name__ == "__main__":
    unittest.main()
