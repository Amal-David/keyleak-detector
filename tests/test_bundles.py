"""Tests for scan bundles (keyleak.bundles).

These pin the *contract* of bundles: what each runs, the passive/navigation/
probing split, the safety defaults, and that every bundle resolves through the
real pack system — so a change in intent fails loudly.
"""

import unittest

from keyleak.bundles import (
    ALLOWED_SCOPES,
    BUNDLES,
    PROBING_PHASES,
    REPO_ONLY_PACKS,
    Bundle,
    ProbePolicy,
    all_known_packs,
    bundle_packs,
    resolve_bundle,
    unpopulated_packs,
    validate_bundles,
    web_packs,
)
from keyleak.detectors import DETECTOR_PACKS, normalize_packs


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
    def test_deep_covers_every_real_runtime_pack(self):
        deep = resolve_bundle("deep")
        # Expected derived from the SOURCE-OF-TRUTH registry, not from web_packs()
        # (the helper deep also uses) — so a real pack deep forgets fails here.
        expected = set(DETECTOR_PACKS) - set(REPO_ONLY_PACKS)
        self.assertEqual(set(deep.packs), expected)
        for pack in (set(DETECTOR_PACKS) - set(REPO_ONLY_PACKS)):
            self.assertIn(pack, deep.packs, f"deep is missing real pack {pack}")
        for pack in REPO_ONLY_PACKS:
            self.assertNotIn(pack, deep.packs)

    def test_every_bundle_pack_is_real(self):
        # The phantom-pack bug: bundles must reference packs that actually exist.
        for bundle in BUNDLES.values():
            for pack in bundle.packs:
                self.assertIn(pack, DETECTOR_PACKS, f"{bundle.id} -> unknown pack {pack}")

    def test_every_bundle_resolves_through_normalize_packs(self):
        # Guard against the integration bug where a bundle's packs would be
        # rejected by the real pack resolver used by scan/site-scan.
        for bundle in BUNDLES.values():
            runtime = [p for p in bundle.packs if p not in REPO_ONLY_PACKS]
            if not runtime:
                continue
            resolved = normalize_packs(runtime, surface="web")
            for pack in runtime:
                self.assertIn(pack, resolved)


class PhaseSplitTests(unittest.TestCase):
    def test_passive_bundle_sends_no_requests(self):
        secrets = resolve_bundle("secrets")
        self.assertFalse(secrets.sends_requests)
        self.assertFalse(secrets.is_probing)
        self.assertEqual(secrets.probe_policy.max_requests, 0)

    def test_navigation_bundle_sends_requests_but_does_not_probe(self):
        quick = resolve_bundle("quick")  # passive + crawl
        self.assertTrue(quick.sends_requests, "crawl hits the network")
        self.assertFalse(quick.is_probing, "crawl is not crafted probing")
        self.assertGreater(quick.probe_policy.max_requests, 0, "crawl needs a budget")
        self.assertFalse(quick.probe_policy.probing)

    def test_all_probing_bundles_have_consistent_policy(self):
        # iterate EVERY probing bundle so a new one with a bad policy fails here.
        probing = [b for b in BUNDLES.values() if b.is_probing]
        self.assertTrue(probing)
        for bundle in probing:
            self.assertTrue(bundle.probe_policy.probing, f"{bundle.id} must allow probing")
            self.assertGreater(bundle.probe_policy.max_requests, 0)
            self.assertGreater(bundle.probe_policy.rate_per_sec, 0)


class SafetyTests(unittest.TestCase):
    def test_no_builtin_bundle_allows_write_probe(self):
        # The mutating BaaS probe must stay OFF for every shipped bundle.
        for bundle in BUNDLES.values():
            self.assertFalse(
                bundle.probe_policy.allow_write_probe,
                f"{bundle.id} must not enable the mutating write probe by default",
            )

    def test_all_scopes_are_allowed_values(self):
        for bundle in BUNDLES.values():
            self.assertIn(bundle.probe_policy.scope, ALLOWED_SCOPES)

    def test_validate_bundles_passes(self):
        validate_bundles()

    def test_validate_rejects_write_probe_without_probing(self):
        bad = Bundle("bad", "x", "x", ("leak",), ("passive",),
                     ProbePolicy(allow_write_probe=True, probing=False))
        # validate a candidate registry WITHOUT mutating the global one
        with self.assertRaises(ValueError):
            validate_bundles({**BUNDLES, bad.id: bad})

    def test_validate_rejects_requests_without_budget(self):
        bad = Bundle("bad2", "x", "x", ("leak",), ("crawl",), ProbePolicy(max_requests=0))
        with self.assertRaises(ValueError):
            validate_bundles({**BUNDLES, bad.id: bad})

    def test_validate_rejects_probing_phase_without_probing_policy(self):
        bad = Bundle("bad3", "x", "x", ("leak",), ("probe",),
                     ProbePolicy(probing=False, max_requests=10))
        with self.assertRaises(ValueError):
            validate_bundles({**BUNDLES, bad.id: bad})

    def test_global_registry_unmutated_by_validation(self):
        # the validator must never have leaked a candidate bundle into BUNDLES
        self.assertNotIn("bad", BUNDLES)
        self.assertNotIn("bad2", BUNDLES)


class PopulationTests(unittest.TestCase):
    def test_unpopulated_packs_reports_program_packs(self):
        # Until M2-M7 land detectors, the new packs are empty; this surfaces them
        # rather than silently running zero checks.
        deep = resolve_bundle("deep")
        empties = set(unpopulated_packs(deep))
        # leak/baas/access-control are populated today; assert they are NOT empty.
        for pack in ("leak", "baas", "access-control"):
            self.assertNotIn(pack, empties)
        # the helper must only ever return packs the bundle actually declares
        self.assertTrue(empties.issubset(set(deep.packs)))


if __name__ == "__main__":
    unittest.main()
