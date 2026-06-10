"""Tests for GitHub Actions hardening detectors (audit D4 / threat-currency).

Each detector must fire on the insecure form AND stay silent on the secure form,
so the test fails if the check stops being meaningful.
"""

from __future__ import annotations

import unittest

from keyleak.local_scanner import scan_text
from keyleak.detectors import detectors_for_packs


def _ids(text: str):
    findings = scan_text(text, "ci.yml", detectors_for_packs(["leak"]))
    return {f.detector_id for f in findings if "gh_actions" in f.detector_id}


class GhActionsHardeningTests(unittest.TestCase):
    def test_unpinned_action_flagged_pinned_clean(self):
        self.assertIn("leak.gh_actions_unpinned_action", _ids("      - uses: actions/checkout@v4.2.0\n"))
        self.assertIn("leak.gh_actions_unpinned_action", _ids("      - uses: org/some-action@main\n"))
        # 40-hex SHA pin is clean.
        self.assertNotIn("leak.gh_actions_unpinned_action", _ids("      - uses: actions/checkout@" + "a1b2c3d4" * 5 + "\n"))
        # Local actions have no @ref and must not flag.
        self.assertNotIn("leak.gh_actions_unpinned_action", _ids("      - uses: ./.github/actions/build\n"))

    def test_unpinned_reusable_workflow_flagged(self):
        # Gate D4-FN1: reusable workflows have extra path segments before @ref.
        self.assertIn("leak.gh_actions_unpinned_action",
                      _ids("    uses: org/repo/.github/workflows/build.yml@main\n"))
        self.assertNotIn("leak.gh_actions_unpinned_action",
                         _ids("    uses: org/repo/.github/workflows/build.yml@" + "a" * 40 + "\n"))

    def test_unpinned_docker_action_flagged_digest_clean(self):
        # Gate D4-FN2: docker:// container actions pinned by tag, not @sha256:.
        self.assertIn("leak.gh_actions_unpinned_docker_action", _ids("      - uses: docker://alpine:3.18\n"))
        self.assertNotIn("leak.gh_actions_unpinned_docker_action",
                         _ids("      - uses: docker://alpine@sha256:" + "a" * 64 + "\n"))

    def test_write_all_flagged(self):
        self.assertIn("leak.gh_actions_write_all_permissions", _ids("permissions: write-all\n"))
        self.assertNotIn("leak.gh_actions_write_all_permissions", _ids("permissions:\n  contents: read\n"))

    def test_secret_echoed_flagged_env_clean(self):
        self.assertIn("leak.gh_actions_secret_echoed_in_run", _ids('run: echo "${{ secrets.NPM_TOKEN }}"\n'))
        self.assertIn("leak.gh_actions_secret_echoed_in_run", _ids('run: printf %s ${{ secrets.AWS_KEY }}\n'))
        # Passing via env (the correct pattern) must not flag.
        self.assertNotIn("leak.gh_actions_secret_echoed_in_run", _ids("env:\n  TOK: ${{ secrets.NPM_TOKEN }}\n"))

    def test_detectors_are_repo_only_not_extension(self):
        # Workflow YAML is scanned on disk, not in the browser; these must not
        # ship to the extension (avoids in-browser noise / patterns.js drift).
        from keyleak.detectors import DETECTORS
        ghs = {d.id: d for d in DETECTORS if d.id in (
            "gh_actions_unpinned_action", "gh_actions_unpinned_docker_action",
            "gh_actions_write_all_permissions", "gh_actions_secret_echoed_in_run")}
        self.assertEqual(len(ghs), 4)
        for det in ghs.values():
            self.assertFalse(det.extension, f"{det.id} should be extension=False")


if __name__ == "__main__":
    unittest.main()
