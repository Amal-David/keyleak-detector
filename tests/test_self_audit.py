import tempfile
import unittest
from pathlib import Path

from keyleak.self_audit import _audit_codeowners


class CodeownersAuditTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        (self.root / ".github").mkdir()

    def _findings(self, content: str):
        (self.root / ".github" / "CODEOWNERS").write_text(content, encoding="utf-8")
        return _audit_codeowners(self.root)

    def test_global_rule_covers_sensitive_paths(self):
        self.assertEqual(self._findings("* @maintainer\n"), [])

    def test_explicit_rules_cover_sensitive_paths(self):
        content = (
            "/.github/workflows/ @maintainer\n"
            "/keyleak/ @maintainer\n"
            "/pyproject.toml @maintainer\n"
        )
        self.assertEqual(self._findings(content), [])

    def test_comments_and_ownerless_patterns_do_not_claim_coverage(self):
        findings = self._findings(
            "# * @maintainer\n"
            "/.github/workflows/ # @maintainer\n"
            "/keyleak/\n"
            "/pyproject.toml\n"
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].detector_id, "self_audit.codeowners_incomplete")

    def test_ownerless_rule_overrides_earlier_global_owner(self):
        findings = self._findings(
            "* @maintainer\n"
            "/.github/workflows/\n"
        )
        self.assertEqual(len(findings), 1)
        self.assertIn(".github/workflows", findings[0].evidence.snippet)

    def test_later_global_owner_restores_coverage(self):
        self.assertEqual(
            self._findings("/.github/workflows/\n* @maintainer\n"),
            [],
        )


if __name__ == "__main__":
    unittest.main()
