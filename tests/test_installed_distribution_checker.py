"""Exercise artifact-checker failure modes without importing the scanner."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import unittest
from unittest import mock

_MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "check_installed_distribution.py"
_SPEC = importlib.util.spec_from_file_location("keyleak_distribution_smoke", _MODULE_PATH)
CHECKER = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(CHECKER)


class InstalledDistributionCheckerTests(unittest.TestCase):
    def setUp(self):
        """Prepare a minimal reference report for each case."""
        self.report = {
            "coverage": {"schema_version": 1, "status": "complete", "attempted": 1,
                         "completed": 1, "skipped": 0, "failed": 0, "reasons": []},
            "verdict": {"status": "SAFE_TO_SHIP"}, "findings": [],
        }

    def check(self, report=None, code=0):
        """Validate a candidate report against expected clean-scan invariants."""
        return CHECKER.check_json_report(
            json.dumps(self.report if report is None else report), exit_code=code,
            expected_exit=0, expected_coverage="complete", expected_verdict="SAFE_TO_SHIP",
            expect_findings=False,
        )

    def test_smoke_subprocess_does_not_inherit_credentials(self):
        """Keep cloud tokens, GitHub credentials, and loader injections out of children."""
        secret_settings = {
            "GITHUB_TOKEN": "ghs-synthetic",
            "AWS_SECRET_ACCESS_KEY": "aws-synthetic",
            "GOOGLE_APPLICATION_CREDENTIALS": "/tmp/credential-file",
            "AZURE_CLIENT_SECRET": "azure-synthetic",
            "KEYLEAK_EXTRA_TOKEN": "hidden",
            "PYTHONPATH": "/tmp/untrusted-code",
            "PYTHONHOME": "/tmp/untrusted-python",
            "LD_PRELOAD": "/tmp/untrusted.so",
            "DYLD_INSERT_LIBRARIES": "/tmp/untrusted.dylib",
            "HOME": "/tmp/credential-home",
            "PATH": "/tmp/untrusted-bin",
            "HTTPS_PROXY": "http://private.proxy",
        }
        with mock.patch.dict(os.environ, secret_settings, clear=True):
            child_env = CHECKER.build_smoke_environment()
        self.assertEqual(child_env["PATH"], os.defpath)
        self.assertEqual(child_env["KEYLEAK_MANAGED_INSTALL"], "1")
        self.assertEqual(child_env["KEYLEAK_NO_DEFAULT_SUPPRESSIONS"], "1")
        for variable, value in secret_settings.items():
            with self.subTest(variable=variable):
                self.assertNotEqual(child_env.get(variable), value)
        self.assertTrue(set(child_env).issubset({
            "PATH", "PYTHONUTF8", "PYTHONSAFEPATH",
            "KEYLEAK_MANAGED_INSTALL", "KEYLEAK_NO_DEFAULT_SUPPRESSIONS",
            "SystemRoot", "WINDIR", "SYSTEMDRIVE",
        }))

    def test_accepts_complete_clean_report(self):
        """Exercise installed-distribution contract: accepts complete clean report."""
        self.assertEqual(self.check(), self.report)

    def test_rejects_wrong_exit(self):
        """Exercise installed-distribution contract: rejects wrong exit."""
        with self.assertRaises(CHECKER.DistributionCheckError):
            self.check(code=2)

    def test_rejects_invalid_json(self):
        """Exercise installed-distribution contract: rejects invalid json."""
        with self.assertRaises(CHECKER.DistributionCheckError):
            CHECKER.check_json_report("not JSON", exit_code=0, expected_exit=0,
                                      expected_coverage="complete", expected_verdict="SAFE_TO_SHIP",
                                      expect_findings=False)

    def test_rejects_non_object(self):
        """Exercise installed-distribution contract: rejects non object."""
        with self.assertRaises(CHECKER.DistributionCheckError):
            self.check([])

    def test_rejects_missing_coverage(self):
        """Exercise installed-distribution contract: rejects missing coverage."""
        del self.report["coverage"]
        with self.assertRaises(CHECKER.DistributionCheckError):
            self.check()

    def test_rejects_boolean_counts(self):
        """Exercise installed-distribution contract: rejects boolean counts."""
        self.report["coverage"]["attempted"] = True
        with self.assertRaises(CHECKER.DistributionCheckError):
            self.check()

    def test_rejects_boolean_schema(self):
        """Exercise installed-distribution contract: rejects boolean schema."""
        self.report["coverage"]["schema_version"] = True
        with self.assertRaises(CHECKER.DistributionCheckError):
            self.check()

    def test_rejects_zero_inspection(self):
        """Exercise installed-distribution contract: rejects zero inspection."""
        self.report["coverage"].update(attempted=0, completed=0)
        with self.assertRaises(CHECKER.DistributionCheckError):
            self.check()

    def test_rejects_inconsistent_counts(self):
        """Exercise installed-distribution contract: rejects inconsistent counts."""
        self.report["coverage"]["skipped"] = 1
        with self.assertRaises(CHECKER.DistributionCheckError):
            self.check()

    def test_rejects_complete_with_reasons(self):
        """Exercise installed-distribution contract: rejects complete with reasons."""
        self.report["coverage"]["reasons"] = ["partial"]
        with self.assertRaises(CHECKER.DistributionCheckError):
            self.check()

    def test_rejects_silent_findings(self):
        """Exercise installed-distribution contract: rejects silent findings."""
        self.report["findings"] = [{"severity": "high"}]
        with self.assertRaises(CHECKER.DistributionCheckError):
            self.check()

    def test_accepts_blocking_secret_report(self):
        """Exercise installed-distribution contract: accepts blocking secret report."""
        self.report["findings"] = [{"severity": "high"}]
        self.report["verdict"]["status"] = "BLOCK_SHIP"
        CHECKER.check_json_report(json.dumps(self.report), exit_code=2, expected_exit=2,
                                  expected_coverage="complete", expected_verdict="BLOCK_SHIP",
                                  expect_findings=True)

    def test_accepts_incomplete_failed_scope(self):
        """Exercise installed-distribution contract: accepts incomplete failed scope."""
        self.report["coverage"].update(status="incomplete", completed=0, failed=1,
                                       reasons=["missing scan target"])
        self.report["verdict"]["status"] = "REVIEW"
        CHECKER.check_json_report(json.dumps(self.report), exit_code=2, expected_exit=2,
                                  expected_coverage="incomplete", expected_verdict="REVIEW",
                                  expect_findings=False)

    def test_rejects_incomplete_success_contract(self):
        """Exercise installed-distribution contract: rejects incomplete success contract."""
        self.report["coverage"].update(status="incomplete", completed=0, failed=1)
        self.report["verdict"]["status"] = "REVIEW"
        with self.assertRaises(CHECKER.DistributionCheckError):
            CHECKER.check_json_report(json.dumps(self.report), exit_code=0, expected_exit=0,
                                      expected_coverage="incomplete", expected_verdict="REVIEW",
                                      expect_findings=False)

    def test_rejects_secret_in_either_output_stream(self):
        """Exercise installed-distribution contract: rejects secret in either output stream."""
        for stdout, stderr in (("synthetic", ""), ("", "synthetic")):
            with self.subTest(stdout=stdout), self.assertRaises(CHECKER.DistributionCheckError):
                CHECKER.check_redaction(subprocess.CompletedProcess([], 2, stdout, stderr), "synthetic")

    def test_accepts_redacted_output(self):
        """Exercise installed-distribution contract: accepts redacted output."""
        CHECKER.check_redaction(subprocess.CompletedProcess([], 2, "[redacted]", ""), "synthetic")


if __name__ == "__main__":
    unittest.main()
