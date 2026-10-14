"""Exercise artifact-checker failure modes without importing the scanner."""
import importlib.util
import json
from pathlib import Path
import subprocess
import unittest

_MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "check_installed_distribution.py"
_SPEC = importlib.util.spec_from_file_location("keyleak_distribution_smoke", _MODULE_PATH)
CHECKER = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(CHECKER)


class InstalledDistributionCheckerTests(unittest.TestCase):
    def setUp(self):
        self.report = {
            "coverage": {"schema_version": 1, "status": "complete", "attempted": 1,
                         "completed": 1, "skipped": 0, "failed": 0, "reasons": []},
            "verdict": {"status": "SAFE_TO_SHIP"}, "findings": [],
        }

    def check(self, report=None, code=0):
        return CHECKER.check_json_report(
            json.dumps(self.report if report is None else report), exit_code=code,
            expected_exit=0, expected_coverage="complete", expected_verdict="SAFE_TO_SHIP",
            expect_findings=False,
        )

    def test_accepts_complete_clean_report(self):
        self.assertEqual(self.check(), self.report)

    def test_rejects_wrong_exit(self):
        with self.assertRaises(CHECKER.DistributionCheckError):
            self.check(code=2)

    def test_rejects_invalid_json(self):
        with self.assertRaises(CHECKER.DistributionCheckError):
            CHECKER.check_json_report("not JSON", exit_code=0, expected_exit=0,
                                      expected_coverage="complete", expected_verdict="SAFE_TO_SHIP",
                                      expect_findings=False)

    def test_rejects_non_object(self):
        with self.assertRaises(CHECKER.DistributionCheckError):
            self.check([])

    def test_rejects_missing_coverage(self):
        del self.report["coverage"]
        with self.assertRaises(CHECKER.DistributionCheckError):
            self.check()

    def test_rejects_boolean_counts(self):
        self.report["coverage"]["attempted"] = True
        with self.assertRaises(CHECKER.DistributionCheckError):
            self.check()

    def test_rejects_boolean_schema(self):
        self.report["coverage"]["schema_version"] = True
        with self.assertRaises(CHECKER.DistributionCheckError):
            self.check()

    def test_rejects_zero_inspection(self):
        self.report["coverage"].update(attempted=0, completed=0)
        with self.assertRaises(CHECKER.DistributionCheckError):
            self.check()

    def test_rejects_inconsistent_counts(self):
        self.report["coverage"]["skipped"] = 1
        with self.assertRaises(CHECKER.DistributionCheckError):
            self.check()

    def test_rejects_complete_with_reasons(self):
        self.report["coverage"]["reasons"] = ["partial"]
        with self.assertRaises(CHECKER.DistributionCheckError):
            self.check()

    def test_rejects_silent_findings(self):
        self.report["findings"] = [{"severity": "high"}]
        with self.assertRaises(CHECKER.DistributionCheckError):
            self.check()

    def test_accepts_blocking_secret_report(self):
        self.report["findings"] = [{"severity": "high"}]
        self.report["verdict"]["status"] = "BLOCK_SHIP"
        CHECKER.check_json_report(json.dumps(self.report), exit_code=2, expected_exit=2,
                                  expected_coverage="complete", expected_verdict="BLOCK_SHIP",
                                  expect_findings=True)

    def test_accepts_incomplete_failed_scope(self):
        self.report["coverage"].update(status="incomplete", completed=0, failed=1,
                                       reasons=["missing scan target"])
        self.report["verdict"]["status"] = "REVIEW"
        CHECKER.check_json_report(json.dumps(self.report), exit_code=2, expected_exit=2,
                                  expected_coverage="incomplete", expected_verdict="REVIEW",
                                  expect_findings=False)

    def test_rejects_incomplete_success_contract(self):
        self.report["coverage"].update(status="incomplete", completed=0, failed=1)
        self.report["verdict"]["status"] = "REVIEW"
        with self.assertRaises(CHECKER.DistributionCheckError):
            CHECKER.check_json_report(json.dumps(self.report), exit_code=0, expected_exit=0,
                                      expected_coverage="incomplete", expected_verdict="REVIEW",
                                      expect_findings=False)

    def test_rejects_secret_in_either_output_stream(self):
        for stdout, stderr in (("synthetic", ""), ("", "synthetic")):
            with self.subTest(stdout=stdout), self.assertRaises(CHECKER.DistributionCheckError):
                CHECKER.check_redaction(subprocess.CompletedProcess([], 2, stdout, stderr), "synthetic")

    def test_accepts_redacted_output(self):
        CHECKER.check_redaction(subprocess.CompletedProcess([], 2, "[redacted]", ""), "synthetic")


if __name__ == "__main__":
    unittest.main()
