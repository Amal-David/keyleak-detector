"""Exercise the real composite-action shell with an offline scanner stub."""

import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import textwrap
import unittest

import yaml

from keyleak.models import Evidence, Finding, ScanReport


ROOT = Path(__file__).resolve().parents[1]
ACTION = yaml.safe_load((ROOT / "action.yml").read_text(encoding="utf-8"))
SCAN = next(step for step in ACTION["runs"]["steps"] if step.get("id") == "scan")


class GitHubActionContractTests(unittest.TestCase):
    def run_action(self, *, inputs=None, scans=None, allowlist=None, hostile_checkout=False):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        temp_root = Path(temporary.name)
        workdir = temp_root / "checkout"
        workdir.mkdir()
        runner_temp = temp_root / "runner-temp"
        runner_temp.mkdir()
        executable_dir = temp_root / "bin"
        executable_dir.mkdir()
        behavior = {}
        for stage in ("self-audit", "local", "browser-scan"):
            behavior[stage] = dict((scans or {}).get(stage, {}))
            scan = behavior[stage]
            severity = {"SAFE_TO_SHIP": "low", "REVIEW": "medium", "BLOCK_SHIP": "high"}[scan.get("verdict", "SAFE_TO_SHIP")]
            report = ScanReport(
                target="https://preview.example.test" if stage == "browser-scan" else "fixture-repo",
                scan_mode=stage,
                generated_at="2026-10-09T00:00:00+00:00",
                findings=[Finding(
                    type="offline_finding", severity=severity, confidence=0.9,
                    detector_id=f"fixture:{index}", source="fixture.js",
                    evidence=Evidence(source="fixture.js", snippet="Offline finding", line=index + 1),
                    risk_reason="Offline test finding", remediation="Review the fixture",
                ) for index in range(scan.get("count", 0))],
            )
            scan["report"] = report.to_dict()
        scanner = executable_dir / "keyleak"
        scanner.write_text(f"#!{sys.executable}\n" + textwrap.dedent("""\
            import json
            import os
            import sys
            if not sys.flags.isolated:
                raise RuntimeError("Scanner must use isolated Python imports")
            with open(os.environ["SCAN_TRACE"], "a", encoding="utf-8") as trace:
                trace.write(json.dumps(sys.argv[1:]) + "\\n")
            scan = json.loads(os.environ["SCAN_BEHAVIOR"]).get(sys.argv[1], {})
            if "raw" in scan:
                print(scan["raw"], end="")
            else:
                print(json.dumps(scan["report"]))
            sys.exit(scan.get("exit", 0))
            """), encoding="utf-8")
        scanner.chmod(0o755)
        # Substitute only the scanner module with the offline CLI fixture.
        # Run it under the same real -I interpreter as production, preserving
        # inherited Python import environment variables for the regression.
        # Report conversion still runs the installed package without stubbing.
        python_launcher = executable_dir / "python"
        python_launcher.write_text(textwrap.dedent(f"""\
            #!/usr/bin/env bash
            if [[ "${{1-}}" == "-I" && "${{2-}}" == "-m" && "${{3-}}" == "keyleak.cli" ]]; then
              shift 3
              exec {shlex.quote(sys.executable)} -I {shlex.quote(str(scanner))} "$@"
            fi
            # A regression must fail offline instead of invoking a real scan.
            for arg in "$@"; do
              if [[ "$arg" == "keyleak.cli" ]]; then
                echo "Refusing unexpected scanner invocation" >&2
                exit 97
              fi
            done
            exec {shlex.quote(sys.executable)} "$@"
            """), encoding="utf-8")
        python_launcher.chmod(0o755)
        if allowlist is not None:
            (workdir / allowlist).write_text("# test policy\n", encoding="utf-8")
        if hostile_checkout:
            (workdir / "keyleak").mkdir()
            (workdir / "keyleak/__init__.py").write_text("raise RuntimeError('untrusted checkout imported')\n", encoding="utf-8")
            (workdir / "json.py").write_text("raise RuntimeError('untrusted JSON module imported')\n", encoding="utf-8")
            (workdir / "sentinel").write_text("must not be overwritten", encoding="utf-8")
            (workdir / "keyleak-report.json").symlink_to(workdir / "sentinel")
            (workdir / "keyleak-report.html").symlink_to(workdir / "sentinel")
        output = temp_root / "outputs"
        output.touch()
        trace = temp_root / "trace"
        env = {
            **os.environ,
            "PATH": str(executable_dir) + os.pathsep + os.environ.get("PATH", ""),
            "GITHUB_OUTPUT": str(output),
            "RUNNER_TEMP": str(runner_temp),
            "GITHUB_TOKEN": "",
            "KL_MODE": "local",
            "KL_URL": "",
            "KL_FORMAT": "json",
            "KL_FAILON": "high",
            "KL_PROFILE": "ci",
            "KL_ALLOWLIST": allowlist or "",
            "KL_BAAS": "false",
            "SCAN_TRACE": str(trace),
            "SCAN_BEHAVIOR": json.dumps(behavior),
            **(inputs or {}),
        }
        result = subprocess.run(
            ["bash", "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", SCAN["run"]],
            cwd=workdir, env=env, capture_output=True, text=True, timeout=10,
        )
        outputs = {}
        lines = iter(output.read_text(encoding="utf-8").splitlines())
        for line in lines:
            if "<<" in line:
                key, delimiter = line.split("<<", 1)
                value = []
                for next_line in lines:
                    if next_line == delimiter:
                        break
                    value.append(next_line)
                outputs[key] = "\n".join(value)
            else:
                key, _, value = line.partition("=")
                outputs[key] = value
        calls = [json.loads(line) for line in trace.read_text(encoding="utf-8").splitlines()] if trace.exists() else []
        return result, outputs, calls, workdir

    def test_invalid_configuration_fails_before_any_scan(self):
        for inputs in (
            {"KL_MODE": "typo"},
            {"KL_MODE": "browser", "KL_URL": ""},
            {"KL_MODE": "both", "KL_URL": ""},
            {"KL_MODE": "browser", "KL_URL": "--help"},
            {"KL_FORMAT": "unsupported"},
            {"KL_FAILON": "none"},
            {"KL_PROFILE": "typo"},
            {"KL_BAAS": "yes"},
        ):
            with self.subTest(inputs=inputs):
                result, outputs, calls, _ = self.run_action(inputs=inputs)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(outputs["verdict"], "BLOCK_SHIP")
                self.assertEqual(calls, [])
                self.assertNotIn("report_paths", outputs)

    def test_scanner_or_blocking_failures_fail_the_action_and_keep_reports(self):
        for failed_scan in ("self-audit", "local", "browser-scan"):
            for exit_code in (1, 2):
                with self.subTest(failed_scan=failed_scan, exit_code=exit_code):
                    result, outputs, calls, workdir = self.run_action(
                        inputs={"KL_MODE": "both", "KL_URL": "https://preview.example.test"},
                        scans={failed_scan: {"exit": exit_code, "count": 1, "verdict": "BLOCK_SHIP"}},
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(outputs["verdict"], "BLOCK_SHIP")
                    self.assertEqual([call[0] for call in calls], ["self-audit", "local", "browser-scan"])
                    self.assertEqual(len(outputs["report_paths"].splitlines()), 3)
                    for report in outputs["report_paths"].splitlines():
                        self.assertTrue((workdir / report).is_file())

    def test_empty_or_malformed_reports_cannot_be_reported_as_safe(self):
        for raw in ("", "not json", "{}", '{"summary":{"total_findings":-1},"verdict":{"status":"SAFE_TO_SHIP"}}'):
            with self.subTest(raw=raw):
                result, outputs, _, _ = self.run_action(scans={"local": {"raw": raw}})
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(outputs["verdict"], "BLOCK_SHIP")
                self.assertEqual(outputs["findings_count"], "")

    def test_combined_scan_counts_all_reports_and_preserves_review_verdict(self):
        result, outputs, _, _ = self.run_action(
            inputs={"KL_MODE": "both", "KL_URL": "https://preview.example.test"},
            scans={"self-audit": {"count": 1}, "local": {"count": 2, "verdict": "REVIEW"}, "browser-scan": {"count": 3}},
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(outputs["verdict"], "REVIEW")
        self.assertEqual(outputs["findings_count"], "6")
        self.assertEqual(Path(outputs["report_path"]).name, "keyleak-browser-report.json")

    def test_clean_local_scan_produces_a_report_in_the_upload_list(self):
        result, outputs, calls, _ = self.run_action()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(outputs["verdict"], "SAFE_TO_SHIP")
        self.assertEqual(outputs["findings_count"], "0")
        self.assertEqual([call[0] for call in calls], ["self-audit", "local"])
        self.assertIn("keyleak-report.json", [Path(path).name for path in outputs["report_paths"].splitlines()])

    def test_browser_only_mode_and_optional_arguments_are_quoted(self):
        allowlist = "policy with spaces --fail-on critical.txt"
        url = "https://preview.example.test/?x=$(touch unexpected)"
        result, _, calls, workdir = self.run_action(
            inputs={"KL_MODE": "browser", "KL_URL": url, "KL_BAAS": "true"},
            allowlist=allowlist,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][:2], ["browser-scan", url])
        self.assertIn("--baas-validate", calls[0])
        self.assertEqual(calls[0][calls[0].index("--allowlist") + 1], allowlist)
        self.assertEqual(calls[0].count("--fail-on"), 1)
        self.assertFalse((workdir / "unexpected").exists())

    def test_non_json_scan_failures_still_fail(self):
        for output_format in ("sarif", "markdown", "html"):
            with self.subTest(output_format=output_format):
                result, outputs, _, _ = self.run_action(
                    inputs={"KL_FORMAT": output_format},
                    scans={"local": {"exit": 2, "count": 1, "verdict": "BLOCK_SHIP"}},
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(outputs["verdict"], "BLOCK_SHIP")
                self.assertIn(f"keyleak-report.{output_format}", [Path(path).name for path in outputs["report_paths"].splitlines()])

    def test_every_format_uses_the_same_real_report_and_does_not_rescan(self):
        for output_format in ("json", "sarif", "markdown", "html"):
            for verdict in ("REVIEW", "BLOCK_SHIP"):
                with self.subTest(output_format=output_format, verdict=verdict):
                    result, outputs, calls, _ = self.run_action(
                        inputs={"KL_MODE": "browser", "KL_URL": "https://preview.example.test", "KL_FORMAT": output_format, "KL_FAILON": "critical"},
                        scans={"browser-scan": {"count": 1, "verdict": verdict}},
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(outputs["verdict"], verdict)
                    self.assertEqual(outputs["findings_count"], "1")
                    self.assertEqual(len(calls), 1)
                    self.assertIn("--json", calls[0])
                    report = Path(outputs["report_path"])
                    self.assertEqual(report.suffix, f".{output_format}")
                    rendered = report.read_text(encoding="utf-8")
                    self.assertIn("Offline test finding", rendered)
                    if output_format == "json":
                        self.assertEqual(json.loads(rendered)["verdict"]["status"], verdict)
                    elif output_format == "sarif":
                        self.assertEqual(len(json.loads(rendered)["runs"][0]["results"]), 1)
                    else:
                        self.assertIn("REVIEW" if verdict == "REVIEW" else "BLOCK SHIP", rendered.upper())

    def test_report_metadata_must_agree_with_actual_findings(self):
        for raw in (
            '{"summary":{"total_findings":1},"verdict":{"status":"BLOCK_SHIP"},"findings":[]}',
            '{"summary":{"total_findings":0},"verdict":{"status":"BLOCK_SHIP"},"findings":[]}',
        ):
            with self.subTest(raw=raw):
                result, outputs, _, _ = self.run_action(inputs={"KL_FORMAT": "html"}, scans={"local": {"raw": raw}})
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(outputs["verdict"], "BLOCK_SHIP")

    def test_untrusted_checkout_modules_and_report_symlinks_are_not_used(self):
        result, outputs, _, workdir = self.run_action(
            inputs={"KL_FORMAT": "html", "PYTHONPATH": "."}, hostile_checkout=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((workdir / "sentinel").read_text(encoding="utf-8"), "must not be overwritten")
        reports = outputs["report_paths"].splitlines()
        self.assertEqual(len(reports), 4)
        for path in reports:
            report = Path(path)
            self.assertTrue(report.is_file())
            self.assertFalse(report.is_relative_to(workdir))
            self.assertTrue(report.is_relative_to(workdir.parent / "runner-temp"))
            self.assertEqual(report.stat().st_mode & 0o077, 0)

    def test_upload_runs_after_failure_and_uses_only_generated_report_paths(self):
        upload = next(step for step in ACTION["runs"]["steps"] if "actions/upload-artifact@" in step.get("uses", ""))
        self.assertIn("always()", upload["if"])
        self.assertEqual(upload["with"]["path"], "${{ steps.scan.outputs.report_paths }}")


class ReleaseWorkflowPermissionTests(unittest.TestCase):
    def test_build_execution_has_no_oidc_and_publish_only_receives_distributions(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/publish.yml").read_text(encoding="utf-8"))
        jobs = workflow["jobs"]
        build = jobs["build"]
        publish = jobs["pypi-publish"]
        self.assertNotEqual(build["permissions"].get("id-token"), "write")
        self.assertEqual(publish["permissions"], {"id-token": "write"})
        self.assertEqual(publish["needs"], "build")
        self.assertTrue(any("run" in step for step in build["steps"]))
        self.assertTrue(all("run" not in step for step in publish["steps"]))
        self.assertFalse(any("actions/checkout@" in step.get("uses", "") for step in publish["steps"]))
        self.assertEqual(len(publish["steps"]), 2)
        for step in publish["steps"]:
            self.assertRegex(step["uses"], r"@[0-9a-f]{40}$")


if __name__ == "__main__":
    unittest.main()
