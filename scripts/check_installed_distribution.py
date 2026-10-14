#!/usr/bin/env python3
"""Smoke-test a non-editable KeyLeak installation outside its source checkout.

Run with the Python interpreter of the environment containing the built wheel.
Only synthetic local files are scanned. No browser or external service needed.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import random
import string
import subprocess
import sys
import tempfile
from typing import Any


class DistributionCheckError(RuntimeError):
    """An installed-artifact contract was not satisfied."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise DistributionCheckError(message)


def check_json_report(
    output: str,
    *,
    exit_code: int,
    expected_exit: int,
    expected_coverage: str,
    expected_verdict: str,
    expect_findings: bool,
) -> dict[str, Any]:
    """Validate independently of KeyLeak's own coverage/verdict helpers."""
    require(exit_code == expected_exit,
            f"Expected exit {expected_exit}, received {exit_code}")
    try:
        report = json.loads(output)
    except (ValueError, TypeError) as exc:
        raise DistributionCheckError("CLI did not emit valid JSON") from exc
    require(isinstance(report, dict), "Report must be a JSON object")
    coverage = report.get("coverage")
    require(isinstance(coverage, dict), "Missing coverage object")
    require(type(coverage.get("schema_version")) is int
            and coverage["schema_version"] == 1, "Unexpected coverage schema")
    require(coverage.get("status") == expected_coverage, "Unexpected coverage status")
    fields = ("attempted", "completed", "skipped", "failed")
    require(all(type(coverage.get(k)) is int and coverage[k] >= 0 for k in fields),
            "Coverage counts must be nonnegative integers")
    require(coverage["attempted"] > 0, "Smoke target was not attempted")
    require(coverage["attempted"] == sum(coverage[k] for k in fields[1:]),
            "Coverage counts do not reconcile")
    if expected_coverage == "complete":
        require(coverage["completed"] > 0
                and coverage["skipped"] == coverage["failed"] == 0,
                "Complete scan must inspect files without skipping or failing")
        require(coverage.get("reasons") == [], "Complete scan has coverage errors")
    else:
        require(expected_exit != 0, "Incomplete scans must not succeed")
        require(coverage["skipped"] + coverage["failed"] > 0,
                "Expected skipped or failed local scope")
    verdict = report.get("verdict")
    require(isinstance(verdict, dict) and verdict.get("status") == expected_verdict,
            "Unexpected verdict")
    findings = report.get("findings")
    require(isinstance(findings, list), "Missing findings array")
    require(bool(findings) == expect_findings, "Unexpected finding presence")
    return report


def check_redaction(result: subprocess.CompletedProcess[str], synthetic_secret: str) -> None:
    require(synthetic_secret not in result.stdout + result.stderr,
            "Synthetic credential appeared unredacted in process output")


def run_smoke() -> None:
    checkout = Path(__file__).resolve().parents[1]
    # Do not inherit KeyLeak settings, live auth material, or PYTHONPATH from
    # the operator. Keep OS loader/PATH settings needed by the installed Python.
    env = {k: v for k, v in os.environ.items()
           if k not in {"PYTHONPATH", "PYTHONHOME"} and not k.startswith("KEYLEAK_")}
    env.update({"KEYLEAK_MANAGED_INSTALL": "1",
                "KEYLEAK_NO_DEFAULT_SUPPRESSIONS": "1",
                "PYTHONSAFEPATH": "1"})
    with tempfile.TemporaryDirectory(prefix="keyleak-wheel-") as name:
        cwd = Path(name)

        def run(*args: str) -> subprocess.CompletedProcess[str]:
            return subprocess.run([sys.executable, "-I", *args], cwd=cwd, env=env,
                                  capture_output=True, text=True, timeout=60)

        probe = run("-c", "import importlib.metadata as m,json,keyleak; "
                    "print(json.dumps({'path':keyleak.__file__,"
                    "'version':keyleak.__version__,'metadata':m.version('keyleak-detector')}))")
        require(probe.returncode == 0, "Installed package cannot be imported")
        try:
            identity = json.loads(probe.stdout)
        except ValueError as exc:
            raise DistributionCheckError("Invalid package identity output") from exc
        location = Path(identity["path"]).resolve()
        require(not location.is_relative_to(checkout),
                "Imported source checkout instead of installed package")
        require(location.is_relative_to(Path(sys.prefix).resolve()),
                "Imported package is outside the test environment")
        require(identity["version"] == identity["metadata"], "Version metadata disagrees")

        executable = Path(sys.executable).parent / ("keyleak.exe" if os.name == "nt" else "keyleak")
        require(executable.is_file(), "Installed console entry point is missing")
        help_result = subprocess.run([str(executable), "--help"], cwd=cwd, env=env,
                                     capture_output=True, text=True, timeout=60)
        require(help_result.returncode == 0 and "site-scan" in help_result.stdout,
                "Installed console help failed")
        site_help = run("-m", "keyleak.cli", "site-scan", "--help")
        require(site_help.returncode == 0 and "--auto-install" in site_help.stdout,
                "Installed CLI is missing explicit installation consent")

        clean = cwd / "clean"
        clean.mkdir()
        (clean / ".env").write_text("LOG_LEVEL=info\n", encoding="utf-8")
        result = run("-m", "keyleak.cli", "--offline", "local", str(clean), "--json")
        check_json_report(result.stdout, exit_code=result.returncode, expected_exit=0,
                          expected_coverage="complete", expected_verdict="SAFE_TO_SHIP",
                          expect_findings=False)

        affected = cwd / "affected"
        affected.mkdir()
        rng = random.Random(20261014)  # reproducible, synthetic fixture; never a real credential
        token = "sk-" + "proj-" + "".join(rng.choices(string.ascii_letters + string.digits, k=48))
        (affected / ".env").write_text("OPENAI_API_KEY=" + token + "\n", encoding="utf-8")
        result = run("-m", "keyleak.cli", "--offline", "local", str(affected), "--json")
        check_redaction(result, token)
        report = check_json_report(result.stdout, exit_code=result.returncode, expected_exit=2,
                                   expected_coverage="complete", expected_verdict="BLOCK_SHIP",
                                   expect_findings=True)
        require(any(f.get("severity") in {"high", "critical"} for f in report["findings"]),
                "Synthetic credential did not cause a blocking finding")
        result = run("-m", "keyleak.cli", "--offline", "local", str(affected), "--sarif")
        check_redaction(result, token)
        require(result.returncode == 2, "SARIF scan did not preserve the gate exit code")
        sarif = json.loads(result.stdout)
        require(sarif.get("version") == "2.1.0" and sarif.get("runs")
                and sarif["runs"][0].get("results"), "Missing SARIF findings")

        missing = cwd / "missing"
        result = run("-m", "keyleak.cli", "--offline", "local", str(missing), "--json")
        check_json_report(result.stdout, exit_code=result.returncode, expected_exit=2,
                          expected_coverage="incomplete", expected_verdict="REVIEW",
                          expect_findings=False)
        oversized = cwd / "oversized"
        oversized.mkdir()
        with (oversized / ".env").open("wb") as handle:
            handle.seek(5 * 1024 * 1024)
            handle.write(b"x")
        result = run("-m", "keyleak.cli", "--offline", "local", str(oversized), "--json")
        check_json_report(result.stdout, exit_code=result.returncode, expected_exit=2,
                          expected_coverage="incomplete", expected_verdict="REVIEW",
                          expect_findings=False)
        print("PASS: installed identity, console entry point, clean/secret scans, "
              "JSON/SARIF redaction, missing/oversized coverage")


def main() -> int:
    argparse.ArgumentParser(description=__doc__).parse_args()
    try:
        run_smoke()
    except (DistributionCheckError, OSError, subprocess.TimeoutExpired, ValueError, KeyError) as exc:
        # Do not dump subprocess output: a redaction regression can contain the
        # synthetic credential, and this checker must not normalize leaking it.
        print(f"Distribution smoke failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
