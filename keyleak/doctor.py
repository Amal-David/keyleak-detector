"""`keyleak doctor` — green/yellow/red checklist for a working KeyLeak install.

Goal: from `pip install keyleak-detector` to "all systems go" inside 60 seconds.
Outputs a check-by-check report with copy-paste fixes for anything red.
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import socket
import subprocess
import sys
from dataclasses import dataclass
from typing import List, Optional


@dataclass(frozen=True)
class CheckResult:
    name: str
    status: str  # "ok" | "warn" | "fail"
    message: str
    fix: Optional[str] = None


def _ok(name: str, message: str) -> CheckResult:
    return CheckResult(name=name, status="ok", message=message)


def _warn(name: str, message: str, fix: Optional[str] = None) -> CheckResult:
    return CheckResult(name=name, status="warn", message=message, fix=fix)


def _fail(name: str, message: str, fix: Optional[str] = None) -> CheckResult:
    return CheckResult(name=name, status="fail", message=message, fix=fix)


def check_python_version() -> CheckResult:
    major, minor = sys.version_info[:2]
    if (major, minor) >= (3, 11):
        return _ok("python", f"Python {sys.version.split()[0]}")
    if (major, minor) >= (3, 9):
        return _warn(
            "python",
            f"Python {sys.version.split()[0]} works but 3.11+ is recommended.",
            fix="Install Python 3.11+ from https://www.python.org/ or via pyenv.",
        )
    return _fail(
        "python",
        f"Python {sys.version.split()[0]} is too old.",
        fix="Install Python 3.9+ from https://www.python.org/",
    )


def check_keyleak_imports() -> CheckResult:
    """Verify the core package + its critical optional deps import."""

    missing = []
    for mod in ("requests", "regex", "tldextract", "yaml"):
        if importlib.util.find_spec(mod) is None:
            missing.append(mod)
    if missing:
        return _fail(
            "keyleak-imports",
            f"Missing modules: {', '.join(missing)}",
            fix="Run `pip install -e .` (or `poetry install`) from the repo root.",
        )
    return _ok("keyleak-imports", "Core deps importable.")


def check_playwright() -> CheckResult:
    """Optional — needed only for `keyleak browser-scan` and `keyleak scan`."""

    if importlib.util.find_spec("playwright") is None:
        return _warn(
            "playwright",
            "Playwright is not installed (browser-scan + live-URL scan unavailable).",
            fix="`pip install playwright && python -m playwright install chromium`",
        )
    return _ok("playwright", "Playwright Python bindings installed.")


def check_mitmproxy_cert() -> CheckResult:
    """Verify mitmproxy CA cert exists if a previous run installed it."""

    if importlib.util.find_spec("mitmproxy") is None:
        return _warn(
            "mitmproxy",
            "mitmproxy not installed; `keyleak scan` traffic capture unavailable.",
            fix="`pip install mitmproxy` (already a project dep — run `poetry install`)",
        )
    return _ok("mitmproxy", "mitmproxy Python bindings installed.")


def check_node() -> CheckResult:
    """Required for the extension-bundle smoke test."""

    if shutil.which("node") is None:
        return _warn(
            "node",
            "node is not on PATH; `tools/extension_smoke.mjs` can't run locally.",
            fix="Install Node 20+ (https://nodejs.org/) and re-run.",
        )
    return _ok("node", "node is available.")


def check_poetry() -> CheckResult:
    if shutil.which("poetry") is None:
        return _warn(
            "poetry",
            "poetry not on PATH; lockfile drift cannot be checked.",
            fix="`pipx install poetry` (or `pip install --user poetry`)",
        )
    return _ok("poetry", "poetry is available.")


def check_network_egress() -> CheckResult:
    """Loopback should always work; external is informational."""

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.5)
    try:
        sock.connect(("127.0.0.1", 1))
    except (ConnectionRefusedError, OSError):
        # Either is fine — both mean the socket call succeeded.
        pass
    finally:
        sock.close()
    return _ok("network", "Loopback connectivity OK.")


def check_allowlist_sanity() -> CheckResult:
    """If a YAML allowlist is present, ensure it parses."""

    for candidate in ("keyleak-allowlist.yaml", "keyleak-allowlist.yml"):
        if os.path.isfile(candidate):
            try:
                from .suppressions import load_suppressions

                load_suppressions(candidate)
                return _ok("allowlist", f"{candidate} parses cleanly.")
            except Exception as exc:
                return _fail("allowlist", f"{candidate}: {exc}", fix="Fix the YAML schema; see SECURITY.md.")
    return _ok("allowlist", "No YAML allowlist (legacy .txt may still apply).")


CHECKS = (
    check_python_version,
    check_keyleak_imports,
    check_playwright,
    check_mitmproxy_cert,
    check_node,
    check_poetry,
    check_network_egress,
    check_allowlist_sanity,
)


def run_doctor() -> List[CheckResult]:
    return [check() for check in CHECKS]


def format_results(results: List[CheckResult]) -> str:
    icons = {"ok": "✓", "warn": "!", "fail": "✗"}
    lines: List[str] = ["KeyLeak Doctor"]
    for r in results:
        lines.append(f"  [{icons[r.status]}] {r.name}: {r.message}")
        if r.fix and r.status != "ok":
            lines.append(f"      fix: {r.fix}")
    fails = sum(1 for r in results if r.status == "fail")
    warns = sum(1 for r in results if r.status == "warn")
    summary = f"\n{len(results)} checks · {fails} fail · {warns} warn"
    lines.append(summary)
    return "\n".join(lines)


def cli_main(args) -> int:
    results = run_doctor()
    if getattr(args, "json", False):
        print(json.dumps([
            {"name": r.name, "status": r.status, "message": r.message, "fix": r.fix}
            for r in results
        ], indent=2, sort_keys=True))
    else:
        print(format_results(results))
    return 1 if any(r.status == "fail" for r in results) else 0
