"""KeyLeak self-supply-chain audit.

Audits the KeyLeak repository for known supply-chain attack surfaces:

- Tag-pinned GitHub Actions ``uses:`` references (must be full SHA pins).
- Dangerous workflow triggers (``pull_request_target``, ``workflow_run``).
- Risky ``extension/package.json`` shapes (``optionalDependencies`` git refs,
  lifecycle scripts ``prepare`` / ``preinstall`` / ``postinstall``).
- Missing ``poetry.lock`` (and drift, if poetry is installed).
- Missing ``.github/CODEOWNERS`` covering ``.github/workflows/``.
- Expired entries in a ``keyleak-allowlist.yaml`` (best-effort, forward-looking
  for Wave 1.2).

The audit returns a regular :class:`~keyleak.models.ScanReport` so the existing
verdict + emit + fail-on logic reused by the CLI works without changes.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Iterable, List, Optional

from .models import Evidence, Finding, ScanReport
from .reporting import build_report


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def run_self_audit(repo_root: Path, *, allow_external_commands: bool = True) -> ScanReport:
    """Run every audit check against ``repo_root`` and return a ``ScanReport``.

    ``allow_external_commands`` disables the optional ``poetry check --lock``
    subprocess for callers that need a strictly in-process assessment.
    """

    repo_root = Path(repo_root).resolve()
    findings: List[Finding] = []

    findings.extend(_audit_workflows(repo_root))
    findings.extend(_audit_extension_package_json(repo_root))
    findings.extend(_audit_poetry_lockfile(repo_root, allow_external_commands=allow_external_commands))
    findings.extend(_audit_codeowners(repo_root))
    findings.extend(_audit_allowlist_yaml(repo_root))

    return build_report(
        str(repo_root),
        findings,
        scan_mode="self-audit",
        profile="self-audit",
        packs=["self-audit"],
    )


# ---------------------------------------------------------------------------
# Workflow audit
# ---------------------------------------------------------------------------

# Match a `uses: owner/repo@ref` line. We only care about the ref.
_USES_LINE_RE = re.compile(r"^\s*-?\s*uses:\s*([^\s#]+)\s*(?:#.*)?$", re.MULTILINE)
_SHA_RE = re.compile(r"^[a-f0-9]{40}$")
# Top-level `on:` block may be inline (`on: [pull_request]`) or block-style.
_ON_INLINE_RE = re.compile(r"^on:\s*(.+)$", re.MULTILINE)
_ON_BLOCK_RE = re.compile(r"^on:\s*\n((?:[ \t]+.+\n?)+)", re.MULTILINE)
_DANGEROUS_TRIGGERS = ("pull_request_target", "workflow_run")
# Local actions like `./.github/actions/foo` don't need SHA pins.
_LOCAL_REF_RE = re.compile(r"^\.{1,2}/")


def _audit_workflows(repo_root: Path) -> List[Finding]:
    findings: List[Finding] = []
    workflows_dir = repo_root / ".github" / "workflows"
    if not workflows_dir.is_dir():
        return findings

    for workflow_path in sorted(workflows_dir.glob("*.y*ml")):
        try:
            content = workflow_path.read_text(encoding="utf-8")
        except OSError as exc:
            findings.append(_finding(
                detector_id="self_audit.workflow_unreadable",
                finding_type="workflow_unreadable",
                severity="medium",
                source=str(workflow_path.relative_to(repo_root)),
                snippet=str(exc),
                risk_reason="Workflow file could not be read.",
                remediation="Check file permissions and re-run self-audit.",
            ))
            continue

        findings.extend(_audit_workflow_uses(workflow_path, repo_root, content))
        findings.extend(_audit_workflow_triggers(workflow_path, repo_root, content))

    return findings


def _audit_workflow_uses(workflow_path: Path, repo_root: Path, content: str) -> List[Finding]:
    findings: List[Finding] = []
    rel = str(workflow_path.relative_to(repo_root))

    for match in _USES_LINE_RE.finditer(content):
        spec = match.group(1).strip().strip('"').strip("'")
        if _LOCAL_REF_RE.match(spec):
            continue  # local composite actions are not SHA-pinned
        if "@" not in spec:
            findings.append(_finding(
                detector_id="self_audit.workflow_uses_unpinned",
                finding_type="workflow_uses_unpinned",
                severity="high",
                source=rel,
                line=content.count("\n", 0, match.start()) + 1,
                snippet=match.group(0).strip(),
                risk_reason=f"Action `{spec}` has no ref pin at all.",
                remediation="Pin to a full 40-character commit SHA.",
            ))
            continue
        ref = spec.rsplit("@", 1)[1]
        if not _SHA_RE.match(ref):
            findings.append(_finding(
                detector_id="self_audit.workflow_uses_tag_pinned",
                finding_type="workflow_uses_tag_pinned",
                severity="high",
                source=rel,
                line=content.count("\n", 0, match.start()) + 1,
                snippet=match.group(0).strip(),
                risk_reason=(
                    f"`{spec}` is tag-pinned. Tags can be moved by the action publisher; "
                    "use a full 40-character commit SHA."
                ),
                remediation=(
                    f"Replace `@{ref}` with the full commit SHA from "
                    f"https://github.com/{spec.rsplit('@', 1)[0]}/commits"
                ),
            ))
    return findings


def _audit_workflow_triggers(workflow_path: Path, repo_root: Path, content: str) -> List[Finding]:
    findings: List[Finding] = []
    rel = str(workflow_path.relative_to(repo_root))

    inline = _ON_INLINE_RE.search(content)
    block = _ON_BLOCK_RE.search(content)
    on_text = ""
    if inline:
        on_text = inline.group(1)
    if block:
        on_text += "\n" + block.group(1)

    for trigger in _DANGEROUS_TRIGGERS:
        if re.search(rf"\b{re.escape(trigger)}\b", on_text):
            findings.append(_finding(
                detector_id="self_audit.workflow_dangerous_trigger",
                finding_type="workflow_dangerous_trigger",
                severity="critical",
                source=rel,
                snippet=f"on: ... {trigger}",
                risk_reason=(
                    f"Workflow uses `{trigger}` trigger, which runs in the context of the base "
                    "repo with write scope. This is the 'Pwn Request' pattern."
                ),
                remediation=(
                    "Switch to `pull_request`. If you must inspect PR state with write scope, "
                    "split into two workflows and pass artifacts between them."
                ),
            ))
    return findings


# ---------------------------------------------------------------------------
# extension/package.json audit
# ---------------------------------------------------------------------------

_GIT_REF_RE = re.compile(r"^(?:github:|git\+|git://|ssh://)", re.IGNORECASE)
_LIFECYCLE_SCRIPTS = ("prepare", "preinstall", "postinstall")


def _audit_extension_package_json(repo_root: Path) -> List[Finding]:
    findings: List[Finding] = []
    package_path = repo_root / "extension" / "package.json"
    if not package_path.is_file():
        return findings

    try:
        data = json.loads(package_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        findings.append(_finding(
            detector_id="self_audit.package_json_unreadable",
            finding_type="package_json_unreadable",
            severity="medium",
            source="extension/package.json",
            snippet=str(exc),
            risk_reason="extension/package.json could not be parsed.",
            remediation="Restore valid JSON in extension/package.json.",
        ))
        return findings

    optional_deps = data.get("optionalDependencies") or {}
    for name, version in optional_deps.items():
        if isinstance(version, str) and _GIT_REF_RE.match(version):
            findings.append(_finding(
                detector_id="self_audit.npm_optional_dep_git_ref",
                finding_type="npm_optional_dep_git_ref",
                severity="high",
                source="extension/package.json",
                snippet=f'"{name}": "{version}"',
                risk_reason=(
                    "optionalDependencies points to a git ref. This is the Mini Shai-Hulud "
                    "vector that hit @tanstack on 2026-05-11."
                ),
                remediation=(
                    "Remove the git-ref dependency. Pin to a published semver from the registry "
                    "or vendor the code in-tree."
                ),
            ))

    scripts = data.get("scripts") or {}
    for hook in _LIFECYCLE_SCRIPTS:
        if hook in scripts:
            findings.append(_finding(
                detector_id="self_audit.npm_lifecycle_script",
                finding_type="npm_lifecycle_script",
                severity="high",
                source="extension/package.json",
                snippet=f'"{hook}": {json.dumps(scripts[hook])}',
                risk_reason=(
                    f"`scripts.{hook}` runs arbitrary code at install time. This is the "
                    "exfil-on-install vector the worm family uses."
                ),
                remediation=(
                    f"Remove `scripts.{hook}`. If you genuinely need a build step, move it to a "
                    "dev-time `build` script that contributors run explicitly."
                ),
            ))
    return findings


# ---------------------------------------------------------------------------
# poetry.lock audit
# ---------------------------------------------------------------------------

def _audit_poetry_lockfile(repo_root: Path, *, allow_external_commands: bool = True) -> List[Finding]:
    findings: List[Finding] = []
    lock_path = repo_root / "poetry.lock"
    pyproject_path = repo_root / "pyproject.toml"
    if not pyproject_path.is_file():
        return findings

    if not lock_path.is_file():
        findings.append(_finding(
            detector_id="self_audit.poetry_lock_missing",
            finding_type="poetry_lock_missing",
            severity="medium",
            source="poetry.lock",
            snippet="missing",
            risk_reason=(
                "poetry.lock is not checked in. Production installs are not reproducible and "
                "transitive deps can drift silently."
            ),
            remediation="Run `poetry lock --no-update` and commit poetry.lock.",
        ))
        return findings

    if not allow_external_commands:
        return findings

    poetry = shutil.which("poetry")
    if poetry is None:
        return findings  # best-effort: skip lock-drift check if poetry isn't installed

    try:
        result = subprocess.run(
            [poetry, "check", "--lock"],
            cwd=repo_root,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return findings

    if result.returncode != 0:
        findings.append(_finding(
            detector_id="self_audit.poetry_lock_drift",
            finding_type="poetry_lock_drift",
            severity="medium",
            source="poetry.lock",
            snippet=(result.stderr or result.stdout or "").strip()[:400] or "poetry check --lock failed",
            risk_reason=(
                "poetry.lock is out of sync with pyproject.toml. Reproducible installs may pick "
                "up unexpected versions."
            ),
            remediation="Run `poetry lock --no-update` and commit the regenerated poetry.lock.",
        ))
    return findings


# ---------------------------------------------------------------------------
# CODEOWNERS audit
# ---------------------------------------------------------------------------

def _audit_codeowners(repo_root: Path) -> List[Finding]:
    findings: List[Finding] = []
    candidates = [
        repo_root / ".github" / "CODEOWNERS",
        repo_root / "CODEOWNERS",
        repo_root / "docs" / "CODEOWNERS",
    ]
    existing = [path for path in candidates if path.is_file()]
    if not existing:
        findings.append(_finding(
            detector_id="self_audit.codeowners_missing",
            finding_type="codeowners_missing",
            severity="medium",
            source=".github/CODEOWNERS",
            snippet="missing",
            risk_reason=(
                "CODEOWNERS is missing. Without it, branch protection cannot require human review "
                "on sensitive paths like .github/workflows/."
            ),
            remediation=(
                "Create .github/CODEOWNERS covering .github/workflows/, keyleak/, pyproject.toml, "
                "poetry.lock, extension/package.json, and keyleak-allowlist.*"
            ),
        ))
        return findings

    content = existing[0].read_text(encoding="utf-8")
    required_patterns = (
        ".github/workflows",
        "keyleak",
        "pyproject.toml",
    )
    missing = [pattern for pattern in required_patterns if pattern not in content]
    if missing:
        findings.append(_finding(
            detector_id="self_audit.codeowners_incomplete",
            finding_type="codeowners_incomplete",
            severity="low",
            source=str(existing[0].relative_to(repo_root)),
            snippet=f"missing patterns: {', '.join(missing)}",
            risk_reason=(
                "CODEOWNERS exists but does not cover all sensitive paths. Without coverage, those "
                "paths can be edited without an owner review."
            ),
            remediation=(
                "Add owner rules for: " + ", ".join(missing)
            ),
        ))
    return findings


# ---------------------------------------------------------------------------
# Allowlist YAML audit (forward-looking for Wave 1.2)
# ---------------------------------------------------------------------------

# Simple line-based date scan. We don't pull in PyYAML just for this.
_EXPIRES_RE = re.compile(r"^\s*expires_at:\s*[\"']?(\d{4}-\d{2}-\d{2})[\"']?\s*$", re.MULTILINE)
_TODAY_OVERRIDE_ENV = "KEYLEAK_SELF_AUDIT_TODAY"  # for tests


def _today_iso() -> str:
    import os
    from datetime import date

    override = os.environ.get(_TODAY_OVERRIDE_ENV)
    if override:
        return override
    return date.today().isoformat()


def _audit_allowlist_yaml(repo_root: Path) -> List[Finding]:
    findings: List[Finding] = []
    candidates = list(repo_root.glob("keyleak-allowlist.y*ml"))
    if not candidates:
        return findings

    today = _today_iso()
    for path in candidates:
        try:
            content = path.read_text(encoding="utf-8")
        except OSError:
            continue
        for match in _EXPIRES_RE.finditer(content):
            expires = match.group(1)
            if expires < today:
                findings.append(_finding(
                    detector_id="self_audit.allowlist_entry_expired",
                    finding_type="allowlist_entry_expired",
                    severity="medium",
                    source=str(path.relative_to(repo_root)),
                    line=content.count("\n", 0, match.start()) + 1,
                    snippet=match.group(0).strip(),
                    risk_reason=(
                        f"Allowlist entry expired on {expires} (today is {today}). Expired entries "
                        "should be removed or renewed to keep the gate honest."
                    ),
                    remediation=(
                        "Remove the expired allowlist entry, or extend `expires_at` after a "
                        "fresh review."
                    ),
                ))
    return findings


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _finding(
    *,
    detector_id: str,
    finding_type: str,
    severity: str,
    source: str,
    snippet: str = "",
    risk_reason: str,
    remediation: str,
    line: Optional[int] = None,
) -> Finding:
    evidence = Evidence(
        source=source,
        snippet=snippet,
        line=line,
        redacted_value=snippet[:120],
    )
    return Finding(
        type=finding_type,
        severity=severity,
        confidence=0.95,
        detector_id=detector_id,
        source=source,
        evidence=evidence,
        risk_reason=risk_reason,
        remediation=remediation,
        validation_status="validated",
        category="self-audit",
    )
