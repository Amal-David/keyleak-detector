"""Dependency lifecycle-hook audit (audit D2 / threat-currency).

The 2025-2026 supply-chain wave (Shai-Hulud lineage, the Bitwarden-CLI hijack,
node-ipc, the Red Hat "Miasma" npm campaign) all executed through a malicious
``preinstall``/``postinstall``/``prepare`` lifecycle script in a *dependency's*
``package.json`` — typically a Bun/Node stager or a ``curl | sh`` one-liner — and
through ``optionalDependencies`` pinned to a git ref.

KeyLeak's regex pack deliberately **skips ``node_modules``** (see
``local_scanner.SKIP_DIRS``), so a malicious dependency's lifecycle hook is
invisible to it. This module walks ``node_modules`` (and the root manifest),
parses each ``package.json`` structurally, and flags dangerous lifecycle commands
and git-ref dependencies — the exact vectors this repo's CLAUDE.md calls out.

Read-only: it parses files on disk and runs nothing.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .models import Evidence, Finding

LIFECYCLE_HOOKS = ("preinstall", "install", "postinstall", "prepare", "prepublish", "prepublishOnly")

# Hard cap so a giant monorepo can't make the audit run unbounded.
MAX_MANIFESTS = 5000

# Dangerous shell patterns inside a lifecycle script. (pattern, label, severity).
_DANGER_PATTERNS: Tuple[Tuple[re.Pattern, str, str], ...] = (
    (re.compile(r"(?:curl|wget)\b[^|&;]*\|\s*(?:sh|bash|node|python3?)\b", re.I),
     "pipes a downloaded script straight into a shell/interpreter", "high"),
    (re.compile(r"base64\b[^|&;]*(?:-d|--decode)\b[^|&;]*\|\s*(?:sh|bash|node|python3?)\b", re.I),
     "decodes base64 and pipes it into a shell/interpreter", "high"),
    (re.compile(r"/dev/tcp/", re.I), "opens a raw TCP socket (reverse-shell shape)", "high"),
    (re.compile(r"\beval\s*\(", re.I), "calls eval() during install", "high"),
    (re.compile(r"\bnode\s+(?:-e|--eval)\b", re.I), "runs inline node -e code during install", "high"),
    (re.compile(r"\bbun\s+(?:run|x|install|add)\b", re.I),
     "invokes Bun during install (Shai-Hulud / Miasma stager pattern)", "medium"),
    (re.compile(r"\b(?:tanstack_runner|router_init|router_runtime|environment_source|bun_installer)\b", re.I),
     "references a known supply-chain payload filename", "high"),
    (re.compile(r"\bnpm_config_[a-z_]*registry\b|\bnpm\s+set\s+registry\b", re.I),
     "rewrites the npm registry during install (dependency-confusion shape)", "medium"),
)

# A dependency value that is a git ref rather than a registry version.
_GIT_REF_RE = re.compile(r"^(?:github:|gitlab:|bitbucket:|git\+|git://|[\w.-]+/[\w.-]+#)", re.I)


def _iter_manifests(root: Path) -> List[Path]:
    """Root package.json + every package.json under node_modules (capped)."""
    out: List[Path] = []
    root_pkg = root / "package.json"
    if root_pkg.is_file():
        out.append(root_pkg)
    nm = root / "node_modules"
    if nm.is_dir():
        for dirpath, dirnames, filenames in os.walk(nm):
            if "package.json" in filenames:
                out.append(Path(dirpath) / "package.json")
                if len(out) >= MAX_MANIFESTS:
                    return out
    return out


def _package_label(manifest: Path, data: Dict) -> str:
    name = data.get("name")
    if isinstance(name, str) and name:
        return name
    return manifest.parent.name


def _scan_scripts(manifest: Path, data: Dict, *, is_root: bool) -> List[Finding]:
    findings: List[Finding] = []
    scripts = data.get("scripts")
    if not isinstance(scripts, dict):
        return findings
    pkg = _package_label(manifest, data)
    for hook in LIFECYCLE_HOOKS:
        cmd = scripts.get(hook)
        if not isinstance(cmd, str) or not cmd.strip():
            continue
        for pattern, label, severity in _DANGER_PATTERNS:
            if pattern.search(cmd):
                where = "the project" if is_root else f"dependency '{pkg}'"
                findings.append(
                    Finding(
                        type="npm_lifecycle_hook",
                        severity=severity,
                        confidence=0.8 if severity == "high" else 0.6,
                        detector_id="leak.npm_lifecycle_hook",
                        source=str(manifest),
                        evidence=Evidence(
                            source=str(manifest),
                            snippet=f'"{hook}": {cmd[:200]}',
                            redacted_value=f"{pkg}:{hook}",
                        ),
                        risk_reason=(
                            f"The {hook} lifecycle script in {where} {label}. Lifecycle hooks run "
                            f"automatically on `npm install` (developer machine and CI), so this is a "
                            f"code-execution vector — the technique behind the 2025-2026 Shai-Hulud / "
                            f"Miasma / Bitwarden-CLI supply-chain compromises."
                        ),
                        remediation=(
                            "Inspect the script and any file it runs. If it is not clearly benign, "
                            "remove the dependency or pin a known-good version, and install with "
                            "`npm ci --ignore-scripts` (or pnpm v10+, which disables install scripts in "
                            "CI by default). Rotate any credential the install could have reached."
                        ),
                        validation_status="lead",
                        category="leak",
                        references=[
                            "https://www.stepsecurity.io/blog/bitwarden-cli-hijacked-on-npm-bun-staged-credential-stealer-targets-developers-github-actions-and-ai-tools",
                        ],
                    )
                )
                break  # one finding per hook is enough
    return findings


def _scan_git_ref_deps(manifest: Path, data: Dict) -> List[Finding]:
    findings: List[Finding] = []
    pkg = _package_label(manifest, data)
    for dep_field in ("optionalDependencies", "dependencies", "devDependencies"):
        deps = data.get(dep_field)
        if not isinstance(deps, dict):
            continue
        for dep_name, spec in deps.items():
            if not isinstance(spec, str) or not _GIT_REF_RE.match(spec.strip()):
                continue
            # optionalDependencies git-ref is the specific Shai-Hulud IOC.
            severity = "high" if dep_field == "optionalDependencies" else "medium"
            findings.append(
                Finding(
                    type="npm_git_ref_dependency",
                    severity=severity,
                    confidence=0.7,
                    detector_id="leak.npm_git_ref_dependency",
                    source=str(manifest),
                    evidence=Evidence(
                        source=str(manifest),
                        snippet=f'"{dep_field}": {{ "{dep_name}": "{spec[:120]}" }}',
                        redacted_value=f"{dep_name}={spec[:80]}",
                    ),
                    risk_reason=(
                        f"'{pkg}' declares {dep_field} entry '{dep_name}' pinned to a git ref "
                        f"({spec[:80]!r}) instead of a registry version. A git ref is mutable and "
                        f"bypasses registry provenance/scanning — Mini Shai-Hulud (2026) smuggled its "
                        f"payload through exactly an optionalDependencies git ref."
                    ),
                    remediation=(
                        "Replace the git ref with a pinned registry version, or vendor and review the "
                        "code. Treat an optionalDependencies git ref in a third-party package as "
                        "suspicious until proven otherwise."
                    ),
                    validation_status="lead",
                    category="leak",
                    references=[
                        "https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem",
                    ],
                )
            )
    return findings


def audit_node_dependencies(root: str, *, max_manifests: int = MAX_MANIFESTS) -> List[Finding]:
    """Audit a project's npm manifests (root + node_modules) for dangerous
    lifecycle hooks and git-ref dependencies. Read-only; runs nothing."""
    root_path = Path(root).expanduser().resolve()
    findings: List[Finding] = []
    manifests = _iter_manifests(root_path)[:max_manifests]
    for manifest in manifests:
        try:
            data = json.loads(manifest.read_text(encoding="utf-8", errors="replace"))
        except (ValueError, OSError):
            continue
        if not isinstance(data, dict):
            continue
        is_root = manifest.parent == root_path
        findings.extend(_scan_scripts(manifest, data, is_root=is_root))
        findings.extend(_scan_git_ref_deps(manifest, data))
    return findings
