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
# Per-file read cap (a crafted 50 MB package.json must not be read whole).
MAX_MANIFEST_BYTES = 4 * 1024 * 1024

# A "download" token and an "exec" token; a lifecycle script containing both
# (in any order — piped, ;-chained, or `sh -c "$(curl ...)"`) is downloading and
# running remote code. Kept as two cheap sub-checks so we catch the non-pipe
# forms the original single regex missed (gate D2-FN).
_DOWNLOAD_RE = re.compile(r"\b(?:curl|wget)\b|New-Object\s+Net\.WebClient|downloadString", re.I)
_EXEC_RE = re.compile(r"\|\s*(?:sh|bash|node|python3?)\b|\b(?:sh|bash)\s+-c\b|\bIEX\b|Invoke-Expression", re.I)

# Dangerous shell patterns inside a lifecycle script. (pattern, label, severity).
# ``None`` pattern entries are handled specially in ``_scan_scripts``.
_DANGER_PATTERNS: Tuple[Tuple[Optional[re.Pattern], str, str], ...] = (
    (re.compile(r"base64\b[^|&;]*(?:-d|--decode)\b", re.I),
     "decodes base64 during install (common stager wrapper)", "high"),
    (re.compile(r"/dev/tcp/", re.I), "opens a raw TCP socket (reverse-shell shape)", "high"),
    (re.compile(r"\beval\s*\(|\bnode\s+(?:-e|--eval)\b", re.I),
     "runs inline eval / node -e code during install", "high"),
    (re.compile(r"\b(?:powershell|pwsh)\b.*(?:IEX|Invoke-Expression|downloadString|FromBase64String)", re.I),
     "runs a PowerShell download-and-execute stager", "high"),
    (re.compile(r"\b(?:tanstack_runner|router_init|router_runtime|environment_source|bun_installer)\b", re.I),
     "references a known supply-chain payload filename", "high"),
    (re.compile(r"\bnpm_config_[a-z_]*registry\b|\bnpm\s+set\s+registry\b", re.I),
     "rewrites the npm registry during install (dependency-confusion shape)", "medium"),
    # Bun is only suspicious WITH a network/payload co-signal — bare `bun run
    # build` is a legitimate package-manager call (avoid FP on Bun shops).
    (re.compile(r"\bbun\s+(?:run|x|install|add)\b(?=.*(?:curl|wget|http|base64|eval|\.js))", re.I),
     "invokes Bun alongside a download/payload (Shai-Hulud / Miasma stager shape)", "high"),
)

# Credentials embedded in a dependency URL (e.g. https://user:token@host/...).
# Dependency specs are emitted into findings, so mask userinfo before they land
# in a report artifact (a git/https spec can carry a secret).
_URL_AUTH_RE = re.compile(r"(?i)\b(https?|git|ssh)://([^/@\s]+)@")


def _sanitize_spec(spec: str) -> str:
    return _URL_AUTH_RE.sub(r"\1://***@", spec.strip())


# A dependency value that is NOT a registry version: a git ref, github shorthand,
# or a remote tarball — all bypass registry provenance.
_GIT_REF_RE = re.compile(
    r"^(?:github:|gitlab:|bitbucket:|git\+|git://"          # explicit VCS schemes
    r"|[\w.-]+/[\w.-]+(?:#.+)?$"                             # bare `user/repo[#ref]` github shorthand
    r"|https?://.*\.(?:tgz|tar\.gz)(?:[?#].*)?$)",          # remote tarball
    re.I,
)


def _iter_manifests(root: Path, *, cap: int) -> Tuple[List[Path], bool]:
    """Root package.json + every package.json under ANY node_modules dir in the
    tree (handles nested monorepo node_modules). Returns (paths, truncated),
    where ``truncated`` reflects the *applied* ``cap``."""
    out: List[Path] = []
    truncated = False
    root_pkg = root / "package.json"
    if root_pkg.is_file() and not root_pkg.is_symlink():
        out.append(root_pkg)
    for dirpath, dirnames, filenames in os.walk(root):
        # Prune VCS/cache dirs for speed; keep walking into node_modules.
        dirnames[:] = [d for d in dirnames if d not in {".git", ".hg", ".svn"}]
        if "node_modules" not in Path(dirpath).parts:
            continue
        if "package.json" in filenames:
            manifest = Path(dirpath) / "package.json"
            if manifest.is_symlink():
                continue
            out.append(manifest)
            if len(out) >= cap:
                truncated = True
                return out, truncated
    return out, truncated


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
        # Download-and-execute co-signal: a script that both fetches remote
        # content AND pipes/feeds it to an interpreter (any order/form: pipe,
        # ;-chained, `sh -c "$(curl ...)"`, PowerShell IEX downloadString).
        matched: Optional[Tuple[str, str]] = None
        if _DOWNLOAD_RE.search(cmd) and _EXEC_RE.search(cmd):
            matched = ("downloads remote content and pipes it into a shell/interpreter", "high")
        else:
            for pattern, label, severity in _DANGER_PATTERNS:
                if pattern is not None and pattern.search(cmd):
                    matched = (label, severity)
                    break
        if matched:
                label, severity = matched
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
            safe_spec = _sanitize_spec(spec)  # mask any embedded credentials
            findings.append(
                Finding(
                    type="npm_git_ref_dependency",
                    severity=severity,
                    confidence=0.7,
                    detector_id="leak.npm_git_ref_dependency",
                    source=str(manifest),
                    evidence=Evidence(
                        source=str(manifest),
                        snippet=f'"{dep_field}": {{ "{dep_name}": "{safe_spec[:120]}" }}',
                        redacted_value=f"{dep_name}={safe_spec[:80]}",
                    ),
                    risk_reason=(
                        f"'{pkg}' declares {dep_field} entry '{dep_name}' pinned to a git ref "
                        f"({safe_spec[:80]!r}) instead of a registry version. A git ref is mutable and "
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
    """Audit a project's npm manifests (root + every nested node_modules) for
    dangerous lifecycle hooks and non-registry (git-ref / tarball) dependencies.
    Read-only; runs nothing. Bounded by ``max_manifests`` and a per-file size cap.

    Coverage is heuristic, not exhaustive — it catches the common stager shapes
    (pipe / ;-chained / command-substitution download-and-exec, base64, eval,
    PowerShell IEX, known payload filenames, Bun-with-payload) and non-registry
    deps; bespoke obfuscation can still evade it.
    """
    root_path = Path(root).expanduser().resolve()
    findings: List[Finding] = []
    cap = min(max(1, int(max_manifests)), MAX_MANIFESTS)
    manifests, truncated = _iter_manifests(root_path, cap=cap)
    for manifest in manifests:
        try:
            if manifest.stat().st_size > MAX_MANIFEST_BYTES:
                continue  # skip implausibly large manifest (DoS guard)
            data = json.loads(manifest.read_text(encoding="utf-8", errors="replace"))
        except (ValueError, OSError):
            continue
        if not isinstance(data, dict):
            continue
        is_root = manifest.parent == root_path
        findings.extend(_scan_scripts(manifest, data, is_root=is_root))
        findings.extend(_scan_git_ref_deps(manifest, data))
    if truncated:
        # Fail loud, not silent: tell the user coverage was capped.
        findings.append(
            Finding(
                type="lifecycle_audit_truncated",
                severity="info",
                confidence=0.5,
                detector_id="leak.lifecycle_audit_truncated",
                source=str(root_path),
                evidence=Evidence(source=str(root_path), redacted_value=f"capped at {cap} manifests"),
                risk_reason=(
                    f"The dependency lifecycle audit stopped after {cap} package.json files; "
                    f"some node_modules manifests were NOT scanned. Coverage is incomplete."
                ),
                remediation="Run the audit on subtrees, or raise the cap, to cover the full dependency tree.",
                validation_status="lead",
                category="leak",
            )
        )
    return findings
