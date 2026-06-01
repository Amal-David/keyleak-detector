"""Allowlist provenance gate.

A malicious PR pattern: in the same commit, the contributor (a) ships a leaking
file and (b) edits ``keyleak-allowlist.yaml`` to add a rule that suppresses
exactly that finding. The launch-gate runs the scan after suppressions are
applied, so the malicious payload ships green.

This module compares the *added* entries in an allowlist YAML diff against the
files changed in the same PR. Any added entry whose scope matches a changed
file (and that would suppress a real finding in that file) is reported as a
``critical`` self-shield finding.

The intended caller is ``.github/workflows/allowlist-provenance.yml`` which
runs::

    keyleak allowlist-diff \\
        --base-allowlist <(git show ${GITHUB_BASE_REF}:keyleak-allowlist.yaml) \\
        --head-allowlist keyleak-allowlist.yaml \\
        --changed-files <(git diff --name-only ${GITHUB_BASE_REF}..HEAD)

In tests, the inputs are passed directly.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

import yaml  # PyYAML

from .local_scanner import scan_file
from .detectors import detectors_for_packs, normalize_packs
from .models import Evidence, Finding, ScanReport
from .reporting import build_report, fail_threshold_met, format_json, format_markdown, format_sarif, report_to_text


def audit_pr_diff(
    repo_root: Path,
    base_allowlist_text: str,
    head_allowlist_text: str,
    changed_files: Sequence[Path],
) -> ScanReport:
    """Return a ScanReport containing any same-PR self-shield findings."""

    repo_root = Path(repo_root).resolve()
    added = _added_entries(base_allowlist_text, head_allowlist_text)

    detectors = list(detectors_for_packs(normalize_packs(None, profile="ci")))

    self_shield: List[Finding] = []
    for entry in added:
        for file_path in changed_files:
            abs_path = (repo_root / file_path).resolve()
            if not _is_safe_under_root(abs_path, repo_root):
                continue
            if not abs_path.is_file():
                continue
            # Skip the allowlist itself.
            if abs_path.name.startswith("keyleak-allowlist"):
                continue

            if not _entry_matches_path(entry, file_path):
                continue

            findings = scan_file(abs_path, detectors)
            for finding in findings:
                if _entry_suppresses(entry, finding):
                    self_shield.append(_self_shield_finding(entry, file_path, finding))

    return build_report(
        str(repo_root),
        self_shield,
        scan_mode="allowlist-diff",
        profile="allowlist-diff",
        packs=["allowlist-diff"],
    )


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _added_entries(base_text: str, head_text: str) -> List[Dict[str, Any]]:
    base = _entries_set(base_text)
    head_entries = _entries_list(head_text)
    return [entry for entry in head_entries if _entry_key(entry) not in base]


def _entries_set(text: str) -> set:
    return {_entry_key(entry) for entry in _entries_list(text)}


def _entries_list(text: str) -> List[Dict[str, Any]]:
    if not text.strip():
        return []
    data = yaml.safe_load(text) or {}
    if not isinstance(data, dict):
        return []
    raw = data.get("entries") or []
    return [entry for entry in raw if isinstance(entry, dict)]


def _entry_key(entry: Dict[str, Any]) -> str:
    return "|".join([
        str(entry.get("id") or ""),
        str(entry.get("detector") or ""),
        str(entry.get("type") or ""),
        str(entry.get("source_contains") or ""),
    ])


def _is_safe_under_root(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root)
    except ValueError:
        return False
    return True


def _entry_matches_path(entry: Dict[str, Any], file_path: Path) -> bool:
    source_contains = entry.get("source_contains")
    if source_contains:
        return source_contains.lower() in str(file_path).lower()
    # Entries with only `id`/`detector`/`type` apply repo-wide. We assume yes
    # and let the finding-level match decide.
    return True


def _entry_suppresses(entry: Dict[str, Any], finding: Finding) -> bool:
    entry_detector = (entry.get("detector") or "").strip()
    entry_type = (entry.get("type") or "").strip()
    entry_source = (entry.get("source_contains") or "").strip().lower()
    entry_id = (entry.get("id") or "").strip()

    if entry_id and entry_id == finding.id:
        return True
    if entry_detector and entry_detector == finding.detector_id:
        return True
    if entry_type and entry_type == finding.type:
        return True
    if entry_source and entry_source in finding.source.lower():
        return True
    return False


def _self_shield_finding(entry: Dict[str, Any], file_path: Path, finding: Finding) -> Finding:
    snippet = (
        f"entry={entry.get('detector') or entry.get('source_contains') or entry.get('id')} "
        f"suppresses {finding.detector_id} in {file_path}"
    )
    return Finding(
        type="allowlist_self_shield",
        severity="critical",
        confidence=0.99,
        detector_id="allowlist_diff.self_shield",
        source=str(file_path),
        evidence=Evidence(
            source=str(file_path),
            snippet=snippet,
            line=finding.evidence.line,
            redacted_value=finding.evidence.redacted_value,
        ),
        risk_reason=(
            "A new allowlist entry was added in the same PR that introduced a finding the entry "
            "now suppresses. This is the supply-chain-on-the-tool pattern — a single PR cannot "
            "both ship a payload and grant itself a waiver."
        ),
        remediation=(
            "Either remove the new allowlist entry, remove the leaking file, or open a separate "
            "PR that adds the allowlist entry first and gets an `allowlist-approved` label from a "
            "CODEOWNER outside the PR author's org."
        ),
        validation_status="validated",
        category="allowlist-diff",
    )


# ---------------------------------------------------------------------------
# CLI entry point (used by .github/workflows/allowlist-provenance.yml)
# ---------------------------------------------------------------------------


def cli_main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="keyleak allowlist-diff")
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--base-allowlist", required=True, help="Path to allowlist YAML before the PR (use /dev/stdin or a file).")
    parser.add_argument("--head-allowlist", required=True, help="Path to allowlist YAML after the PR.")
    parser.add_argument("--changed-files", required=True, help="Path to a file listing one changed path per line.")
    parser.add_argument("--fail-on", default="critical", choices=["low", "medium", "high", "critical"])
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--sarif", action="store_true")
    parser.add_argument("--markdown", action="store_true")
    args = parser.parse_args(argv)

    base_text = Path(args.base_allowlist).read_text(encoding="utf-8") if args.base_allowlist != "/dev/null" else ""
    head_text = Path(args.head_allowlist).read_text(encoding="utf-8")
    changed = [Path(line.strip()) for line in Path(args.changed_files).read_text(encoding="utf-8").splitlines() if line.strip()]

    report = audit_pr_diff(Path(args.repo_root), base_text, head_text, changed)

    if args.json:
        print(format_json(report))
    elif args.sarif:
        print(format_sarif(report))
    elif args.markdown:
        print(format_markdown(report))
    else:
        print(report_to_text(report))

    return 2 if fail_threshold_met(report, args.fail_on) else 0


if __name__ == "__main__":
    sys.exit(cli_main())
