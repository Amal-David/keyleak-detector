"""Baseline and allowlist support for repeatable CI scans."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set

from .models import Finding, ScanReport


@dataclass
class SuppressionSet:
    ids: Set[str] = field(default_factory=set)
    detector_ids: Set[str] = field(default_factory=set)
    types: Set[str] = field(default_factory=set)
    signatures: Set[str] = field(default_factory=set)
    source_contains: List[str] = field(default_factory=list)


def apply_suppressions(
    report: ScanReport,
    baseline_path: str = "",
    allowlist_path: str = "",
) -> ScanReport:
    suppressions = SuppressionSet()
    if baseline_path:
        suppressions = merge_suppressions(suppressions, load_suppressions(baseline_path, baseline_mode=True))
    if allowlist_path:
        suppressions = merge_suppressions(suppressions, load_suppressions(allowlist_path))

    if not any(
        [
            suppressions.ids,
            suppressions.detector_ids,
            suppressions.types,
            suppressions.signatures,
            suppressions.source_contains,
        ]
    ):
        return report

    findings = [finding for finding in report.findings if not is_suppressed(finding, suppressions)]
    return ScanReport(
        target=report.target,
        scan_mode=report.scan_mode,
        findings=findings,
        generated_at=report.generated_at,
        retest_command=report.retest_command,
    )


def merge_suppressions(left: SuppressionSet, right: SuppressionSet) -> SuppressionSet:
    return SuppressionSet(
        ids=left.ids | right.ids,
        detector_ids=left.detector_ids | right.detector_ids,
        types=left.types | right.types,
        signatures=left.signatures | right.signatures,
        source_contains=[*left.source_contains, *right.source_contains],
    )


def load_suppressions(path: str, baseline_mode: bool = False) -> SuppressionSet:
    file_path = Path(path).expanduser()
    text = file_path.read_text(encoding="utf-8")
    if file_path.suffix.lower() == ".json":
        return _from_json(json.loads(text), baseline_mode=baseline_mode)
    return _from_lines(text.splitlines())


def is_suppressed(finding: Finding, suppressions: SuppressionSet) -> bool:
    if finding.id in suppressions.ids:
        return True
    if finding.detector_id in suppressions.detector_ids:
        return True
    if finding.type in suppressions.types:
        return True
    if finding_signature(finding) in suppressions.signatures:
        return True

    source = finding.source.lower()
    return any(part.lower() in source for part in suppressions.source_contains)


def finding_signature(finding: Finding) -> str:
    return "|".join(
        [
            finding.detector_id,
            finding.source,
            finding.evidence.redacted_value,
        ]
    )


def _from_json(payload: Any, baseline_mode: bool = False) -> SuppressionSet:
    suppressions = SuppressionSet()

    if isinstance(payload, list):
        _add_items(suppressions, payload, baseline_mode=baseline_mode)
        return suppressions

    if not isinstance(payload, dict):
        raise ValueError("suppression JSON must be an object or list")

    _add_strings(suppressions.ids, payload.get("ids") or payload.get("finding_ids"))
    _add_strings(suppressions.detector_ids, payload.get("detector_ids"))
    _add_strings(suppressions.types, payload.get("types"))
    _add_strings(suppressions.signatures, payload.get("signatures"))
    _add_strings(suppressions.source_contains, payload.get("source_contains") or payload.get("sources"))
    _add_items(suppressions, payload.get("findings") or [], baseline_mode=True)
    _add_items(suppressions, payload.get("rules") or [], baseline_mode=baseline_mode)

    return suppressions


def _from_lines(lines: Iterable[str]) -> SuppressionSet:
    suppressions = SuppressionSet()
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        key, value = _split_line_rule(line)
        if key == "id":
            suppressions.ids.add(value)
        elif key == "detector":
            suppressions.detector_ids.add(value)
        elif key == "type":
            suppressions.types.add(value)
        elif key == "source":
            suppressions.source_contains.append(value)
        elif key == "signature":
            suppressions.signatures.add(value)
        else:
            suppressions.ids.add(value)
    return suppressions


def _add_items(suppressions: SuppressionSet, items: Iterable[Any], baseline_mode: bool = False) -> None:
    for item in items:
        if isinstance(item, str):
            suppressions.ids.add(item)
            continue
        if not isinstance(item, dict):
            continue

        _add_optional(suppressions.ids, item.get("id"))
        _add_optional(suppressions.detector_ids, item.get("detector_id"))
        _add_optional(suppressions.types, item.get("type"))
        _add_optional(suppressions.signatures, _signature_from_dict(item))
        _add_optional(suppressions.source_contains, item.get("source_contains"))
        if not baseline_mode:
            _add_optional(suppressions.source_contains, item.get("source"))


def _signature_from_dict(item: Dict[str, Any]) -> Optional[str]:
    detector_id = item.get("detector_id")
    source = item.get("source")
    evidence = item.get("evidence") or {}
    redacted_value = item.get("redacted_value") or evidence.get("redacted_value")
    if not detector_id or not source or not redacted_value:
        return None
    return "|".join([str(detector_id), str(source), str(redacted_value)])


def _add_strings(target: Any, values: Any) -> None:
    if isinstance(values, str):
        target.add(values) if hasattr(target, "add") else target.append(values)
        return
    for value in values or []:
        _add_optional(target, value)


def _add_optional(target: Any, value: Any) -> None:
    if value is None:
        return
    text = str(value).strip()
    if not text:
        return
    target.add(text) if hasattr(target, "add") else target.append(text)


def _split_line_rule(line: str):
    if ":" not in line:
        return "", line
    key, value = line.split(":", 1)
    return key.strip().lower(), value.strip()
