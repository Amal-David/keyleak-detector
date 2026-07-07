"""Finding diff between two KeyLeak reports (Wave 3.3).

In the first hour of an incident, the question that matters is *what is new*
between the last known-good report and the current one. ``keyleak diff``
takes two reports and emits only the findings present in the second but not
the first, sorted by severity.

Inputs accepted:
- KeyLeak JSON reports (the native format).
- SARIF 2.1.0 reports.

    We identify findings by their stable ``fingerprint`` field when available,
falling back to the older ``id`` field for legacy reports.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Set

from .models import Finding, ScanReport
from .reporting import build_report


def load_report(path: Path) -> ScanReport:
    """Load a JSON or SARIF report. Returns a normalized ``ScanReport``."""

    text = path.read_text(encoding="utf-8")
    data = json.loads(text)
    if isinstance(data, dict) and "runs" in data:
        return _sarif_to_report(data, target=str(path))
    return ScanReport.from_dict(data)


def _sarif_to_report(sarif: Dict[str, Any], target: str = "") -> ScanReport:
    findings: List[Dict[str, Any]] = []
    runs = sarif.get("runs") or []
    if not runs:
        return ScanReport(target=target, scan_mode="diff", findings=[])
    rules_by_id: Dict[str, Dict[str, Any]] = {}
    for run in runs:
        tool = run.get("tool") or {}
        driver = tool.get("driver") or {}
        for rule in driver.get("rules") or []:
            if rule.get("id"):
                rules_by_id[rule["id"]] = rule
        for result in run.get("results") or []:
            rule_id = result.get("ruleId") or "sarif:unknown"
            locations = result.get("locations") or []
            location = locations[0] if locations else {}
            phys = (location.get("physicalLocation") or {})
            artifact = (phys.get("artifactLocation") or {}).get("uri") or ""
            region = phys.get("region") or {}
            findings.append({
                "id": (result.get("partialFingerprints") or {}).get("findingId") or "",
                "fingerprint": (result.get("partialFingerprints") or {}).get("findingFingerprint") or "",
                "type": (rules_by_id.get(rule_id, {}).get("name")) or rule_id,
                "severity": _sarif_level_to_severity(result.get("level")),
                "detector_id": rule_id,
                "source": artifact,
                "risk_reason": (result.get("message") or {}).get("text") or "",
                "remediation": ((rules_by_id.get(rule_id, {}).get("help") or {}).get("text")) or "",
                "evidence": {
                    "source": artifact,
                    "line": region.get("startLine"),
                    "redacted_value": "",
                },
                "validation_status": "lead",
                "category": ((result.get("properties") or {}).get("category")) or "",
            })
    return ScanReport(target=target, scan_mode="diff", findings=[Finding.from_dict(f) for f in findings])


def _sarif_level_to_severity(level: Any) -> str:
    text = str(level or "").lower()
    if text == "error":
        return "high"
    if text == "warning":
        return "medium"
    return "low"


def diff_reports(baseline: ScanReport, current: ScanReport) -> ScanReport:
    """Return a ScanReport containing only findings *new* in ``current``."""

    baseline_ids: Set[str] = {_identity(f) for f in baseline.findings if _identity(f)}
    new_findings = [f for f in current.findings if _identity(f) and _identity(f) not in baseline_ids]
    return build_report(
        current.target or baseline.target,
        new_findings,
        scan_mode="diff",
        profile=current.extra.get("profile") if isinstance(current.extra, dict) else "diff",
        packs=current.extra.get("packs") if isinstance(current.extra, dict) else None,
    )


def _identity(finding: Finding) -> str:
    return finding.fingerprint or finding.id
