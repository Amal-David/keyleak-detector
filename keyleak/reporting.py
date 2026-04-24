"""Report builders and output formatters."""

from __future__ import annotations

import json
from typing import Any, Dict, Iterable, List, Optional

from .models import Finding, ScanReport, SEVERITY_ORDER, finding_from_legacy
from .redaction import redact_url


def build_report(
    target: str,
    findings: Iterable[Any],
    scan_mode: str = "runtime",
    attack_vectors: Optional[Dict[str, Any]] = None,
) -> ScanReport:
    normalized = normalize_findings(findings)
    normalized.extend(_attack_vector_findings(attack_vectors or {}))
    normalized.sort(key=lambda finding: SEVERITY_ORDER.get(finding.severity, 0), reverse=True)

    return ScanReport(
        target=target,
        scan_mode=scan_mode,
        findings=normalized,
        retest_command=_retest_command(target, scan_mode),
    )


def normalize_findings(findings: Iterable[Any]) -> List[Finding]:
    normalized: List[Finding] = []
    for raw in findings or []:
        if isinstance(raw, Finding):
            normalized.append(raw)
        elif isinstance(raw, dict):
            normalized.append(finding_from_legacy(raw))
    return normalized


def format_json(report: ScanReport) -> str:
    return json.dumps(report.to_dict(), indent=2, sort_keys=True)


def format_markdown(report: ScanReport) -> str:
    payload = report.to_dict()
    lines = [
        f"# KeyLeak Report: {payload['verdict']['label']}",
        "",
        f"- Target: `{payload['target']}`",
        f"- Scan mode: `{payload['scan_mode']}`",
        f"- Generated: `{payload['generated_at']}`",
        f"- Reason: {payload['verdict']['reason']}",
        f"- Re-test: `{payload['retest_command']}`",
        "",
        "## Findings",
    ]

    if not report.findings:
        lines.append("No findings detected.")
        return "\n".join(lines)

    for finding in report.findings:
        item = finding.to_dict()
        lines.extend(
            [
                "",
                f"### {item['severity'].upper()}: {item['type']}",
                f"- ID: `{item['id']}`",
                f"- Source: `{item['source']}`",
                f"- Evidence: `{item['evidence']['redacted_value']}`",
                f"- Why it matters: {item['risk_reason']}",
                f"- Fix: {item['remediation']}",
            ]
        )
    return "\n".join(lines)


def format_sarif(report: ScanReport) -> str:
    rules = {}
    results = []

    for finding in report.findings:
        item = finding.to_dict()
        detector_id = item["detector_id"]
        rules[detector_id] = {
            "id": detector_id,
            "name": item["type"],
            "shortDescription": {"text": item["type"]},
            "fullDescription": {"text": item["risk_reason"]},
            "help": {"text": item["remediation"]},
        }
        results.append(
            {
                "ruleId": detector_id,
                "level": _sarif_level(item["severity"]),
                "message": {"text": item["risk_reason"]},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": item["source"]},
                            "region": {"startLine": item["evidence"].get("line") or 1},
                        }
                    }
                ],
                "partialFingerprints": {"findingId": item["id"]},
            }
        )

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "KeyLeak Detector",
                        "informationUri": "https://github.com/Amal-David/keyleak-detector",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2, sort_keys=True)


def report_to_text(report: ScanReport) -> str:
    payload = report.to_dict()
    summary = payload["summary"]
    lines = [
        f"{payload['verdict']['label']}: {summary['critical_severity']} critical, "
        f"{summary['high_severity']} high, {summary['medium_severity']} medium, "
        f"{summary['low_severity']} low",
        payload["verdict"]["reason"],
        f"Re-test: {payload['retest_command']}",
    ]

    for finding in payload["findings"][:10]:
        lines.append(
            f"- {finding['severity'].upper()} {finding['type']} at {finding['source']}: "
            f"{finding['evidence']['redacted_value']}"
        )
    if len(payload["findings"]) > 10:
        lines.append(f"... {len(payload['findings']) - 10} more findings")
    return "\n".join(lines)


def fail_threshold_met(report: ScanReport, threshold: str) -> bool:
    threshold_rank = SEVERITY_ORDER.get(str(threshold).lower(), SEVERITY_ORDER["high"])
    return any(SEVERITY_ORDER.get(finding.severity, 0) >= threshold_rank for finding in report.findings)


def _attack_vector_findings(attack_vectors: Dict[str, Any]) -> List[Finding]:
    converted: List[Finding] = []
    for host_result in attack_vectors.get("subdomains", []) or []:
        host = host_result.get("host") or host_result.get("url") or "attack-surface"
        for finding in host_result.get("findings", []) or []:
            raw = dict(finding)
            raw.setdefault("source", f"Attack Surface: {host}")
            raw.setdefault("url", host_result.get("url", ""))
            converted.append(finding_from_legacy(raw, detector_prefix="attack-surface"))
    return converted


def _retest_command(target: str, scan_mode: str) -> str:
    safe_target = redact_url(target)
    if scan_mode == "local":
        return f"keyleak local {safe_target}"
    return f"keyleak scan {safe_target}"


def _sarif_level(severity: str) -> str:
    if severity in {"critical", "high"}:
        return "error"
    if severity == "medium":
        return "warning"
    return "note"
