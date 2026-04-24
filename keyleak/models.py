"""Stable report models used by the CLI and web UI."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .redaction import redact_snippet, redact_url, redact_value, stable_id


SEVERITY_ORDER = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

VERDICT_SAFE = "SAFE_TO_SHIP"
VERDICT_REVIEW = "REVIEW"
VERDICT_BLOCK = "BLOCK_SHIP"


@dataclass
class Evidence:
    source: str
    snippet: str = ""
    line: Optional[int] = None
    request_url: str = ""
    response_status: Optional[int] = None
    redacted_value: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "snippet": self.snippet,
            "line": self.line,
            "request_url": self.request_url,
            "response_status": self.response_status,
            "redacted_value": self.redacted_value,
        }


@dataclass
class Finding:
    type: str
    severity: str
    confidence: float
    detector_id: str
    source: str
    evidence: Evidence
    risk_reason: str
    remediation: str
    validation_status: str = "not_validated"
    references: List[str] = field(default_factory=list)
    id: str = ""

    def __post_init__(self) -> None:
        self.severity = normalize_severity(self.severity)
        if not self.id:
            self.id = stable_id(self.type, self.detector_id, self.source, self.evidence.redacted_value)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "severity": self.severity,
            "confidence": self.confidence,
            "detector_id": self.detector_id,
            "source": self.source,
            "evidence": self.evidence.to_dict(),
            "redacted_value": self.evidence.redacted_value,
            "risk_reason": self.risk_reason,
            "remediation": self.remediation,
            "references": self.references,
            "validation_status": self.validation_status,
        }


@dataclass
class ScanReport:
    target: str
    scan_mode: str
    findings: List[Finding]
    generated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    retest_command: str = ""

    @property
    def summary(self) -> Dict[str, int]:
        counts = {
            "total_findings": len(self.findings),
            "critical_severity": 0,
            "high_severity": 0,
            "medium_severity": 0,
            "low_severity": 0,
            "info_severity": 0,
        }
        for finding in self.findings:
            key = f"{finding.severity}_severity"
            counts[key] = counts.get(key, 0) + 1
        return counts

    @property
    def verdict(self) -> Dict[str, str]:
        counts = self.summary
        if counts["critical_severity"] or counts["high_severity"]:
            return {
                "status": VERDICT_BLOCK,
                "label": "BLOCK SHIP",
                "reason": "Critical or high-confidence exposures need fixing before release.",
            }
        if counts["medium_severity"]:
            return {
                "status": VERDICT_REVIEW,
                "label": "REVIEW",
                "reason": "Potential exposures or hardening issues need human review.",
            }
        return {
            "status": VERDICT_SAFE,
            "label": "SAFE TO SHIP",
            "reason": "No medium, high, or critical findings were detected in this scan.",
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": redact_url(self.target),
            "scan_mode": self.scan_mode,
            "generated_at": self.generated_at,
            "verdict": self.verdict,
            "summary": self.summary,
            "retest_command": self.retest_command,
            "findings": [finding.to_dict() for finding in self.findings],
        }


def normalize_severity(severity: object) -> str:
    text = str(severity or "info").lower()
    if text not in SEVERITY_ORDER:
        return "info"
    return text


def confidence_for_severity(severity: str, source: str = "") -> float:
    severity = normalize_severity(severity)
    if severity in {"critical", "high"}:
        return 0.9
    if severity == "medium":
        return 0.7
    if source.lower() in {"url", "request header", "response header"}:
        return 0.65
    return 0.55


def finding_from_legacy(raw: Dict[str, Any], detector_prefix: str = "runtime") -> Finding:
    finding_type = str(raw.get("type") or "unknown")
    severity = normalize_severity(raw.get("severity"))
    source = str(raw.get("source") or "unknown")
    raw_value = raw.get("value", raw.get("match", ""))
    redacted_value = redact_value(raw_value)
    snippet = raw.get("context_lines") or raw.get("context") or raw.get("details") or ""

    evidence = Evidence(
        source=source,
        snippet=redact_snippet(snippet, raw_value),
        line=raw.get("line"),
        request_url=redact_url(raw.get("url", "")),
        response_status=raw.get("status_code"),
        redacted_value=redacted_value,
    )

    return Finding(
        type=finding_type,
        severity=severity,
        confidence=float(raw.get("confidence") or confidence_for_severity(severity, source)),
        detector_id=str(raw.get("detector_id") or f"{detector_prefix}:{finding_type}"),
        source=source,
        evidence=evidence,
        risk_reason=str(raw.get("context") or raw.get("details") or f"{finding_type} detected in {source}"),
        remediation=str(raw.get("recommendation") or "Review this finding and remove exposed sensitive data."),
        validation_status=str(raw.get("validation_status") or "not_validated"),
        references=list(raw.get("references") or []),
    )
