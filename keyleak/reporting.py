"""Report builders and output formatters."""

from __future__ import annotations

import html
import json
import shlex
from typing import Any, Dict, Iterable, List, Optional

from .models import Finding, ScanReport, SEVERITY_ORDER, finding_from_legacy
from .privacy_filter import scrub_snippet
from .redaction import redact_url


def _scrub_finding_pii(finding: Finding) -> Finding:
    """Mask adjacent PII in a finding's evidence snippet, preserving the matched
    (already-redacted) secret token.

    This is the single chokepoint that enforces KeyLeak's privacy promise for
    *every* scan mode: previously only ``local_scanner`` scrubbed, so live
    browser/BaaS/site findings could carry third-party emails/phones/cards into
    a report (audit W7). Idempotent — re-scrubbing already-scrubbed text is a
    no-op — so local_scanner's earlier pass is unaffected.
    """
    ev = finding.evidence
    if ev is not None and ev.snippet:
        ev.snippet = scrub_snippet(ev.snippet, ev.redacted_value or None)
    return finding


def build_report(
    target: str,
    findings: Iterable[Any],
    scan_mode: str = "runtime",
    attack_vectors: Optional[Dict[str, Any]] = None,
    profile: str = "launch-gate",
    packs: Optional[Iterable[str]] = None,
) -> ScanReport:
    normalized = normalize_findings(findings)
    normalized.extend(_attack_vector_findings(attack_vectors or {}))
    normalized.sort(key=lambda finding: SEVERITY_ORDER.get(finding.severity, 0), reverse=True)
    selected_packs = list(packs or _packs_from_findings(normalized))

    return ScanReport(
        target=target,
        scan_mode=scan_mode,
        findings=normalized,
        retest_command=_retest_command(target, scan_mode),
        extra={
            "profile": profile,
            "packs": selected_packs,
            "pack_summary": _pack_summary(normalized, selected_packs),
        },
    )


def normalize_findings(findings: Iterable[Any]) -> List[Finding]:
    normalized: List[Finding] = []
    for raw in findings or []:
        if isinstance(raw, Finding):
            normalized.append(raw)
        elif isinstance(raw, dict):
            if "evidence" in raw or "risk_reason" in raw:
                normalized.append(Finding.from_dict(raw))
            else:
                normalized.append(finding_from_legacy(raw))
    # Single PII-scrub chokepoint: applies to every scan mode before any
    # serializer sees the findings (audit W7).
    for finding in normalized:
        _scrub_finding_pii(finding)
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
        f"- Packs: `{', '.join(payload.get('packs') or []) or 'none'}`",
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
                f"- Pack: `{item.get('category') or 'unknown'}`",
                f"- Evidence: `{item['evidence']['redacted_value']}`",
            ]
        )
        rem_v2 = item.get("remediation_v2")
        if rem_v2:
            lines.extend(
                [
                    f"- What leaked: {rem_v2.get('what_leaked') or ''}",
                    f"- Why it matters: {rem_v2.get('why_it_matters') or item['risk_reason']}",
                    "- Fix steps:",
                ]
            )
            for index, step in enumerate(rem_v2.get("fix_steps") or [], start=1):
                lines.append(f"    {index}. {step}")
            if rem_v2.get("verify_command"):
                lines.append(f"- Verify: `{rem_v2['verify_command']}`")
        else:
            lines.append(f"- Why it matters: {item['risk_reason']}")
            lines.append(f"- Fix: {item['remediation']}")
    return "\n".join(lines)


def format_html(report: ScanReport) -> str:
    """Return a self-contained HTML vulnerability report."""
    payload = report.to_dict()
    verdict = payload["verdict"]
    summary = payload["summary"]
    packs = payload.get("packs") or []

    e = html.escape  # shorthand

    # --- verdict class & badge text ---
    verdict_status = verdict["status"]
    if verdict_status == "BLOCK_SHIP":
        verdict_cls = "block"
        verdict_badge = "Block Ship"
    elif verdict_status == "REVIEW":
        verdict_cls = "review"
        verdict_badge = "Review"
    else:
        verdict_cls = "safe"
        verdict_badge = "Safe to Ship"

    # --- findings cards ---
    finding_cards = []
    for finding in report.findings:
        item = finding.to_dict()
        sev = e(item["severity"])
        sev_lower = item["severity"].lower()
        finding_type = e(item["type"])
        risk = e(item["risk_reason"])
        evidence_text = e(item["evidence"]["redacted_value"])
        remediation_text = e(item["remediation"])
        validation = item.get("validation_status", "")

        confirmed_badge = ""
        if validation == "confirmed" or validation == "validated":
            confirmed_badge = '<span class="badge-confirmed">confirmed</span>'

        card = f"""    <div class="finding {e(sev_lower)}">
      <div class="finding-head">
        <span class="sev {e(sev_lower)}">{sev.upper()}</span>
        <span class="finding-type">{finding_type}</span>
        {confirmed_badge}
      </div>
      <div class="finding-detail">{risk}</div>
      <div class="finding-evidence">{evidence_text}</div>
      <div class="finding-fix">Fix: <code>{remediation_text}</code></div>
    </div>"""
        finding_cards.append(card)

    findings_html = "\n\n".join(finding_cards) if finding_cards else "    <p>No findings detected.</p>"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>KeyLeak Vulnerability Report</title>
<style>
  :root {{
    --bg: #0a0a0f;
    --surface: #12121a;
    --surface2: #1a1a26;
    --border: #2a2a3a;
    --text: #e0e0e8;
    --text2: #8888a0;
    --red: #ff4d6a;
    --red-bg: rgba(255,77,106,.08);
    --orange: #ff9f43;
    --orange-bg: rgba(255,159,67,.08);
    --yellow: #ffd43b;
    --yellow-bg: rgba(255,212,59,.08);
    --green: #51cf66;
    --blue: #4dabf7;
    --blue-bg: rgba(77,171,247,.06);
    --mono: 'SF Mono', 'Cascadia Code', 'Fira Code', monospace;
    --sans: -apple-system, BlinkMacSystemFont, 'Inter', 'Segoe UI', sans-serif;
  }}
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ background: var(--bg); color: var(--text); font-family: var(--sans); line-height: 1.5; padding: 40px 20px; }}
  .wrap {{ max-width: 860px; margin: 0 auto; }}

  /* Header */
  .header {{ margin-bottom: 40px; }}
  .header h1 {{ font-size: 15px; font-weight: 500; color: var(--text2); letter-spacing: .5px; text-transform: uppercase; margin-bottom: 8px; }}
  .target {{ font-size: 22px; font-weight: 600; color: var(--text); font-family: var(--mono); margin-bottom: 16px; }}
  .meta {{ display: flex; gap: 24px; font-size: 13px; color: var(--text2); flex-wrap: wrap; }}
  .meta span {{ display: flex; align-items: center; gap: 6px; }}

  /* Verdict banner */
  .verdict {{ display: flex; align-items: center; gap: 16px; padding: 16px 20px; border-radius: 10px; margin-bottom: 32px; border: 1px solid; }}
  .verdict.block {{ background: var(--red-bg); border-color: rgba(255,77,106,.2); }}
  .verdict.review {{ background: var(--yellow-bg); border-color: rgba(255,212,59,.2); }}
  .verdict.safe {{ background: rgba(81,207,102,.08); border-color: rgba(81,207,102,.2); }}
  .verdict-badge {{ font-size: 11px; font-weight: 700; letter-spacing: 1px; text-transform: uppercase; padding: 4px 10px; border-radius: 4px; white-space: nowrap; }}
  .verdict.block .verdict-badge {{ background: var(--red); color: #0a0a0f; }}
  .verdict.review .verdict-badge {{ background: var(--yellow); color: #0a0a0f; }}
  .verdict.safe .verdict-badge {{ background: var(--green); color: #0a0a0f; }}
  .verdict-text {{ font-size: 14px; color: var(--text); }}

  /* Stats row */
  .stats {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 32px; }}
  .stat {{ background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 16px; text-align: center; }}
  .stat-num {{ font-size: 28px; font-weight: 700; font-family: var(--mono); }}
  .stat-num.crit {{ color: var(--red); }}
  .stat-num.high {{ color: var(--orange); }}
  .stat-num.med {{ color: var(--yellow); }}
  .stat-num.low {{ color: var(--blue); }}
  .stat-label {{ font-size: 11px; color: var(--text2); text-transform: uppercase; letter-spacing: .5px; margin-top: 4px; }}

  /* Section */
  .section {{ margin-bottom: 32px; }}
  .section-title {{ font-size: 13px; font-weight: 600; color: var(--text2); text-transform: uppercase; letter-spacing: .5px; margin-bottom: 12px; padding-bottom: 8px; border-bottom: 1px solid var(--border); }}

  /* Finding card */
  .finding {{ background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 16px 20px; margin-bottom: 10px; border-left: 3px solid transparent; }}
  .finding.critical {{ border-left-color: var(--red); }}
  .finding.high {{ border-left-color: var(--orange); }}
  .finding.medium {{ border-left-color: var(--yellow); }}
  .finding.low {{ border-left-color: var(--blue); }}
  .finding-head {{ display: flex; align-items: center; gap: 10px; margin-bottom: 8px; }}
  .sev {{ font-size: 10px; font-weight: 700; letter-spacing: .5px; text-transform: uppercase; padding: 2px 8px; border-radius: 3px; }}
  .sev.critical {{ background: var(--red); color: #0a0a0f; }}
  .sev.high {{ background: var(--orange); color: #0a0a0f; }}
  .sev.medium {{ background: var(--yellow); color: #0a0a0f; }}
  .sev.low {{ background: var(--blue); color: #0a0a0f; }}
  .badge-confirmed {{ font-size: 10px; color: var(--green); border: 1px solid rgba(81,207,102,.3); padding: 1px 6px; border-radius: 3px; }}
  .finding-type {{ font-size: 14px; font-weight: 600; color: var(--text); }}
  .finding-detail {{ font-size: 13px; color: var(--text2); margin-bottom: 6px; }}
  .finding-evidence {{ font-family: var(--mono); font-size: 12px; background: var(--surface2); padding: 8px 12px; border-radius: 6px; color: var(--text); margin: 8px 0; overflow-x: auto; white-space: nowrap; }}
  .finding-fix {{ font-size: 12px; color: var(--text2); margin-top: 8px; }}
  .finding-fix code {{ font-family: var(--mono); font-size: 11px; background: var(--surface2); padding: 2px 6px; border-radius: 3px; color: var(--yellow); }}

  /* Footer */
  .footer {{ margin-top: 40px; padding-top: 20px; border-top: 1px solid var(--border); font-size: 12px; color: var(--text2); display: flex; justify-content: space-between; }}
</style>
</head>
<body>
<div class="wrap">

  <div class="header">
    <h1>KeyLeak Vulnerability Report</h1>
    <div class="target">{e(payload["target"])}</div>
    <div class="meta">
      <span>Scan: {e(payload["scan_mode"])}</span>
      <span>Packs: {e(", ".join(packs) or "none")}</span>
      <span>{e(payload["generated_at"])}</span>
    </div>
  </div>

  <div class="verdict {e(verdict_cls)}">
    <span class="verdict-badge">{e(verdict_badge)}</span>
    <span class="verdict-text">{e(verdict["reason"])}</span>
  </div>

  <div class="stats">
    <div class="stat"><div class="stat-num crit">{summary["critical_severity"]}</div><div class="stat-label">Critical</div></div>
    <div class="stat"><div class="stat-num high">{summary["high_severity"]}</div><div class="stat-label">High</div></div>
    <div class="stat"><div class="stat-num med">{summary["medium_severity"]}</div><div class="stat-label">Medium</div></div>
    <div class="stat"><div class="stat-num low">{summary["low_severity"]}</div><div class="stat-label">Low</div></div>
  </div>

  <div class="section">
    <div class="section-title">Findings</div>

{findings_html}
  </div>

  <div class="footer">
    <span>Generated by KeyLeak Detector</span>
    <span>{e(payload["retest_command"])}</span>
  </div>

</div>
</body>
</html>"""


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
            "properties": {"category": item.get("category") or ""},
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
                "properties": {"category": item.get("category") or ""},
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
        f"Packs: {', '.join(payload.get('packs') or []) or 'none'}",
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
            raw.setdefault("category", "access-control")
            raw.setdefault("validation_status", "lead")
            converted.append(finding_from_legacy(raw, detector_prefix="attack-surface"))
    return converted


def _packs_from_findings(findings: Iterable[Finding]) -> List[str]:
    packs = []
    seen = set()
    for finding in findings:
        category = finding.category or "leak"
        if category not in seen:
            seen.add(category)
            packs.append(category)
    return packs


def _pack_summary(findings: Iterable[Finding], selected_packs: Iterable[str]) -> Dict[str, Dict[str, int]]:
    summary: Dict[str, Dict[str, int]] = {
        pack: {
            "total_findings": 0,
            "critical_severity": 0,
            "high_severity": 0,
            "medium_severity": 0,
            "low_severity": 0,
            "info_severity": 0,
        }
        for pack in selected_packs
    }
    for finding in findings:
        pack = finding.category or "leak"
        if pack not in summary:
            summary[pack] = {
                "total_findings": 0,
                "critical_severity": 0,
                "high_severity": 0,
                "medium_severity": 0,
                "low_severity": 0,
                "info_severity": 0,
            }
        summary[pack]["total_findings"] += 1
        severity_key = f"{finding.severity}_severity"
        summary[pack][severity_key] = summary[pack].get(severity_key, 0) + 1
    return summary


def _retest_command(target: str, scan_mode: str) -> str:
    safe_target = shlex.quote(redact_url(target))
    if scan_mode == "local":
        return f"keyleak local {safe_target}"
    return f"keyleak scan {safe_target}"


def _sarif_level(severity: str) -> str:
    if severity in {"critical", "high"}:
        return "error"
    if severity == "medium":
        return "warning"
    return "note"
