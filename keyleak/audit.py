"""Agentic audit orchestration for the KeyLeak CLI.

The audit front door is deliberately small: it plans a bounded scan, delegates
evidence collection to the existing deterministic scanners, and writes durable
redacted artifacts that an agent can cite or re-run.
"""

from __future__ import annotations

import json
import re
import shlex
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urlparse

from .access_control import compare_access_control_urls
from .archive_scanner import scan_archive
from .doctor import run_doctor
from .local_scanner import DEFAULT_INCLUDES, scan_path
from .models import Finding, ScanReport
from .net_guard import scan_target_block_reason, url_block_reason
from .redaction import redact_url, redact_value
from .reporting import build_report
from .self_audit import run_self_audit
from .suppressions import apply_suppressions


INTENTS = ("ship", "security-audit", "bug-bounty")
DEPTHS = ("passive", "active", "exploit-validation")
NETWORK_DEPTHS = {"active", "exploit-validation"}
NETWORK_TARGET_TYPES = {"url", "domain"}
ARCHIVE_SUFFIXES = (".zip", ".tar", ".tgz", ".tar.gz", ".tar.bz2")


class AuditError(RuntimeError):
    """Raised for audit planning or execution failures."""


class AuditAuthorizationError(AuditError):
    """Raised when a requested network/probing audit lacks explicit scope."""


@dataclass
class AuditOptions:
    target: str
    intent: str = "security-audit"
    depth: Optional[str] = None
    authorized_scope: str = ""
    out_dir: str = ""
    launch_profile: str = ""
    max_pages: int = 100
    max_subdomains: int = 50
    crawl_depth: int = 3
    scan_budget_seconds: int = 30
    headless: bool = True
    baas_validate: bool = False
    bearer: str = ""
    cookie: str = ""
    bearer_b: str = ""
    cookie_b: str = ""
    auth_state_path: str = ""
    offline: bool = False
    proxy: Optional[str] = None
    auto_install: bool = True
    baseline_path: str = ""
    allowlist_path: str = ""
    apply_default_suppressions: bool = True


def classify_target(target: str) -> str:
    """Classify an audit target as local_path, archive, url, or domain."""

    raw = str(target or "").strip()
    if not raw:
        raise AuditError("audit target is required")

    parsed = urlparse(raw)
    if parsed.scheme:
        if parsed.scheme in {"http", "https"} and parsed.netloc:
            return "url"
        raise AuditError("audit targets must be local paths, archives, http(s) URLs, or domains")

    path = Path(raw).expanduser()
    if path.exists():
        if path.is_file() and _is_archive_path(path):
            return "archive"
        return "local_path"

    if _looks_like_domain(raw):
        return "domain"

    if "/" in raw or raw.startswith("."):
        return "local_path"

    raise AuditError(f"could not classify audit target {raw!r}")


def default_depth(intent: str) -> str:
    if intent in {"security-audit", "bug-bounty"}:
        return "exploit-validation"
    return "active"


def default_launch_profile(intent: str) -> str:
    if intent in {"security-audit", "bug-bounty"}:
        return "full"
    return "launch-gate"


def plan_audit(options: AuditOptions) -> Dict[str, Any]:
    normalized = _normalize_options(options)
    target_type = classify_target(normalized.target)
    _guard_authorization(normalized, target_type)

    phases = [
        {
            "id": "preflight",
            "title": "Preflight environment and scope checks",
            "status": "planned",
            "command": "keyleak doctor --json",
            "network": False,
        }
    ]

    if target_type == "local_path":
        phases.extend([
            {
                "id": "local_evidence",
                "title": "Local evidence scan",
                "status": "planned",
                "command": _command([
                    "keyleak", "local", normalized.target,
                    "--launch-profile", normalized.launch_profile,
                    "--json",
                ]),
                "network": False,
            },
            {
                "id": "self_audit",
                "title": "Repository supply-chain self-audit",
                "status": "planned",
                "command": _command(["keyleak", "self-audit", normalized.target, "--json"]),
                "network": False,
            },
        ])
    elif target_type == "archive":
        phases.append({
            "id": "archive_evidence",
            "title": "Archive evidence scan",
            "status": "planned",
            "command": _command([
                "keyleak", "archive", normalized.target,
                "--launch-profile", normalized.launch_profile,
                "--out", "archive-envelope.json",
            ]),
            "network": False,
        })
    elif target_type == "url":
        phases.append(_runtime_phase_for_url(normalized))
    elif target_type == "domain":
        phases.append(_runtime_phase_for_domain(normalized))

    if normalized.depth == "exploit-validation":
        phases.append(_authz_phase(normalized, target_type))

    phases.append({
        "id": "triage",
        "title": "Triage, verdict, retest, and next probes",
        "status": "planned",
        "network": False,
    })

    return {
        "target": _safe_target(normalized.target),
        "target_type": target_type,
        "intent": normalized.intent,
        "depth": normalized.depth,
        "launch_profile": normalized.launch_profile,
        "authorization_scope": {
            "provided": bool(normalized.authorized_scope.strip()),
            "scope": _scrub_sensitive_text(normalized.authorized_scope.strip()),
        },
        "credential_inputs": {
            "auth_state_path": bool(normalized.auth_state_path.strip()),
            "user_a_bearer": bool(normalized.bearer.strip()),
            "user_a_cookie": bool(normalized.cookie.strip()),
            "user_b_bearer": bool(normalized.bearer_b.strip()),
            "user_b_cookie": bool(normalized.cookie_b.strip()),
        },
        "bounds": {
            "crawl_depth": normalized.crawl_depth,
            "max_pages": normalized.max_pages,
            "max_subdomains": normalized.max_subdomains,
            "scan_budget_seconds": normalized.scan_budget_seconds,
            "offline": normalized.offline,
            "proxy": bool(normalized.proxy),
        },
        "phases": phases,
    }


def run_audit(options: AuditOptions) -> ScanReport:
    """Run an audit and write redacted artifacts."""

    normalized = _normalize_options(options)
    target_type = classify_target(normalized.target)
    _guard_authorization(normalized, target_type)
    artifact_dir = _resolve_artifact_dir(normalized)

    plan = plan_audit(normalized)
    findings: List[Finding] = []
    coverage: Dict[str, Any] = {
        "target_type": target_type,
        "intent": normalized.intent,
        "depth": normalized.depth,
        "phases": [],
    }
    validation_attempts: List[Dict[str, Any]] = []
    skipped_phases: List[Dict[str, str]] = []
    source_reports: List[ScanReport] = []

    _complete_phase(plan, "preflight", coverage, _run_preflight())

    if target_type == "local_path":
        _run_local_phase(normalized, plan, findings, coverage, skipped_phases, source_reports)
    elif target_type == "archive":
        _run_archive_phase(normalized, plan, findings, coverage, source_reports)
    elif target_type in NETWORK_TARGET_TYPES:
        _run_runtime_phase(normalized, target_type, plan, findings, coverage, skipped_phases, validation_attempts, source_reports)

    if normalized.depth == "exploit-validation":
        _run_authz_phase(normalized, target_type, plan, findings, coverage, skipped_phases, validation_attempts)

    next_probes = _next_probes(normalized, target_type, skipped_phases)
    _complete_phase(
        plan,
        "triage",
        coverage,
        {
            "next_probes": next_probes,
            "source_reports": [report.scan_mode for report in source_reports],
        },
    )

    report = build_report(
        normalized.target,
        _sanitize_findings(findings),
        scan_mode="audit",
        profile=normalized.launch_profile,
        packs=_packs_from_reports(source_reports),
    )
    report.retest_command = _audit_retest_command(normalized)
    report.extra.update({
        "audit_plan": _scrub_payload(plan),
        "coverage": _scrub_payload(_public_coverage(coverage)),
        "validation_attempts": _scrub_payload(validation_attempts),
        "skipped_phases": _scrub_payload(skipped_phases),
        "authorization_scope": _scrub_sensitive_text(normalized.authorized_scope.strip()),
        "artifact_dir": str(artifact_dir),
        "next_probes": next_probes,
    })

    try:
        report = apply_suppressions(
            report,
            baseline_path=normalized.baseline_path,
            allowlist_path=normalized.allowlist_path,
            apply_defaults=normalized.apply_default_suppressions,
        )
    except (OSError, ValueError) as exc:
        raise AuditError(f"unable to load suppression file: {exc}") from exc

    _write_artifacts(artifact_dir, report)
    return report


def _normalize_options(options: AuditOptions) -> AuditOptions:
    intent = str(options.intent or "security-audit").strip()
    if intent not in INTENTS:
        raise AuditError(f"--intent must be one of: {', '.join(INTENTS)}")
    depth = str(options.depth or default_depth(intent)).strip()
    if depth not in DEPTHS:
        raise AuditError(f"--depth must be one of: {', '.join(DEPTHS)}")
    launch_profile = str(options.launch_profile or default_launch_profile(intent)).strip()
    return AuditOptions(
        target=str(options.target or "").strip(),
        intent=intent,
        depth=depth,
        authorized_scope=str(options.authorized_scope or ""),
        out_dir=str(options.out_dir or ""),
        launch_profile=launch_profile,
        max_pages=int(options.max_pages),
        max_subdomains=int(options.max_subdomains),
        crawl_depth=int(options.crawl_depth),
        scan_budget_seconds=int(options.scan_budget_seconds),
        headless=bool(options.headless),
        baas_validate=bool(options.baas_validate),
        bearer=str(options.bearer or ""),
        cookie=str(options.cookie or ""),
        bearer_b=str(options.bearer_b or ""),
        cookie_b=str(options.cookie_b or ""),
        auth_state_path=str(options.auth_state_path or ""),
        offline=bool(options.offline),
        proxy=options.proxy,
        auto_install=bool(options.auto_install),
        baseline_path=str(options.baseline_path or ""),
        allowlist_path=str(options.allowlist_path or ""),
        apply_default_suppressions=bool(options.apply_default_suppressions),
    )


def _guard_authorization(options: AuditOptions, target_type: str) -> None:
    if target_type in NETWORK_TARGET_TYPES and options.depth in NETWORK_DEPTHS:
        if not options.authorized_scope.strip():
            raise AuditAuthorizationError(
                "Refusing active network/probing audit without --authorized-scope. "
                "Pass a short scope statement such as "
                "`--authorized-scope \"owned preview deployment\"`."
            )


def _runtime_phase_for_url(options: AuditOptions) -> Dict[str, Any]:
    if options.depth == "passive":
        return {
            "id": "runtime_evidence",
            "title": "Runtime evidence scan",
            "status": "skipped",
            "reason": "passive URL audit does not navigate live pages",
            "network": False,
        }
    command = [
        "keyleak", "browser-scan", options.target,
        "--scan-budget", str(options.scan_budget_seconds),
        "--json",
    ]
    if _should_baas_validate(options):
        command.append("--baas-validate")
    if options.auth_state_path:
        command.extend(["--auth-state", "<redacted-auth-state-path>"])
    return {
        "id": "runtime_evidence",
        "title": "Single-URL browser evidence scan",
        "status": "planned",
        "command": _command(command),
        "network": True,
    }


def _runtime_phase_for_domain(options: AuditOptions) -> Dict[str, Any]:
    if options.depth == "passive":
        return {
            "id": "runtime_evidence",
            "title": "Runtime evidence scan",
            "status": "skipped",
            "reason": "passive domain audit does not enumerate or crawl",
            "network": False,
        }
    command = [
        "keyleak", "site-scan", options.target,
        "--launch-profile", options.launch_profile,
        "--depth", str(options.crawl_depth),
        "--max-pages", str(options.max_pages),
        "--max-subdomains", str(options.max_subdomains),
        "--scan-budget", str(options.scan_budget_seconds),
        "--json",
    ]
    if _should_baas_validate(options):
        command.append("--baas-validate")
    return {
        "id": "runtime_evidence",
        "title": "Domain runtime evidence scan",
        "status": "planned",
        "command": _command(command),
        "network": True,
    }


def _authz_phase(options: AuditOptions, target_type: str) -> Dict[str, Any]:
    if target_type not in NETWORK_TARGET_TYPES:
        return {
            "id": "access_control_two_user",
            "title": "Two-user access-control comparison",
            "status": "skipped",
            "reason": "target has no live URL coverage",
            "network": False,
        }
    if not (_has_user_a_auth(options) and _has_user_b_auth(options)):
        return {
            "id": "access_control_two_user",
            "title": "Two-user access-control comparison",
            "status": "skipped",
            "reason": "requires explicit user A and user B credentials (--bearer/--cookie plus --bearer-b/--cookie-b)",
            "network": False,
        }
    return {
        "id": "access_control_two_user",
        "title": "Two-user access-control comparison",
        "status": "planned",
        "network": True,
    }


def _run_preflight() -> Dict[str, Any]:
    results = run_doctor()
    return {
        "checks": [
            {"name": item.name, "status": item.status, "message": item.message}
            for item in results
        ],
        "failures": [item.name for item in results if item.status == "fail"],
        "warnings": [item.name for item in results if item.status == "warn"],
    }


def _run_local_phase(
    options: AuditOptions,
    plan: Dict[str, Any],
    findings: List[Finding],
    coverage: Dict[str, Any],
    skipped_phases: List[Dict[str, str]],
    source_reports: List[ScanReport],
) -> None:
    target = Path(options.target).expanduser()
    if not target.exists():
        raise AuditError(f"local audit target not found: {target}")
    report = scan_path(
        str(target),
        includes=DEFAULT_INCLUDES,
        profile=options.launch_profile,
    )
    findings.extend(report.findings)
    source_reports.append(report)
    _complete_phase(
        plan,
        "local_evidence",
        coverage,
        {"scanner": "local", "findings": len(report.findings), "target": str(target.resolve())},
    )

    if _looks_repo_like(target):
        self_report = run_self_audit(target.resolve())
        findings.extend(self_report.findings)
        source_reports.append(self_report)
        _complete_phase(
            plan,
            "self_audit",
            coverage,
            {"scanner": "self-audit", "findings": len(self_report.findings)},
        )
    else:
        _skip_phase(
            plan,
            "self_audit",
            coverage,
            skipped_phases,
            "target is not a repository or workflow tree",
        )


def _run_archive_phase(
    options: AuditOptions,
    plan: Dict[str, Any],
    findings: List[Finding],
    coverage: Dict[str, Any],
    source_reports: List[ScanReport],
) -> None:
    envelope = scan_archive(options.target, profile=options.launch_profile)
    report = ScanReport.from_dict(envelope.get("report") or {})
    findings.extend(report.findings)
    source_reports.append(report)
    _complete_phase(
        plan,
        "archive_evidence",
        coverage,
        {
            "scanner": "archive",
            "findings": len(report.findings),
            "chain_of_custody": bool(envelope.get("self_hash")),
        },
    )


def _run_runtime_phase(
    options: AuditOptions,
    target_type: str,
    plan: Dict[str, Any],
    findings: List[Finding],
    coverage: Dict[str, Any],
    skipped_phases: List[Dict[str, str]],
    validation_attempts: List[Dict[str, Any]],
    source_reports: List[ScanReport],
) -> None:
    if options.depth == "passive":
        _skip_phase(
            plan,
            "runtime_evidence",
            coverage,
            skipped_phases,
            "passive audit does not issue live navigation or crawl requests",
        )
        return

    if target_type == "url":
        reason = url_block_reason(options.target)
        if reason:
            raise AuditError(f"SSRF guard refused target: {reason}")
        from .browser_scanner import run_browser_scan

        report = run_browser_scan(
            options.target,
            auth_state_path=options.auth_state_path or None,
            scan_budget_seconds=options.scan_budget_seconds,
            headless=options.headless,
            baas_validate=_should_baas_validate(options),
            proxy=options.proxy,
        )
        findings.extend(report.findings)
        source_reports.append(report)
        _complete_phase(
            plan,
            "runtime_evidence",
            coverage,
            {
                "scanner": "browser-scan",
                "findings": len(report.findings),
                "pages_scanned": 1,
                "scanned_urls": [options.target],
            },
        )
        coverage.setdefault("_runtime_urls", []).append(options.target)
        if _should_baas_validate(options):
            validation_attempts.append({
                "kind": "baas",
                "status": "attempted",
                "scanner": "browser-scan",
                "finding_count": _validation_finding_count(report),
            })
        return

    from .site_scanner import scan_site

    report = scan_site(
        options.target,
        depth=options.crawl_depth,
        max_pages=options.max_pages,
        max_subdomains=options.max_subdomains,
        headless=options.headless,
        baas_validate=_should_baas_validate(options),
        scan_budget_seconds=options.scan_budget_seconds,
        launch_profile=options.launch_profile,
        offline=options.offline,
        proxy=options.proxy,
        auto_install=options.auto_install,
        target_guard=scan_target_block_reason,
    )
    findings.extend(report.findings)
    source_reports.append(report)
    _complete_phase(
        plan,
        "runtime_evidence",
        coverage,
        {
            "scanner": "site-scan",
            "findings": len(report.findings),
            "hosts_scanned": report.extra.get("hosts_scanned", 0),
            "pages_scanned": report.extra.get("pages_scanned", 0),
            "pages_failed": report.extra.get("pages_failed", 0),
            "subdomains": report.extra.get("subdomains", []),
            "scanned_urls": report.extra.get("scanned_urls", []),
            "discovery_sources": report.extra.get("discovery_sources", {}),
        },
    )
    coverage.setdefault("_runtime_urls", []).extend(report.extra.get("scanned_urls", []))
    if _should_baas_validate(options):
        validation_attempts.append({
            "kind": "baas",
            "status": "attempted",
            "scanner": "site-scan",
            "finding_count": _validation_finding_count(report),
        })


def _run_authz_phase(
    options: AuditOptions,
    target_type: str,
    plan: Dict[str, Any],
    findings: List[Finding],
    coverage: Dict[str, Any],
    skipped_phases: List[Dict[str, str]],
    validation_attempts: List[Dict[str, Any]],
) -> None:
    if target_type not in NETWORK_TARGET_TYPES:
        _skip_phase(plan, "access_control_two_user", coverage, skipped_phases, "target has no live URL coverage")
        return
    if not (_has_user_a_auth(options) and _has_user_b_auth(options)):
        _skip_phase(
            plan,
            "access_control_two_user",
            coverage,
            skipped_phases,
            "requires explicit user A and user B credentials (--bearer/--cookie plus --bearer-b/--cookie-b)",
        )
        return

    scanned_urls = _scanned_urls_from_coverage(coverage) or [options.target]
    authz_findings = compare_access_control_urls(
        scanned_urls,
        _auth_config(options.bearer, options.cookie),
        _auth_config(options.bearer_b, options.cookie_b),
    )
    findings.extend(authz_findings)
    validation_attempts.append({
        "kind": "two-user-access-control",
        "status": "attempted",
        "candidate_urls": len(scanned_urls),
        "finding_count": len(authz_findings),
    })
    _complete_phase(
        plan,
        "access_control_two_user",
        coverage,
        {
            "scanner": "two-user-access-control",
            "candidate_urls": len(scanned_urls),
            "findings": len(authz_findings),
        },
    )


def _complete_phase(plan: Dict[str, Any], phase_id: str, coverage: Dict[str, Any], detail: Dict[str, Any]) -> None:
    phase = _find_phase(plan, phase_id)
    if phase is not None:
        phase["status"] = "completed"
        phase["result"] = _scrub_payload(detail)
    coverage["phases"].append({
        "id": phase_id,
        "status": "completed",
        **_scrub_payload(detail),
    })


def _skip_phase(
    plan: Dict[str, Any],
    phase_id: str,
    coverage: Dict[str, Any],
    skipped_phases: List[Dict[str, str]],
    reason: str,
) -> None:
    phase = _find_phase(plan, phase_id)
    if phase is not None:
        phase["status"] = "skipped"
        phase["reason"] = reason
    skipped = {"id": phase_id, "reason": reason}
    skipped_phases.append(skipped)
    coverage["phases"].append({"id": phase_id, "status": "skipped", "reason": reason})


def _find_phase(plan: Dict[str, Any], phase_id: str) -> Optional[Dict[str, Any]]:
    for phase in plan.get("phases") or []:
        if phase.get("id") == phase_id:
            return phase
    return None


def _write_artifacts(artifact_dir: Path, report: ScanReport) -> None:
    artifact_dir.mkdir(parents=True, exist_ok=True)
    payload = _scrub_payload(report.to_dict())
    _write_json(artifact_dir / "audit-plan.json", payload.get("audit_plan") or {})
    _write_json(artifact_dir / "report.json", payload)
    _write_json(artifact_dir / "coverage.json", payload.get("coverage") or {})
    _write_json(artifact_dir / "evidence-ledger.json", _evidence_ledger(payload))

    findings_path = artifact_dir / "findings.jsonl"
    findings_path.write_text(
        "".join(json.dumps(_scrub_payload(item), sort_keys=True) + "\n" for item in payload.get("findings") or []),
        encoding="utf-8",
    )
    (artifact_dir / "summary.md").write_text(_summary_markdown(payload), encoding="utf-8")


def _write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(_scrub_payload(payload), indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _evidence_ledger(payload: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "target": payload.get("target", ""),
        "generated_at": payload.get("generated_at", ""),
        "artifact_dir": payload.get("artifact_dir", ""),
        "entries": [
            {
                "finding_id": finding.get("id", ""),
                "detector_id": finding.get("detector_id", ""),
                "severity": finding.get("severity", ""),
                "validation_status": finding.get("validation_status", "lead"),
                "source": finding.get("source", ""),
                "evidence": {
                    "source": (finding.get("evidence") or {}).get("source", ""),
                    "request_url": (finding.get("evidence") or {}).get("request_url", ""),
                    "response_status": (finding.get("evidence") or {}).get("response_status"),
                    "redacted_value": (finding.get("evidence") or {}).get("redacted_value", ""),
                },
                "fingerprint": finding.get("fingerprint", ""),
            }
            for finding in payload.get("findings") or []
        ],
    }


def _summary_markdown(payload: Dict[str, Any]) -> str:
    verdict = payload.get("verdict") or {}
    summary = payload.get("summary") or {}
    lines = [
        f"# KeyLeak Audit: {verdict.get('label', 'REVIEW')}",
        "",
        f"- Target: `{payload.get('target', '')}`",
        f"- Scan mode: `{payload.get('scan_mode', '')}`",
        f"- Generated: `{payload.get('generated_at', '')}`",
        f"- Artifact dir: `{payload.get('artifact_dir', '')}`",
        f"- Reason: {verdict.get('reason', '')}",
        f"- Re-test: `{payload.get('retest_command', '')}`",
        "",
        "## Summary",
        "",
        f"- Critical: `{summary.get('critical_severity', 0)}`",
        f"- High: `{summary.get('high_severity', 0)}`",
        f"- Medium: `{summary.get('medium_severity', 0)}`",
        f"- Low: `{summary.get('low_severity', 0)}`",
        "",
        "## Phases",
        "",
    ]
    for phase in ((payload.get("audit_plan") or {}).get("phases") or []):
        reason = f" — {phase.get('reason')}" if phase.get("reason") else ""
        lines.append(f"- `{phase.get('id')}`: {phase.get('status')}{reason}")
    probes = payload.get("next_probes") or []
    if probes:
        lines.extend(["", "## Next Probes", ""])
        for probe in probes:
            lines.append(f"- {probe}")
    return "\n".join(lines) + "\n"


def _resolve_artifact_dir(options: AuditOptions) -> Path:
    if options.out_dir:
        return Path(options.out_dir).expanduser().resolve()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return (Path(".keyleak") / "audits" / f"{stamp}-{_target_slug(options.target)}").resolve()


def _target_slug(target: str) -> str:
    parsed = urlparse(str(target or ""))
    if parsed.netloc:
        base = parsed.netloc + parsed.path
    else:
        base = Path(str(target or "target")).name or str(target or "target")
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", base).strip("-._").lower()
    return (slug or "target")[:80]


def _audit_retest_command(options: AuditOptions) -> str:
    command = [
        "keyleak", "audit", options.target,
        "--intent", options.intent,
        "--depth", options.depth or default_depth(options.intent),
    ]
    if options.authorized_scope:
        command.extend(["--authorized-scope", _scrub_sensitive_text(options.authorized_scope)])
    return _command(command)


def _next_probes(options: AuditOptions, target_type: str, skipped_phases: Iterable[Dict[str, str]]) -> List[str]:
    probes: List[str] = []
    skipped_ids = {item.get("id") for item in skipped_phases}
    if target_type in NETWORK_TARGET_TYPES and "access_control_two_user" in skipped_ids:
        probes.append("Provide throwaway user A and user B credentials with --bearer/--cookie plus --bearer-b/--cookie-b for two-user access-control validation.")
    if target_type == "url" and options.depth == "active":
        probes.append("Run the same target with --depth exploit-validation and explicit scope to add BaaS validation and two-user comparison.")
    if target_type == "domain" and options.max_pages < 100:
        probes.append("Increase --max-pages and --max-subdomains if the authorized scope includes more of the domain.")
    if target_type in {"local_path", "archive"}:
        probes.append("Audit a deployed URL or domain with explicit scope to add runtime and exploit-validation evidence.")
    return probes


def _sanitize_findings(findings: Iterable[Finding]) -> List[Finding]:
    return [Finding.from_dict(_scrub_payload(finding.to_dict())) for finding in findings]


def _scrub_payload(value: Any) -> Any:
    if isinstance(value, dict):
        cleaned: Dict[str, Any] = {}
        for key, item in value.items():
            if _sensitive_key(str(key)):
                cleaned[key] = "[redacted]"
            else:
                cleaned[key] = _scrub_payload(item)
        return cleaned
    if isinstance(value, list):
        return [_scrub_payload(item) for item in value]
    if isinstance(value, str):
        return _scrub_sensitive_text(value)
    return value


def _scrub_sensitive_text(text: str) -> str:
    if not text:
        return text
    scrubbed = redact_url(text)
    scrubbed = re.sub(r"(?i)\bbearer\s+([A-Za-z0-9._~+/=-]{6,})", "Bearer [redacted]", scrubbed)
    scrubbed = re.sub(
        r"(?i)\b(authorization|proxy-authorization|cookie|set-cookie|x-api-key|api[_-]?key|token|secret)\b\s*[:=]\s*([^\s,;]+)",
        lambda match: f"{match.group(1)}=[redacted]",
        scrubbed,
    )
    scrubbed = re.sub(
        r"\b(?:sk|rk|pk|ghp|gho|github_pat|xox[baprs])[-_A-Za-z0-9]{8,}\b",
        lambda match: redact_value(match.group(0)),
        scrubbed,
    )
    return scrubbed


def _sensitive_key(key: str) -> bool:
    lowered = key.lower().replace("-", "_")
    return lowered in {
        "authorization",
        "proxy_authorization",
        "cookie",
        "set_cookie",
        "bearer",
        "bearer_token",
        "bearer_b",
        "cookie_b",
        "auth_header",
        "auth_headers",
        "auth_config",
        "comparison_auth_config",
    }


def _packs_from_reports(reports: Iterable[ScanReport]) -> List[str]:
    packs: List[str] = []
    seen = set()
    for report in reports:
        for pack in report.extra.get("packs") or []:
            if pack not in seen:
                seen.add(pack)
                packs.append(pack)
    return packs or ["leak", "appsec", "access-control", "baas"]


def _validation_finding_count(report: ScanReport) -> int:
    return sum(1 for finding in report.findings if finding.validation_status in {"validated", "confirmed"})


def _scanned_urls_from_coverage(coverage: Dict[str, Any]) -> List[str]:
    raw_urls = [str(url) for url in coverage.get("_runtime_urls") or [] if str(url or "")]
    if raw_urls:
        return list(dict.fromkeys(raw_urls))
    urls: List[str] = []
    for phase in coverage.get("phases") or []:
        for url in phase.get("scanned_urls") or []:
            if url not in urls:
                urls.append(url)
    return urls


def _public_coverage(coverage: Dict[str, Any]) -> Dict[str, Any]:
    return {key: value for key, value in coverage.items() if not str(key).startswith("_")}


def _has_user_a_auth(options: AuditOptions) -> bool:
    return bool(options.bearer.strip() or options.cookie.strip())


def _has_user_b_auth(options: AuditOptions) -> bool:
    return bool(options.bearer_b.strip() or options.cookie_b.strip())


def _auth_config(bearer: str, cookie: str) -> Dict[str, str]:
    return {"bearer_token": bearer.strip(), "cookie": cookie.strip()}


def _should_baas_validate(options: AuditOptions) -> bool:
    return options.baas_validate or options.depth == "exploit-validation"


def _looks_repo_like(target: Path) -> bool:
    if target.is_file():
        return False
    markers = (".git", ".github", "pyproject.toml", "package.json", "poetry.lock")
    return any((target / marker).exists() for marker in markers)


def _is_archive_path(path: Path) -> bool:
    suffixes = "".join(path.suffixes).lower()
    return path.suffix.lower() in {".zip", ".tar", ".tgz"} or any(suffixes.endswith(suffix) for suffix in ARCHIVE_SUFFIXES)


def _looks_like_domain(raw: str) -> bool:
    if "/" in raw or raw.startswith("."):
        return False
    return bool(re.match(r"^[A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,}(?::\d+)?$", raw))


def _safe_target(target: str) -> str:
    return redact_url(str(target or ""))


def _command(parts: Iterable[str]) -> str:
    return " ".join(shlex.quote(str(part)) for part in parts if str(part) != "")
