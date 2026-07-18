"""Agentic audit orchestration for the KeyLeak CLI.

The audit front door is deliberately small: it plans a bounded scan, delegates
evidence collection to the existing deterministic scanners, and writes durable
redacted artifacts that an agent can cite or re-run.
"""

from __future__ import annotations

import json
import os
import re
import shlex
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urlparse, urlsplit, urlunsplit

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
ASSESSMENT_MODES = ("balanced", "blue-team", "red-team")
NETWORK_DEPTHS = {"active", "exploit-validation"}
NETWORK_TARGET_TYPES = {"url", "domain"}
ARCHIVE_SUFFIXES = (".zip", ".tar", ".tgz", ".tar.gz", ".tar.bz2")
MAX_CRAWL_DEPTH = 5
MAX_PAGES = 500
MAX_SUBDOMAINS = 100
MAX_SCAN_BUDGET_SECONDS = 120

INTENT_PRESENTATION = {
    "ship": {
        "blue_team": "Release-readiness evidence for the operator's own code or deployment.",
        "red_team": "Maps attacker-relevant exposure questions to read-only KeyLeak evidence; it does not exploit targets.",
    },
    "security-audit": {
        "blue_team": "Defensive evidence collection for secrets, configuration, and access-control regressions.",
        "red_team": "Maps adversarial hypotheses to bounded, read-only KeyLeak checks; it does not fuzz or write to targets.",
    },
    "bug-bounty": {
        "blue_team": "Defensive evidence suitable for responsible disclosure and remediation.",
        "red_team": "Maps in-scope hypotheses to bounded, read-only KeyLeak checks; it does not exploit, fuzz, or write to targets.",
    },
}

ASSESSMENT_MODE_PRESENTATION = {
    "balanced": "Pairs defensive posture evidence with bounded attacker-perspective questions.",
    "blue-team": "Prioritizes defensive posture, remediation, and release-readiness evidence.",
    "red-team": "Prioritizes attacker-perspective exposure questions within the same bounded, read-only KeyLeak capabilities.",
}


class AuditError(RuntimeError):
    """Raised for audit planning or execution failures."""


class AuditAuthorizationError(AuditError):
    """Raised when a requested network/probing audit lacks explicit scope."""


@dataclass
class AuditOptions:
    target: str
    intent: str = "security-audit"
    assessment_mode: str = "balanced"
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
    auth_state_path: str = ""
    offline: bool = False
    proxy: Optional[str] = None
    include_subdomains: bool = False
    baseline_path: str = ""
    allowlist_path: str = ""
    apply_default_suppressions: bool = True
    network_attested: bool = False


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

    runtime_block_reason = _runtime_block_reason(normalized, target_type)
    _apply_network_attestation_status(phases, runtime_block_reason)

    return {
        "target": _safe_target(normalized.target),
        "target_type": target_type,
        "intent": normalized.intent,
        "intent_mapping": INTENT_PRESENTATION[normalized.intent],
        "assessment_mode": normalized.assessment_mode,
        "assessment_focus": ASSESSMENT_MODE_PRESENTATION[normalized.assessment_mode],
        "depth": normalized.depth,
        "launch_profile": normalized.launch_profile,
        "operator_attestation": {
            "provided": bool(normalized.authorized_scope.strip()),
            "scope": _scrub_sensitive_text(normalized.authorized_scope.strip()),
            "network_attested": normalized.network_attested,
            "technical_authorization_proof": False,
            "notice": (
                "This is an operator attestation, not independent technical proof of authorization. "
                "Network phases require both this statement and --attest-network-scope."
            ),
        },
        "credential_inputs": {
            "auth_state_path": bool(normalized.auth_state_path.strip()),
        },
        "bounds": {
            "crawl_depth": normalized.crawl_depth,
            "max_pages": normalized.max_pages,
            "max_subdomains": normalized.max_subdomains,
            "scan_budget_seconds": normalized.scan_budget_seconds,
            "offline": normalized.offline,
            "proxy": bool(normalized.proxy),
            "include_subdomains": normalized.include_subdomains,
        },
        "execution_constraints": {
            "local_first": True,
            "dispatch": "Direct, in-process KeyLeak APIs only; no shell, arbitrary PATH tool, script, or package execution.",
            "network_scope": _network_scope_note(target_type, normalized.include_subdomains),
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
    audit_coverage: Dict[str, Any] = {
        "target_type": target_type,
        "intent": normalized.intent,
        "depth": normalized.depth,
        "phases": [],
    }
    validation_attempts: List[Dict[str, Any]] = []
    skipped_phases: List[Dict[str, str]] = []
    source_reports: List[ScanReport] = []

    preflight = _run_preflight()
    if preflight["failures"]:
        _partial_phase(
            plan,
            "preflight",
            audit_coverage,
            preflight,
            "preflight checks failed: " + ", ".join(preflight["failures"]),
        )
    else:
        _complete_phase(plan, "preflight", audit_coverage, preflight)

    if target_type == "local_path":
        try:
            _run_local_phase(normalized, plan, findings, audit_coverage, skipped_phases, source_reports)
        except Exception as exc:
            _partial_phase(
                plan,
                "local_evidence",
                audit_coverage,
                _phase_failure_detail("local", exc),
                "local scan failed; no local evidence was collected",
            )
            _skip_phase(
                plan,
                "self_audit",
                audit_coverage,
                skipped_phases,
                "self-audit was not run because local evidence collection failed",
            )
    elif target_type == "archive":
        try:
            _run_archive_phase(normalized, plan, findings, audit_coverage, source_reports)
        except Exception as exc:
            _partial_phase(
                plan,
                "archive_evidence",
                audit_coverage,
                _phase_failure_detail("archive", exc),
                "archive scan failed; no archive evidence was collected",
            )
    elif target_type in NETWORK_TARGET_TYPES:
        try:
            _run_runtime_phase(
                normalized,
                target_type,
                plan,
                findings,
                audit_coverage,
                skipped_phases,
                validation_attempts,
                source_reports,
            )
        except Exception as exc:
            _partial_phase(
                plan,
                "runtime_evidence",
                audit_coverage,
                _phase_failure_detail("runtime", exc),
                "runtime scan failed; no runtime evidence was collected",
            )

    if normalized.depth == "exploit-validation":
        _run_authz_phase(normalized, target_type, plan, audit_coverage, skipped_phases)

    next_probes = _next_probes(normalized, target_type, skipped_phases)
    _complete_phase(
        plan,
        "triage",
        audit_coverage,
        {
            "next_probes": next_probes,
            "source_reports": [report.scan_mode for report in source_reports],
        },
    )
    _finalize_audit_coverage(audit_coverage, plan)

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
        "audit_coverage": _scrub_payload(_public_coverage(audit_coverage)),
        "validation_attempts": _scrub_payload(validation_attempts),
        "skipped_phases": _scrub_payload(skipped_phases),
        "operator_attestation": _scrub_payload(plan["operator_attestation"]),
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
    assessment_mode = str(options.assessment_mode or "balanced").strip()
    if assessment_mode not in ASSESSMENT_MODES:
        raise AuditError(f"--assessment-mode must be one of: {', '.join(ASSESSMENT_MODES)}")
    return AuditOptions(
        target=str(options.target or "").strip(),
        intent=intent,
        assessment_mode=assessment_mode,
        depth=depth,
        authorized_scope=str(options.authorized_scope or ""),
        network_attested=bool(options.network_attested),
        out_dir=str(options.out_dir or ""),
        launch_profile=launch_profile,
        max_pages=_bounded_int("max_pages", options.max_pages, MAX_PAGES),
        max_subdomains=_bounded_int("max_subdomains", options.max_subdomains, MAX_SUBDOMAINS),
        crawl_depth=_bounded_int("crawl_depth", options.crawl_depth, MAX_CRAWL_DEPTH),
        scan_budget_seconds=_bounded_int("scan_budget_seconds", options.scan_budget_seconds, MAX_SCAN_BUDGET_SECONDS),
        headless=bool(options.headless),
        baas_validate=bool(options.baas_validate),
        auth_state_path=str(options.auth_state_path or ""),
        offline=bool(options.offline),
        proxy=options.proxy,
        include_subdomains=bool(options.include_subdomains),
        baseline_path=str(options.baseline_path or ""),
        allowlist_path=str(options.allowlist_path or ""),
        apply_default_suppressions=bool(options.apply_default_suppressions),
    )


def _guard_authorization(options: AuditOptions, target_type: str) -> None:
    reason = _runtime_block_reason(options, target_type)
    if reason:
        raise AuditAuthorizationError(reason)


def _runtime_block_reason(options: AuditOptions, target_type: str) -> str:
    network_reason = _network_block_reason(options, target_type)
    if network_reason:
        return network_reason
    if (
        target_type == "domain"
        and options.include_subdomains
        and options.auth_state_path.strip()
        and options.depth in NETWORK_DEPTHS
    ):
        return (
            "Refusing --auth-state with --include-subdomains because site-scan cannot apply a single-user "
            "browser state to every discovered host. Use an exact URL/host or remove --auth-state."
        )
    return ""


def _network_block_reason(options: AuditOptions, target_type: str) -> str:
    if target_type not in NETWORK_TARGET_TYPES or options.depth not in NETWORK_DEPTHS:
        return ""
    if options.offline:
        return (
            "Refusing live network audit under --offline. The browser scanner launches Chromium in a separate "
            "process, so offline mode does not permit URL or domain audits."
        )
    if not options.authorized_scope.strip():
        return (
            "Refusing active network audit without --authorized-scope and "
            "--attest-network-scope. The text scope is an operator attestation, not technical proof of authorization."
        )
    if not options.network_attested:
        return (
            "Refusing active network audit without --attest-network-scope. "
            "This explicit operator attestation is not independent technical proof of authorization."
        )
    return ""


def _apply_network_attestation_status(phases: List[Dict[str, Any]], reason: str) -> None:
    if not reason:
        return
    for phase in phases:
        if phase.get("network"):
            phase["status"] = "blocked"
            phase["reason"] = reason


def _network_scope_note(target_type: str, include_subdomains: bool) -> str:
    if target_type in NETWORK_TARGET_TYPES:
        if target_type == "domain" and include_subdomains:
            return (
                "Requested registrable-domain and subdomain scope is enabled by explicit operator opt-in. "
                "Discovered hosts receive the existing SSRF guard, but browser redirect and subresource containment "
                "is not enforced."
            )
        if target_type == "domain":
            return (
                "Requested single-host scope: this domain starts at its exact host unless --include-subdomains is "
                "explicitly supplied. Browser redirect and subresource containment is not enforced."
            )
        return (
            "Partial containment: the initial URL/host is SSRF-guarded where the existing scanner applies that guard, "
            "but the browser path does not currently enforce redirect or subresource containment."
        )
    return "No network phase is planned for this target type."


def _runtime_phase_for_url(options: AuditOptions) -> Dict[str, Any]:
    return _browser_runtime_phase(options.target, options, "Single-URL browser evidence scan")


def _browser_runtime_phase(target: str, options: AuditOptions, title: str) -> Dict[str, Any]:
    if options.depth == "passive":
        return {
            "id": "runtime_evidence",
            "title": "Runtime evidence scan",
            "status": "skipped",
            "reason": "passive URL audit does not navigate live pages",
            "network": False,
        }
    command = [
        "keyleak", "browser-scan", _safe_target(target),
        "--scan-budget", str(options.scan_budget_seconds),
        "--json",
    ]
    if _should_baas_validate(options):
        command.append("--baas-validate")
    if options.auth_state_path:
        command.extend(["--auth-state", "<redacted-auth-state-path>"])
    return {
        "id": "runtime_evidence",
        "title": title,
        "status": "planned",
        "command": _command(command),
        "network": True,
    }


def _runtime_phase_for_domain(options: AuditOptions) -> Dict[str, Any]:
    if not options.include_subdomains:
        return _browser_runtime_phase(
            _domain_as_url(options.target),
            options,
            "Single-host browser evidence scan",
        )
    if options.depth == "passive":
        return {
            "id": "runtime_evidence",
            "title": "Runtime evidence scan",
            "status": "skipped",
            "reason": "passive domain audit does not enumerate or crawl",
            "network": False,
        }
    command = [
        "keyleak", "site-scan", _safe_target(options.target),
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
    return {
        "id": "access_control_two_user",
        "title": "Two-user access-control comparison",
        "status": "skipped",
        "reason": "unavailable from the audit command until a non-command-line credential handoff is implemented",
        "network": False,
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
    local_detail = {
        "scanner": "local",
        "findings": len(report.findings),
        "target": str(target.resolve()),
        "symlinks_skipped": _local_symlink_count(target),
    }
    if local_detail["symlinks_skipped"]:
        _partial_phase(
            plan,
            "local_evidence",
            coverage,
            local_detail,
            "symlinked files are excluded to preserve the requested local-root scope",
        )
    else:
        _complete_phase(plan, "local_evidence", coverage, local_detail)

    if _looks_repo_like(target):
        try:
            self_report = run_self_audit(target.resolve(), allow_external_commands=False)
        except Exception as exc:
            _partial_phase(
                plan,
                "self_audit",
                coverage,
                _phase_failure_detail("self-audit", exc),
                "self-audit failed; supply-chain evidence was not collected",
            )
            return
        findings.extend(self_report.findings)
        source_reports.append(self_report)
        _partial_phase(
            plan,
            "self_audit",
            coverage,
            {
                "scanner": "self-audit",
                "findings": len(self_report.findings),
                "skipped_checks": ["poetry_lock_drift_external_command"],
            },
            "the optional poetry lock-drift subprocess is intentionally skipped in agentic audits",
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

    browser_target = options.target
    if target_type == "domain" and not options.include_subdomains:
        browser_target = _domain_as_url(options.target)

    if target_type == "url" or (target_type == "domain" and not options.include_subdomains):
        reason = url_block_reason(browser_target)
        if reason:
            raise AuditError(f"SSRF guard refused target: {reason}")
        from .browser_scanner import run_browser_scan

        try:
            report = run_browser_scan(
                browser_target,
                auth_state_path=_validated_auth_state_path(options.auth_state_path),
                scan_budget_seconds=options.scan_budget_seconds,
                headless=options.headless,
                baas_validate=_should_baas_validate(options),
                proxy=options.proxy,
            )
        except Exception as exc:
            _partial_phase(
                plan,
                "runtime_evidence",
                coverage,
                _phase_failure_detail("browser-scan", exc),
                "browser scan failed; no runtime evidence was collected",
            )
            return
        findings.extend(report.findings)
        source_reports.append(report)
        runtime_detail = {
            "scanner": "browser-scan",
            "findings": len(report.findings),
            "pages_scanned": 1,
            "scanned_urls": [browser_target],
        }
        child_coverage_reason = _child_coverage_reason(report)
        if child_coverage_reason:
            _partial_phase(plan, "runtime_evidence", coverage, runtime_detail, child_coverage_reason)
        else:
            _complete_phase(plan, "runtime_evidence", coverage, runtime_detail)
        coverage.setdefault("_runtime_urls", []).append(browser_target)
        if _should_baas_validate(options):
            validation_attempts.append({
                "kind": "baas",
                "status": "attempted",
                "scanner": "browser-scan",
                "finding_count": _validation_finding_count(report),
            })
        return

    from .site_scanner import scan_site

    try:
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
            target_guard=scan_target_block_reason,
            external_discovery=False,
        )
    except Exception as exc:
        _partial_phase(
            plan,
            "runtime_evidence",
            coverage,
            _phase_failure_detail("site-scan", exc),
            "site scan failed; no runtime evidence was collected",
        )
        return
    findings.extend(report.findings)
    source_reports.append(report)
    runtime_detail = {
        "scanner": "site-scan",
        "findings": len(report.findings),
        "hosts_scanned": report.extra.get("hosts_scanned", 0),
        "pages_scanned": report.extra.get("pages_scanned", 0),
        "pages_failed": report.extra.get("pages_failed", 0),
        "subdomains": report.extra.get("subdomains", []),
        "scanned_urls": report.extra.get("scanned_urls", []),
        "discovery_sources": report.extra.get("discovery_sources", {}),
    }
    child_coverage_reason = _child_coverage_reason(report)
    if int(runtime_detail["pages_failed"] or 0) > 0 or child_coverage_reason:
        reasons = []
        if int(runtime_detail["pages_failed"] or 0) > 0:
            reasons.append(f"{runtime_detail['pages_failed']} page(s) could not be scanned")
        if child_coverage_reason:
            reasons.append(child_coverage_reason)
        _partial_phase(
            plan,
            "runtime_evidence",
            coverage,
            runtime_detail,
            "; ".join(reasons),
        )
    else:
        _complete_phase(plan, "runtime_evidence", coverage, runtime_detail)
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
    coverage: Dict[str, Any],
    skipped_phases: List[Dict[str, str]],
) -> None:
    if target_type not in NETWORK_TARGET_TYPES:
        _skip_phase(plan, "access_control_two_user", coverage, skipped_phases, "target has no live URL coverage")
        return
    _skip_phase(
        plan,
        "access_control_two_user",
        coverage,
        skipped_phases,
        "unavailable from the audit command until a non-command-line credential handoff is implemented",
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


def _partial_phase(
    plan: Dict[str, Any],
    phase_id: str,
    coverage: Dict[str, Any],
    detail: Dict[str, Any],
    reason: str,
) -> None:
    phase = _find_phase(plan, phase_id)
    if phase is not None:
        phase["status"] = "partial"
        phase["reason"] = reason
        phase["result"] = _scrub_payload(detail)
    coverage["phases"].append({
        "id": phase_id,
        "status": "partial",
        "reason": reason,
        **_scrub_payload(detail),
    })


def _phase_failure_detail(scanner: str, exc: Exception) -> Dict[str, str]:
    return {"scanner": scanner, "error_type": exc.__class__.__name__}


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
    _write_json(artifact_dir / "coverage.json", payload.get("audit_coverage") or {})
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
    audit_coverage = payload.get("audit_coverage") or {}
    if audit_coverage:
        lines.extend([
            f"- Audit coverage: `{audit_coverage.get('status', 'incomplete')}`",
            f"- Incomplete phases: `{', '.join(audit_coverage.get('incomplete_phase_ids') or ['none'])}`",
            f"- Network scope: {((payload.get('audit_plan') or {}).get('execution_constraints') or {}).get('network_scope', '')}",
            "",
        ])
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
        base = (parsed.hostname or "target") + parsed.path
    else:
        base = Path(str(target or "target")).name or str(target or "target")
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", base).strip("-._").lower()
    return (slug or "target")[:80]


def _audit_retest_command(options: AuditOptions) -> str:
    command = [
        "keyleak", "audit", _safe_target(options.target),
        "--intent", options.intent,
        "--depth", options.depth or default_depth(options.intent),
    ]
    if options.authorized_scope:
        command.extend(["--authorized-scope", _scrub_sensitive_text(options.authorized_scope)])
    if options.network_attested:
        command.append("--attest-network-scope")
    if options.include_subdomains:
        command.append("--include-subdomains")
    return _command(command)


def _next_probes(options: AuditOptions, target_type: str, skipped_phases: Iterable[Dict[str, str]]) -> List[str]:
    probes: List[str] = []
    skipped_ids = {item.get("id") for item in skipped_phases}
    if target_type in NETWORK_TARGET_TYPES and "access_control_two_user" in skipped_ids:
        probes.append(
            "Two-user access-control comparison is not available through the audit command until a non-command-line credential handoff is implemented."
        )
    if target_type == "url" and options.depth == "active":
        probes.append("Run the same target with --depth exploit-validation and explicit scope to add BaaS validation evidence.")
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


def _child_coverage_reason(report: ScanReport) -> str:
    child_coverage = report.extra.get("coverage")
    if not isinstance(child_coverage, dict):
        return "child scanner did not expose coverage metadata"
    if child_coverage.get("status") == "complete":
        return ""
    reason = str(child_coverage.get("reason") or "").strip()
    suffix = f": {_scrub_sensitive_text(reason)}" if reason else ""
    return f"child scanner reported incomplete coverage{suffix}"


def _finalize_audit_coverage(coverage: Dict[str, Any], plan: Dict[str, Any]) -> None:
    incomplete = [
        {
            "id": str(phase.get("id") or "unknown"),
            "status": str(phase.get("status") or "unknown"),
            "reason": str(phase.get("reason") or ""),
        }
        for phase in plan.get("phases") or []
        if phase.get("status") != "completed"
    ]
    coverage["incomplete_phases"] = incomplete
    coverage["incomplete_phase_ids"] = [phase["id"] for phase in incomplete]
    coverage["status"] = "complete" if not incomplete else "incomplete"


def _should_baas_validate(options: AuditOptions) -> bool:
    return options.baas_validate or options.depth == "exploit-validation"


def _looks_repo_like(target: Path) -> bool:
    if target.is_file():
        return False
    markers = (".git", ".github", "pyproject.toml", "package.json", "poetry.lock")
    return any((target / marker).exists() for marker in markers)


def _local_symlink_count(target: Path) -> int:
    if not target.is_dir():
        return 0
    count = 0
    for root, directories, files in os.walk(target):
        root_path = Path(root)
        count += sum(1 for directory in directories if (root_path / directory).is_symlink())
        count += sum(1 for filename in files if (root_path / filename).is_symlink())
    return count


def _is_archive_path(path: Path) -> bool:
    suffixes = "".join(path.suffixes).lower()
    return path.suffix.lower() in {".zip", ".tar", ".tgz"} or any(suffixes.endswith(suffix) for suffix in ARCHIVE_SUFFIXES)


def _looks_like_domain(raw: str) -> bool:
    if "/" in raw or raw.startswith("."):
        return False
    return bool(re.match(r"^[A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,}(?::\d+)?$", raw))


def _domain_as_url(domain: str) -> str:
    return f"https://{str(domain or '').strip()}"


def _validated_auth_state_path(value: str) -> Optional[str]:
    if not value:
        return None
    path = Path(value).expanduser().resolve()
    if not path.is_file():
        raise AuditError("auth state file does not exist or is not a regular file")
    if path.stat().st_mode & 0o077:
        raise AuditError("auth state file must not be accessible to group or other users")
    return str(path)


def _bounded_int(name: str, value: object, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise AuditError(f"{name} must be an integer") from exc
    if parsed < 1 or parsed > maximum:
        raise AuditError(f"{name} must be between 1 and {maximum}")
    return parsed


def _safe_target(target: str) -> str:
    raw = str(target or "")
    parsed = urlsplit(raw)
    if parsed.scheme and parsed.netloc:
        host = parsed.hostname or ""
        try:
            port = parsed.port
        except ValueError:
            port = None
        netloc = f"{host}:{port}" if port else host
        raw = urlunsplit((parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment))
    return redact_url(raw)


def _command(parts: Iterable[str]) -> str:
    return " ".join(shlex.quote(str(part)) for part in parts if str(part) != "")
