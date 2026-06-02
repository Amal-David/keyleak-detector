"""Attack-vector correlation engine (meta-analysis).

Individual findings are rarely the whole story — an ethical hacker chains them
(a leaked anon key + a table with no RLS; an exposed source map + a secret in the
bundle). This module derives composite **attack vectors** from combinations of
findings, escalating severity and narrating the path.

Design (see docs/vuln-research/design/correlation-engine.md):
- **Deterministic rule engine** — transparent, offline, reproducible. No LLM in the
  default path; every vector cites exactly which findings triggered it.
- Legs match on the **real fields that exist today** — ``finding.type`` and
  ``finding.detector_id`` — not on an invented class taxonomy.
- ``same_host`` rules require co-location. Host comes from the site-scan
  ``provenance`` map (finding.id -> [urls]) when present, else falls back to the
  host parsed from ``evidence.request_url`` / ``finding.source`` — so single-URL
  and BaaS-validation findings (which have no provenance entry) still chain.

Only rules whose every leg maps to a finding type KeyLeak emits today are shipped.
More rules activate as later milestones add finding types (jwt_alg_none, ssrf_*,
actuator_exposed, ...); those are listed in the design doc, not enabled here.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from fnmatch import fnmatch
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlsplit

from .models import Finding

_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_MAX_VECTORS = 100


@dataclass(frozen=True)
class ChainLeg:
    """One required ingredient of a chain. Matches a finding if its ``type`` is in
    ``types`` OR its ``detector_id`` matches any glob in ``detector_globs``."""

    types: Tuple[str, ...] = ()
    detector_globs: Tuple[str, ...] = ()
    min_count: int = 1

    def matches(self, finding: Finding) -> bool:
        if self.types and finding.type in self.types:
            return True
        if self.detector_globs and any(fnmatch(finding.detector_id or "", g) for g in self.detector_globs):
            return True
        return False


@dataclass(frozen=True)
class ChainRule:
    id: str
    name: str
    legs: Tuple[ChainLeg, ...]
    severity: str
    narrative: str
    remediation: str
    same_host: bool = True
    references: Tuple[str, ...] = ()


@dataclass
class AttackVector:
    id: str
    rule_id: str
    name: str
    severity: str
    confidence: str  # "confirmed" if any leg came from an active/confirmed probe
    member_finding_ids: List[str]
    hosts: List[str]
    narrative: str
    remediation: str
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "id": self.id, "rule_id": self.rule_id, "name": self.name,
            "severity": self.severity, "confidence": self.confidence,
            "member_finding_ids": self.member_finding_ids, "hosts": self.hosts,
            "narrative": self.narrative, "remediation": self.remediation,
            "references": self.references,
        }


_RLS_DOC = "https://supabase.com/docs/guides/auth/row-level-security"

# Anon BaaS keys are public by design; the danger is what they unlock.
_ANON_KEY_TYPES = ("supabase_publishable_key", "supabase_url", "firebase_client_config")
_SECRET_TYPES = (
    "openai_api_key", "anthropic_api_key", "aws_access_key", "aws_secret_key",
    "stripe_secret_key", "github_pat", "google_service_account", "private_key",
    "database_url", "sendgrid_api_key", "slack_token",
)

SEED_CHAINS: Tuple[ChainRule, ...] = (
    ChainRule(
        id="rls-anon-fulldb",
        name="Full database read via published anon key + missing RLS",
        legs=(ChainLeg(types=_ANON_KEY_TYPES), ChainLeg(types=("baas_open_table",))),
        severity="critical",
        narrative="The page ships a public BaaS anon key (expected) AND at least one "
                  "table is readable by that key because Row-Level Security is missing. "
                  "Together this is unauthenticated read of real data — the published "
                  "key becomes a full data-exfiltration credential.",
        remediation="Enable RLS on every exposed table and write least-privilege "
                    "policies. The anon key itself does not need rotation; the missing "
                    "policy is the vulnerability.",
        references=(_RLS_DOC,),
    ),
    ChainRule(
        id="rls-anon-write-takeover",
        name="Unauthenticated writes via anon key + missing write RLS",
        legs=(ChainLeg(types=_ANON_KEY_TYPES), ChainLeg(types=("baas_writable_table",))),
        severity="critical",
        narrative="The published anon key can INSERT/UPDATE rows because write-side RLS "
                  "is missing — anyone can tamper with or poison the data set.",
        remediation="Add INSERT/UPDATE/DELETE policies (WITH CHECK) on the affected "
                    "tables; never rely on client code to gate writes.",
        references=(_RLS_DOC,),
    ),
    ChainRule(
        id="cors-wildcard-open-table",
        name="Any-origin data theft via wildcard CORS + open table",
        legs=(ChainLeg(types=("baas_cors_wildcard",)), ChainLeg(types=("baas_open_table",))),
        severity="high",
        narrative="The BaaS REST API returns Access-Control-Allow-Origin: * AND a table "
                  "is anon-readable, so any website a victim visits can read that data "
                  "cross-origin and exfiltrate it.",
        remediation="Restrict CORS to your application's origin and enable RLS on the "
                    "exposed tables.",
        references=(_RLS_DOC,),
    ),
    ChainRule(
        id="service-role-leak",
        name="Total BaaS compromise via leaked service_role key",
        legs=(ChainLeg(types=("baas_service_role_exposed",)),),
        severity="critical",
        same_host=False,  # a single leaked RLS-bypassing key is game over on its own
        narrative="A service_role key (which BYPASSES Row-Level Security) is exposed in "
                  "the client. This is full read/write to every table regardless of any "
                  "policy — the strongest possible BaaS compromise.",
        remediation="Rotate the service_role key immediately, remove it from all client "
                    "bundles, and keep it server-side only.",
        references=(_RLS_DOC,),
    ),
    ChainRule(
        id="sourcemap-secret-recovery",
        name="Secret recovery accelerated by exposed source map",
        legs=(ChainLeg(types=("source_map_reference",)), ChainLeg(types=_SECRET_TYPES)),
        severity="high",
        narrative="An exposed source map reveals pre-minified code AND a real secret is "
                  "present in the shipped JS. The source map makes the secret (and the "
                  "auth/authz flow around it) trivial to locate and abuse.",
        remediation="Stop publishing source maps to production, and rotate + server-side "
                    "the exposed secret.",
    ),
)


def _host_of(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    text = str(value)
    try:
        host = urlsplit(text if "//" in text else "//" + text).hostname
    except ValueError:
        return None
    return host.lower() if host else None


def _finding_host(finding: Finding, provenance: Dict[str, List[str]]) -> Optional[str]:
    for url in provenance.get(finding.id, []) or []:
        host = _host_of(url)
        if host:
            return host
    evidence = getattr(finding, "evidence", None)
    for candidate in (getattr(evidence, "request_url", None), finding.source):
        host = _host_of(candidate)
        if host:
            return host
    return None


def _satisfy(rule: ChainRule, scope: List[Finding]) -> Optional[List[Finding]]:
    """Return the participating findings if every leg is satisfied within ``scope``
    by DISTINCT findings, else None."""
    used: set = set()
    members: List[Finding] = []
    for leg in rule.legs:
        matched = [f for f in scope if id(f) not in used and leg.matches(f)]
        if len(matched) < leg.min_count:
            return None
        chosen = matched[: leg.min_count]
        for f in chosen:
            used.add(id(f))
        members.extend(chosen)
    return members


def _max_severity(severities) -> str:
    best = "info"
    for sev in severities:
        if _SEVERITY_RANK.get(sev, 0) > _SEVERITY_RANK.get(best, 0):
            best = sev
    return best


def _stable_id(rule_id: str, member_ids) -> str:
    payload = rule_id + "|" + "|".join(sorted(member_ids))
    hash_value = 2166136261
    for char in payload:
        hash_value ^= ord(char)
        hash_value = (hash_value * 16777619) & 0xFFFFFFFF
    return f"chain_{hash_value:08x}"


def correlate(findings: List[Finding], provenance: Optional[Dict[str, List[str]]] = None) -> List[AttackVector]:
    """Derive composite attack vectors from a finding list.

    ``provenance`` is the site-scan finding.id -> [urls] map (optional); absent it,
    host co-location falls back to each finding's own request_url/source.
    """
    provenance = provenance or {}
    by_host: Dict[Optional[str], List[Finding]] = defaultdict(list)
    for finding in findings:
        by_host[_finding_host(finding, provenance)].append(finding)

    vectors: List[AttackVector] = []
    seen: set = set()
    for rule in SEED_CHAINS:
        if rule.same_host:
            # only real hosts qualify; findings with an unknown host cannot anchor a
            # same-host chain (avoids correlating across unrelated targets).
            scopes = [(host, group) for host, group in by_host.items() if host is not None]
        else:
            scopes = [(None, list(findings))]

        for host, scope in scopes:
            members = _satisfy(rule, scope)
            if not members:
                continue
            member_ids = [m.id for m in members]
            key = (rule.id, tuple(sorted(member_ids)))
            if key in seen:
                continue
            seen.add(key)
            severity = _max_severity([rule.severity] + [m.severity for m in members])
            confidence = "confirmed" if any(
                getattr(m, "validation_status", "lead") == "confirmed" for m in members
            ) else "lead"
            vectors.append(AttackVector(
                id=_stable_id(rule.id, member_ids),
                rule_id=rule.id,
                name=rule.name,
                severity=severity,
                confidence=confidence,
                member_finding_ids=member_ids,
                hosts=[host] if host else [],
                narrative=rule.narrative,
                remediation=rule.remediation,
                references=list(rule.references),
            ))

    vectors.sort(key=lambda v: (-_SEVERITY_RANK.get(v.severity, 0), -len(v.member_finding_ids)))
    return vectors[:_MAX_VECTORS]
