"""Scan bundles: named groups of detector packs + active phases + probe policy.

A bundle answers "what does this scan actually run": which detector PACKS, which
active PHASES (subdomain enumeration, crawl, form/fuzz, auth-differential, BaaS
probe, MITM), and under what read-only PROBE POLICY. Bundles compose the existing
pack/profile model (see ``keyleak.detectors.DETECTOR_PACKS``) rather than
replacing it, so users can invoke a meaningful group of checks — not just
"everything" or each detector independently.

Invariants enforced by ``validate_bundles`` (run at import):
- every referenced pack is known (existing or planned),
- every phase is a known phase,
- a bundle with active-request phases must carry an active probe policy,
- the read-only probe invariant holds for every bundle (KeyLeak never sends
  destructive payloads).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Tuple

from .detectors import DETECTOR_PACKS

# Packs planned by the runtime-vulnerability program but not yet populated with
# detectors. Declared here so bundles can reference and validate them now; remove
# each entry as it lands in ``DETECTOR_PACKS``.
PLANNED_PACKS: Tuple[str, ...] = ("injection", "authn", "client", "api", "recon", "headers")

# Repo-only packs that have no meaning for a runtime web scan (they need source).
REPO_ONLY_PACKS: Tuple[str, ...] = ("correctness", "housekeeping")

# Every phase a bundle may enable. ``passive`` is always implied.
ACTIVE_PHASES: Tuple[str, ...] = (
    "passive", "crawl", "subdomain", "probe", "forms", "fuzz",
    "authz_diff", "baas_probe", "mitm",
)

# Phases that send crafted/extra requests (require explicit opt-in or inputs).
_ACTIVE_REQUEST_PHASES = frozenset(
    {"probe", "forms", "fuzz", "authz_diff", "baas_probe", "mitm"}
)


@dataclass(frozen=True)
class ProbePolicy:
    """Bounds for any active probing a bundle performs. Read-only by invariant."""

    active: bool = False
    read_only: bool = True            # KeyLeak never sends destructive payloads
    max_requests: int = 0             # 0 = no active requests
    rate_per_sec: float = 2.0
    scope: str = "same-registrable-domain"


@dataclass(frozen=True)
class Bundle:
    id: str
    title: str
    description: str
    packs: Tuple[str, ...]
    active_phases: Tuple[str, ...] = ("passive",)
    probe_policy: ProbePolicy = field(default_factory=ProbePolicy)

    @property
    def is_active(self) -> bool:
        """True if the bundle sends any crafted/extra requests."""
        return any(phase in _ACTIVE_REQUEST_PHASES for phase in self.active_phases)


def all_known_packs() -> set:
    return set(DETECTOR_PACKS) | set(PLANNED_PACKS)


def web_packs() -> Tuple[str, ...]:
    """Runtime-relevant packs (everything except the repo-only packs), sorted."""
    return tuple(sorted(all_known_packs() - set(REPO_ONLY_PACKS)))


_PASSIVE = ProbePolicy()
_ACTIVE = ProbePolicy(active=True, max_requests=200, rate_per_sec=2.0)


BUNDLES: Dict[str, Bundle] = {
    bundle.id: bundle
    for bundle in [
        Bundle(
            "secrets", "Secrets only",
            "Leaked keys, tokens, and source maps (passive, no crafted requests).",
            ("leak",), ("passive",), _PASSIVE,
        ),
        Bundle(
            "quick", "Quick hygiene",
            "Fast passive pass: secrets, security headers, and client-side issues.",
            ("leak", "headers", "client"), ("passive", "crawl"), _PASSIVE,
        ),
        Bundle(
            "baas", "BaaS / RLS",
            "Supabase/Firebase/Appwrite RLS read-only probe matrix.",
            ("baas",), ("passive", "baas_probe"), _ACTIVE,
        ),
        Bundle(
            "authz", "Authorization",
            "IDOR/BOLA/BFLA and RLS. Needs two users (--bearer A/B) and/or an anon key.",
            ("access-control", "authn", "api", "baas"),
            ("passive", "authz_diff", "baas_probe"), _ACTIVE,
        ),
        Bundle(
            "injection", "Injection (active)",
            "Input-validation fuzzing: SQLi/NoSQLi/SSTI/command/SSRF/open-redirect/traversal.",
            ("injection", "api"), ("passive", "crawl", "forms", "fuzz"), _ACTIVE,
        ),
        Bundle(
            "recon", "Recon / attack surface",
            "Subdomains, debug/admin endpoints, exposed files, and header audit.",
            ("recon", "leak", "headers"),
            ("passive", "subdomain", "crawl", "probe"), _ACTIVE,
        ),
        Bundle(
            "deep", "Deep scan (everything)",
            "All runtime packs + all phases + attack-vector correlation.",
            web_packs(),
            ("passive", "subdomain", "crawl", "probe", "forms", "fuzz",
             "authz_diff", "baas_probe", "mitm"),
            _ACTIVE,
        ),
    ]
}


def resolve_bundle(bundle_id: str) -> Bundle:
    key = (bundle_id or "").strip().lower()
    if key not in BUNDLES:
        available = ", ".join(sorted(BUNDLES))
        raise KeyError(f"Unknown scan bundle {bundle_id!r}. Available: {available}")
    return BUNDLES[key]


def bundle_packs(bundle_id: str) -> Tuple[str, ...]:
    return resolve_bundle(bundle_id).packs


def validate_bundles() -> None:
    known = all_known_packs()
    for bundle in BUNDLES.values():
        unknown_packs = [pack for pack in bundle.packs if pack not in known]
        if unknown_packs:
            raise ValueError(f"Bundle {bundle.id!r} references unknown packs: {unknown_packs}")
        unknown_phases = [phase for phase in bundle.active_phases if phase not in ACTIVE_PHASES]
        if unknown_phases:
            raise ValueError(f"Bundle {bundle.id!r} has unknown phases: {unknown_phases}")
        if bundle.is_active and not bundle.probe_policy.active:
            raise ValueError(f"Bundle {bundle.id!r} has active phases but an inactive probe policy")
        if not bundle.probe_policy.read_only:
            raise ValueError(f"Bundle {bundle.id!r} violates the read-only probe invariant")


validate_bundles()
