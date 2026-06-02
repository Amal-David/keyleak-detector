"""Scan bundles: named groups of detector packs + scan phases + probe policy.

A bundle answers "what does this scan actually run": which detector PACKS, which
PHASES, and under what PROBE POLICY. Bundles compose the existing pack/profile
model (see ``keyleak.detectors.DETECTOR_PACKS``) rather than replacing it, so a
user can invoke a meaningful group of checks — not just "everything" or each
detector independently.

Phase taxonomy (explicit, because "active" was ambiguous):
- **passive** — analyze already-fetched content; sends ZERO new requests.
- **navigation** (``crawl``, ``subdomain``) — read-only enumeration that DOES send
  real requests (same-origin GETs, public CT logs), but no crafted/attack payloads.
- **probing** (``probe``, ``forms``, ``fuzz``, ``authz_diff``, ``baas_probe``,
  ``mitm``) — sends crafted/attack-shaped requests.

Safety: probing is read-only by default. The one mutating probe that exists today
(``baas_validator._probe_write_access``, a POST insert) is OFF unless a bundle's
``ProbePolicy.allow_write_probe`` is explicitly true — which no built-in bundle
sets. ``validate_bundles`` enforces the budget/scope/probing invariants.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Mapping, Optional, Tuple

from .detectors import DETECTOR_PACKS, detectors_for_packs

# Repo-only packs that have no meaning for a runtime web scan (they need source).
REPO_ONLY_PACKS: Tuple[str, ...] = ("correctness", "housekeeping")

# Phase taxonomy.
PASSIVE_PHASES: frozenset = frozenset({"passive"})
NAVIGATION_PHASES: frozenset = frozenset({"crawl", "subdomain"})
PROBING_PHASES: frozenset = frozenset(
    {"probe", "forms", "fuzz", "authz_diff", "baas_probe", "mitm"}
)
ALL_PHASES: Tuple[str, ...] = tuple(sorted(PASSIVE_PHASES | NAVIGATION_PHASES | PROBING_PHASES))

ALLOWED_SCOPES: frozenset = frozenset({"same-registrable-domain", "same-origin"})


@dataclass(frozen=True)
class ProbePolicy:
    """Bounds + safety flags for the requests a bundle is allowed to send."""

    probing: bool = False             # may send crafted/attack-shaped requests
    allow_write_probe: bool = False   # opt-in for the single mutating BaaS probe; default OFF
    max_requests: int = 0             # network budget for navigation + probing (0 = passive only)
    rate_per_sec: float = 2.0
    scope: str = "same-registrable-domain"


@dataclass(frozen=True)
class Bundle:
    id: str
    title: str
    description: str
    packs: Tuple[str, ...]
    phases: Tuple[str, ...] = ("passive",)
    probe_policy: ProbePolicy = field(default_factory=ProbePolicy)

    @property
    def sends_requests(self) -> bool:
        """True if the bundle hits the network at all (navigation or probing)."""
        return any(p in NAVIGATION_PHASES or p in PROBING_PHASES for p in self.phases)

    @property
    def is_probing(self) -> bool:
        """True if the bundle sends crafted/attack-shaped requests."""
        return any(p in PROBING_PHASES for p in self.phases)


def all_known_packs() -> set:
    return set(DETECTOR_PACKS)


def web_packs() -> Tuple[str, ...]:
    """Runtime-relevant packs (everything except the repo-only packs), sorted."""
    return tuple(sorted(all_known_packs() - set(REPO_ONLY_PACKS)))


def unpopulated_packs(bundle: "Bundle") -> Tuple[str, ...]:
    """Bundle packs that have no detectors yet (so they contribute nothing until
    their milestone lands). Surfaced so callers can 'skip loudly' rather than
    silently run zero checks."""
    return tuple(p for p in bundle.packs if not detectors_for_packs([p]))


def runnable_packs(bundle: "Bundle") -> Tuple[str, ...]:
    """Bundle packs that have at least one detector today (the part that will
    actually run). Empty tuple means the bundle has no runnable detectors yet."""
    return tuple(p for p in bundle.packs if detectors_for_packs([p]))


_PASSIVE = ProbePolicy()                                              # 0 requests
_NAV = ProbePolicy(probing=False, max_requests=300, rate_per_sec=3.0)  # crawl/subdomain only
_PROBE = ProbePolicy(probing=True, max_requests=300, rate_per_sec=2.0)  # crafted probes, no writes


BUNDLES: Dict[str, Bundle] = {
    bundle.id: bundle
    for bundle in [
        Bundle(
            "secrets", "Secrets only",
            "Leaked keys, tokens, and source maps (passive, no new requests).",
            ("leak",), ("passive",), _PASSIVE,
        ),
        Bundle(
            "quick", "Quick hygiene",
            "Fast pass: secrets, security headers, client-side issues (crawl, no probes).",
            ("leak", "headers", "client"), ("passive", "crawl"), _NAV,
        ),
        Bundle(
            "baas", "BaaS / RLS",
            "Supabase/Firebase/Appwrite RLS read-only probe matrix.",
            ("baas",), ("passive", "baas_probe"), _PROBE,
        ),
        Bundle(
            "authz", "Authorization",
            "IDOR/BOLA/BFLA and RLS. Needs two users (--bearer A/B) and/or an anon key.",
            ("access-control", "authn", "api", "baas"),
            ("passive", "authz_diff", "baas_probe"), _PROBE,
        ),
        Bundle(
            "injection", "Injection (active)",
            "Input-validation fuzzing: SQLi/NoSQLi/SSTI/command/SSRF/open-redirect/traversal.",
            ("injection", "api"), ("passive", "crawl", "forms", "fuzz"), _PROBE,
        ),
        Bundle(
            "recon", "Recon / attack surface",
            "Subdomains, debug/admin endpoints, exposed files, and header audit.",
            ("recon", "leak", "headers"),
            ("passive", "subdomain", "crawl", "probe"), _PROBE,
        ),
        Bundle(
            "deep", "Deep scan (everything)",
            "All runtime packs + all phases + attack-vector correlation. MITM is opt-in.",
            web_packs(),
            ("passive", "subdomain", "crawl", "probe", "forms", "fuzz",
             "authz_diff", "baas_probe", "mitm"),
            _PROBE,
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


def validate_bundles(bundles: Optional[Mapping[str, "Bundle"]] = None) -> None:
    """Validate the bundle registry (or a supplied mapping) against its invariants.

    Takes ``bundles`` so callers/tests can validate a candidate registry without
    mutating the module global.
    """
    registry = BUNDLES if bundles is None else bundles
    known = all_known_packs()
    for bundle in registry.values():
        unknown_packs = [pack for pack in bundle.packs if pack not in known]
        if unknown_packs:
            raise ValueError(f"Bundle {bundle.id!r} references unknown packs: {unknown_packs}")
        unknown_phases = [phase for phase in bundle.phases if phase not in ALL_PHASES]
        if unknown_phases:
            raise ValueError(f"Bundle {bundle.id!r} has unknown phases: {unknown_phases}")
        policy = bundle.probe_policy
        if bundle.sends_requests and policy.max_requests <= 0:
            raise ValueError(f"Bundle {bundle.id!r} sends requests but has no request budget")
        if bundle.is_probing and not policy.probing:
            raise ValueError(f"Bundle {bundle.id!r} has probing phases but a non-probing policy")
        if bundle.sends_requests and policy.rate_per_sec <= 0:
            raise ValueError(f"Bundle {bundle.id!r} sends requests but has a non-positive rate limit")
        if policy.allow_write_probe and not policy.probing:
            raise ValueError(f"Bundle {bundle.id!r} allows write probe without a probing policy")
        if policy.scope not in ALLOWED_SCOPES:
            raise ValueError(f"Bundle {bundle.id!r} has invalid scope {policy.scope!r}")


validate_bundles()
