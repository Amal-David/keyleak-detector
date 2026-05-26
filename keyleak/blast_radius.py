"""Blast-radius enumeration (Wave 3.3).

Given a Finding, attempt to enumerate the scope of the leaked credential via
read-only API probes:

- GitHub PAT (``ghp_*``): ``GET /user`` + ``GET /user/repos``
- AWS access keys (``AKIA*``/``ASIA*``): ``sts:GetCallerIdentity``
- Stripe (``sk_live_*``, ``rk_live_*``): ``GET /v1/balance`` (read-only)
- OpenAI (``sk-proj-*``, ``sk-*``): ``GET /v1/models``

Each probe is wrapped behind a callable injected at the call site, so tests
never touch the network.

The probes are **read-only by design**. ``keyleak diff --revoke`` would call
the vendor's *revocation* endpoint; this module focuses on the enumeration
half so the IR analyst can answer "what does this unlock?"
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from .models import Finding


Prober = Callable[[str], Dict[str, Any]]


@dataclass
class BlastRadius:
    detector_id: str
    redacted_value: str
    scope: Dict[str, Any] = field(default_factory=dict)
    status: str = "unknown"  # "ok", "rejected", "skipped", "error"
    note: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "detector_id": self.detector_id,
            "redacted_value": self.redacted_value,
            "scope": self.scope,
            "status": self.status,
            "note": self.note,
        }


# ---------------------------------------------------------------------------
# Default probes — overridable in tests.
# ---------------------------------------------------------------------------

def _default_probe(detector_id: str) -> Optional[Prober]:
    """Return the production prober for ``detector_id`` or None."""

    return {
        "leak.github_pat": _probe_github_pat,
        "leak.aws_access_key": _probe_aws_access_key,
        "leak.stripe_secret_key": _probe_stripe_secret_key,
        "leak.openai_api_key": _probe_openai_api_key,
        "leak.gemini_api_key": _probe_gemini_api_key,
        "leak.bearer_token": _probe_jwt_claims,
        "leak.jwt_token": _probe_jwt_claims,
    }.get(detector_id)


def _probe_github_pat(token: str) -> Dict[str, Any]:  # pragma: no cover — production net path
    import requests

    headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github+json"}
    r = requests.get("https://api.github.com/user", headers=headers, timeout=10)
    if r.status_code != 200:
        return {"status": "rejected", "code": r.status_code}
    user = r.json()
    rr = requests.get("https://api.github.com/user/repos?per_page=1", headers=headers, timeout=10)
    return {
        "status": "ok",
        "login": user.get("login"),
        "scopes": r.headers.get("X-OAuth-Scopes", ""),
        "repos_first_page_count": len(rr.json() or []) if rr.status_code == 200 else None,
    }


def _probe_aws_access_key(token: str) -> Dict[str, Any]:  # pragma: no cover
    return {"status": "skipped", "note": "AWS sts:GetCallerIdentity requires SigV4 — not implemented in OSS core"}


def _probe_stripe_secret_key(token: str) -> Dict[str, Any]:  # pragma: no cover
    import requests

    r = requests.get("https://api.stripe.com/v1/balance", auth=(token, ""), timeout=10)
    if r.status_code != 200:
        return {"status": "rejected", "code": r.status_code}
    body = r.json()
    return {
        "status": "ok",
        "available_count": len(body.get("available") or []),
    }


def _probe_gemini_api_key(token: str) -> Dict[str, Any]:  # pragma: no cover
    import requests

    r = requests.get(
        f"https://generativelanguage.googleapis.com/v1beta/models?key={token}",
        timeout=10,
    )
    if r.status_code != 200:
        return {"status": "rejected", "code": r.status_code}
    data = r.json()
    return {"status": "ok", "model_count": len((data or {}).get("models") or [])}


def _probe_jwt_claims(token: str) -> Dict[str, Any]:
    """Decode JWT claims without verification and flag suspicious permissions."""
    import base64
    import json as _json
    import time

    parts = token.split(".")
    if len(parts) != 3:
        return {"status": "error", "note": "Not a valid JWT (expected 3 segments)"}

    try:
        payload = parts[1]
        payload += "=" * ((4 - len(payload) % 4) % 4)
        claims = _json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        return {"status": "error", "note": "Failed to decode JWT payload"}

    flags = []
    role = str(claims.get("role") or "")
    if "service_role" in role:
        flags.append("CRITICAL: service_role bypasses all RLS")
    elif any(w in role.lower() for w in ("admin", "superuser", "root")):
        flags.append(f"HIGH: elevated role '{role}'")

    if claims.get("is_admin") is True or claims.get("admin") is True:
        flags.append("HIGH: admin flag is true")

    scope = claims.get("scope") or claims.get("scp") or ""
    scope_str = " ".join(scope) if isinstance(scope, list) else str(scope)
    dangerous = [s for s in ("admin", "write", "delete", "manage") if s in scope_str.lower()]
    if dangerous:
        flags.append(f"HIGH: broad scope ({', '.join(dangerous)})")

    now = int(time.time())
    exp = claims.get("exp")
    if exp:
        remaining = exp - now
        if remaining < 0:
            flags.append("INFO: token is expired")
        elif remaining > 365 * 86400:
            flags.append(f"MEDIUM: expires in {remaining // (365*86400)}+ years")
    else:
        flags.append("MEDIUM: no expiry set")

    return {
        "status": "ok",
        "iss": claims.get("iss"),
        "sub": claims.get("sub"),
        "role": role or None,
        "scope": scope_str or None,
        "exp": exp,
        "flags": flags,
    }


def _probe_openai_api_key(token: str) -> Dict[str, Any]:  # pragma: no cover
    import requests

    r = requests.get(
        "https://api.openai.com/v1/models",
        headers={"Authorization": f"Bearer {token}"},
        timeout=10,
    )
    if r.status_code != 200:
        return {"status": "rejected", "code": r.status_code}
    data = r.json()
    return {"status": "ok", "model_count": len((data or {}).get("data") or [])}


# ---------------------------------------------------------------------------
# Public surface
# ---------------------------------------------------------------------------

def compute_blast_radius(
    finding: Finding,
    raw_value: Optional[str] = None,
    *,
    probes: Optional[Dict[str, Prober]] = None,
) -> BlastRadius:
    """Compute blast radius for a single finding.

    ``raw_value`` is the actual token (post-redaction recovery is the
    operator's responsibility — KeyLeak never persists it). If not provided,
    the result is ``status='skipped'``.
    """

    probes = probes or {}
    probe = probes.get(finding.detector_id) or _default_probe(finding.detector_id)
    if not probe:
        return BlastRadius(
            detector_id=finding.detector_id,
            redacted_value=finding.evidence.redacted_value,
            status="skipped",
            note=f"No probe available for {finding.detector_id}",
        )
    if not raw_value:
        return BlastRadius(
            detector_id=finding.detector_id,
            redacted_value=finding.evidence.redacted_value,
            status="skipped",
            note="raw_value not provided; pass the recovered token to compute_blast_radius",
        )
    try:
        scope = probe(raw_value)
    except Exception as exc:  # pragma: no cover — defensive
        return BlastRadius(
            detector_id=finding.detector_id,
            redacted_value=finding.evidence.redacted_value,
            status="error",
            note=str(exc),
        )
    return BlastRadius(
        detector_id=finding.detector_id,
        redacted_value=finding.evidence.redacted_value,
        scope=scope,
        status=str(scope.get("status") or "ok"),
        note=str(scope.get("note") or ""),
    )
