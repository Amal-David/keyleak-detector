"""Versioned report integrity envelopes, optionally authenticated with HMAC."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional


COC_HMAC_KEY_ENV = "KEYLEAK_COC_KEY"


def canonical_findings_bytes(report_dict: Dict[str, Any]) -> bytes:
    """Deterministic serialization of just the findings list."""

    findings = report_dict.get("findings") or []
    return json.dumps(findings, sort_keys=True, separators=(",", ":")).encode("utf-8")


def findings_sha256(report_dict: Dict[str, Any]) -> str:
    return hashlib.sha256(canonical_findings_bytes(report_dict)).hexdigest()


def build_envelope(
    report_dict: Dict[str, Any],
    *,
    prev_hash: str = "",
    signer: str = "anonymous",
    signature_mode: str = "hmac-sha256",
    now: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Bind the entire report and envelope metadata; hash-only mode is not authentication."""
    if signature_mode not in {"hmac-sha256", "none"}:
        raise ValueError("Unsupported envelope signature mode")
    report_bytes = json.dumps(report_dict, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    generated_at = (now or datetime.now(timezone.utc)).isoformat()
    key = os.environ.get(COC_HMAC_KEY_ENV)
    if signature_mode == "hmac-sha256" and not key:
        signature_mode = "none"
    envelope = {
        "version": "2",
        "envelope": "keyleak.chain_of_custody",
        "generated_at": generated_at,
        "signer": signer,
        "prev_hash": prev_hash,
        "findings_sha256": findings_sha256(report_dict),
        "report_sha256": hashlib.sha256(report_bytes).hexdigest(),
        "signature_mode": signature_mode,
    }
    self_hash = hashlib.sha256(json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    envelope.update(
        self_hash=self_hash,
        signature=hmac.new(key.encode("utf-8"), self_hash.encode("utf-8"), hashlib.sha256).hexdigest() if signature_mode == "hmac-sha256" else "",
        report=json.loads(report_bytes),
    )
    return envelope


def verify_envelope(envelope: Dict[str, Any], *, require_signature: bool = False) -> bool:
    """Verify integrity; legacy v1 binds findings only. Require a signature for authenticity."""
    if not isinstance(envelope, dict) or envelope.get("version") not in ("1", "2"):
        return False
    report = envelope.get("report")
    if not isinstance(report, dict):
        return False
    digest = findings_sha256(report)
    if digest != envelope.get("findings_sha256"):
        return False

    if envelope["version"] == "2":
        if envelope.get("envelope") != "keyleak.chain_of_custody":
            return False
        try:
            report_bytes = json.dumps(report, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
            if hashlib.sha256(report_bytes).hexdigest() != envelope.get("report_sha256"):
                return False
            metadata = {k: v for k, v in envelope.items() if k not in {"report", "self_hash", "signature"}}
            self_payload = json.dumps(metadata, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
        except (TypeError, ValueError):
            return False
    else:
        self_payload = f"{envelope.get('prev_hash', '')}|{digest}|{envelope.get('generated_at', '')}|{envelope.get('signer', '')}".encode("utf-8")
    expected_self_hash = hashlib.sha256(self_payload).hexdigest()
    if expected_self_hash != envelope.get("self_hash"):
        return False

    mode = envelope.get("signature_mode") or "none"
    sig = envelope.get("signature") or ""
    if mode == "none":
        return not require_signature and not sig
    if mode == "hmac-sha256":
        key = os.environ.get(COC_HMAC_KEY_ENV)
        if not key or not isinstance(sig, str):
            return False
        expected = hmac.new(key.encode("utf-8"), expected_self_hash.encode("utf-8"), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, sig.strip().lower())
    return False
