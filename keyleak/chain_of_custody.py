"""Chain-of-custody envelope for KeyLeak reports.

Wraps a :class:`~keyleak.models.ScanReport` with a hash-chained signature so
the report becomes legally defensible: identifier, timestamp, finding hash,
previous-record hash, and (optionally) a cryptographic signature. The same
envelope is used by Wave 3.1 (time-machine archive scans) and the Wave 1.7
disclosure flow.
"""

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
    """Build the chain-of-custody envelope for ``report_dict``.

    Returns a dict shaped like::

        {
          "version": "1",
          "envelope": "keyleak.chain_of_custody",
          "generated_at": "...",
          "signer": "...",
          "prev_hash": "...",
          "findings_sha256": "...",
          "self_hash": "...",
          "signature_mode": "hmac-sha256" | "none",
          "signature": "...",
          "report": <original report dict>
        }

    ``self_hash`` is HMAC-SHA256 over ``prev_hash + findings_sha256 +
    generated_at + signer``. The signature is HMAC-SHA256 over ``self_hash``
    when ``signature_mode == 'hmac-sha256'``.
    """

    generated_at = (now or datetime.now(timezone.utc)).isoformat()
    digest = findings_sha256(report_dict)

    self_payload = f"{prev_hash}|{digest}|{generated_at}|{signer}".encode("utf-8")
    self_hash = hashlib.sha256(self_payload).hexdigest()

    signature = ""
    if signature_mode == "hmac-sha256":
        key = os.environ.get(COC_HMAC_KEY_ENV)
        if not key:
            signature_mode = "none"
        else:
            signature = hmac.new(key.encode("utf-8"), self_hash.encode("utf-8"), hashlib.sha256).hexdigest()

    return {
        "version": "1",
        "envelope": "keyleak.chain_of_custody",
        "generated_at": generated_at,
        "signer": signer,
        "prev_hash": prev_hash,
        "findings_sha256": digest,
        "self_hash": self_hash,
        "signature_mode": signature_mode,
        "signature": signature,
        "report": report_dict,
    }


def verify_envelope(envelope: Dict[str, Any]) -> bool:
    """Verify ``envelope``'s self-hash + signature.

    Returns True if every check passes:
    - Recomputed self_hash matches the embedded one.
    - HMAC signature verifies under ``KEYLEAK_COC_KEY`` (if mode is hmac).
    - ``findings_sha256`` matches the embedded report.
    """

    report = envelope.get("report") or {}
    digest = findings_sha256(report)
    if digest != envelope.get("findings_sha256"):
        return False

    self_payload = f"{envelope.get('prev_hash', '')}|{digest}|{envelope.get('generated_at', '')}|{envelope.get('signer', '')}".encode("utf-8")
    expected_self_hash = hashlib.sha256(self_payload).hexdigest()
    if expected_self_hash != envelope.get("self_hash"):
        return False

    mode = envelope.get("signature_mode") or "none"
    sig = envelope.get("signature") or ""
    if mode == "none":
        return not sig
    if mode == "hmac-sha256":
        key = os.environ.get(COC_HMAC_KEY_ENV)
        if not key:
            return False
        expected = hmac.new(key.encode("utf-8"), expected_self_hash.encode("utf-8"), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, sig.strip().lower())
    return False
