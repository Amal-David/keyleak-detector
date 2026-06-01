"""Responsible-disclosure CLI (Wave 1.7).

When KeyLeak finds a third-party credential during a pentest or launch-gate
scan, the operator becomes a knowing possessor of an active credential. This
module emits a signed, timestamped disclosure packet that routes to the
vendor's published security contact, mitigating CFAA / Computer Misuse Act
exposure.

Signing modes (same as :mod:`keyleak.suppressions`):
- ``hmac-sha256`` (default in tests, deterministic): HMAC-SHA256 over the
  canonical JSON payload using a key from ``KEYLEAK_DISCLOSE_KEY``.
- ``cosign`` (production): shells out to ``cosign sign-blob`` if installed.
- ``none``: emits the packet unsigned. Suitable for offline review only.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


VENDOR_CONTACTS_PATH = Path(__file__).parent / "data" / "vendor_contacts.json"
DISCLOSE_HMAC_KEY_ENV = "KEYLEAK_DISCLOSE_KEY"


class DiscloseError(RuntimeError):
    """Raised on a recoverable error in the disclose pipeline."""


def load_vendor_contacts(path: Optional[Path] = None) -> Dict[str, Dict[str, Any]]:
    """Load the in-repo vendor-contacts table."""

    path = path or VENDOR_CONTACTS_PATH
    if not path.is_file():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    return {key: value for key, value in data.items() if not key.startswith("_")}


def build_packet(
    finding: Dict[str, Any],
    vendor_contacts: Optional[Dict[str, Dict[str, Any]]] = None,
    reporter: Optional[str] = None,
    now: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Build the unsigned disclosure packet for ``finding``.

    ``finding`` is the dict shape produced by ``Finding.to_dict()``.
    """

    contacts = vendor_contacts if vendor_contacts is not None else load_vendor_contacts()
    detector_id = finding.get("detector_id") or ""
    vendor = contacts.get(detector_id) or {}

    now = (now or datetime.now(timezone.utc)).isoformat()

    return {
        "version": "1",
        "kind": "keyleak.disclosure",
        "generated_at": now,
        "reporter": reporter or "anonymous",
        "finding": {
            "id": finding.get("id"),
            "detector_id": detector_id,
            "severity": finding.get("severity"),
            "source": finding.get("source"),
            "redacted_value": (finding.get("evidence") or {}).get("redacted_value") or finding.get("redacted_value") or "",
        },
        "vendor": {
            "contact": vendor.get("contact") or "(no contact mapping; consult vendor documentation)",
            "form": vendor.get("form"),
        },
        "narrative": (
            "KeyLeak Detector observed a credential matching the detector above in the public "
            "scan target listed in 'source'. The credential is redacted in this packet; the raw "
            "value was not retained, copied, or used. Please rotate and acknowledge receipt."
        ),
    }


def canonical_payload(packet: Dict[str, Any]) -> bytes:
    """Return the deterministic byte string used for signing/verification."""

    return json.dumps(packet, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_packet(packet: Dict[str, Any], mode: str = "hmac-sha256") -> Dict[str, Any]:
    """Return a copy of ``packet`` with ``signature_mode`` / ``signature`` set."""

    payload = canonical_payload(packet)
    if mode == "none":
        return {**packet, "signature_mode": "none", "signature": ""}
    if mode == "hmac-sha256":
        key = os.environ.get(DISCLOSE_HMAC_KEY_ENV)
        if not key:
            raise DiscloseError(
                f"signature mode 'hmac-sha256' requires {DISCLOSE_HMAC_KEY_ENV} env var"
            )
        sig = hmac.new(key.encode("utf-8"), payload, hashlib.sha256).hexdigest()
        return {**packet, "signature_mode": mode, "signature": sig}
    if mode == "cosign":
        cosign = shutil.which("cosign")
        if not cosign:
            raise DiscloseError("signature mode 'cosign' but cosign is not on PATH")
        result = subprocess.run(
            [cosign, "sign-blob", "--yes", "-"],
            input=payload,
            capture_output=True,
            check=False,
            timeout=60,
        )
        if result.returncode != 0:
            raise DiscloseError(
                f"cosign sign-blob failed: {result.stderr.decode('utf-8', errors='replace')}"
            )
        return {**packet, "signature_mode": mode, "signature": result.stdout.decode("utf-8").strip()}
    raise DiscloseError(f"unknown signature mode: {mode!r}")


def verify_packet(packet: Dict[str, Any]) -> bool:
    """Verify a previously-signed packet. Returns True on success."""

    mode = packet.get("signature_mode") or "none"
    sig = packet.get("signature") or ""
    if mode == "none":
        return not sig

    body = {k: v for k, v in packet.items() if k not in {"signature", "signature_mode"}}
    payload = canonical_payload(body)

    if mode == "hmac-sha256":
        key = os.environ.get(DISCLOSE_HMAC_KEY_ENV)
        if not key:
            return False
        expected = hmac.new(key.encode("utf-8"), payload, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, sig.strip().lower())
    if mode == "cosign":
        cosign = shutil.which("cosign")
        if not cosign:
            return False
        # Best-effort verification.
        import tempfile

        with tempfile.NamedTemporaryFile("wb", delete=False, suffix=".payload") as payload_file:
            payload_file.write(payload)
            payload_path = payload_file.name
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".sig") as sig_file:
            sig_file.write(sig)
            sig_path = sig_file.name
        try:
            result = subprocess.run(
                [cosign, "verify-blob", "--signature", sig_path, payload_path],
                capture_output=True,
                timeout=60,
                check=False,
            )
        finally:
            Path(payload_path).unlink(missing_ok=True)
            Path(sig_path).unlink(missing_ok=True)
        return result.returncode == 0
    return False


def find_finding_in_report(report_data: Dict[str, Any], finding_id: str) -> Optional[Dict[str, Any]]:
    """Locate a finding by id within a serialized scan report."""

    for finding in report_data.get("findings") or []:
        if finding.get("id") == finding_id:
            return finding
    return None


def cli(args) -> int:
    """Implement ``keyleak disclose`` (called from :mod:`keyleak.cli`)."""

    report_path = Path(args.from_report)
    if not report_path.is_file():
        print(f"--from-report not found: {report_path}", file=sys.stderr)
        return 1

    try:
        report_data = json.loads(report_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"Could not parse report: {exc}", file=sys.stderr)
        return 1

    finding = find_finding_in_report(report_data, args.finding_id)
    if finding is None:
        print(f"Finding not in report: {args.finding_id}", file=sys.stderr)
        return 1

    packet = build_packet(finding, reporter=args.reporter)
    try:
        signed = sign_packet(packet, mode=args.signature_mode)
    except DiscloseError as exc:
        print(f"Disclosure signing failed: {exc}", file=sys.stderr)
        return 1

    payload = json.dumps(signed, indent=2, sort_keys=True)
    if args.out:
        Path(args.out).write_text(payload, encoding="utf-8")
        print(f"Wrote {args.out}")
    else:
        print(payload)
    return 0
