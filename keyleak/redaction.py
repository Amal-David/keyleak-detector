"""Redaction helpers for findings and reports."""

from __future__ import annotations

import hashlib
import hmac
import os
import re
from typing import Optional


SECRET_QUERY_KEYS = {
    "access_token",
    "api_key",
    "apikey",
    "auth",
    "authorization",
    "client_secret",
    "code",
    "cookie",
    "key",
    "password",
    "refresh_token",
    "secret",
    "session",
    "token",
}


# Env override for deterministic redaction in tests. Hex-encoded bytes.
REDACTION_SALT_ENV = "KEYLEAK_REDACTION_SALT_HEX"


def new_run_salt() -> bytes:
    """Return per-scan HMAC salt.

    Honors ``KEYLEAK_REDACTION_SALT_HEX`` for deterministic tests; otherwise
    32 bytes from ``os.urandom``.
    """

    override = os.environ.get(REDACTION_SALT_ENV)
    if override:
        try:
            return bytes.fromhex(override)
        except ValueError:
            pass  # fall through to urandom
    return os.urandom(32)


def stable_id(*parts: object, prefix: str = "finding") -> str:
    payload = "\n".join("" if part is None else str(part) for part in parts)
    digest = hashlib.sha256(payload.encode("utf-8", errors="replace")).hexdigest()[:16]
    return f"{prefix}_{digest}"


def redact_value(
    value: object,
    keep_start: int = 6,
    keep_end: int = 4,
    *,
    run_salt: Optional[bytes] = None,
) -> str:
    """Redact a value before it's emitted in a finding.

    - If ``run_salt`` is supplied: emit ``[redacted:<8-hex>]`` where the 8 hex
      chars are HMAC-SHA256(salt, value). This is the diff-resistant mode used
      by the scanner — two reports of the same content scanned with different
      salts produce different HMACs, so an analyst cannot diff them to recover
      the secret. Within one scan (same salt), the same secret produces the
      same HMAC, so dedup still works.
    - Without ``run_salt``: legacy prefix/suffix masking ``aBcDeF...[redacted]...wxyz``.
      Callers that haven't migrated still work.
    """

    if value is None:
        return ""

    text = str(value).strip()
    if not text:
        return ""

    if run_salt is not None:
        digest = hmac.new(run_salt, text.encode("utf-8"), hashlib.sha256).hexdigest()[:8]
        return f"[redacted:{digest}]"

    if len(text) <= keep_start + keep_end + 6:
        if len(text) <= 4:
            return "[redacted]"
        return f"{text[:2]}...[redacted]"

    return f"{text[:keep_start]}...[redacted]...{text[-keep_end:]}"


def redact_url(url: object) -> str:
    if not url:
        return ""

    text = str(url)

    def replace_secret(match: re.Match[str]) -> str:
        separator = match.group(1)
        key = match.group(2)
        value = match.group(3)
        if key.lower() in SECRET_QUERY_KEYS:
            return f"{separator}{key}={redact_value(value)}"
        return match.group(0)

    return re.sub(r"([?&])([^=&]+)=([^&#]+)", replace_secret, text)


def redact_snippet(
    snippet: object,
    raw_value: Optional[object] = None,
    *,
    run_salt: Optional[bytes] = None,
) -> str:
    if snippet is None:
        return ""

    text = str(snippet)
    if raw_value:
        raw_text = str(raw_value)
        if raw_text and raw_text in text:
            return text.replace(raw_text, redact_value(raw_text, run_salt=run_salt))
    return text
