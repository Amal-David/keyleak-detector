"""Stable, privacy-preserving finding fingerprints."""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
from typing import Optional


FINGERPRINT_PREFIX = "klfp1"
FINDING_FINGERPRINT_HMAC_KEY_ENV = "KEYLEAK_FINDING_FINGERPRINT_KEY"
logger = logging.getLogger(__name__)
_warned_missing_key = False


def finding_fingerprint(
    *,
    detector_id: object,
    source: object,
    raw_value: object,
    request_url: object = "",
    line: Optional[object] = None,
) -> str:
    """Return a stable report fingerprint without storing the raw value.

    ``Finding.id`` intentionally stays tied to the rendered report identity for
    backwards compatibility. This fingerprint is a separate baseline/diff key
    computed while the raw match is still in memory, then only the digest is
    persisted.
    """

    text = "" if raw_value is None else str(raw_value)
    if not text:
        return ""
    parts = [
        FINGERPRINT_PREFIX,
        "" if detector_id is None else str(detector_id),
        "" if source is None else str(source),
        "" if request_url is None else str(request_url),
        text,
    ]
    payload = "\0".join(parts).encode("utf-8", errors="replace")
    key = os.environ.get(FINDING_FINGERPRINT_HMAC_KEY_ENV)
    if not key:
        global _warned_missing_key
        if not _warned_missing_key:
            logger.warning(
                "%s is not set; finding fingerprints are disabled.",
                FINDING_FINGERPRINT_HMAC_KEY_ENV,
            )
            _warned_missing_key = True
        return ""
    digest = hmac.new(key.encode("utf-8"), payload, hashlib.sha256).hexdigest()[:24]
    return f"{FINGERPRINT_PREFIX}_{digest}"
