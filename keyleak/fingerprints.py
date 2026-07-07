"""Stable, privacy-preserving finding fingerprints."""

from __future__ import annotations

import hashlib
from typing import Optional


FINGERPRINT_PREFIX = "klfp1"


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
        "" if line is None else str(line),
        text,
    ]
    digest = hashlib.sha256("\0".join(parts).encode("utf-8", errors="replace")).hexdigest()[:24]
    return f"{FINGERPRINT_PREFIX}_{digest}"
