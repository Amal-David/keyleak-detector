"""Redaction helpers for findings and reports."""

from __future__ import annotations

import hashlib
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


def stable_id(*parts: object, prefix: str = "finding") -> str:
    payload = "\n".join("" if part is None else str(part) for part in parts)
    digest = hashlib.sha256(payload.encode("utf-8", errors="replace")).hexdigest()[:16]
    return f"{prefix}_{digest}"


def redact_value(value: object, keep_start: int = 6, keep_end: int = 4) -> str:
    if value is None:
        return ""

    text = str(value).strip()
    if not text:
        return ""

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


def redact_snippet(snippet: object, raw_value: Optional[object] = None) -> str:
    if snippet is None:
        return ""

    text = str(snippet)
    if raw_value:
        raw_text = str(raw_value)
        if raw_text and raw_text in text:
            return text.replace(raw_text, redact_value(raw_text))
    return text
