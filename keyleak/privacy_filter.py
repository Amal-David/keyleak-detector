"""PII pre-emission scrubber.

KeyLeak scans authenticated traffic and local files — the snippet around a
detector hit often includes adjacent PII (email addresses, phone numbers,
payment data, user names) that has no business in a findings report. Without
this filter, the same network capture that catches a Stripe key also leaks the
customer's support-ticket thread.

Ordering matters. The scrubber runs **after** detector match, when the
``Evidence.snippet`` is built. Running it before would risk masking a real
secret that happens to live inside a PII-shaped string. The scrubber's job is
to keep adjacent PII out of the snippet, not to hide the matched secret.
"""

from __future__ import annotations

import re
from typing import List, Optional, Tuple


# Order matters: longer / more-specific patterns must apply before shorter ones.
_PATTERNS: List[Tuple[re.Pattern[str], str]] = [
    # Email addresses.
    (re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"), "[email]"),
    # US-style phone numbers like +1 555-123-4567 or (555) 123-4567.
    # The leading ``(?<![\w])`` stops the pattern from starting *inside* a longer
    # alphanumeric token — without it, a secret like ``sk_live_4242424242424242``
    # had its embedded digits masked as ``[phone]``, corrupting the evidence
    # (audit gate FIX1-MF2).
    (
        re.compile(
            r"(?<![\w])(?:\+\d{1,3}[\s.-]?)?(?:\(?\d{3}\)?[\s.-]?)\d{3}[\s.-]?\d{4}\b"
        ),
        "[phone]",
    ),
    # SSN-like 3-2-4 digit groups.
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[ssn]"),
    # Card-like 16-digit numbers (with separators allowed).
    (
        re.compile(r"\b(?:\d[ -]?){13,19}\d\b"),
        "[card-or-num]",
    ),
    # Street-address-ish patterns (number + words + STREET-TYPE).
    (
        re.compile(
            r"\b\d{1,5}\s+[A-Za-z][A-Za-z0-9.\s]{2,40}\b(?:Street|St|Avenue|Ave|Boulevard|Blvd|Road|Rd|Drive|Dr|Lane|Ln|Way|Court|Ct)\b",
            re.IGNORECASE,
        ),
        "[addr]",
    ),
]


def scrub_text(text: str) -> str:
    """Mask PII in ``text``. Used for free-form bodies."""

    if not text:
        return text
    out = text
    for pattern, replacement in _PATTERNS:
        out = pattern.sub(replacement, out)
    return out


def scrub_snippet(snippet: str, preserve: Optional[str] = None) -> str:
    """Mask PII in a finding snippet while preserving the matched (already-redacted)
    secret token.

    ``preserve`` is the *already-redacted* secret value (e.g.
    ``"[redacted:abc123]"`` or ``"AKIA...[redacted]...wxyz"``). It is replaced
    with a sentinel before scrubbing and restored after — so a PII scrubber
    that happens to overlap with the redacted shape doesn't double-mask the
    finding itself.
    """

    if not snippet:
        return snippet
    if not preserve:
        return scrub_text(snippet)

    sentinel = "\x01KEYLEAK_FINDING\x01"
    placeholder_snippet = snippet.replace(preserve, sentinel)
    scrubbed = scrub_text(placeholder_snippet)
    return scrubbed.replace(sentinel, preserve)
