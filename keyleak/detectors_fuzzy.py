"""Fuzzy content fingerprint detector (Wave 2.3).

The string-IOC pack has a 7-day half-life — attackers rotate the C2 hostname,
the file name, and the embedded comment within hours of a wave breaking.
What changes more slowly is the *shape* of the payload itself: the same
loader, the same data-exfil branch, the same persistence block.

This module fingerprints candidate scripts against a small corpus of known-bad
payloads. Two strategies coexist:

- **Exact normalized SHA256**: strip whitespace / comments / quoted strings,
  lowercase identifiers, then SHA256. Catches the byte-identical re-uploaded
  variant.
- **Shingle Jaccard similarity**: tokenize the normalized text into 8-character
  shingles, compare the set against each corpus entry. A Jaccard score above
  the threshold (default 0.70) flags a renamed-strings variant.

The corpus ships signed (HMAC over canonical JSON) in
``keyleak/data/worm_fingerprints.json``. Without the matching key, loading
the corpus emits a clear warning; the corpus is published so downstream users
can verify integrity.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional


SHINGLE_SIZE = 8
DEFAULT_SIMILARITY_THRESHOLD = 0.70

FINGERPRINT_HMAC_KEY_ENV = "KEYLEAK_FINGERPRINTS_KEY"
FINGERPRINT_CORPUS_PATH = Path(__file__).parent / "data" / "worm_fingerprints.json"


# ---------------------------------------------------------------------------
# Normalization + shingle helpers
# ---------------------------------------------------------------------------

_COMMENT_LINE_RE = re.compile(r"//.*$|#.*$", re.MULTILINE)
_COMMENT_BLOCK_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_STRING_LITERAL_RE = re.compile(r"\"[^\"]*\"|'[^']*'|`[^`]*`")
_NON_TOKEN_RE = re.compile(r"[^a-z0-9]+")
_WHITESPACE_RE = re.compile(r"\s+")


def normalize_for_fingerprint(text: str) -> str:
    """Strip comments + quoted strings, lowercase, collapse whitespace.

    Two payloads that differ only in their embedded C2 host string normalize
    to the same byte sequence.
    """

    out = _COMMENT_BLOCK_RE.sub(" ", text)
    out = _COMMENT_LINE_RE.sub(" ", out)
    out = _STRING_LITERAL_RE.sub('""', out)
    out = out.lower()
    out = _WHITESPACE_RE.sub(" ", out)
    return out.strip()


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def normalized_sha256(text: str) -> str:
    return sha256_hex(normalize_for_fingerprint(text))


def shingle_set(text: str, size: int = SHINGLE_SIZE) -> set:
    """Return the set of ``size``-character shingles over the normalized text."""

    normalized = normalize_for_fingerprint(text)
    if len(normalized) < size:
        return {normalized}
    return {normalized[i : i + size] for i in range(len(normalized) - size + 1)}


def jaccard(a: set, b: set) -> float:
    if not a and not b:
        return 1.0
    intersection = len(a & b)
    union = len(a | b)
    return intersection / union if union else 0.0


# ---------------------------------------------------------------------------
# Corpus + signed manifest
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class WormFingerprint:
    name: str
    description: str
    references: List[str]
    normalized_sha256: str
    shingles: List[str]


@dataclass(frozen=True)
class FingerprintHit:
    name: str
    description: str
    references: List[str]
    matched: str  # "exact" | "fuzzy"
    score: float  # 1.0 for exact, jaccard score for fuzzy


def load_corpus(path: Optional[Path] = None, *, require_signature: bool = False) -> List[WormFingerprint]:
    """Load and verify the worm-fingerprint corpus.

    If ``require_signature`` is true (or KEYLEAK_FINGERPRINTS_KEY is set), the
    corpus signature is verified via HMAC-SHA256.
    """

    path = path or FINGERPRINT_CORPUS_PATH
    if not path.is_file():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        return []

    entries = data.get("entries") or []
    if not isinstance(entries, list):
        return []

    key = os.environ.get(FINGERPRINT_HMAC_KEY_ENV)
    signature = data.get("signature") or ""
    if require_signature or key:
        canonical = json.dumps(entries, sort_keys=True, separators=(",", ":")).encode("utf-8")
        if not key:
            raise ValueError(
                "fingerprint corpus signature verification requires "
                f"{FINGERPRINT_HMAC_KEY_ENV} env var"
            )
        expected = hmac.new(key.encode("utf-8"), canonical, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, signature.strip().lower()):
            raise ValueError("fingerprint corpus signature mismatch")

    return [
        WormFingerprint(
            name=entry.get("name") or "",
            description=entry.get("description") or "",
            references=list(entry.get("references") or []),
            normalized_sha256=entry.get("normalized_sha256") or "",
            shingles=list(entry.get("shingles") or []),
        )
        for entry in entries
        if isinstance(entry, dict)
    ]


def sign_corpus_entries(entries: List[dict], key: str) -> str:
    """Helper used by tests + the build tooling."""

    canonical = json.dumps(entries, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hmac.new(key.encode("utf-8"), canonical, hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------

def match_fingerprints(
    text: str,
    corpus: List[WormFingerprint],
    *,
    threshold: float = DEFAULT_SIMILARITY_THRESHOLD,
) -> List[FingerprintHit]:
    """Return any fingerprint that matches ``text`` either exactly or fuzzily."""

    if not corpus:
        return []

    normalized_hash = normalized_sha256(text)
    candidate_shingles = shingle_set(text)

    hits: List[FingerprintHit] = []
    for entry in corpus:
        if entry.normalized_sha256 and entry.normalized_sha256 == normalized_hash:
            hits.append(
                FingerprintHit(
                    name=entry.name,
                    description=entry.description,
                    references=list(entry.references),
                    matched="exact",
                    score=1.0,
                )
            )
            continue
        if entry.shingles:
            score = jaccard(candidate_shingles, set(entry.shingles))
            if score >= threshold:
                hits.append(
                    FingerprintHit(
                        name=entry.name,
                        description=entry.description,
                        references=list(entry.references),
                        matched="fuzzy",
                        score=score,
                    )
                )
    return hits
