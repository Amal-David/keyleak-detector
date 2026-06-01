"""IOC feed ingestion (Wave 3.2).

Pulls upstream IOC feeds (OSV.dev MAL- advisories + OpenSSF malicious-packages)
and normalizes them into the KeyLeak IOC schema:

    {
      "version": 1,
      "generated_at": "<ISO>",
      "signature_mode": "hmac-sha256" | "none",
      "signature": "...",
      "entries": [
        {
          "id": "MAL-2026-1234",
          "ecosystem": "npm",
          "package": "@x/y",
          "versions": ["1.0.0", "1.0.1"],
          "references": ["..."],
          "summary": "..."
        }
      ]
    }

The pull functions are abstracted behind a ``fetcher`` callable so tests can
inject mock responses without touching the network. The free public tier
uses OSV.dev (CC-BY 4.0). The paid ``keyleak-feed-pro`` tier (Wave 3.10) is
a separate signed bundle distributed via GitHub Releases.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional


OSV_API_BASE = "https://api.osv.dev/v1"
FEED_HMAC_KEY_ENV = "KEYLEAK_FEED_KEY"


@dataclass
class FeedEntry:
    id: str
    ecosystem: str  # e.g. "npm", "PyPI"
    package: str
    versions: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "ecosystem": self.ecosystem,
            "package": self.package,
            "versions": list(self.versions),
            "references": list(self.references),
            "summary": self.summary,
        }


# Type alias for the fetcher callable. Tests inject a mock that returns a
# pre-canned payload.
Fetcher = Callable[[str, Dict[str, Any]], Dict[str, Any]]


def http_post_json(url: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    """Default HTTP fetcher — used in production, mocked in tests."""

    import requests

    response = requests.post(url, json=payload, timeout=30)
    response.raise_for_status()
    return response.json()


def query_osv_malicious(
    ecosystem: str = "npm",
    *,
    fetcher: Optional[Fetcher] = None,
) -> List[FeedEntry]:
    """Query OSV.dev for malicious-package advisories in ``ecosystem``.

    Note: OSV's ``MAL-*`` advisory IDs cover malicious-package reports across
    npm / PyPI / Maven / RubyGems / cargo. This function only requests
    advisories that have a ``MAL-`` prefix in their ID.
    """

    fetcher = fetcher or (lambda u, p: http_post_json(u, p))
    payload = {"query": {"package": {"ecosystem": ecosystem}}}
    raw = fetcher(f"{OSV_API_BASE}/querybatch", payload)
    return _parse_osv_response(raw, ecosystem)


def _parse_osv_response(raw: Dict[str, Any], ecosystem: str) -> List[FeedEntry]:
    entries: List[FeedEntry] = []
    for vuln in raw.get("vulns") or []:
        vid = str(vuln.get("id") or "")
        if not vid.startswith("MAL-"):
            continue
        affected = vuln.get("affected") or []
        for a in affected:
            pkg = (a.get("package") or {}).get("name") or ""
            if not pkg:
                continue
            versions = a.get("versions") or []
            entries.append(
                FeedEntry(
                    id=vid,
                    ecosystem=ecosystem,
                    package=pkg,
                    versions=[str(v) for v in versions],
                    references=[ref.get("url") for ref in vuln.get("references") or [] if ref.get("url")],
                    summary=str(vuln.get("summary") or ""),
                )
            )
    return entries


def sign_entries(entries: List[Dict[str, Any]], key: str) -> str:
    canonical = json.dumps(entries, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hmac.new(key.encode("utf-8"), canonical, hashlib.sha256).hexdigest()


def build_manifest(
    entries: List[FeedEntry],
    *,
    now: Optional[datetime] = None,
    sign: bool = True,
) -> Dict[str, Any]:
    """Build the signed manifest from a list of feed entries."""

    generated_at = (now or datetime.now(timezone.utc)).isoformat()
    payload = [entry.to_dict() for entry in entries]
    document: Dict[str, Any] = {
        "version": 1,
        "generated_at": generated_at,
        "entries": payload,
    }
    if sign:
        key = os.environ.get(FEED_HMAC_KEY_ENV)
        if key:
            document["signature_mode"] = "hmac-sha256"
            document["signature"] = sign_entries(payload, key)
        else:
            document["signature_mode"] = "none"
            document["signature"] = ""
    else:
        document["signature_mode"] = "none"
        document["signature"] = ""
    return document


def verify_manifest(document: Dict[str, Any]) -> bool:
    mode = document.get("signature_mode") or "none"
    sig = document.get("signature") or ""
    if mode == "none":
        return not sig
    if mode == "hmac-sha256":
        key = os.environ.get(FEED_HMAC_KEY_ENV)
        if not key:
            return False
        canonical = json.dumps(document.get("entries") or [], sort_keys=True, separators=(",", ":")).encode("utf-8")
        expected = hmac.new(key.encode("utf-8"), canonical, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, sig.strip().lower())
    return False
