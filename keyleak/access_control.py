"""Two-user access-control comparison helpers."""

from __future__ import annotations

from difflib import SequenceMatcher
import re
from typing import Any, Callable, Dict, Iterable, List, Optional
from urllib.parse import urlparse

import requests

from .models import Evidence, Finding
from .redaction import redact_url


_OBJECT_ID_RE = re.compile(
    r"(?:/(?:users?|accounts?|customers?|tenants?|organizations?|orgs?|projects?|orders?)/[0-9a-fA-F-]{6,}"
    r"|[?&](?:user|account|customer|tenant|organization|project|order)[_-]?id=[0-9a-fA-F-]{6,})"
)


def compare_access_control_urls(
    candidate_urls: Iterable[str],
    user_a_auth: Dict[str, Any],
    user_b_auth: Optional[Dict[str, Any]],
    fetch: Callable[..., Any] = requests.get,
    max_urls: int = 10,
) -> List[Finding]:
    """Compare object-looking URLs with two explicit auth contexts."""
    if not _has_auth(user_a_auth) or not _has_auth(user_b_auth or {}):
        return []

    # Guard the real-network fetch against SSRF (candidate URLs are crawl-derived
    # and so attacker-influenceable). Injected probers (tests) are trusted and
    # never hit the network, so they bypass the guard.
    guard_hosts = fetch is requests.get
    from .net_guard import url_block_reason

    findings: List[Finding] = []
    for url in _candidate_object_urls(candidate_urls)[:max_urls]:
        if guard_hosts and url_block_reason(url):
            continue
        try:
            response_a = fetch(
                url,
                headers=_auth_headers(user_a_auth),
                cookies=_auth_cookies(user_a_auth),
                timeout=15,
                allow_redirects=False,
            )
            response_b = fetch(
                url,
                headers=_auth_headers(user_b_auth or {}),
                cookies=_auth_cookies(user_b_auth or {}),
                timeout=15,
                allow_redirects=False,
            )
        except requests.RequestException:
            continue
        except Exception:
            # Injectable `fetch` may raise non-requests exceptions; skip the URL.
            continue

        if not _successful(response_a) or not _successful(response_b):
            continue

        similarity = _body_similarity(getattr(response_a, "text", ""), getattr(response_b, "text", ""))
        if similarity < 0.85:
            continue

        safe_url = redact_url(url)
        evidence = Evidence(
            source="Two-user access-control comparison",
            snippet=f"User A and user B both received similar 2xx responses for {safe_url}.",
            request_url=safe_url,
            response_status=getattr(response_b, "status_code", None),
            redacted_value=f"GET {urlparse(url).path} similarity={similarity:.2f}",
        )
        findings.append(
            Finding(
                type="idor",
                severity="high",
                confidence=0.82,
                detector_id="access-control.two_user_comparison",
                source="Two-user access-control comparison",
                evidence=evidence,
                risk_reason=(
                    "Two explicit user contexts received similar successful responses for an object-looking URL. "
                    "This is validated evidence of a possible missing ownership or tenant check."
                ),
                remediation=(
                    "Require server-side ownership checks on this object path, scope queries by tenant/user, "
                    "and add a negative test proving user B cannot read user A objects."
                ),
                validation_status="validated",
                category="access-control",
                references=["https://owasp.org/Top10/A01_2021-Broken_Access_Control/"],
            )
        )

    return findings


def _candidate_object_urls(urls: Iterable[str]) -> List[str]:
    seen = set()
    candidates = []
    for url in urls:
        text = str(url or "")
        if text in seen:
            continue
        seen.add(text)
        try:
            parsed = urlparse(text)
        except ValueError:
            continue
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            continue
        if _OBJECT_ID_RE.search(text):
            candidates.append(text)
    return candidates


def _has_auth(auth: Dict[str, Any]) -> bool:
    return bool(str(auth.get("bearer_token") or "").strip() or str(auth.get("cookie") or "").strip())


def _auth_headers(auth: Dict[str, Any]) -> Dict[str, str]:
    bearer = str(auth.get("bearer_token") or "").strip()
    if bearer:
        return {"Authorization": f"Bearer {bearer}"}
    return {}


def _auth_cookies(auth: Dict[str, Any]) -> Dict[str, str]:
    cookie_header = str(auth.get("cookie") or "").strip()
    cookies: Dict[str, str] = {}
    for part in cookie_header.split(";"):
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        cookies[key.strip()] = value.strip()
    return cookies


def _successful(response: Any) -> bool:
    status_code = int(getattr(response, "status_code", 0) or 0)
    return 200 <= status_code < 300


def _body_similarity(left: str, right: str) -> float:
    left_sample = str(left or "")[:5000]
    right_sample = str(right or "")[:5000]
    if not left_sample and not right_sample:
        return 1.0
    return SequenceMatcher(None, left_sample, right_sample).ratio()
