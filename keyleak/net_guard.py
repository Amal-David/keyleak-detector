"""SSRF guard for scan targets.

The web ``/scan`` endpoint drives a real browser/crawler against a
caller-supplied URL. Without a guard, anyone who can reach the server can make
it fetch internal services or cloud-metadata endpoints (``169.254.169.254``) and
read back whatever secrets the response contains. This module decides whether a
target host is safe to scan.

Policy:
- Link-local (incl. cloud metadata), multicast, and the unspecified address are
  **always** refused — never a legitimate scan target.
- Loopback and private (RFC1918 / IPv6 ULA) addresses are refused unless the
  operator opts in via ``KEYLEAK_ALLOW_PRIVATE_TARGETS`` (e.g. to scan a local
  dev app from the web UI).
"""

from __future__ import annotations

import ipaddress
import os
import socket
from typing import Any, Dict, Optional
from urllib.parse import urlparse, urljoin

ALLOW_PRIVATE_ENV = "KEYLEAK_ALLOW_PRIVATE_TARGETS"


class SSRFBlocked(Exception):
    """Raised when a request target (initial or via redirect) fails the guard."""


def _allow_private_default() -> bool:
    return os.environ.get(ALLOW_PRIVATE_ENV, "").strip().lower() in {"1", "true", "yes", "on"}


def scan_target_block_reason(hostname: Optional[str], *, allow_private: Optional[bool] = None) -> Optional[str]:
    """Return a human-readable reason if ``hostname`` must not be scanned, else None.

    Resolves the host and checks every resolved address, so a hostname that
    resolves to an internal IP is caught too.
    """
    if not hostname:
        return "Invalid URL host."
    if allow_private is None:
        allow_private = _allow_private_default()
    try:
        infos = socket.getaddrinfo(hostname, None)
    except OSError:
        return f"Could not resolve host '{hostname}'."
    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except ValueError:
            continue
        # Cloud metadata (169.254.169.254) is link-local; always block link-local,
        # multicast, and the unspecified address regardless of the opt-in.
        if ip.is_link_local or ip.is_multicast or ip.is_unspecified:
            return (f"Refusing to scan '{hostname}' — it resolves to a non-routable or "
                    f"cloud-metadata address ({ip}).")
        if (ip.is_loopback or ip.is_private) and not allow_private:
            return (f"Refusing to scan '{hostname}' — it resolves to an internal address "
                    f"({ip}). Set {ALLOW_PRIVATE_ENV}=1 to allow scanning internal/local hosts.")
    return None


def url_block_reason(url: str, *, allow_private: Optional[bool] = None) -> Optional[str]:
    """Return a block reason for ``url`` (parses host, then applies the guard)."""
    try:
        host = urlparse(url).hostname
    except Exception:
        return "unparseable URL"
    if not host:
        return "URL has no host"
    return scan_target_block_reason(host, allow_private=allow_private)


def guarded_request(
    method: str,
    url: str,
    *,
    allow_private: Optional[bool] = None,
    max_redirects: int = 3,
    session: Any = None,
    **kwargs: Any,
) -> Any:
    """SSRF-safe HTTP request: validates the target host before connecting and
    **re-validates every redirect hop** instead of letting ``requests`` follow
    3xx into an unvalidated (possibly internal) host.

    This is the shared egress primitive for probes that fetch attacker-influenced
    URLs (BaaS config from page JS, subdomains from CT logs). Auto-redirects are
    forced off; redirects are followed manually, guarding each ``Location``.

    Raises ``SSRFBlocked`` if the initial target or any redirect target is
    refused by the guard. Returns the final ``requests.Response``.

    Residual risk (documented, not closed here): DNS rebinding between this
    guard's resolution and the socket connect — see ``docs/audit``. Mitigated by
    read-only probes, request caps, and host pre-validation; full connection-time
    IP pinning is tracked as follow-up.
    """
    import requests as _requests

    sess = session or _requests
    kwargs.pop("allow_redirects", None)  # we follow manually
    current = url
    for _hop in range(max_redirects + 1):
        reason = url_block_reason(current, allow_private=allow_private)
        if reason:
            raise SSRFBlocked(reason)
        resp = sess.request(method, current, allow_redirects=False, **kwargs)
        if resp.status_code in (301, 302, 303, 307, 308) and resp.headers.get("location"):
            current = urljoin(current, resp.headers["location"])
            continue
        return resp
    raise SSRFBlocked(f"Too many redirects (>{max_redirects}) starting from {url!r}.")
