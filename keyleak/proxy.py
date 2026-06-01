"""Opt-in outbound proxy support for scans (privacy).

A single `--proxy <url>` flag routes a scan's outbound traffic through an
HTTP/HTTPS/SOCKS5 proxy so the operator can stay private. Two convenience
aliases point at locally-running, trustworthy SOCKS5 proxies:

    warp -> socks5://127.0.0.1:40000   (Cloudflare WARP `warp-cli set-mode proxy`)
    tor  -> socks5://127.0.0.1:9050    (Tor SOCKS port)

Both are loopback endpoints, so they avoid the man-in-the-middle risk of random
free public proxies (whose operator can read all traffic — including discovered
secrets) and they coexist with `--offline`'s loopback-only socket guard.

This module is the single source of truth for normalizing a proxy value into the
shapes `requests` and Playwright each expect.
"""

from __future__ import annotations

import socket
from typing import Dict, Optional
from urllib.parse import urlparse


class ProxyError(ValueError):
    """Raised for an invalid, unreachable, or unsupported proxy configuration."""


WARP_PROXY = "socks5://127.0.0.1:40000"
TOR_PROXY = "socks5://127.0.0.1:9050"

_ALIASES: Dict[str, str] = {
    "warp": WARP_PROXY,
    "tor": TOR_PROXY,
}

# Schemes we can route through both `requests` and Playwright.
VALID_SCHEMES = ("http", "https", "socks5")

_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}

# Fallback ports for preflight when a proxy URL omits one.
_DEFAULT_PORTS = {"http": 8080, "https": 8080, "socks5": 1080}


def resolve_proxy(value: Optional[str]) -> Optional[str]:
    """Normalize a raw `--proxy` value into a validated proxy URL (or None).

    Resolves the ``warp``/``tor`` aliases and validates the URL scheme. Returns
    None for an empty/unset value. Raises ``ProxyError`` for anything malformed.
    """
    if not value:
        return None
    candidate = value.strip()
    if not candidate:
        return None

    alias = _ALIASES.get(candidate.lower())
    if alias:
        return alias

    if "://" not in candidate:
        raise ProxyError(
            f"Proxy {candidate!r} is missing a scheme. Use one of "
            f"{', '.join(s + '://' for s in VALID_SCHEMES)}, or the aliases "
            "'warp' / 'tor'."
        )

    scheme = urlparse(candidate).scheme.lower()
    if scheme not in VALID_SCHEMES:
        raise ProxyError(
            f"Unsupported proxy scheme {scheme!r}. Supported: "
            f"{', '.join(VALID_SCHEMES)}."
        )
    return candidate


def _host_port(url: str) -> "tuple[str, int]":
    parsed = urlparse(url)
    host = parsed.hostname or ""
    port = parsed.port or _DEFAULT_PORTS.get((parsed.scheme or "").lower(), 0)
    return host, port


def is_loopback_proxy(url: Optional[str]) -> bool:
    """True when the proxy host is a loopback address (works under --offline)."""
    if not url:
        return False
    host, _ = _host_port(url)
    return host in _LOOPBACK_HOSTS


def _require_pysocks(url: str) -> None:
    """SOCKS proxies need PySocks installed for `requests` to use them."""
    try:
        import socks  # noqa: F401  (PySocks)
    except ImportError as exc:  # pragma: no cover - depends on optional extra
        raise ProxyError(
            f"SOCKS proxy {url!r} requires PySocks. Install it with "
            "`pip install requests[socks]` (or `pip install PySocks`)."
        ) from exc


def requests_proxies(url: Optional[str]) -> Optional[Dict[str, str]]:
    """Return a ``proxies=`` mapping for `requests`, or None when no proxy set."""
    if not url:
        return None
    if urlparse(url).scheme.lower().startswith("socks"):
        _require_pysocks(url)
    return {"http": url, "https": url}


def playwright_proxy(url: Optional[str]) -> Optional[Dict[str, str]]:
    """Return a ``proxy=`` dict for Playwright launch/context, or None."""
    if not url:
        return None
    return {"server": url}


def preflight(url: Optional[str], timeout: float = 2.0) -> None:
    """Verify the proxy is reachable, raising ``ProxyError`` with a hint if not.

    A cheap TCP connect to the proxy host:port. Catches the common case of a
    WARP/Tor daemon that isn't running before a scan wastes time failing per
    request.
    """
    if not url:
        return
    host, port = _host_port(url)
    if not host or not port:
        raise ProxyError(f"Proxy {url!r} is missing a host or port.")
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return
    except OSError as exc:
        raise ProxyError(_unreachable_hint(url, host, port, exc)) from exc


def _unreachable_hint(url: str, host: str, port: int, exc: OSError) -> str:
    base = f"Proxy {url!r} is not reachable at {host}:{port} ({exc})."
    if url == WARP_PROXY:
        return (
            base + " Start Cloudflare WARP in proxy mode: "
            "`warp-cli set-mode proxy && warp-cli connect`."
        )
    if url == TOR_PROXY:
        return base + " Start Tor so it exposes its SOCKS port on 127.0.0.1:9050."
    return base
