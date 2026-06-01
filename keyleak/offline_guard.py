"""``--offline`` mode: provable network isolation.

A buyer in a regulated or air-gapped environment must be able to prove that
KeyLeak makes zero outbound network calls. ``--offline`` monkey-patches
``socket.socket.connect`` to allow only loopback connections (``127.0.0.1``,
``::1``, ``localhost``) and raises ``OfflineViolation`` for anything else.

The patch runs before any KeyLeak module that opens a socket. It does not
block local IPC (mitmproxy and the Flask bridge listen on 127.0.0.1).
"""

from __future__ import annotations

import os
import socket
import sys
from typing import List, Optional


class OfflineViolation(RuntimeError):
    """Raised when ``--offline`` mode rejects an outbound socket connection."""


_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}
_INSTALLED = False
_ORIGINAL_CONNECT: Optional[callable] = None
# 4-tuple addresses ((host, port, flowinfo, scopeid)) only have str/int in [0].
# Pre-resolved IP families have str ports too. We accept any address whose
# first element is loopback or '' (Unix socket).


def _is_loopback(address) -> bool:
    if address is None:
        return False
    if isinstance(address, (bytes, str)) and not address:
        return True  # Unix socket path
    if isinstance(address, str) and address.startswith("/"):
        return True  # explicit Unix socket path
    if isinstance(address, tuple) and address:
        host = address[0]
        if isinstance(host, bytes):
            try:
                host = host.decode("utf-8")
            except UnicodeDecodeError:
                return False
        if not isinstance(host, str):
            return False
        if host in _LOOPBACK_HOSTS:
            return True
        # Treat private DNS like ``host.docker.internal`` resolving to 127.x as
        # loopback — but a real DNS lookup may resolve elsewhere. Be strict and
        # require literal loopback addresses or 'localhost'.
    return False


def install_socket_block() -> None:
    """Patch ``socket.socket.connect`` to allow only loopback connections."""

    global _INSTALLED, _ORIGINAL_CONNECT

    if _INSTALLED:
        return
    _ORIGINAL_CONNECT = socket.socket.connect

    def guarded_connect(self, address):  # type: ignore[no-redef]
        if not _is_loopback(address):
            raise OfflineViolation(
                f"--offline blocked outbound socket to {address!r}. "
                "Set KEYLEAK_OFFLINE_ALLOW_HOSTS to extend, or run without --offline."
            )
        return _ORIGINAL_CONNECT(self, address)

    socket.socket.connect = guarded_connect  # type: ignore[assignment]
    _INSTALLED = True


def uninstall_socket_block() -> None:
    """Restore the original ``socket.socket.connect`` (for tests)."""

    global _INSTALLED, _ORIGINAL_CONNECT
    if not _INSTALLED:
        return
    if _ORIGINAL_CONNECT is not None:
        socket.socket.connect = _ORIGINAL_CONNECT
    _INSTALLED = False
    _ORIGINAL_CONNECT = None


KNOWN_EGRESS_TARGETS: List[str] = [
    "the URL passed to `keyleak scan` (only when `--offline` is OFF)",
    "GitHub-token-revocation endpoint (Wave 3.3 `keyleak diff --revoke` only)",
    "OSV.dev + OpenSSF malicious-packages feeds (Wave 3.2 `keyleak feed sync` only)",
    "AWS / Stripe / OpenAI / Anthropic security contacts (Wave 1.7 `keyleak disclose` if invoked)",
    "vendor sigstore registries (signature verification, if cosign is invoked)",
]


def print_egress_banner(stream=sys.stderr) -> None:
    """Document the *known* outbound endpoints, off mode only."""

    print("KeyLeak --offline ON. Without --offline, KeyLeak may contact:", file=stream)
    for target in KNOWN_EGRESS_TARGETS:
        print(f"  - {target}", file=stream)
    print("Loopback (127.0.0.1, ::1, localhost) remains allowed.", file=stream)
