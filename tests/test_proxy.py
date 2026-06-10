"""Tests for the opt-in outbound proxy helper (keyleak/proxy.py).

Pure-Python normalization, validation, and threading checks. No real network —
``preflight`` is exercised against a closed loopback port to assert the error
path, and the threading tests mock the HTTP/Playwright layers.

unittest to match the repo's existing test style.
"""

from __future__ import annotations

import socket
import unittest
from unittest import mock

import keyleak.proxy as proxy
from keyleak.proxy import (
    TOR_PROXY,
    WARP_PROXY,
    ProxyError,
    is_loopback_proxy,
    playwright_proxy,
    preflight,
    requests_proxies,
    resolve_proxy,
)


class ResolveProxyTests(unittest.TestCase):
    def test_warp_alias(self):
        self.assertEqual(resolve_proxy("warp"), WARP_PROXY)
        self.assertEqual(resolve_proxy("WARP"), WARP_PROXY)  # case-insensitive

    def test_tor_alias(self):
        self.assertEqual(resolve_proxy("tor"), TOR_PROXY)

    def test_passthrough_valid_urls(self):
        for url in ("http://h:8080", "https://h:8080", "socks5://127.0.0.1:9050"):
            self.assertEqual(resolve_proxy(url), url)

    def test_empty_returns_none(self):
        self.assertIsNone(resolve_proxy(""))
        self.assertIsNone(resolve_proxy(None))
        self.assertIsNone(resolve_proxy("   "))

    def test_missing_scheme_rejected(self):
        with self.assertRaises(ProxyError):
            resolve_proxy("127.0.0.1:8080")

    def test_unsupported_scheme_rejected(self):
        with self.assertRaises(ProxyError):
            resolve_proxy("ftp://host:21")


class DictShapeTests(unittest.TestCase):
    def test_requests_proxies_http(self):
        self.assertEqual(
            requests_proxies("http://h:8080"),
            {"http": "http://h:8080", "https": "http://h:8080"},
        )

    def test_requests_proxies_none(self):
        self.assertIsNone(requests_proxies(None))
        self.assertIsNone(requests_proxies(""))

    def test_requests_proxies_socks_requires_pysocks(self):
        # Simulate PySocks missing regardless of the test env.
        with mock.patch.object(proxy, "_require_pysocks",
                               side_effect=ProxyError("need PySocks")):
            with self.assertRaises(ProxyError):
                requests_proxies("socks5://127.0.0.1:9050")

    def test_playwright_proxy(self):
        self.assertEqual(playwright_proxy(WARP_PROXY), {"server": WARP_PROXY})
        self.assertIsNone(playwright_proxy(None))


class LoopbackTests(unittest.TestCase):
    def test_warp_and_tor_are_loopback(self):
        self.assertTrue(is_loopback_proxy(WARP_PROXY))
        self.assertTrue(is_loopback_proxy(TOR_PROXY))
        self.assertTrue(is_loopback_proxy("http://localhost:8080"))

    def test_external_host_not_loopback(self):
        self.assertFalse(is_loopback_proxy("http://1.2.3.4:8080"))
        self.assertFalse(is_loopback_proxy(None))


class PreflightTests(unittest.TestCase):
    def test_none_is_noop(self):
        self.assertIsNone(preflight(None))

    def test_unreachable_loopback_proxy_raises(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            _, port = sock.getsockname()

        with self.assertRaises(ProxyError) as ctx:
            preflight(f"socks5://127.0.0.1:{port}", timeout=0.2)
        self.assertIn("not reachable", str(ctx.exception))

    def test_unreachable_warp_gives_hint(self):
        with mock.patch.object(proxy.socket, "create_connection",
                               side_effect=OSError("closed")):
            with self.assertRaises(ProxyError) as ctx:
                preflight(WARP_PROXY, timeout=0.2)
        self.assertIn("warp-cli", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
