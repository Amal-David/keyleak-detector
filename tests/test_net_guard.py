"""Tests for the SSRF scan-target guard (keyleak/net_guard.py).

IP literals are used as the hostname so getaddrinfo resolves without real DNS.
"""

from __future__ import annotations

import unittest

from keyleak.net_guard import (
    SSRFBlocked,
    guarded_request,
    scan_target_block_reason as block,
    url_block_reason,
)


class _FakeResp:
    def __init__(self, status_code, headers=None, text=""):
        self.status_code = status_code
        self.headers = headers or {}
        self.text = text


class _FakeSession:
    """Records requests and returns canned responses in order."""

    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs.get("allow_redirects")))
        return self._responses.pop(0)


class NetGuardTests(unittest.TestCase):
    def test_public_ip_allowed(self):
        self.assertIsNone(block("93.184.216.34"))

    def test_loopback_blocked_by_default(self):
        self.assertIsNotNone(block("127.0.0.1"))

    def test_private_blocked_by_default(self):
        self.assertIsNotNone(block("10.0.0.1"))
        self.assertIsNotNone(block("192.168.1.5"))

    def test_loopback_and_private_allowed_with_optin(self):
        self.assertIsNone(block("127.0.0.1", allow_private=True))
        self.assertIsNone(block("10.0.0.1", allow_private=True))

    def test_cloud_metadata_always_blocked(self):
        # Link-local / metadata must stay blocked even with the opt-in.
        self.assertIsNotNone(block("169.254.169.254"))
        self.assertIsNotNone(block("169.254.169.254", allow_private=True))

    def test_empty_host_blocked(self):
        self.assertIsNotNone(block(""))
        self.assertIsNotNone(block(None))


class GuardedRequestTests(unittest.TestCase):
    """guarded_request must (a) never auto-follow redirects, and (b) re-validate
    every redirect Location so a public host cannot 302 into an internal one
    (audit gate MF-1)."""

    def test_blocks_redirect_to_internal_host(self):
        # Public first hop redirects to cloud metadata → must raise, and must
        # NOT issue a second request to the internal target.
        sess = _FakeSession([
            _FakeResp(302, {"location": "http://169.254.169.254/latest/meta-data/"}),
        ])
        with self.assertRaises(SSRFBlocked):
            guarded_request("GET", "https://93.184.216.34/", session=sess)
        # Only the first hop was attempted; the internal redirect was refused.
        self.assertEqual(len(sess.calls), 1)
        # And auto-redirects were disabled on the request we did make.
        self.assertEqual(sess.calls[0][2], False)

    def test_blocks_initial_internal_target_without_request(self):
        sess = _FakeSession([_FakeResp(200)])
        with self.assertRaises(SSRFBlocked):
            guarded_request("GET", "http://10.0.0.5/x", session=sess)
        self.assertEqual(sess.calls, [])  # never even issued

    def test_follows_public_redirect_chain(self):
        sess = _FakeSession([
            _FakeResp(301, {"location": "https://93.184.216.34/v2"}),
            _FakeResp(200, text="ok"),
        ])
        resp = guarded_request("GET", "https://93.184.216.34/v1", session=sess)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(sess.calls), 2)

    def test_too_many_redirects_raises(self):
        sess = _FakeSession([_FakeResp(302, {"location": "https://93.184.216.34/next"}) for _ in range(10)])
        with self.assertRaises(SSRFBlocked):
            guarded_request("GET", "https://93.184.216.34/", session=sess, max_redirects=2)

    def test_url_block_reason_parses_host(self):
        self.assertIsNone(url_block_reason("https://93.184.216.34/path"))
        self.assertIsNotNone(url_block_reason("http://169.254.169.254/"))
        self.assertIsNotNone(url_block_reason("notaurl"))

    def test_url_block_reason_rejects_non_http_schemes(self):
        # R2 hardening: only http(s) may egress (gopher/ftp/file/data blocked).
        for url in ["gopher://93.184.216.34:6379/", "ftp://93.184.216.34/x",
                    "file:///etc/passwd", "data:text/plain,hi"]:
            self.assertIsNotNone(url_block_reason(url), url)


if __name__ == "__main__":
    unittest.main()
