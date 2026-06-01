"""Tests for the SSRF scan-target guard (keyleak/net_guard.py).

IP literals are used as the hostname so getaddrinfo resolves without real DNS.
"""

from __future__ import annotations

import unittest

from keyleak.net_guard import scan_target_block_reason as block


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


if __name__ == "__main__":
    unittest.main()
