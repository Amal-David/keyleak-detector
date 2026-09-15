"""Focused contracts for authenticated extension scans and active-scan tracking."""

from __future__ import annotations

import asyncio
import unittest

from keyleak.extension_runtime import ActiveScanCounter, challenge_proof, proof_matches


class ExtensionRuntimeTests(unittest.TestCase):
    def test_challenge_proof_requires_a_valid_challenge_and_exact_proof(self):
        token = "local-install-secret"
        challenge = "a" * 64
        proof = challenge_proof(token, challenge)

        self.assertEqual(len(proof), 64)
        self.assertTrue(proof_matches(token, challenge, proof))
        self.assertFalse(proof_matches(token, challenge, "0" * 64))
        self.assertEqual(challenge_proof(token, "not-a-challenge"), "")

    def test_active_scan_counter_resets_when_async_handler_fails(self):
        counter = ActiveScanCounter()

        @counter.track
        async def failing_scan():
            self.assertTrue(counter.active)
            raise RuntimeError("scan failed")

        with self.assertRaisesRegex(RuntimeError, "scan failed"):
            asyncio.run(failing_scan())

        self.assertFalse(counter.active)


if __name__ == "__main__":
    unittest.main()
