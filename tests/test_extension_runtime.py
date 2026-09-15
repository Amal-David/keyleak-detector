"""Focused contracts for authenticated extension scans and active-scan tracking."""

from __future__ import annotations

import asyncio
import importlib
import os
import unittest
from unittest import mock

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

    def test_challenged_health_requires_proof_without_returning_a_proof(self):
        with mock.patch(
            "pattern_importer.get_enhanced_patterns",
            return_value={},
        ):
            web_app = importlib.import_module("app")

        token = "local-install-secret"
        challenge = "a" * 64
        proof = challenge_proof(token, challenge)
        client = web_app.app.test_client()

        with mock.patch.dict(
            os.environ,
            {"KEYLEAK_EXTENSION_TOKEN": token},
            clear=False,
        ):
            self.assertEqual(client.get("/healthz").status_code, 200)
            self.assertEqual(
                client.get(f"/healthz?challenge={challenge}").status_code,
                401,
            )
            self.assertEqual(
                client.get(
                    f"/healthz?challenge={challenge}",
                    headers={"X-KeyLeak-Proof": "0" * 64},
                ).status_code,
                401,
            )
            response = client.get(
                f"/healthz?challenge={challenge}",
                headers={"X-KeyLeak-Proof": proof},
            )

        self.assertEqual(response.status_code, 200)
        self.assertNotIn("proof", response.get_json())


if __name__ == "__main__":
    unittest.main()
