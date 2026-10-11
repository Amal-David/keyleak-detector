import unittest
import contextlib
import io
import json
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

from scripts.evaluate_binary_rea import (
    CANARY,
    PUBLIC_EXAMPLE,
    XOR_KEY,
    _procedure_address,
    _pseudocode_text,
    _sanitized_excerpt,
    main,
)


class ReaEvaluationOutputTests(unittest.TestCase):
    def test_reads_pseudocode_from_pinned_rea_evidence_v2_envelope(self):
        pseudocode = "decoded[i] = encoded[i] ^ 0xaa;"
        response = {
            "ok": True,
            "data": {
                "schema_version": 2,
                "operation": "procedure_pseudo_code",
                "normalized_result": pseudocode,
                "provider": {"id": "ghidra", "version": "12.1.2"},
            },
            "meta": {"command": "decompile"},
        }

        self.assertEqual(_pseudocode_text(response), pseudocode)

    def test_finds_procedure_address_inside_evidence_v2_results(self):
        response = {
            "ok": True,
            "data": {
                "normalized_result": {
                    "items": [
                        {"address": "0x1010", "value": "reveal_token", "value_truncated": False}
                    ],
                    "total": 1,
                }
            },
            "meta": {"command": "search"},
        }

        self.assertEqual(_procedure_address(response, "reveal_token"), "0x1010")

    def test_sanitizes_pseudocode_text_extracted_from_evidence_envelope(self):
        response = {
            "data": {"normalized_result": f"decoded = '{CANARY}';"}
        }

        excerpt = _sanitized_excerpt(_pseudocode_text(response))

        self.assertNotIn(CANARY, excerpt)
        self.assertIn("<SYNTHETIC_CANARY>", excerpt)

    def test_requires_xor_operation_in_decompile_before_reporting_success(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            rea_cli = root / "rea"
            rea_cli.write_text("synthetic executable placeholder")
            artifacts = root / "artifacts"
            artifacts.mkdir()
            plain_binary = artifacts / "plain.elf"
            public_binary = artifacts / "public.elf"
            xor_binary = artifacts / "xor.elf"
            plain_binary.write_bytes(CANARY.encode() + b"\0")
            public_binary.write_bytes(PUBLIC_EXAMPLE.encode() + b"\0")
            xor_binary.write_bytes(bytes(ord(char) ^ XOR_KEY for char in CANARY) + b"\0")
            pseudocode = {"value": "decoded[i] = encoded[i] + 0xaa;"}

            def rea_response(_rea, args):
                if args[0] == "providers":
                    return {"data": {"analysis_provider_candidates": [{
                        "provider": {"id": "ghidra"},
                        "availability": {"status": "available"},
                    }]}}
                if args[0] == "search" and args[3] == "--kind" and args[4] == "strings":
                    value = CANARY if args[1].endswith("plain.elf") else (
                        PUBLIC_EXAMPLE if args[1].endswith("public.elf") else ""
                    )
                    return {"items": [{"value": value}]} if value else {"items": []}
                if args[0] == "search":
                    return {"items": [{"address": "0x1010", "value": "reveal_token"}]}
                if args[0] == "decompile":
                    return {"data": {"normalized_result": pseudocode["value"]}}
                return {}

            args = ["evaluate_binary_rea.py", "--rea", str(rea_cli)]
            with patch.object(sys, "argv", args), \
                    patch("scripts.evaluate_binary_rea.shutil.which", return_value="cc"), \
                    patch("scripts.evaluate_binary_rea._make_corpus", return_value=(artifacts, plain_binary, public_binary, xor_binary)), \
                    patch("scripts.evaluate_binary_rea._rea_json", side_effect=rea_response), \
                    contextlib.redirect_stdout(io.StringIO()) as output:
                with self.assertRaisesRegex(RuntimeError, "did not expose the XOR operation"):
                    main()
                pseudocode["value"] = "decoded[i] = encoded[i] ^ 0xaa;"
                self.assertEqual(main(), 0)

        result = json.loads(output.getvalue())
        self.assertTrue(result["rea_ghidra"]["xor_operation_visible"])
        self.assertEqual(result["integration_gate"]["decision"], "NO_GO")


if __name__ == "__main__":
    unittest.main()
