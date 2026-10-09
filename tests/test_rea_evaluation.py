import unittest

from scripts.evaluate_binary_rea import CANARY, _procedure_address, _pseudocode_text, _sanitized_excerpt


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


if __name__ == "__main__":
    unittest.main()
