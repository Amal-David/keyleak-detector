import unittest

from scripts.evaluate_binary_rea import _procedure_address, _pseudocode_text


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


if __name__ == "__main__":
    unittest.main()
