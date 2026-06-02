"""Regression: browser-scan findings must never carry the raw secret.

The browser/full-site path used to store the cleartext match in
``evidence.redacted_value`` and ``snippet``, leaking secrets into reports,
CI artifacts, and the /scan JSON. These tests pin the redaction.
"""

from __future__ import annotations

import unittest

from keyleak.browser_scanner import _to_finding, evaluate_findings_payload

SECRET = "sk-proj-ABCDEF1234567890SECRETVALUE0987654321"


class BrowserRedactionTests(unittest.TestCase):
    def test_to_finding_redacts_value(self):
        f = _to_finding(
            {"detector_id": "leak.openai_api_key", "type": "openai_api_key",
             "severity": "critical", "source": "localStorage:t", "value": SECRET},
            "https://app.example.test/",
        )
        self.assertNotIn(SECRET, f.evidence.redacted_value)
        self.assertNotIn(SECRET, f.evidence.snippet)
        self.assertIn("[redacted", f.evidence.redacted_value)

    def test_report_dict_contains_no_raw_secret(self):
        report = evaluate_findings_payload(
            [{"detector_id": "leak.openai_api_key", "type": "openai_api_key",
              "severity": "critical", "source": "localStorage:t", "value": SECRET}],
            "https://app.example.test/",
        )
        import json
        blob = json.dumps(report.to_dict())
        self.assertNotIn(SECRET, blob)
        self.assertIn("[redacted", blob)


if __name__ == "__main__":
    unittest.main()
