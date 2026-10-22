import unittest
import time

from keyleak.redaction import redact_url, redact_value


class UrlRedactionTests(unittest.TestCase):
    def test_preserves_raw_spelling_and_redacts_only_existing_secret_keys(self):
        marker = "synthetic-qa-value-only"
        masked = redact_value(marker)
        cases = {
            f"https://example.com/?token={marker}&page=2": f"https://example.com/?token={masked}&page=2",
            f"https://example.com/?TOKEN={marker}#section": f"https://example.com/?TOKEN={masked}#section",
            f"https://example.com/?not?token={marker}": f"https://example.com/?not?token={marker}",
            f"https://example.com/?empty=#fragment?token={marker}": f"https://example.com/?empty=#fragment?token={masked}",
            f"https://example.com/?={marker}?token={marker}": f"https://example.com/?={marker}?token={masked}",
            "https://example.com/?token=&page=2&&end": "https://example.com/?token=&page=2&&end",
            f"https://example.com/?token={marker}?nested=1": "https://example.com/?token=" + redact_value(marker + "?nested=1"),
            "https://example.com/?page=a%2Bb+z&%74oken=x": "https://example.com/?page=a%2Bb+z&%74oken=[redacted]",
            f"https://example.com/?%54oKeN={marker}": f"https://example.com/?%54oKeN={masked}",
            f"https://example.com/?%61pi%5Fkey={marker}&%70age=a%2Bb+z": f"https://example.com/?%61pi%5Fkey={masked}&%70age=a%2Bb+z",
        }
        for original, expected in cases.items():
            with self.subTest(original=original):
                self.assertEqual(redact_url(original), expected)
        self.assertEqual(redact_url(None), "")

    def test_long_non_parameter_text_is_preserved(self):
        text = "https://example.com/" + "section?part%" * 10000
        started = time.monotonic()
        self.assertEqual(redact_url(text), text)
        self.assertLess(time.monotonic() - started, 2.0)
