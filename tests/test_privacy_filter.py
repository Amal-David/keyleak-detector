"""Tests for the PII scrubber (keyleak/privacy_filter.py).

Covers the audit gate finding FIX1-MF2: the phone pattern must not start inside
a longer alphanumeric token and mangle a secret's digits.
"""

from __future__ import annotations

import unittest

from keyleak.privacy_filter import scrub_text, scrub_snippet


class ScrubTextTests(unittest.TestCase):
    def test_masks_email_phone_ssn(self):
        out = scrub_text("owner jane.doe@acme.com call 555-123-4567 ssn 123-45-6789")
        self.assertNotIn("jane.doe@acme.com", out)
        self.assertNotIn("555-123-4567", out)
        self.assertNotIn("123-45-6789", out)
        self.assertIn("[email]", out)
        self.assertIn("[phone]", out)
        self.assertIn("[ssn]", out)

    def test_does_not_eat_digits_inside_secret_token(self):
        # Regression: previously masked as 'sk_live_424242[phone]'.
        self.assertEqual(scrub_text("token_4242424242424242"), "token_4242424242424242")
        self.assertEqual(scrub_text("token_5551234567abc"), "token_5551234567abc")

    def test_masks_standalone_phone(self):
        self.assertEqual(scrub_text("call +1 555-123-4567 now"), "call [phone] now")

    def test_idempotent(self):
        once = scrub_text("mail a@b.com phone 555-123-4567")
        twice = scrub_text(once)
        self.assertEqual(once, twice)


class ScrubSnippetTests(unittest.TestCase):
    def test_preserves_redacted_token(self):
        preserved = "AKIA...[redacted]...wxyz"
        snippet = f"owner bob@corp.io key={preserved}"
        out = scrub_snippet(snippet, preserved)
        self.assertIn(preserved, out)
        self.assertNotIn("bob@corp.io", out)
        self.assertIn("[email]", out)


if __name__ == "__main__":
    unittest.main()
