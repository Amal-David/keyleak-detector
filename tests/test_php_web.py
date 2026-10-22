import importlib
import unittest
from types import SimpleNamespace
from unittest import mock


class PhpWebTests(unittest.TestCase):
    def setUp(self):
        with mock.patch("pattern_importer.get_enhanced_patterns", return_value={}):
            self.web = importlib.import_module("app")
        self.client = self.web.app.test_client()

    def test_form_is_local_only_and_requires_authorization(self):
        with mock.patch("keyleak.php_scanner.scan_php_url") as scan:
            self.assertEqual(self.client.get("/php-check").status_code, 200)
            self.assertEqual(self.client.get("/php-check", environ_overrides={"REMOTE_ADDR": "203.0.113.1"}).status_code, 403)
            self.assertEqual(self.client.get("/php-check", headers={"Host": "rebind.example"}).status_code, 403)
            self.assertEqual(self.client.post("/php-check", data={"url": "x" * 9000, "authorized": "yes"}).status_code, 413)
            self.assertEqual(self.client.post("/php-check", data={"url": "https://example.com"}).status_code, 400)
            self.assertEqual(self.client.post("/php-check", data={"url": "https://example.com", "authorized": "yes"},
                                              headers={"Origin": "https://untrusted.example"}).status_code, 403)
        scan.assert_not_called()

    def test_each_result_is_visible_and_does_not_claim_safe(self):
        for status, label in [("unknown", "Patch status unknown"), ("potentially_affected", "Potentially affected"),
                              ("patched_version_reported", "Patched version reported")]:
            report = SimpleNamespace(extra={"php_assessment": {"status": status, "version": "8.4.27", "reason": "Verify origin."}})
            with self.subTest(status=status), mock.patch("keyleak.php_scanner.scan_php_url", return_value=report):
                response = self.client.post("/php-check", data={"url": "https://example.com", "authorized": "yes"})
                self.assertEqual(response.status_code, 200)
                self.assertIn(label, response.get_data(as_text=True))
                self.assertIn('value="https://example.com"', response.get_data(as_text=True))
                self.assertNotIn("SAFE TO SHIP", response.get_data(as_text=True))
                self.assertEqual(response.headers["Cache-Control"], "no-store")
                self.assertEqual(response.headers["Referrer-Policy"], "same-origin")

    def test_invalid_target_is_an_error_and_result_text_is_escaped(self):
        with mock.patch("keyleak.php_scanner.scan_php_url", side_effect=ValueError("Invalid URL")):
            response = self.client.post("/php-check", data={"url": "bad", "authorized": "yes"})
            self.assertEqual(response.status_code, 400)
        report = SimpleNamespace(extra={"php_assessment": {"status": "unknown", "version": "", "reason": "<script>alert(1)</script>"}})
        with mock.patch("keyleak.php_scanner.scan_php_url", return_value=report):
            response = self.client.post("/php-check", data={"url": "https://example.com", "authorized": "yes"})
            self.assertNotIn("<script>", response.get_data(as_text=True))
