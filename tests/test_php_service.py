import unittest
from types import SimpleNamespace
from unittest import mock

from keyleak import php_service


class PhpServiceTests(unittest.TestCase):
    def setUp(self):
        self.client = php_service.app.test_client()
        with php_service._lock:
            php_service._requests.clear()
            php_service._targets.clear()

    def test_public_response_is_limited_to_assessment_and_cors_is_explicit(self):
        report = SimpleNamespace(extra={"php_assessment": {"status": "unknown", "version": "", "reason": "No PHP banner."}})
        with mock.patch("keyleak.php_service.scan_php_url", return_value=report) as scan:
            response = self.client.post("/api/check", json={"url": "https://example.com", "authorized": True},
                                        headers={"Origin": "https://keyleakdetector.com"})
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.get_json(), report.extra["php_assessment"])
            self.assertEqual(response.headers["Access-Control-Allow-Origin"], "https://keyleakdetector.com")
            self.assertEqual(scan.call_args.args, ("https://example.com",))
            response = self.client.post("/api/check", json={"url": "https://elsewhere.example", "authorized": True},
                                        headers={"Origin": "https://untrusted.example"})
            self.assertEqual(response.status_code, 403)
            self.assertEqual(scan.call_count, 1)

    def test_limits_and_invalid_inputs_do_not_fetch(self):
        with mock.patch("keyleak.php_service.scan_php_url") as scan:
            for payload in ({}, [], {"url": "https://example.com", "authorized": "true"}):
                self.assertEqual(self.client.post("/api/check", json=payload).status_code, 400)
            self.assertEqual(self.client.post("/api/check", data="x" * 5000, content_type="application/json").status_code, 413)
            with php_service._lock:
                php_service._requests.extend([php_service.time.monotonic()] * 120)
            self.assertEqual(self.client.post("/api/check", json={"url": "https://example.com", "authorized": True}).status_code, 429)
            scan.assert_not_called()

    def test_target_limit_and_capacity_are_enforced(self):
        report = SimpleNamespace(extra={"php_assessment": {"status": "unknown"}})
        with mock.patch("keyleak.php_service.scan_php_url", return_value=report) as scan:
            payload = {"url": "https://example.com", "authorized": True}
            self.assertEqual(self.client.post("/api/check", json=payload).status_code, 200)
            self.assertEqual(self.client.post("/api/check", json=payload).status_code, 429)
            self.assertEqual(scan.call_count, 1)
        with mock.patch.object(php_service, "_slots") as slots:
            slots.acquire.return_value = False
            self.assertEqual(self.client.post("/api/check", json={"url": "https://other.example", "authorized": True}).status_code, 429)

    def test_errors_are_generic_and_capacity_is_released(self):
        with mock.patch("keyleak.php_service.scan_php_url", side_effect=ValueError("private-address-secret")), \
                mock.patch.object(php_service, "_slots") as slots:
            slots.acquire.return_value = True
            response = self.client.post("/api/check", json={"url": "https://example.com", "authorized": True})
            self.assertEqual(response.status_code, 400)
            self.assertNotIn("private-address-secret", response.get_data(as_text=True))
            slots.release.assert_called_once()
