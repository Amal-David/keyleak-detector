import unittest
import socket
from unittest import mock

import requests

from keyleak.php_scanner import assess_php_headers, scan_php_url


class PhpScannerTests(unittest.TestCase):
    def test_upstream_fix_boundaries(self):
        for branch, fixed in [("8.2", 35), ("8.3", 36), ("8.4", 27), ("8.5", 12)]:
            for patch, expected in [(fixed - 1, "potentially_affected"), (fixed, "patched_version_reported")]:
                with self.subTest(branch=branch, patch=patch):
                    self.assertEqual(assess_php_headers({"X-Powered-By": f"PHP/{branch}.{patch}"})["status"], expected)

    def test_ambiguous_vendor_hidden_and_future_versions_are_unknown(self):
        for headers in [{}, {"Server": "nginx"}, {"X-Powered-By": "PHP"},
                        {"Server": "PHP/8.4"}, {"Server": "PHP/8.4.27RC1"},
                        {"Server": "PHP/8.3.10-ubuntu1"}, {"Server": "PHP/8.6.0"},
                        {"Server": "PHP/8.4.27", "X-Powered-By": "PHP/8.2.1"}]:
            with self.subTest(headers=headers):
                self.assertEqual(assess_php_headers(headers)["status"], "unknown")
        self.assertEqual(assess_php_headers({"Set-Cookie": "PHP/8.4.27"})["status"], "unknown")
        self.assertEqual(assess_php_headers({"Server": "PHP/8.4.27"}, 403)["status"], "unknown")

    def test_unsupported_old_branch_is_only_potentially_affected(self):
        result = assess_php_headers({"Server": "Apache PHP/7.4.33"})
        self.assertEqual(result["status"], "potentially_affected")
        self.assertIn("backports", result["reason"])

    @mock.patch("keyleak.php_scanner.url_block_reason", return_value=None)
    @mock.patch("keyleak.php_scanner.requests.Session")
    def test_fetch_is_bounded_credential_free_and_never_says_safe(self, session_type, guard):
        session = session_type.return_value.__enter__.return_value
        response = session.get.return_value.__enter__.return_value
        response.headers = {"X-Powered-By": "PHP/8.4.27", "Set-Cookie": "secret-cookie"}
        response.status_code = 200
        report = scan_php_url("https://example.com/", proxy="http://127.0.0.1:8888")
        self.assertFalse(session.trust_env)
        kwargs = session.get.call_args.kwargs
        self.assertFalse(kwargs["allow_redirects"])
        self.assertTrue(kwargs["stream"])
        self.assertEqual(kwargs["proxies"]["https"], "http://127.0.0.1:8888")
        self.assertNotEqual(report.verdict["status"], "SAFE_TO_SHIP")
        self.assertNotIn("secret-cookie", str(report.to_dict()))
        self.assertEqual(report.findings[0].validation_status, "lead")
        guard.assert_called_once_with("https://example.com/", allow_private=False)

    @mock.patch("keyleak.php_scanner.requests.Session")
    def test_invalid_offline_and_internal_inputs_never_fetch(self, session):
        for url in ["file:///etc/passwd", "https://u:p@example.com", "https://example.com/?token=x",
                    "https://@example.com", "https://:secret@example.com",
                    "https://example.com/#secret", "https://example.com:8080", "https://example.com/\n"]:
            with self.subTest(url=url), self.assertRaises(ValueError):
                scan_php_url(url)
        with self.assertRaises(ValueError):
            scan_php_url("https://example.com", offline=True)
        with mock.patch("keyleak.php_scanner.socket.getaddrinfo", return_value=[
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 80))]), self.assertRaises(ValueError):
            scan_php_url("http://127.0.0.1")
        session.assert_not_called()

    @mock.patch("keyleak.php_scanner._fetch_public_headers", side_effect=OSError("sensitive internal error"))
    def test_failures_and_redirects_remain_unknown(self, fetch):
        report = scan_php_url("https://example.com")
        self.assertEqual(report.extra["php_assessment"]["status"], "unknown")
        self.assertEqual(report.extra["coverage"]["status"], "incomplete")
        self.assertNotIn("sensitive internal error", str(report.to_dict()))
        self.assertEqual(assess_php_headers({"Server": "PHP/8.4.27"}, 302)["status"], "unknown")

    def test_numeric_connection_is_pinned_after_public_dns_validation(self):
        addresses = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80))]
        with mock.patch("keyleak.php_scanner.socket.getaddrinfo", return_value=addresses) as dns, \
                mock.patch("keyleak.php_scanner.socket.socket") as socket_type, \
                mock.patch("keyleak.php_scanner.http.client.HTTPConnection") as connection_type:
            response = connection_type.return_value.getresponse.return_value
            response.getheaders.return_value = [("Server", "PHP/8.4.27")]
            response.status = 200
            report = scan_php_url("http://example.com")
            dns.assert_called_once()
            socket_type.return_value.connect.assert_called_once_with(("93.184.216.34", 80))
            self.assertEqual(report.extra["php_assessment"]["status"], "patched_version_reported")
            connection_type.return_value.close.assert_called_once()

    def test_reserved_or_mixed_dns_answers_never_create_a_socket(self):
        for ip in ("100.64.0.1", "169.254.169.254", "10.0.0.1", "224.0.0.1", "::1"):
            addresses = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80)),
                         (socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 80))]
            with self.subTest(ip=ip), mock.patch("keyleak.php_scanner.socket.getaddrinfo", return_value=addresses), \
                    mock.patch("keyleak.php_scanner.socket.socket") as socket_type, self.assertRaises(ValueError):
                scan_php_url("http://example.com")
            socket_type.assert_not_called()

    def test_https_keeps_original_hostname_and_conflicting_headers(self):
        addresses = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]
        with mock.patch("keyleak.php_scanner.socket.getaddrinfo", return_value=addresses), \
                mock.patch("keyleak.php_scanner.socket.socket") as socket_type, \
                mock.patch("keyleak.php_scanner.ssl.create_default_context") as context, \
                mock.patch("keyleak.php_scanner.http.client.HTTPConnection") as connection_type:
            response = connection_type.return_value.getresponse.return_value
            response.getheaders.return_value = [("X-Powered-By", "PHP/8.4.27"), ("x-powered-by", "PHP/8.2.1")]
            response.status = 200
            report = scan_php_url("https://example.com")
            context.return_value.wrap_socket.assert_called_once_with(socket_type.return_value, server_hostname="example.com")
            self.assertEqual(report.extra["php_assessment"]["status"], "unknown")
