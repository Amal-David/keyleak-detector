import ssl
import unittest
from unittest import mock

import attack_vector_scanner as scanner


class AttackVectorTLSTests(unittest.TestCase):
    def test_certificate_inspection_requires_verified_tls_12_before_handshake(self):
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED

        def handshake(*args, **kwargs):
            self.assertGreaterEqual(context.minimum_version, ssl.TLSVersion.TLSv1_2)
            self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
            self.assertTrue(context.check_hostname)
            self.assertEqual(kwargs["server_hostname"], "example.test")
            connection = mock.MagicMock()
            connection.__enter__.return_value.getpeercert.return_value = {}
            return connection

        with (
            mock.patch.object(scanner.ssl, "create_default_context", return_value=context),
            mock.patch.object(scanner.socket, "create_connection"),
            mock.patch.object(context, "wrap_socket", side_effect=handshake),
        ):
            findings = scanner._check_tls_posture("example.test", "https://example.test/")
            context.minimum_version = ssl.TLSVersion.TLSv1_3
            scanner._check_tls_posture("example.test", "https://example.test/")
            self.assertEqual(context.minimum_version, ssl.TLSVersion.TLSv1_3)
        self.assertEqual(findings, [])
