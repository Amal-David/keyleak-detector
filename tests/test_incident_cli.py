import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from keyleak.cli import main
from keyleak.php_scanner import scan_php_url


class IncidentCliTests(unittest.TestCase):
    def test_permission_acknowledgement_is_required(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit), mock.patch("requests.Session") as session:
            main(["php-check", "https://example.com"])
        session.assert_not_called()

    def test_offline_php_refuses_before_installing_global_socket_block(self):
        with mock.patch("keyleak.cli.install_socket_block"), mock.patch("requests.Session") as session:
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(["--offline", "php-check", "https://example.com", "--authorized"]), 1)
        session.assert_not_called()

    def test_local_critical_result_uses_existing_reports_and_failure_status(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "requirements.txt"
            path.write_text("litellm==1.107.0\n")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = main(["incident-check", str(path), "--json", "--railway"])
            payload = json.loads(output.getvalue())
            self.assertEqual(code, 2)
            self.assertEqual(payload["verdict"]["status"], "BLOCK_SHIP")
            self.assertTrue(any(f["detector_id"] == "incident:railway-rotation" for f in payload["findings"]))

    def test_unknown_php_is_not_success(self):
        with mock.patch("keyleak.php_scanner.url_block_reason", return_value=None), mock.patch("requests.Session") as session:
            response = session.return_value.__enter__.return_value.get.return_value.__enter__.return_value
            response.headers = {}
            response.status_code = 200
            report = scan_php_url("https://example.com")
        output = io.StringIO()
        with mock.patch("keyleak.php_scanner.scan_php_url", return_value=report), contextlib.redirect_stdout(output):
            code = main(["php-check", "https://example.com", "--authorized", "--json"])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(output.getvalue())["php_assessment"]["status"], "unknown")
