import json
from pathlib import Path
import subprocess
import unittest

from keyleak.php_scanner import assess_php_headers
from keyleak.php_service import app


class PublicPhpPageTests(unittest.TestCase):
    def test_browser_version_policy_matches_python_advisory_boundaries(self):
        cases = ["8.1.33", "7.4.33", "8.2.34", "8.2.35", "8.3.35", "8.3.36",
                 "8.4.26", "8.4.27", "8.5.11", "8.5.12", "8.6.0", "9.0.0",
                 "8.4.27RC1", "8.3.10-ubuntu1", "8.4", "8..4", ""]
        script = Path(__file__).resolve().parents[1] / "site/php-check/checker.js"
        output = subprocess.check_output(["node", "-e",
            "const {assessPHPVersion}=require(process.argv[1]);console.log(JSON.stringify(JSON.parse(process.argv[2]).map(v=>assessPHPVersion(v).status)))",
            str(script), json.dumps(cases)], text=True)
        expected = [assess_php_headers({"X-Powered-By": "PHP/" + version})["status"] for version in cases]
        self.assertEqual(json.loads(output), expected)

    def test_public_service_serves_only_its_frontend_and_health(self):
        client = app.test_client()
        self.assertEqual(client.get("/").status_code, 200)
        self.assertIn(b"url-form", client.get("/").data)
        self.assertEqual(client.get("/checker.js").status_code, 200)
        self.assertEqual(client.get("/healthz").get_json()["status"], "ok")
        self.assertEqual(client.get("/scan").status_code, 404)
        self.assertEqual(client.get("/../.env").status_code, 404)
