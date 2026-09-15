"""Convex detector and extension capture contracts use synthetic inputs only."""

from pathlib import Path
import unittest

from keyleak.detectors import find_detector
from keyleak.local_scanner import scan_text


REPO_ROOT = Path(__file__).resolve().parents[1]


class ConvexDetectorTests(unittest.TestCase):
    def test_deployment_url_is_an_observation_not_a_secret(self):
        detector = find_detector("baas.convex_deployment_url")
        self.assertIsNotNone(detector)
        self.assertEqual(detector.severity, "info")
        self.assertEqual(detector.validation_status, "lead")

        findings = scan_text(
            "NEXT_PUBLIC_CONVEX_URL=https://happy-animal-123.convex.cloud",
            "app.js",
            [detector],
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].type, "convex_deployment_url")

    def test_unrelated_hosts_do_not_match(self):
        detector = find_detector("baas.convex_deployment_url")
        self.assertEqual(
            scan_text("https://convex.cloud.evil.example", "app.js", [detector]),
            [],
        )

    def test_injector_forwards_only_sanitized_convex_query_metadata(self):
        injector = (REPO_ROOT / "extension" / "injector.js").read_text(encoding="utf-8")
        worker = (REPO_ROOT / "extension" / "service-worker.js").read_text(encoding="utf-8")

        self.assertIn("convex-client", injector)
        self.assertIn("udfPath", injector)
        self.assertIn("authenticated", injector)
        self.assertNotIn("modification.args", injector)
        self.assertNotIn("message.value", injector)
        self.assertIn("ConvexTabState", worker)
        self.assertIn("convexTabStates", worker)

    def test_support_document_states_the_safe_boundary(self):
        support = (REPO_ROOT / "docs" / "CONVEX_SUPPORT.md").read_text(encoding="utf-8")

        self.assertIn("does not invoke mutations or actions", support)
        self.assertIn("does not guess function names", support)
        self.assertIn("public deployment URL is not a vulnerability", support)
        self.assertIn("Transition", support)


if __name__ == "__main__":
    unittest.main()
