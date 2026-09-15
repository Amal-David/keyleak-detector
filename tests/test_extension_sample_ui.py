"""Static safety contract for the extension's BaaS sample preview."""

from pathlib import Path
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]


class ExtensionSampleUiTests(unittest.TestCase):
    def test_popup_labels_and_escapes_the_redacted_sample(self):
        popup_js = (REPO_ROOT / "extension" / "popup" / "popup.js").read_text(
            encoding="utf-8"
        )
        popup_html = (REPO_ROOT / "extension" / "popup" / "popup.html").read_text(
            encoding="utf-8"
        )

        self.assertIn("evidence.sample", popup_js)
        self.assertIn("redacted sample row", popup_js.lower())
        self.assertIn("escapeHtml(evidence.sample)", popup_js)
        self.assertIn("REVEAL RAW SAMPLE", popup_js)
        self.assertIn("reveal_backend_sample", popup_js)
        self.assertIn("rawSampleMount.textContent", popup_js)
        self.assertNotIn("rawSampleMount.innerHTML", popup_js)
        self.assertIn(".sample-preview", popup_html)
        self.assertIn(".raw-sample-preview", popup_html)
        self.assertIn("white-space: pre-wrap", popup_html)


if __name__ == "__main__":
    unittest.main()
