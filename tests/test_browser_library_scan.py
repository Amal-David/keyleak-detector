"""run_browser_scan emits vulnerable-library findings from the page probe."""

from __future__ import annotations

import importlib.util
import unittest
from typing import Any, Dict
from unittest import mock

HAS_PLAYWRIGHT = importlib.util.find_spec("playwright") is not None


@unittest.skipUnless(HAS_PLAYWRIGHT, "Playwright not installed; integration test skipped.")
class BrowserLibraryScanTests(unittest.TestCase):
    def _run_with_evaluate_results(self, results):
        """Drive run_browser_scan with a fully-mocked Playwright; page.evaluate
        returns ``results`` in call order: __keyleak_run, baas_extract, library_scan.
        """
        from keyleak.browser_scanner import run_browser_scan

        page = mock.MagicMock()
        page.evaluate.side_effect = list(results)
        context = mock.MagicMock()
        context.new_page.return_value = page
        browser = mock.MagicMock()
        browser.new_context.return_value = context
        p = mock.MagicMock()
        p.chromium.launch.return_value = browser
        cm = mock.MagicMock()
        cm.__enter__.return_value = p

        with mock.patch("playwright.sync_api.sync_playwright", return_value=cm):
            return run_browser_scan("https://app.example.test/")

    def test_old_jquery_produces_vulnerable_library_finding(self):
        report = self._run_with_evaluate_results([
            [],                                                  # __keyleak_run
            None,                                                # __keyleak_baas_extract
            [{"name": "jquery", "version": "1.10.2", "source": "global"}],  # library scan
        ])
        types = [f.type for f in report.findings]
        self.assertIn("vulnerable_js_library", types)
        f = next(f for f in report.findings if f.type == "vulnerable_js_library")
        self.assertEqual(f.detector_id, "appsec.vulnerable_js_library")
        self.assertTrue(any("CVE-" in r for r in f.references))

    def test_modern_library_produces_no_finding(self):
        report = self._run_with_evaluate_results([
            [],
            None,
            [{"name": "jquery", "version": "3.7.1", "source": "global"}],
        ])
        self.assertNotIn("vulnerable_js_library", [f.type for f in report.findings])


if __name__ == "__main__":
    unittest.main()
