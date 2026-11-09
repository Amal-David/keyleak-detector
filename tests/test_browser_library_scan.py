"""run_browser_scan emits vulnerable-library findings from the page probe."""

from __future__ import annotations

import importlib.util
import unittest
from typing import Any, Dict
from unittest import mock

HAS_PLAYWRIGHT = importlib.util.find_spec("playwright") is not None


@unittest.skipUnless(HAS_PLAYWRIGHT, "Playwright not installed; integration test skipped.")
class BrowserLibraryScanTests(unittest.TestCase):
    def _run_with_evaluate_results(self, results, routes=()):
        """Drive run_browser_scan with a fully-mocked Playwright; page.evaluate
        returns ``results`` in call order: __keyleak_run, baas_extract, library_scan.
        """
        from keyleak.browser_scanner import run_browser_scan

        page = mock.MagicMock()
        page.evaluate.side_effect = list(results)
        context = mock.MagicMock()
        context.new_page.return_value = page
        page.context = context
        page.goto.side_effect = lambda *_args, **_kwargs: [
            next(call.args[1] for call in context.new_cdp_session.return_value.on.call_args_list
                 if call.args[0] == "Fetch.requestPaused")(route) for route in routes
        ]
        browser = mock.MagicMock()
        browser.new_context.return_value = context
        p = mock.MagicMock()
        p.chromium.launch.return_value = browser
        cm = mock.MagicMock()
        cm.__enter__.return_value = p

        with mock.patch("playwright.sync_api.sync_playwright", return_value=cm):
            report = run_browser_scan(
                "https://app.example.test/",
                target_guard=lambda _host: None,
            )

        context.new_cdp_session.return_value.send.assert_any_call("Fetch.enable", mock.ANY)
        context.route_web_socket.assert_called_once()
        return report

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

    def test_invalid_analyzer_result_cannot_produce_a_clean_report(self):
        for result in (None, {}, "", False):
            with self.subTest(result=result):
                with self.assertRaisesRegex(RuntimeError, "scan is incomplete"):
                    self._run_with_evaluate_results([result])

    def test_browser_routes_obey_the_scan_wide_validation_budget(self):
        route = {"requestId": "script", "request": {
            "url": "https://app.example.test/script.js", "method": "GET", "headers": {},
        }}
        with mock.patch("keyleak.browser_scanner.MAX_BROWSER_GUARD_CHECKS", 0), \
                mock.patch("keyleak.browser_scanner.guarded_request") as fetch:
            report = self._run_with_evaluate_results([[], None, []], [route])
        fetch.assert_not_called()
        self.assertEqual(report.extra["egress_blocked_requests"]["total"], 1)
        self.assertTrue(report.extra["coverage_incomplete"])

    def test_fetch_failure_reports_incomplete_coverage_without_an_unsafe_egress_count(self):
        route = {"requestId": "script", "request": {
            "url": "https://app.example.test/script.js", "method": "GET", "headers": {},
        }}
        with mock.patch("keyleak.browser_scanner.guarded_request", side_effect=TimeoutError("private-token")):
            report = self._run_with_evaluate_results([[], None, []], [route])
        self.assertEqual(report.extra["egress_blocked_requests"]["total"], 0)
        self.assertTrue(report.extra["coverage_incomplete"])
        self.assertIn("Failed to fetch 1 browser request(s).", report.extra["coverage"]["reasons"])
        self.assertNotIn("private-token", str(report.to_dict()))


if __name__ == "__main__":
    unittest.main()
