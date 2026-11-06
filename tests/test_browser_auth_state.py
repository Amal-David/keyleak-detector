"""Authenticated browser-state isolation contracts.

All Playwright objects are mocked. These tests exercise only how KeyLeak loads
and scopes a supplied storageState document before any browser request runs.
"""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from keyleak.browser_scanner import run_browser_scan


HAS_PLAYWRIGHT = importlib.util.find_spec("playwright") is not None


def _cookie(name: str, domain: str) -> dict:
    return {
        "name": name,
        "value": f"{name}-secret",
        "domain": domain,
        "path": "/",
        "expires": -1,
        "httpOnly": True,
        "secure": True,
        "sameSite": "Lax",
    }


@unittest.skipUnless(HAS_PLAYWRIGHT, "Playwright not installed; auth-state contract skipped.")
class BrowserAuthStateTests(unittest.TestCase):
    def _context_storage_state(self, state: dict) -> object:
        page = mock.MagicMock()
        page.evaluate.side_effect = [[], None, [], []]

        context = mock.MagicMock()
        context.new_page.return_value = page
        context.new_cdp_session.side_effect = RuntimeError("CDP unavailable in unit test")

        browser = mock.MagicMock()
        browser.new_context.return_value = context
        playwright = mock.MagicMock()
        playwright.chromium.launch.return_value = browser
        manager = mock.MagicMock()
        manager.__enter__.return_value = playwright

        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "auth-state.json"
            state_path.write_text(json.dumps(state), encoding="utf-8")
            with mock.patch(
                "playwright.sync_api.sync_playwright",
                return_value=manager,
            ):
                run_browser_scan(
                    "https://app.example.test/dashboard",
                    auth_state_path=str(state_path),
                    scan_budget_seconds=3,
                    target_guard=lambda _host: None,
                )

        return browser.new_context.call_args.kwargs["storage_state"]

    def test_auth_state_is_sanitized_to_the_exact_target_origin(self):
        raw_state = {
            "cookies": [
                _cookie("exact", "app.example.test"),
                _cookie("parent-domain", ".example.test"),
                _cookie("target-subdomains", ".app.example.test"),
                _cookie("sibling", "api.example.test"),
                _cookie("foreign", "login.vendor.test"),
            ],
            "origins": [
                {
                    "origin": "https://app.example.test",
                    "localStorage": [{"name": "exact", "value": "target-secret"}],
                },
                {
                    "origin": "http://app.example.test",
                    "localStorage": [{"name": "wrong-scheme", "value": "secret"}],
                },
                {
                    "origin": "https://app.example.test:8443",
                    "localStorage": [{"name": "wrong-port", "value": "secret"}],
                },
                {
                    "origin": "https://login.vendor.test",
                    "localStorage": [{"name": "foreign", "value": "secret"}],
                },
            ],
        }

        sanitized = self._context_storage_state(raw_state)

        self.assertIsInstance(sanitized, dict)
        self.assertEqual(
            {cookie["name"] for cookie in sanitized.get("cookies", [])},
            {"exact"},
        )
        self.assertEqual(
            {origin["origin"] for origin in sanitized.get("origins", [])},
            {"https://app.example.test"},
        )

    def test_broad_cookie_is_not_loaded_as_an_off_origin_credential(self):
        sanitized = self._context_storage_state(
            {
                "cookies": [_cookie("broad-session", ".example.test")],
                "origins": [],
            }
        )

        self.assertIsInstance(sanitized, dict)
        self.assertEqual(sanitized.get("cookies"), [])


if __name__ == "__main__":
    unittest.main()
