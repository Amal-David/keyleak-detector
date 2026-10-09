"""Offline regressions for the legacy web scan's proxy and response boundaries.

The browser, proxy transport, pattern download and DNS are all replaced; these
tests exercise the real request hooks and Flask response builders without
starting a browser or contacting a scan target.
"""

from __future__ import annotations

import asyncio
import copy
import json
from queue import Queue
import socket
import threading
import time
from types import SimpleNamespace
import unittest
from unittest import mock


# Importing the legacy app otherwise downloads detector rules. Keep collection
# offline without replacing the application or the functions under test.
with mock.patch(
    "pattern_importer.get_enhanced_patterns",
    side_effect=lambda **kwargs: kwargs["custom_patterns"],
):
    import app as web_app


TARGET = "https://app.example.test/"
SECRET = "captured-" + "value-1234567890"
NEIGHBOR = "adjacent-" + "value-0987654321"


class _Headers(dict):
    """The case-insensitive subset of mitmproxy Headers used by the hooks."""

    def __init__(self, values=()):
        super().__init__((key.lower(), value) for key, value in dict(values).items())

    def pop(self, key, *args):
        return super().pop(key.lower(), *args)

    def get(self, key, *args):
        return super().get(key.lower(), *args)


def _flow(url, headers=None):
    return SimpleNamespace(
        request=SimpleNamespace(pretty_url=url, headers=_Headers(headers or {})),
        response=None,
    )


def _resolve(host, *_args, **_kwargs):
    ip = {
        "127.0.0.1": "127.0.0.1",
        "localhost": "127.0.0.1",
        "private.example.test": "10.1.2.3",
        "metadata.example.test": "169.254.169.254",
        "169.254.169.254": "169.254.169.254",
    }.get(host, "93.184.216.34")
    return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, 0))]


class WebScanSecurityTests(unittest.TestCase):
    def setUp(self):
        for patcher in (
            mock.patch("keyleak.net_guard.socket.getaddrinfo", side_effect=_resolve),
            mock.patch("socket.socket.connect", side_effect=AssertionError("Test attempted network I/O")),
            mock.patch.dict("os.environ", {"KEYLEAK_ALLOW_PRIVATE_TARGETS": "0"}),
            mock.patch.object(web_app, "_legacy_scan_lock", threading.Lock()),
            mock.patch.object(
                web_app, "http",
                SimpleNamespace(Response=SimpleNamespace(make=lambda status, body, headers: SimpleNamespace(
                    status_code=status, body=body, headers=headers,
                ))),
            ),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.handler = web_app.RequestHandler()

    def test_proxy_revalidates_redirect_and_subresource_connections(self):
        for host, blocked in (
            ("app.example.test", False),
            ("cdn.example.test", False),
            ("private.example.test", True),
            ("metadata.example.test", True),
            ("127.0.0.1", True),
        ):
            with self.subTest(host=host):
                connection = SimpleNamespace(server=SimpleNamespace(address=(host, 443), error=None))
                self.handler.server_connect(connection)
                self.assertEqual(connection.server.error is not None, blocked)

    def test_private_target_opt_in_still_rejects_metadata(self):
        with mock.patch.dict("os.environ", {"KEYLEAK_ALLOW_PRIVATE_TARGETS": "1"}):
            local = _flow("http://127.0.0.1:3000/")
            metadata = _flow("http://169.254.169.254/latest/meta-data/")
            self.handler.requestheaders(local)
            self.handler.requestheaders(metadata)
        self.assertIsNone(local.response)
        self.assertEqual(metadata.response.status_code, 403)

    def test_request_guard_fails_closed_on_invalid_or_unresolved_target(self):
        for url in ("file:///etc/passwd", "https://app.example.test:invalid/", "http://metadata.example.test/"):
            with self.subTest(url=url):
                flow = _flow(url)
                self.handler.requestheaders(flow)
                self.assertEqual(flow.response.status_code, 403)
        with mock.patch("keyleak.net_guard.socket.getaddrinfo", side_effect=socket.gaierror):
            flow = _flow(TARGET)
            self.handler.requestheaders(flow)
            self.assertEqual(flow.response.status_code, 403)

    def test_supplied_credentials_are_scoped_to_full_origin_at_every_hop(self):
        supplied = {"Authorization": "Bearer operator-fixture", "X-User-Id": "user-a", "Cookie": "session=fixture"}
        scope = self.handler.register_auth_scope(TARGET, supplied)
        for url, allowed in (
            (TARGET, True),
            ("https://app.example.test:443/redirected", True),
            ("https://cdn.example.test/script.js", False),
            ("https://app.example.test:8443/", False),
            ("http://app.example.test/", False),
        ):
            with self.subTest(url=url):
                flow = _flow(url, {**supplied, web_app._SCAN_SCOPE_HEADER: scope, "Accept": "*/*"})
                self.handler.requestheaders(flow)
                self.assertIsNone(flow.response)
                self.assertNotIn(web_app._SCAN_SCOPE_HEADER.lower(), flow.request.headers)
                self.assertEqual(flow.request.headers["accept"], "*/*")
                for name in supplied:
                    self.assertEqual(name.lower() in flow.request.headers, allowed)

    def test_overlapping_scans_do_not_union_credential_destinations(self):
        supplied = {"Authorization": "Bearer shared-fixture"}
        scope_a = self.handler.register_auth_scope(TARGET, supplied)
        target_b = "https://other.example.test/"
        scope_b = self.handler.register_auth_scope(target_b, supplied)
        for scope, url, allowed in ((scope_a, target_b, False), (scope_b, TARGET, False), (scope_b, target_b, True)):
            flow = _flow(url, {**supplied, web_app._SCAN_SCOPE_HEADER: scope})
            self.handler.requestheaders(flow)
            self.assertEqual("authorization" in flow.request.headers, allowed)
        self.handler.release_auth_scope(scope_a)
        self.assertIn(scope_b, self.handler._auth_scopes)
        expired = _flow(TARGET, {**supplied, web_app._SCAN_SCOPE_HEADER: scope_a})
        self.handler.requestheaders(expired)
        self.assertEqual(expired.response.status_code, 403)

    def test_missing_scope_cannot_use_a_registered_credential(self):
        supplied = {"Authorization": "Bearer operator-fixture"}
        self.handler.register_auth_scope(TARGET, supplied)
        flow = _flow(TARGET, supplied)
        self.handler.requestheaders(flow)
        self.assertNotIn("authorization", flow.request.headers)

    def test_busy_legacy_scanner_does_not_reset_findings_or_start_another_browser(self):
        original = [{"type": "fixture", "value": SECRET}]
        self.handler.findings = original
        lock = web_app._legacy_scan_lock
        lock.acquire()
        try:
            with (
                mock.patch.object(web_app, "request_handler", self.handler),
                mock.patch.object(web_app, "async_playwright") as browser,
                mock.patch.object(web_app, "start_proxy_in_thread") as start_proxy,
                web_app.app.test_request_context("/scan", method="POST", json={
                    "url": TARGET, "scan_mode": "basic",
                }),
            ):
                response, status = asyncio.run(web_app.scan())
            self.assertEqual(status, 409)
            self.assertIn("already running", response.get_json()["error"])
            self.assertIs(self.handler.findings, original)
            self.assertEqual(self.handler._auth_scopes, {})
            self.assertTrue(lock.locked())
            browser.assert_not_called()
            start_proxy.assert_not_called()
        finally:
            lock.release()

    def test_invalid_url_error_does_not_reflect_supplied_port_text(self):
        with web_app.app.test_request_context("/scan", method="POST", json={
            "url": f"https://app.example.test:{SECRET}/", "scan_mode": "basic",
        }):
            response, status = asyncio.run(web_app.scan())
        self.assertEqual(status, 400)
        self.assertNotIn(SECRET, response.get_data(as_text=True))
        self.assertFalse(web_app._legacy_scan_lock.locked())

    def _browser(self):
        page = SimpleNamespace(
            goto=mock.AsyncMock(return_value=SimpleNamespace(status=200)),
            wait_for_load_state=mock.AsyncMock(),
            evaluate=mock.AsyncMock(),
            content=mock.AsyncMock(return_value="<script>fixture content</script>"),
        )
        context = SimpleNamespace(new_page=mock.AsyncMock(return_value=page), add_cookies=mock.AsyncMock())
        browser = SimpleNamespace(new_context=mock.AsyncMock(return_value=context), close=mock.AsyncMock())
        playwright = SimpleNamespace(chromium=SimpleNamespace(launch=mock.AsyncMock(return_value=browser)))
        manager = mock.MagicMock()
        manager.__aenter__ = mock.AsyncMock(return_value=playwright)
        manager.__aexit__ = mock.AsyncMock(return_value=False)
        return manager, playwright, browser

    def _scan(self, *, fail_context=False, padded_auth=False):
        manager, playwright, browser = self._browser()
        if fail_context:
            async def fail_with_headers(**options):
                raise RuntimeError(f"fixture context failed: {options['extra_http_headers']!r}; session=cookie-fixture")
            browser.new_context.side_effect = fail_with_headers
        raw_findings = [
            {"type": "api_key", "severity": "high", "value": SECRET, "source": "fixture.js",
             "context_lines": f"key={SECRET}; adjacent={NEIGHBOR}"},
            {"type": "api_key", "severity": "high", "value": NEIGHBOR, "source": "fixture.js"},
        ]
        attacks = {"status": "completed", "summary": {}, "subdomains": [{
            "host": "app.example.test", "url": TARGET, "summary": {},
            "findings": [{"type": "technology_fingerprint", "severity": "low", "value": SECRET,
                          "details": f"Returned data: {SECRET}"}],
        }]}
        queue = Queue()
        auth_config = {"mode": "both", "bearer_token": "operator-fixture",
                       "cookie": "session=cookie-fixture", "claimed_user_id": "user-fixture"}
        if padded_auth:
            auth_config["bearer_token"] = "  operator-fixture\t"
            auth_config["claimed_user_id"] = " user-fixture "
        with (
            mock.patch.object(web_app, "request_handler", self.handler),
            mock.patch.object(web_app, "mitm_running", True),
            mock.patch.object(web_app, "async_playwright", return_value=manager),
            mock.patch.object(web_app.asyncio, "sleep", new=mock.AsyncMock()),
            mock.patch.object(web_app, "analyze_content", side_effect=lambda *_args: copy.deepcopy(raw_findings)),
            mock.patch.object(web_app, "run_attack_vector_scan", return_value=attacks),
            mock.patch.dict(web_app._scan_queues, {"fixture-scan": queue}, clear=True),
            mock.patch.dict(web_app._scan_queue_created, {"fixture-scan": time.monotonic()}, clear=True),
            web_app.app.test_request_context("/scan", method="POST", json={
                "url": TARGET, "scan_mode": "extensive", "scan_id": "fixture-scan",
                "auth_config": auth_config,
            }),
        ):
            result = asyncio.run(web_app.scan())
            response, status = result if isinstance(result, tuple) else (result, 200)
            payload = response.get_json()
            events = ""
            if status == 200:
                events = web_app.scan_events("fixture-scan").get_data(as_text=True)
        return payload, status, events, playwright, browser

    def test_legacy_json_and_sse_export_only_redacted_findings(self):
        payload, status, events, playwright, browser = self._scan()
        self.assertEqual(status, 200)
        for output in (json.dumps(payload), events):
            self.assertNotIn(SECRET, output)
            self.assertNotIn(NEIGHBOR, output)
            self.assertIn("[redacted", output)
        self.assertEqual(payload["findings"], payload["report"]["findings"])
        for finding in payload["findings"] + payload["attack_vectors"]["subdomains"][0]["findings"]:
            self.assertNotIn("value", finding)
            self.assertNotIn("context_lines", finding)
        launch = playwright.chromium.launch.call_args.kwargs
        self.assertEqual(launch["proxy"]["bypass"], "<-loopback>")
        options = browser.new_context.call_args.kwargs
        self.assertIn(web_app._SCAN_SCOPE_HEADER, options["extra_http_headers"])
        self.assertEqual(options["service_workers"], "block")
        self.assertEqual(self.handler._auth_scopes, {})
        self.assertFalse(web_app._legacy_scan_lock.locked())

    def test_auth_scope_is_released_if_browser_initialization_fails(self):
        with self.assertLogs(web_app.logger, level="ERROR") as captured:
            payload, status, _events, _playwright, browser = self._scan(fail_context=True)
        self.assertEqual(status, 500)
        scope = browser.new_context.call_args.kwargs["extra_http_headers"][web_app._SCAN_SCOPE_HEADER]
        self.assertEqual(self.handler._auth_scopes, {})
        self.assertFalse(web_app._legacy_scan_lock.locked())
        for sensitive in ("operator-fixture", "cookie-fixture", "user-fixture", scope):
            self.assertNotIn(sensitive, json.dumps(payload))
            self.assertNotIn(sensitive, "\n".join(captured.output))

    def test_normalized_auth_values_are_redacted_from_errors(self):
        with self.assertLogs(web_app.logger, level="ERROR") as captured:
            payload, status, _events, _playwright, browser = self._scan(fail_context=True, padded_auth=True)
        self.assertEqual(status, 500)
        headers = browser.new_context.call_args.kwargs["extra_http_headers"]
        self.assertEqual(headers["Authorization"], "Bearer operator-fixture")
        self.assertEqual(headers["X-User-Id"], "user-fixture")
        for sensitive in ("operator-fixture", "user-fixture"):
            self.assertNotIn(sensitive, json.dumps(payload))
            self.assertNotIn(sensitive, "\n".join(captured.output))


if __name__ == "__main__":
    unittest.main()
