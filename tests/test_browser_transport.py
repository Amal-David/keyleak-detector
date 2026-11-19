"""Browser egress tests use mocked HTTP and an owned loopback deny proxy."""

import socket
import base64
import gzip
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
import time
import unittest
from unittest.mock import Mock
from unittest.mock import patch
from urllib.parse import urlsplit

from urllib3._collections import HTTPHeaderDict

from keyleak.net_guard import SSRFBlocked
from keyleak.browser_transport import denied_browser_proxy, install_guarded_routes


def _paused(url, method="GET", headers=None, body=None, *, request_id="request", previous=None):
    event = {"requestId": request_id, "request": {"url": url, "method": method, "headers": dict(headers or {})}}
    if body is not None:
        event["request"]["postDataEntries"] = [{"bytes": base64.b64encode(body).decode("ascii")}]
    if previous is not None:
        event["redirectedRequestId"] = previous
    return event


def _response(status=200, headers=None):
    response = Mock(status_code=status, headers=dict(headers or {}))
    response.raw = Mock(headers=HTTPHeaderDict(headers or {}))
    response.iter_content.return_value = [b"fixture"]
    return response


class BrowserTransportTests(unittest.TestCase):
    def setUp(self):
        self.context, self.fetch = Mock(), Mock()
        self.session = self.context.new_cdp_session.return_value
        self.state = install_guarded_routes(
            Mock(context=self.context), "https://owned.example.test/",
            lambda url: "private" if urlsplit(url).hostname == "127.0.0.1" else None,
            self.fetch,
        )
        self.intercept = self.session.on.call_args.args[1]
        self.session.send.reset_mock()

    def test_credentials_are_limited_to_the_exact_target_origin(self):
        sensitive = {"Authorization": "synthetic", "Cookie": "session=fixture", "X-API-Key": "fixture"}
        for url, expected in (("https://owned.example.test/api", sensitive),
                              ("https://other.example.test/api", {}),
                              ("http://owned.example.test/api", {}),
                              ("https://owned.example.test:8443/api", {})):
            with self.subTest(url=url):
                response = _response()
                self.fetch.return_value = response
                event = _paused(url, headers={**sensitive, "Accept": "*/*", "Host": "owned.example.test",
                                            "accept-encoding": "gzip, deflate, br, zstd"})
                self.intercept(event)
                self.assertEqual(self.fetch.call_args.kwargs["headers"],
                                 {**expected, "Accept": "*/*", "Accept-Encoding": "gzip, deflate"})
                self.assertEqual(self.session.send.call_args.args[0], "Fetch.fulfillRequest")
                response.close.assert_called_once()
        self.assertEqual(self.state["blocked"], 0)

    def test_each_redirect_is_fulfilled_separately_and_credentials_stay_stripped(self):
        responses = [_response(302, {"location": "https://other.example.test/next"}),
                     _response(302, {"location": "https://owned.example.test/final"}), _response()]
        self.fetch.side_effect = responses
        self.intercept(_paused("https://owned.example.test/start", "POST",
                               {"Authorization": "synthetic", "Content-Type": "application/json"}, b"{}",
                               request_id="start"))
        self.assertEqual(self.fetch.call_count, 1)
        self.assertEqual(self.session.send.call_args.args[1]["responseCode"], 302)
        for url, request_id, previous in (("https://other.example.test/next", "next", "start"),
                                           ("https://owned.example.test/final", "final", "next")):
            self.intercept(_paused(url, headers={"Authorization": "synthetic", "Cookie": "session=fixture"},
                                   request_id=request_id, previous=previous))
        calls = self.fetch.call_args_list
        self.assertEqual(calls[0].args[0], "POST")
        for call in calls[1:]:
            self.assertEqual(call.args[0], "GET")
            self.assertIsNone(call.kwargs["data"])
            self.assertEqual(call.kwargs["headers"], {"Accept-Encoding": "gzip, deflate"})
        for response in responses:
            response.close.assert_called_once()
        self.assertEqual(self.session.send.call_count, 3)

    def test_private_redirect_and_native_websocket_cannot_bypass_http_checks(self):
        self.fetch.return_value = _response(302, {"location": "http://127.0.0.1/private"})
        self.intercept(_paused("https://owned.example.test/start", request_id="start"))
        self.intercept(_paused("http://127.0.0.1/private", previous="start"))
        self.fetch.assert_called_once()
        self.assertEqual(self.session.send.call_args.args[0], "Fetch.failRequest")
        socket_route = Mock()
        self.context.route_web_socket.call_args.args[1](socket_route)
        socket_route.close.assert_not_called()
        socket_route.connect_to_server.assert_not_called()
        self.assertEqual(self.state["blocked"], 2)

    def test_native_proxy_never_forwards_a_tunnel(self):
        with denied_browser_proxy() as proxy:
            endpoint = urlsplit(proxy["server"])
            with socket.create_connection((endpoint.hostname, endpoint.port), timeout=2) as connection:
                try:
                    connection.sendall(b"CONNECT unowned.invalid:443 HTTP/1.1\r\n\r\n")
                    self.assertEqual(connection.recv(128), b"")
                except ConnectionResetError:
                    pass

    def test_oversized_responses_are_closed_and_reported_as_failed(self):
        response = _response()
        response.iter_content.return_value = [b"12345678", b"9"]
        self.fetch.return_value = response
        with patch("keyleak.browser_transport.MAX_RESPONSE_BYTES", 8):
            self.intercept(_paused("https://owned.example.test/oversized"))
        self.assertTrue(self.fetch.call_args.kwargs["stream"])
        response.close.assert_called_once()
        self.assertEqual(self.session.send.call_args.args[0], "Fetch.failRequest")
        self.assertEqual(self.state["blocked"], 0)
        self.assertEqual(self.state["failed"], 1)

    def test_fetch_failures_are_distinct_from_unsafe_egress_without_logging_secrets(self):
        for error, blocked, failed in ((TimeoutError("private-token"), 0, 1),
                                       (SSRFBlocked("private address"), 1, 0)):
            with self.subTest(error=type(error).__name__):
                self.state.update(blocked=0, failed=0)
                self.fetch.side_effect = error
                with patch("keyleak.browser_transport._LOG.debug") as log:
                    self.intercept(_paused("https://owned.example.test/start"))
                self.assertNotIn("private-token", str(log.call_args_list))
                self.assertEqual(self.state, {"blocked": blocked, "failed": failed})
                self.assertEqual(self.session.send.call_args.args[0], "Fetch.failRequest")

    def test_closed_request_abort_does_not_raise_or_log_sensitive_diagnostics(self):
        self.fetch.side_effect = TimeoutError("private-token")
        self.session.send.side_effect = RuntimeError("private-route-token")
        with patch("keyleak.browser_transport._LOG.debug") as log:
            self.intercept(_paused("https://owned.example.test/start"))
        self.assertEqual(self.state, {"blocked": 0, "failed": 1})
        self.assertEqual(log.call_count, 2)
        self.assertNotIn("private-token", str(log.call_args_list))
        self.assertNotIn("private-route-token", str(log.call_args_list))

    def test_total_deadline_stops_streaming_and_is_shared_across_redirects(self):
        response = _response()
        self.fetch.return_value = response
        with patch("keyleak.browser_transport.time.monotonic", side_effect=[0, 0, 0, 0, 31]):
            self.intercept(_paused("https://owned.example.test/slow"))
        response.close.assert_called_once()
        self.assertEqual(self.session.send.call_args.args[0], "Fetch.failRequest")
        self.state.update(blocked=0, failed=0)
        self.fetch.return_value = _response(302, {"location": "/next"})
        with patch("keyleak.browser_transport.time.monotonic", return_value=0):
            self.intercept(_paused("https://owned.example.test/start", request_id="start"))
        self.fetch.reset_mock()
        with patch("keyleak.browser_transport.time.monotonic", return_value=31):
            self.intercept(_paused("https://owned.example.test/next", previous="start"))
        self.fetch.assert_not_called()
        self.assertEqual(self.state, {"blocked": 0, "failed": 1})

    def test_redirect_and_final_cookies_are_stored_separately_and_scoped(self):
        redirect = _response(302, {"location": "/final"})
        redirect.raw.headers.add("Set-Cookie", "session=fixture; Path=/; Secure; HttpOnly; SameSite=Strict")
        redirect.raw.headers.add("Set-Cookie", "foreign=ignored; Domain=other.example.test")
        final = _response(headers={"Set-Cookie": "combined-cookie-must-not-be-forwarded"})
        final.raw.headers = HTTPHeaderDict()
        final.raw.headers.add("Set-Cookie", "access=fixture; Path=/api; Secure")
        final.raw.headers.add("Set-Cookie", "refresh=fixture; Expires=Wed, 09 Jun 2038 10:18:14 GMT; Path=/; Secure")
        self.fetch.side_effect = [redirect, final]
        self.intercept(_paused("https://owned.example.test/start", request_id="start"))
        self.intercept(_paused("https://owned.example.test/final", headers={"Cookie": "session=fixture"}, previous="start"))
        self.assertEqual(self.fetch.call_args.kwargs["headers"]["Cookie"], "session=fixture")
        cookies = [call.args[0][0] for call in self.context.add_cookies.call_args_list]
        self.assertEqual([cookie["name"] for cookie in cookies], ["session", "access", "refresh"])
        self.assertTrue(cookies[0]["httpOnly"])
        self.assertEqual(cookies[0]["sameSite"], "Strict")
        self.assertEqual(cookies[1]["path"], "/api")
        self.assertGreater(cookies[2]["expires"], 2_000_000_000)
        self.assertFalse(any(header["name"].lower() == "set-cookie"
                             for header in self.session.send.call_args.args[1]["responseHeaders"]))

    def test_real_browser_retains_redirect_and_multiple_cookies_and_decodes_gzip(self):
        import requests
        from playwright.sync_api import Error, sync_playwright
        from keyleak.net_guard import guarded_request

        received = []
        posted = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                posted.append((self.path, self.rfile.read(int(self.headers.get("Content-Length", 0)))))
                if self.path in {"/post302", "/post307"}:
                    self.send_response(302 if self.path == "/post302" else 307)
                    self.send_header("Location", "/post-final")
                else:
                    self.send_response(200)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def do_GET(self):
                received.append((self.path, {key.lower(): value for key, value in self.headers.items()}))
                if self.path == "/slow":
                    self.send_response(200)
                    self.send_header("Content-Length", "1000")
                    self.end_headers()
                    for _ in range(1000):
                        try:
                            self.wfile.write(b"x")
                            self.wfile.flush()
                        except OSError:
                            return
                        time.sleep(0.02)
                    return
                if self.path in {"/start", "/leave"}:
                    self.send_response(302)
                    self.send_header("Location", "/nested/final" if self.path == "/start"
                                     else f"http://127.0.0.1:{self.server.server_port}/foreign")
                    if self.path == "/start":
                        self.send_header("Set-Cookie", "session=redirect; Path=/; HttpOnly")
                    self.end_headers()
                    return
                self.send_response(200)
                body = gzip.compress(b'<html><body>decoded fixture<script>window.storageRead = localStorage.getItem("target-only");</script><img src="relative.png"></body></html>')
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Encoding", "gzip")
                self.send_header("Content-Length", str(len(body)))
                if self.path == "/nested/final":
                    self.send_header("Set-Cookie", "access=fixture; Path=/api; HttpOnly")
                    self.send_header("Set-Cookie", "refresh=fixture; Expires=Wed, 09 Jun 2038 10:18:14 GMT; Path=/")
                    self.send_header("Set-Cookie", "stale=deleted; Max-Age=0; Path=/")
                    self.send_header("Set-Cookie", "foreign=ignored; Domain=example.test; Path=/")
                if self.path == "/foreign":
                    self.send_header("Set-Cookie", "untrusted=ignored; Path=/")
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            target = f"http://localhost:{server.server_port}"
            with denied_browser_proxy() as proxy, sync_playwright() as playwright:
                browser = playwright.chromium.launch(proxy=proxy)
                try:
                    context = browser.new_context(service_workers="block")
                    context.add_cookies([{"name": "stale", "value": "fixture", "url": target}])

                    def fetch(method, url, **kwargs):
                        with requests.Session() as session:
                            session.trust_env = False
                            return guarded_request(method, url, allow_private=True, follow_redirects=False,
                                                   session=session, **kwargs)

                    page = context.new_page()
                    state = install_guarded_routes(
                        page, target,
                        lambda url: None if urlsplit(url).hostname in {"localhost", "127.0.0.1"}
                        and urlsplit(url).port == server.server_port else "outside owned test server",
                        fetch,
                    )
                    page.goto(target + "/start")
                    self.assertEqual(page.url, target + "/nested/final")
                    self.assertEqual(page.evaluate("window.origin"), target)
                    self.assertIn("decoded fixture", page.content())
                    cookies = {cookie["name"]: cookie for cookie in context.cookies()}
                    self.assertEqual(set(cookies), {"session", "access", "refresh"})
                    self.assertTrue(cookies["access"]["httpOnly"])
                    self.assertEqual(cookies["access"]["path"], "/api")
                    page.goto(target + "/api/check")
                    page.evaluate("fetch('/omit', {credentials: 'omit'}).then(r => r.text())")
                    for path in ("/post302", "/post307"):
                        page.evaluate("path => fetch(path, {method: 'POST', body: new Uint8Array([0, 255])}).then(r => r.text())", path)
                    page.evaluate('localStorage.setItem("target-only", "fixture")')
                    page.goto(target + "/leave")
                    foreign = f"http://127.0.0.1:{server.server_port}"
                    self.assertEqual(page.url, foreign + "/foreign")
                    self.assertEqual(page.evaluate("window.origin"), foreign)
                    self.assertIsNone(page.evaluate("window.storageRead"))
                    self.assertNotIn("untrusted", {cookie["name"] for cookie in context.cookies()})
                    self.assertEqual(state, {"blocked": 0, "failed": 0})
                    limited_context = browser.new_context(service_workers="block")
                    limited_page = limited_context.new_page()
                    limited_state = install_guarded_routes(
                        limited_page, target,
                        lambda url: None if urlsplit(url).hostname == "localhost"
                        and urlsplit(url).port == server.server_port else "outside owned test server",
                        fetch, request_timeout=0.15,
                    )
                    started = time.monotonic()
                    with self.assertRaises(Error):
                        limited_page.goto(target + "/slow", timeout=5000)
                    self.assertLess(time.monotonic() - started, 2)
                    self.assertEqual(limited_state, {"blocked": 0, "failed": 1})
                finally:
                    browser.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
        by_path = dict(received)
        self.assertIn("/nested/relative.png", by_path)
        self.assertIn("session=redirect", by_path["/nested/final"].get("cookie", ""))
        self.assertNotIn("access=fixture", by_path["/nested/final"].get("cookie", ""))
        self.assertIn("access=fixture", by_path["/api/check"].get("cookie", ""))
        self.assertNotIn("cookie", by_path["/foreign"])
        self.assertNotIn("cookie", by_path["/omit"])
        self.assertEqual(by_path["/foreign"]["host"], f"127.0.0.1:{server.server_port}")
        self.assertEqual(by_path["/nested/final"]["accept-encoding"], "gzip, deflate")
        self.assertIn("/post-final", by_path)
        self.assertEqual(posted, [("/post302", b"\x00\xff"), ("/post307", b"\x00\xff"), ("/post-final", b"\x00\xff")])


if __name__ == "__main__":
    unittest.main()
