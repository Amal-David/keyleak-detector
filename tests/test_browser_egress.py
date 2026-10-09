"""Request-level browser egress guards."""

from __future__ import annotations

import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import threading
from unittest import mock

from keyleak.browser_scanner import (
    install_browser_egress_guards,
)
from keyleak.models import coverage_is_incomplete


class _Request:
    def __init__(self, url, method="GET", post_data_buffer=None, headers=None):
        self.url = url
        self.method = method
        self.post_data_buffer = post_data_buffer
        self.headers = headers or {}


class _Response:
    def __init__(self, status=200, headers=None):
        self.status = status
        self.headers = headers or {}


class _Route:
    def __init__(self, url, responses, **request_kwargs):
        self.request = _Request(url, **request_kwargs)
        self.responses = list(responses)
        self.fetches = []
        self.aborted = False
        self.fulfilled = None

    def fetch(self, **kwargs):
        self.fetches.append(kwargs)
        return self.responses.pop(0)

    def abort(self):
        self.aborted = True

    def fulfill(self, **kwargs):
        self.fulfilled = kwargs


class _Context:
    def route(self, pattern, handler):
        self.request_route = (pattern, handler)

    def route_web_socket(self, pattern, handler):
        self.websocket_route = (pattern, handler)


class _LocalEgressHandler(BaseHTTPRequestHandler):
    requests = []

    def do_GET(self):
        type(self).requests.append(self.path)
        if self.path == "/page":
            port = self.server.server_port
            body = (
                f'<img src="http://127.0.0.1:{port}/blocked-image">'
                f'<script>new WebSocket("ws://127.0.0.1:{port}/blocked-socket");'
                'fetch("/redirect").catch(() => {});</script>'
            ).encode()
            self.send_response(200)
            self.send_header("content-type", "text/html")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header(
                "location",
                f"http://127.0.0.1:{self.server.server_port}/blocked-redirect",
            )
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("content-length", "0")
        self.end_headers()

    def log_message(self, format, *args):
        return


class BrowserEgressTests(unittest.TestCase):
    def test_blocks_private_redirect_before_following_it(self):
        context = _Context()
        install_browser_egress_guards(context)
        route = _Route(
            "https://93.184.216.34/start",
            [_Response(302, {"location": "http://169.254.169.254/latest/meta-data/"})],
        )

        context.request_route[1](route)

        self.assertEqual(len(route.fetches), 1)
        self.assertTrue(route.aborted)
        self.assertIsNone(route.fulfilled)

    def test_allows_safe_cross_origin_subresource(self):
        context = _Context()
        install_browser_egress_guards(context)
        route = _Route("https://8.8.8.8/app.js", [_Response()])

        context.request_route[1](route)

        self.assertFalse(route.aborted)
        self.assertIsNotNone(route.fulfilled)

    def test_follows_safe_redirects_one_checked_hop_at_a_time(self):
        context = _Context()
        checked_hosts = []
        install_browser_egress_guards(
            context,
            target_guard=lambda host: checked_hosts.append(host) and None,
        )
        route = _Route(
            "https://93.184.216.34/start",
            [
                _Response(302, {"location": "https://8.8.8.8/final"}),
                _Response(200),
            ],
            headers={"authorization": "Bearer secret", "accept": "*/*"},
        )

        context.request_route[1](route)

        self.assertEqual(len(route.fetches), 2)
        self.assertEqual(route.fetches[0], {"max_redirects": 0})
        self.assertEqual(route.fetches[1]["url"], "https://8.8.8.8/final")
        self.assertNotIn("authorization", route.fetches[1]["headers"])
        self.assertIn("accept", route.fetches[1]["headers"])
        self.assertIsNotNone(route.fulfilled)
        self.assertEqual(checked_hosts, ["93.184.216.34", "8.8.8.8"])

    def test_blocks_unsafe_websocket_before_connecting(self):
        context = _Context()
        blocked_requests = []
        install_browser_egress_guards(context, blocked_requests=blocked_requests)
        socket = mock.Mock(url="ws://127.0.0.1:8080/socket")

        context.websocket_route[1](socket)

        socket.connect_to_server.assert_not_called()
        self.assertEqual(blocked_requests, ["ws://127.0.0.1:8080/socket"])

    def test_allows_safe_cross_origin_websocket(self):
        context = _Context()
        install_browser_egress_guards(context)
        socket = mock.Mock(url="wss://8.8.8.8/socket")

        context.websocket_route[1](socket)

        socket.connect_to_server.assert_called_once_with()

    @unittest.skipUnless(
        importlib.util.find_spec("playwright") is not None,
        "Playwright not installed",
    )
    def test_local_page_cannot_egress_to_blocked_subresources_or_redirects(self):
        from keyleak.browser_scanner import run_browser_scan

        _LocalEgressHandler.requests = []
        server = ThreadingHTTPServer(("127.0.0.1", 0), _LocalEgressHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f"http://localhost:{server.server_port}/page"
            report = run_browser_scan(
                url,
                scan_budget_seconds=5,
                target_guard=lambda host: None if host == "localhost" else "blocked test target",
            )
            clean_report = run_browser_scan(
                f"http://localhost:{server.server_port}/clean",
                scan_budget_seconds=5,
                target_guard=lambda host: None if host == "localhost" else "blocked test target",
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

        self.assertIn("/page", _LocalEgressHandler.requests)
        self.assertIn("/redirect", _LocalEgressHandler.requests)
        self.assertNotIn("/blocked-image", _LocalEgressHandler.requests)
        self.assertNotIn("/blocked-redirect", _LocalEgressHandler.requests)
        self.assertNotIn("/blocked-socket", _LocalEgressHandler.requests)
        self.assertIn("coverage", report.extra)
        self.assertTrue(coverage_is_incomplete(report.extra["coverage"]))
        self.assertFalse(coverage_is_incomplete(clean_report.extra["coverage"]))


if __name__ == "__main__":
    unittest.main()
