"""Browser egress tests use mocked HTTP and an owned loopback deny proxy."""

import socket
from types import SimpleNamespace
import unittest
from unittest.mock import Mock
from unittest.mock import patch
from urllib.parse import urlsplit

from keyleak.browser_transport import denied_browser_proxy, install_guarded_routes


def _route(url, method="GET", headers=None, body=None):
    return Mock(request=SimpleNamespace(url=url, method=method, post_data_buffer=body,
                                        all_headers=lambda: dict(headers or {})))


def _response(status=200, headers=None):
    response = Mock(status_code=status, headers=dict(headers or {}))
    response.iter_content.return_value = [b"fixture"]
    return response


class BrowserTransportTests(unittest.TestCase):
    def setUp(self):
        self.context, self.fetch = Mock(), Mock()
        self.state = install_guarded_routes(
            self.context, "https://owned.example.test/",
            lambda url: "private" if urlsplit(url).hostname == "127.0.0.1" else None,
            self.fetch,
        )
        self.intercept = self.context.route.call_args.args[1]

    def test_credentials_are_limited_to_the_exact_target_origin(self):
        sensitive = {"Authorization": "synthetic", "Cookie": "session=fixture", "X-API-Key": "fixture"}
        for url, expected in (("https://owned.example.test/api", sensitive),
                              ("https://other.example.test/api", {}),
                              ("http://owned.example.test/api", {}),
                              ("https://owned.example.test:8443/api", {})):
            with self.subTest(url=url):
                response = _response()
                self.fetch.return_value = response
                route = _route(url, headers={**sensitive, "Accept": "*/*"})
                self.intercept(route)
                self.assertEqual(self.fetch.call_args.kwargs["headers"], {**expected, "Accept": "*/*"})
                route.fulfill.assert_called_once()
                response.close.assert_called_once()
        self.assertEqual(self.state["blocked"], 0)

    def test_redirects_strip_credentials_irreversibly_and_convert_post_to_get(self):
        responses = [_response(302, {"location": "https://other.example.test/next"}),
                     _response(302, {"location": "https://owned.example.test/final"}), _response()]
        self.fetch.side_effect = responses
        route = _route("https://owned.example.test/start", "POST",
                       {"Authorization": "synthetic", "Content-Type": "application/json"}, b"{}")
        self.intercept(route)
        calls = self.fetch.call_args_list
        self.assertEqual(calls[0].args[0], "POST")
        for call in calls[1:]:
            self.assertEqual(call.args[0], "GET")
            self.assertIsNone(call.kwargs["data"])
            self.assertEqual(call.kwargs["headers"], {})
        for response in responses:
            response.close.assert_called_once()
        route.fulfill.assert_called_once()

    def test_private_redirect_and_native_websocket_cannot_bypass_http_checks(self):
        self.fetch.return_value = _response(302, {"location": "http://127.0.0.1/private"})
        route = _route("https://owned.example.test/start")
        self.intercept(route)
        self.fetch.assert_called_once()
        route.abort.assert_called_once()
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

    def test_oversized_responses_are_closed_and_reported_as_blocked(self):
        response = _response()
        response.iter_content.return_value = [b"12345678", b"9"]
        self.fetch.return_value = response
        route = _route("https://owned.example.test/oversized")
        with patch("keyleak.browser_transport.MAX_RESPONSE_BYTES", 8):
            self.intercept(route)
        self.assertTrue(self.fetch.call_args.kwargs["stream"])
        response.close.assert_called_once()
        route.fulfill.assert_not_called()
        route.abort.assert_called_once()
        self.assertEqual(self.state["blocked"], 1)


if __name__ == "__main__":
    unittest.main()
