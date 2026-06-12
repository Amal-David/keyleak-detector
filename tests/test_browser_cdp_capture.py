"""CDP network capture tests for browser-scan."""

from __future__ import annotations

import base64
import importlib.util
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from keyleak.browser_scanner import (
    CDP_MAX_BODY_BYTES,
    _CdpNetworkCapture,
    _decode_cdp_body,
    _is_text_mime,
)
from keyleak.redaction import stable_id


def _fake_openai_key(*chunks):
    return "".join(("sk", "-proj-", *chunks))


SECRET = _fake_openai_key("ABCDEF123456", "7890SECRET", "VALUE0987654321")
FETCH_ONLY_SECRET = _fake_openai_key("XT9mQ2vL7pR4", "sN8wY3cH6zD1", "aF5uG0kJbE9tM2qV7")
HAS_PLAYWRIGHT = importlib.util.find_spec("playwright") is not None


class FakeCdpSession:
    def __init__(self, bodies=None):
        self.handlers = {}
        self.sent = []
        self.bodies = bodies or {}
        self.detached = False

    def send(self, method, params=None):
        self.sent.append((method, params or {}))
        if method == "Network.getResponseBody":
            return self.bodies.get((params or {}).get("requestId"), {"body": "", "base64Encoded": False})
        return {}

    def on(self, event_name, handler):
        self.handlers[event_name] = handler

    def emit(self, event_name, params):
        self.handlers[event_name](params)

    def detach(self):
        self.detached = True


class CdpBodyDecodingTests(unittest.TestCase):
    def test_base64_body_decodes_as_text(self):
        encoded = base64.b64encode(b'{"token":"value"}').decode("ascii")
        self.assertEqual(_decode_cdp_body({"body": encoded, "base64Encoded": True}), '{"token":"value"}')

    def test_oversized_body_is_skipped(self):
        body = "x" * (CDP_MAX_BODY_BYTES + 1)
        self.assertEqual(_decode_cdp_body({"body": body, "base64Encoded": False}), "")

    def test_text_mime_accepts_json_and_javascript(self):
        self.assertTrue(_is_text_mime("application/json"))
        self.assertTrue(_is_text_mime("", {"content-type": "application/javascript"}))
        self.assertFalse(_is_text_mime("image/png"))


class CdpNetworkCaptureTests(unittest.TestCase):
    def test_response_body_findings_are_redacted_and_keep_request_metadata(self):
        cdp = FakeCdpSession(bodies={
            "1": {"body": json.dumps({"api_key": SECRET}), "base64Encoded": False},
        })
        capture = _CdpNetworkCapture(cdp, "https://app.example.test/", b"0" * 32)
        capture.start()
        cdp.emit("Network.responseReceived", {
            "requestId": "1",
            "response": {
                "url": f"https://app.example.test/api/config?token={SECRET}#fragment",
                "status": 200,
                "mimeType": "application/json",
                "headers": {"content-type": "application/json"},
            },
        })
        cdp.emit("Network.loadingFinished", {"requestId": "1"})

        self.assertTrue(any(f.detector_id == "leak.openai_api_key" for f in capture.findings))
        payload = json.dumps([finding.to_dict() for finding in capture.findings])
        self.assertNotIn(SECRET, payload)
        finding = next(f for f in capture.findings if f.detector_id == "leak.openai_api_key")
        self.assertTrue(finding.evidence.request_url.startswith("https://app.example.test/api/config?token="))
        self.assertNotIn(SECRET, finding.evidence.request_url)
        self.assertEqual(finding.evidence.response_status, 200)
        self.assertTrue(finding.source.startswith("CDP Response Body:"))
        self.assertNotIn(SECRET, finding.source)
        self.assertEqual(
            finding.id,
            stable_id(
                finding.type,
                finding.detector_id,
                finding.source,
                finding.evidence.redacted_value,
                finding.evidence.line,
                finding.evidence.request_url,
            ),
        )
        self.assertNotIn("1", capture.requests)

    def test_request_body_and_console_output_are_scanned(self):
        cdp = FakeCdpSession()
        capture = _CdpNetworkCapture(cdp, "https://app.example.test/", b"1" * 32)
        capture.start()
        cdp.emit("Network.requestWillBeSent", {
            "requestId": "2",
            "request": {
                "url": f"https://app.example.test/api/infer?token={SECRET}#fragment",
                "method": "POST",
                "headers": {"content-type": "application/json"},
                "postData": json.dumps({"token": SECRET}),
            },
        })
        cdp.emit("Runtime.consoleAPICalled", {
            "type": "log",
            "args": [{"value": SECRET}],
        })

        sources = [finding.source for finding in capture.findings]
        self.assertTrue(any(source.startswith("CDP Request Body:") for source in sources))
        self.assertTrue(any(source == "CDP Console log" for source in sources))
        payload = json.dumps([finding.to_dict() for finding in capture.findings])
        self.assertNotIn(SECRET, payload)

    def test_websocket_frames_are_scanned(self):
        cdp = FakeCdpSession()
        capture = _CdpNetworkCapture(cdp, "https://app.example.test/", b"3" * 32)
        capture.start()
        cdp.emit("Network.webSocketCreated", {
            "requestId": "ws-1",
            "url": f"wss://app.example.test/socket?token={SECRET}#fragment",
        })
        cdp.emit("Network.webSocketFrameReceived", {
            "requestId": "ws-1",
            "response": {"opcode": 1, "payloadData": json.dumps({"token": SECRET})},
        })

        finding = next(f for f in capture.findings if f.detector_id == "leak.openai_api_key")
        self.assertTrue(finding.source.startswith("CDP WebSocket Frame:"))
        self.assertNotIn(SECRET, json.dumps([finding.to_dict() for finding in capture.findings]))
        cdp.emit("Network.webSocketClosed", {"requestId": "ws-1"})
        self.assertNotIn("ws-1", capture.requests)

    def test_log_entries_are_scanned(self):
        cdp = FakeCdpSession()
        capture = _CdpNetworkCapture(cdp, "https://app.example.test/", b"4" * 32)
        capture.start()
        cdp.emit("Log.entryAdded", {
            "entry": {
                "level": "warning",
                "url": f"https://app.example.test/log?token={SECRET}#fragment",
                "text": SECRET,
            },
        })

        sources = [finding.source for finding in capture.findings]
        self.assertIn("CDP Log warning", sources)
        self.assertNotIn(SECRET, json.dumps([finding.to_dict() for finding in capture.findings]))

    def test_unavailable_response_body_does_not_fail_capture(self):
        class FailingBodySession(FakeCdpSession):
            def send(self, method, params=None):
                if method == "Network.getResponseBody":
                    raise RuntimeError("body evicted")
                return super().send(method, params)

        cdp = FailingBodySession()
        capture = _CdpNetworkCapture(cdp, "https://app.example.test/", b"2" * 32)
        capture.start()
        cdp.emit("Network.responseReceived", {
            "requestId": "3",
            "response": {
                "url": "https://app.example.test/api/config",
                "status": 200,
                "mimeType": "application/json",
                "headers": {"content-type": "application/json"},
            },
        })
        cdp.emit("Network.loadingFinished", {"requestId": "3"})
        self.assertEqual(capture.findings, [])
        self.assertNotIn("3", capture.requests)

    def test_failed_http_request_is_forgotten(self):
        cdp = FakeCdpSession()
        capture = _CdpNetworkCapture(cdp, "https://app.example.test/", b"5" * 32)
        capture.start()
        cdp.emit("Network.requestWillBeSent", {
            "requestId": "failed-1",
            "request": {"url": "https://app.example.test/missing", "method": "GET"},
        })
        self.assertIn("failed-1", capture.requests)
        cdp.emit("Network.loadingFailed", {"requestId": "failed-1"})
        self.assertNotIn("failed-1", capture.requests)


class _CdpFixtureHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/config":
            body = json.dumps({"api_key": FETCH_ONLY_SECRET}).encode("utf-8")
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        body = b"""
<!doctype html>
<html>
<body>
  <script>
    fetch('/config').then(function (response) {
      return response.json();
    }).then(function () {
      document.body.dataset.loaded = 'true';
    });
  </script>
</body>
</html>
"""
        self.send_response(200)
        self.send_header("content-type", "text/html")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        return


@unittest.skipUnless(HAS_PLAYWRIGHT, "Playwright not installed; live CDP integration skipped.")
class BrowserCdpIntegrationTests(unittest.TestCase):
    def test_browser_scan_captures_fetch_response_body_via_cdp(self):
        from keyleak.browser_scanner import run_browser_scan

        server = ThreadingHTTPServer(("127.0.0.1", 0), _CdpFixtureHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f"http://127.0.0.1:{server.server_port}/"
            try:
                report = run_browser_scan(url, scan_budget_seconds=5)
            except Exception as exc:
                message = str(exc)
                if "playwright install" in message or "Executable doesn't exist" in message:
                    self.skipTest(f"Playwright Chromium is not installed: {message}")
                raise
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

        matching = [
            finding for finding in report.findings
            if finding.detector_id == "leak.openai_api_key"
            and finding.source.startswith("CDP Response Body:")
        ]
        self.assertTrue(matching, "expected CDP response body to surface the fetch-only key")
        payload = json.dumps(report.to_dict())
        self.assertNotIn(FETCH_ONLY_SECRET, payload)


if __name__ == "__main__":
    unittest.main()
