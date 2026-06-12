"""CDP network capture tests for browser-scan."""

from __future__ import annotations

import base64
import json
import unittest

from keyleak.browser_scanner import (
    CDP_MAX_BODY_BYTES,
    _CdpNetworkCapture,
    _decode_cdp_body,
    _is_text_mime,
)


SECRET = "sk-proj-ABCDEF1234567890SECRETVALUE0987654321"


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
                "url": "https://app.example.test/api/config",
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
        self.assertEqual(finding.evidence.request_url, "https://app.example.test/api/config")
        self.assertEqual(finding.evidence.response_status, 200)
        self.assertTrue(finding.source.startswith("CDP Response Body:"))

    def test_request_body_and_console_output_are_scanned(self):
        cdp = FakeCdpSession()
        capture = _CdpNetworkCapture(cdp, "https://app.example.test/", b"1" * 32)
        capture.start()
        cdp.emit("Network.requestWillBeSent", {
            "requestId": "2",
            "request": {
                "url": "https://app.example.test/api/infer",
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


if __name__ == "__main__":
    unittest.main()
