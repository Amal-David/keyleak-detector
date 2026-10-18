"""Synthetic, offline contract tests for the shared AI integration boundary."""

import asyncio
import contextlib
import io
import json
import os
from pathlib import Path
import socket
import tempfile
import threading
import unittest
from unittest.mock import patch

from keyleak.ai import KeyLeakTools, anthropic_tools, openai_tools
from keyleak.ai.adapters import execute_anthropic_call, execute_openai_call, parse_arguments
from keyleak.ai.schemas import tool_definitions
from keyleak.ai.service import MAX_INPUT_BYTES, _BoundedPattern
from keyleak.detectors import DETECTORS
from keyleak.local_scanner import scan_text


def synthetic_token():
    """Generate a detector-shaped fixture; never use a real provider credential."""
    return "sk-" + "A0b1C2d3E4f5G6h7I8j9K0l1M2n3O4p5Q6r7S8t9"


class ServiceTests(unittest.TestCase):
    """Exercise validation, data minimization, cancellation, and limits."""

    def setUp(self):
        """Create a text-only service for each independent case."""
        self.service = KeyLeakTools()
        self.addCleanup(self.service.close)

    def test_no_network_or_logs(self):
        """A successful detection neither connects nor writes private input."""
        secret = synthetic_token()
        out, err = io.StringIO(), io.StringIO()
        with patch.object(socket.socket, "connect", side_effect=AssertionError("network forbidden")), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            result = self.service.call("keyleak_scan_text", {"text": f"OPENAI_API_KEY={secret}\nprivate adjacent content"})
        self.assertTrue(result["ok"])
        self.assertGreater(result["finding_count"], 0)
        serialized = json.dumps(result)
        for value in (secret, secret[:12], "private adjacent content", "OPENAI_API_KEY"):
            self.assertNotIn(value, serialized)
        self.assertEqual((out.getvalue(), err.getvalue()), ("", ""))
        self.assertTrue(all(f["value"] == "[redacted]" for f in result["findings"]))

    def test_minimal_evidence_skips_fingerprints_and_context(self):
        """The AI path does not touch fingerprint keys or adjacent snippets."""
        with patch("keyleak.local_scanner.finding_fingerprint", side_effect=AssertionError), patch("keyleak.local_scanner._snippet_for", side_effect=AssertionError):
            result = self.service.call("keyleak_scan_text", {"text": synthetic_token()})
        self.assertTrue(result["ok"])
        self.assertGreater(result["finding_count"], 0)

    def test_empty_input_is_not_security_certification(self):
        """An empty clean scan has a limited static assessment."""
        result = self.service.call("keyleak_scan_text", {"text": ""})
        self.assertEqual(result["assessment"], "no_findings_detected")
        self.assertIn("not a security certification", result["notice"])

    def test_unknown_tools_cannot_access_live_scanners(self):
        """Network and credential-validation operations are absent and uncallable."""
        for name in ("scan_url", "validate_key", "audit", "keyleak_site_scan", None, []):
            with self.subTest(name=name):
                self.assertEqual(self.service.call(name, {})["error"]["code"], "unknown_tool")

    def test_closed_arguments(self):
        """Reject unknown options, omitted inputs, coercions, and wrong containers."""
        for args in ({}, {"text": 3}, {"text": None}, {"text": False}, {"text": "x", "url": "x"}, [], None, {"text": {}}):
            with self.subTest(args=args):
                self.assertEqual(self.service.call("keyleak_scan_text", args)["error"]["code"], "invalid_arguments")

    def test_utf8_size_and_nul_limits(self):
        """Limit encoded bytes, not just character counts, and reject binary text."""
        for text in ("x" * (MAX_INPUT_BYTES + 1), "🙂" * (MAX_INPUT_BYTES // 4 + 1)):
            self.assertEqual(self.service.call("keyleak_scan_text", {"text": text})["error"]["code"], "input_too_large")
        for text in ("a\0b", "\ud800"):
            self.assertEqual(self.service.call("keyleak_scan_text", {"text": text})["error"]["code"], "invalid_text")
        self.assertTrue(self.service.call("keyleak_scan_text", {"text": "x" * MAX_INPUT_BYTES})["ok"])

    def test_finding_limit_is_visible(self):
        """A truncated report never claims complete coverage."""
        # Isolate the finding cap from scheduler-dependent regex timing; the
        # actual deadline and catastrophic-pattern path have separate tests.
        with patch("keyleak.ai.service.REGEX_SECONDS", 1.0):
            result = self.service.call("keyleak_scan_text", {"text": "\n".join(synthetic_token() for _ in range(120))})
        self.assertEqual(result["finding_count"], 100)
        self.assertFalse(result["complete"])
        self.assertIn("finding_limit", result["incomplete_reasons"])

    def test_timeout_is_incomplete(self):
        """Timeouts are visible and never converted into a clean result."""
        with patch("keyleak.ai.service.scan_text", side_effect=TimeoutError):
            result = self.service.call("keyleak_scan_text", {"text": "synthetic"})
        self.assertFalse(result["complete"])
        self.assertEqual(result["assessment"], "incomplete")

    def test_regex_has_real_timeout(self):
        """The matcher caps pathological expression execution on local text."""
        import time
        pattern = _BoundedPattern("(a+)+$", threading.Event(), time.monotonic() + 1)
        with self.assertRaises(TimeoutError):
            list(pattern.finditer("a" * 50000 + "!"))

    def test_errors_do_not_reflect_exception(self):
        """Exceptions containing secret fixtures become static error messages."""
        with patch("keyleak.ai.service.scan_text", side_effect=RuntimeError(synthetic_token())):
            result = self.service.call("keyleak_scan_text", {"text": "x"})
        self.assertEqual(result["error"]["code"], "scan_failed")
        self.assertNotIn(synthetic_token(), json.dumps(result))

    def test_cancel_before_start(self):
        """Cancelled calls do not begin scanning."""
        cancel = threading.Event()
        cancel.set()
        with patch("keyleak.ai.service.scan_text") as scan:
            result = self.service.call("keyleak_scan_text", {"text": "x"}, cancel=cancel)
        scan.assert_not_called()
        self.assertEqual(result["error"]["code"], "cancelled")

    def test_busy_is_bounded(self):
        """A second call does not queue unlimited scanner work."""
        self.service._slot.acquire()
        try:
            self.assertEqual(self.service.call("keyleak_scan_text", {"text": "x"})["error"]["code"], "busy")
        finally:
            self.service._slot.release()

    def test_closed_service(self):
        """A closed service cannot read files or process more requests."""
        self.service.close()
        self.assertFalse(self.service.call("keyleak_capabilities", {})["ok"])

    def test_plain_static_scanner_parity(self):
        """Bounded matcher retains existing detector and false-positive behavior."""
        content = f"first\n{synthetic_token()}\n" + "sk-indigo-twilight-color-1"
        expected = scan_text(content, "test", [d for d in DETECTORS if d.pack == "leak"], run_salt=b"synthetic")
        actual = self.service.call("keyleak_scan_text", {"text": content})
        self.assertEqual([(f.detector_id, f.evidence.line) for f in expected], [(f["detector_id"], f["line"]) for f in actual["findings"]])

    def test_provider_adapters(self):
        """Both native adapters return redacted data and provider-specific errors."""
        arguments = {"text": synthetic_token()}
        oa = execute_openai_call(self.service, name="keyleak_scan_text", arguments=json.dumps(arguments), call_id="call_1")
        an = execute_anthropic_call(self.service, name="keyleak_scan_text", arguments=arguments, tool_use_id="tool_1")
        self.assertEqual(json.loads(oa["output"]), json.loads(an["content"]))
        self.assertNotIn(synthetic_token(), json.dumps([oa, an]))
        bad = execute_anthropic_call(self.service, name="keyleak_scan_text", arguments=[], tool_use_id="tool_1")
        self.assertTrue(bad["is_error"])
        bad = execute_openai_call(self.service, name="keyleak_scan_text", arguments='{"text":', call_id="call_1")
        self.assertFalse(json.loads(bad["output"])["ok"])

    def test_strict_json_parser(self):
        """Reject duplicate keys, non-finite values, deep input, and JSON scalars."""
        for value in ('{"text":"a","text":"b"}', '{"text":NaN}', 'null', '[]', '"x"', '[' * 2000, None, "\ud800"):
            with self.subTest(value=str(value)[:10]):
                self.assertIsNone(parse_arguments(value))

    def test_schemas_are_isolated_and_closed(self):
        """Mutating one returned definition cannot modify the service contract."""
        tools = tool_definitions()
        tools[0]["inputSchema"]["additionalProperties"] = True
        self.assertFalse(tool_definitions()[0]["inputSchema"]["additionalProperties"])
        for tool in openai_tools():
            self.assertTrue(tool["strict"])
            self.assertEqual(set(tool["parameters"]["properties"]), set(tool["parameters"]["required"]))
        self.assertEqual([t["name"] for t in anthropic_tools()], [t["name"] for t in openai_tools()])


class FileTests(unittest.TestCase):
    """Exercise explicit, descriptor-relative local file authorization."""

    def setUp(self):
        """Create only synthetic files under a private temporary directory."""
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "fixture.txt").write_text(synthetic_token(), encoding="utf-8")

    def service(self, files=("fixture.txt",)):
        """Register temporary grants and close them during test cleanup."""
        service = KeyLeakTools(root=self.root, files=files)
        self.addCleanup(service.close)
        return service

    def test_file_access_is_default_deny(self):
        """A text-only host cannot access even an otherwise readable file."""
        with KeyLeakTools() as service:
            self.assertEqual(service.call("keyleak_scan_file", {"file_id": "file_1"})["error"]["code"], "file_not_granted")

    def test_grant_and_opaque_metadata(self):
        """Only the host's opaque alias reaches output; no pathname or token does."""
        service = self.service()
        result = service.call("keyleak_scan_file", {"file_id": "file_1"})
        self.assertGreater(result["finding_count"], 0)
        self.assertEqual(service.capabilities()["file_ids"], ["file_1"])
        self.assertNotIn(str(self.root), json.dumps(result))
        self.assertNotIn("fixture.txt", json.dumps(result))
        self.assertNotIn(synthetic_token(), json.dumps(result))

    def test_model_cannot_select_paths(self):
        """URLs, absolute paths, and traversal cannot become filesystem reads."""
        service = self.service()
        with patch.object(service, "_read_file") as reader:
            for file_id in ("../fixture.txt", str(self.root / "fixture.txt"), "https://example.test", "file_2"):
                self.assertEqual(service.call("keyleak_scan_file", {"file_id": file_id})["error"]["code"], "file_not_granted")
            reader.assert_not_called()

    def test_host_grants_reject_traversal(self):
        """Host setup also refuses ambiguous, absolute, and traversing paths."""
        for name in ("../fixture.txt", "a/../fixture.txt", "/tmp/x", "./fixture.txt", "a//b", "a\\b", "a\0b"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                KeyLeakTools(root=self.root, files=(name,))

    def test_link_and_special_files_are_rejected(self):
        """Symlinks, hardlinks, directories, and FIFOs are never scanned."""
        (self.root / "link").symlink_to(self.root / "fixture.txt")
        (self.root / "folder").mkdir()
        os.mkfifo(self.root / "fifo")
        for name in ("link", "folder", "fifo"):
            with self.subTest(name=name):
                result = self.service((name,)).call("keyleak_scan_file", {"file_id": "file_1"})
                self.assertEqual(result["error"]["code"], "file_unavailable")
        os.link(self.root / "fixture.txt", self.root / "hardlink")
        self.assertEqual(self.service(("hardlink",)).call("keyleak_scan_file", {"file_id": "file_1"})["error"]["code"], "file_unavailable")

    def test_nested_directory_link_is_rejected(self):
        """A grant cannot cross a symlink in an intermediate component."""
        (self.root / "alias").symlink_to(self.root, target_is_directory=True)
        self.assertEqual(self.service(("alias/fixture.txt",)).call("keyleak_scan_file", {"file_id": "file_1"})["error"]["code"], "file_unavailable")

    def test_file_helper_is_cancelled_and_reaped(self):
        """Cancellation kills a pending snapshot without returning its data."""
        import subprocess
        from unittest.mock import Mock
        service = self.service()
        cancel = threading.Event()
        process = Mock()
        process.poll.side_effect = lambda: 0 if process.kill.called else None

        def communicate(*args, **kwargs):
            """Simulate a stalled read until its parent terminates the helper."""
            if process.kill.called:
                return (b"", b"")
            cancel.set()
            raise subprocess.TimeoutExpired("private-helper", kwargs["timeout"])

        process.communicate.side_effect = communicate
        with patch("keyleak.ai.service.subprocess.Popen", return_value=process) as launch:
            result = service.call("keyleak_scan_file", {"file_id": "file_1"}, cancel=cancel)
        self.assertEqual(result["error"]["code"], "cancelled")
        process.kill.assert_called_once()
        self.assertEqual(launch.call_args.kwargs["env"], {})
        self.assertNotIn("fixture.txt", " ".join(launch.call_args.args[0]))
        self.assertIsNone(service._reader_process)

    def test_uninterruptible_helper_blocks_new_readers(self):
        """A kernel-stuck helper is retained without an unbounded cleanup wait."""
        import subprocess
        from unittest.mock import Mock
        service = self.service()
        process = Mock()
        process.poll.return_value = None
        process.communicate.side_effect = subprocess.TimeoutExpired("private-helper", 0.01)
        with patch("keyleak.ai.service.subprocess.Popen", return_value=process) as launch, patch("keyleak.ai.service.FILE_READ_SECONDS", 0.01):
            self.assertFalse(service.call("keyleak_scan_file", {"file_id": "file_1"})["ok"])
            self.assertEqual(service.call("keyleak_scan_file", {"file_id": "file_1"})["error"]["code"], "busy")
            launch.assert_called_once()
        self.assertIs(service._reader_process, process)
        process.poll.return_value = 0
        process.communicate.side_effect = None
        process.communicate.return_value = (b"", b"")

    def test_file_helper_timeout_is_static(self):
        """A read deadline fails closed and never reports a clean scan."""
        import subprocess
        from unittest.mock import Mock
        service = self.service()
        process = Mock()
        process.poll.side_effect = lambda: 0 if process.kill.called else None
        process.communicate.side_effect = lambda *a, **kw: (b"", b"") if process.kill.called else (_ for _ in ()).throw(subprocess.TimeoutExpired("private-helper", 0.01))
        with patch("keyleak.ai.service.subprocess.Popen", return_value=process), patch("keyleak.ai.service.FILE_READ_SECONDS", 0.01):
            result = service.call("keyleak_scan_file", {"file_id": "file_1"})
        self.assertEqual(result["error"]["code"], "file_unavailable")
        process.kill.assert_called_once()

    def test_deleted_and_changed_to_link(self):
        """Grants are checked at read time, not just setup time."""
        service = self.service()
        (self.root / "fixture.txt").unlink()
        result = service.call("keyleak_scan_file", {"file_id": "file_1"})
        self.assertEqual(result["error"]["code"], "file_unavailable")
        (self.root / "fixture.txt").symlink_to("/etc/passwd")
        self.assertEqual(service.call("keyleak_scan_file", {"file_id": "file_1"})["error"]["code"], "file_unavailable")

    def test_binary_and_oversized_files(self):
        """Reject invalid UTF-8, NUL payloads, and oversized local inputs."""
        for data, code in ((b"\xff", "invalid_text"), (b"a\0b", "invalid_text"), (b"x" * (MAX_INPUT_BYTES + 1), "input_too_large")):
            (self.root / "fixture.txt").write_bytes(data)
            result = self.service().call("keyleak_scan_file", {"file_id": "file_1"})
            self.assertEqual(result["error"]["code"], code)


class AsyncTests(unittest.IsolatedAsyncioTestCase):
    """Verify cancellation reaches worker threads and releases concurrency slots."""

    async def test_async_cancel_stops_worker(self):
        """Transport cancellation signals the running detector loop promptly."""
        started = threading.Event()
        stopped = threading.Event()
        service = KeyLeakTools()
        original = service._scan

        def scan(content, source, size, cancel):
            """Wait cooperatively as a synthetic long-running scanner."""
            started.set()
            cancel.wait(2)
            stopped.set()
            return original(content, source, size, cancel)

        with patch.object(service, "_scan", side_effect=scan):
            task = asyncio.create_task(service.call_async("keyleak_scan_text", {"text": "x"}))
            await asyncio.to_thread(started.wait, 1)
            second = await service.call_async("keyleak_scan_text", {"text": "second"})
            self.assertEqual(second["error"]["code"], "busy")
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            self.assertTrue(await asyncio.to_thread(stopped.wait, 1))
        service.close()
