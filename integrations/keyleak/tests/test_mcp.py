"""Optional MCP interoperability checks; synthetic local inputs only."""

import asyncio
import json
from pathlib import Path
import subprocess
import sys
import unittest

from jsonschema import Draft202012Validator
from mcp import Client
from mcp.client.stdio import StdioServerParameters

from keyleak.ai.mcp_server import create_server
from keyleak.ai.service import KeyLeakTools
from keyleak.ai.schemas import tool_definitions
from keyleak.ai.adapters import MAX_JSON_BYTES


class MCPTests(unittest.IsolatedAsyncioTestCase):
    """Validate the actual SDK server using its native in-process client."""

    async def test_list_call_and_output_schemas(self):
        """All three definitions expose safe annotations and valid JSON output."""
        with KeyLeakTools() as service:
            async with Client(create_server(service)) as client:
                listed = await client.list_tools()
                self.assertEqual(len(listed.tools), 3)
                for tool in listed.tools:
                    self.assertTrue(tool.annotations.read_only_hint)
                    self.assertFalse(tool.annotations.open_world_hint)
                    Draft202012Validator.check_schema(tool.input_schema)
                    Draft202012Validator.check_schema(tool.output_schema)
                for name, args in (("keyleak_capabilities", {}), ("keyleak_scan_text", {"text": "synthetic"}), ("keyleak_scan_file", {"file_id": "file_1"})):
                    result = await client.call_tool(name, args)
                    schema = next(t["outputSchema"] for t in tool_definitions() if t["name"] == name)
                    Draft202012Validator(schema).validate(result.structured_content)
                    self.assertEqual(json.loads(result.content[0].text), result.structured_content)

    async def test_malformed_call_is_sanitized(self):
        """Malformed user data never appears in a tool error."""
        marker = "PRIVATE_SYNTHETIC_CANARY"
        with KeyLeakTools() as service:
            async with Client(create_server(service)) as client:
                result = await client.call_tool("keyleak_scan_text", {"text": {marker: marker}})
                self.assertTrue(result.is_error)
                self.assertNotIn(marker, result.model_dump_json())

    async def test_sdk_cancellation_reaches_scanner(self):
        """Actual MCP cancellation stops synthetic work without exposing payloads."""
        import threading
        from unittest.mock import patch
        started, stopped = threading.Event(), threading.Event()
        with KeyLeakTools() as service:
            original = service._scan

            def slow_scan(content, source, size, cancel):
                """Wait for transport cancellation in a local synthetic scanner."""
                started.set()
                cancel.wait(3)
                stopped.set()
                return original(content, source, size, cancel)

            with patch.object(service, "_scan", side_effect=slow_scan):
                async with Client(create_server(service)) as client:
                    task = asyncio.create_task(client.call_tool("keyleak_scan_text", {"text": "synthetic"}))
                    self.assertTrue(await asyncio.to_thread(started.wait, 1))
                    task.cancel()
                    with self.assertRaises(asyncio.CancelledError):
                        await task
                    self.assertTrue(await asyncio.to_thread(stopped.wait, 1))

    async def test_cancel_while_stdin_is_open(self):
        """A pending blocking readline is abandoned during transport teardown."""
        import threading
        from unittest.mock import AsyncMock, Mock, patch
        from keyleak.ai.mcp_server import _BoundedInput
        started, release = threading.Event(), threading.Event()

        def blocking_read(_size):
            """Keep a synthetic pipe open until test cleanup releases it."""
            started.set()
            release.wait(3)
            return b""

        fake_stdin = Mock()
        fake_stdin.buffer.readline.side_effect = blocking_read
        try:
            with patch("keyleak.ai.mcp_server.sys.stdin", fake_stdin):
                task = asyncio.create_task(_BoundedInput(AsyncMock()).__anext__())
                self.assertTrue(await asyncio.to_thread(started.wait, 1))
                task.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await asyncio.wait_for(task, timeout=0.5)
        finally:
            release.set()

    async def test_output_backpressure_is_cancellable(self):
        """A full stdout pipe does not block cancellation or transport shutdown."""
        import os
        from unittest.mock import Mock, patch
        from keyleak.ai.mcp_server import _PrivateOutput
        reader, writer = os.pipe()
        output = None
        try:
            fake_stdout = Mock()
            fake_stdout.fileno.return_value = writer
            with patch("keyleak.ai.mcp_server.sys.stdout", fake_stdout):
                output = _PrivateOutput()
            try:
                while True:
                    os.write(writer, b"x" * 4096)
            except BlockingIOError:
                pass
            task = asyncio.create_task(output.write("synthetic"))
            await asyncio.sleep(0.01)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await asyncio.wait_for(task, timeout=0.5)
        finally:
            if output is not None:
                output.close()
            os.close(reader)
            os.close(writer)

    async def test_sdk_telemetry_is_disabled(self):
        """The local server cannot inherit the SDK's default trace middleware."""
        with KeyLeakTools() as service:
            self.assertEqual(create_server(service).middleware, [])

    async def test_real_stdio_client(self):
        """Exercise initialization, discovery, and execution across real pipes."""
        server = StdioServerParameters(command=sys.executable, args=["-I", "-m", "keyleak.ai", "--stdio"], env={})
        async with Client(server, read_timeout_seconds=10) as client:
            tools = await client.list_tools()
            self.assertEqual(len(tools.tools), 3)
            result = await client.call_tool("keyleak_scan_text", {"text": "local synthetic input"})
            self.assertTrue(result.structured_content["ok"])


class WireTests(unittest.TestCase):
    """Check startup, malformed wire input, and bounded transport behavior."""

    def run_server(self, data):
        """Launch a private, non-networked stdio subprocess with bounded runtime."""
        return subprocess.run([sys.executable, "-I", "-m", "keyleak.ai", "--stdio"], input=data, capture_output=True, timeout=10, env={})

    def test_malformed_frame_never_echoes_data(self):
        """JSON parse errors do not expose raw transport input or tracebacks."""
        canary = b"PRIVATE_SYNTHETIC_CANARY"
        result = self.run_server(b'{"text":"' + canary + b'"\n')
        self.assertNotIn(canary, result.stdout + result.stderr)
        self.assertNotIn(b"Traceback", result.stderr)

    def test_oversized_wire_frame_closes(self):
        """An oversized frame closes promptly without allocating unbounded input."""
        result = self.run_server(b"x" * (MAX_JSON_BYTES + 1000))
        self.assertNotIn(b"xxxx", result.stdout + result.stderr)

    def test_invalid_envelopes_keep_connection_alive(self):
        """Invalid JSON and non-string methods return errors, then ping still works."""
        import select
        process = subprocess.Popen([sys.executable, "-I", "-m", "keyleak.ai", "--stdio"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={})

        def exchange(frame):
            """Send one frame and read its bounded-time protocol response."""
            process.stdin.write(frame + b"\n")
            process.stdin.flush()
            self.assertTrue(select.select([process.stdout], [], [], 20)[0])
            return json.loads(process.stdout.readline())

        try:
            initialized = exchange(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "test", "version": "1"}}}).encode())
            self.assertIn("result", initialized)
            process.stdin.write(b'{"jsonrpc":"2.0","method":"notifications/initialized"}\n')
            process.stdin.flush()
            for bad in (b'{"private":"PRIVATE_SYNTHETIC_CANARY"', b'{"jsonrpc":"2.0","id":2,"method":[]}', b'{"jsonrpc":"2.0","id":2,"method":{}}'):
                result = exchange(bad)
                self.assertIn(result["error"]["code"], [-32700, -32600])
                self.assertIsNone(result["id"])
                self.assertNotIn("PRIVATE_SYNTHETIC_CANARY", json.dumps(result))
            pong = exchange(b'{"jsonrpc":"2.0","id":3,"method":"ping"}')
            self.assertEqual(pong["id"], 3)
            self.assertIn("result", pong)
        finally:
            process.stdin.close()
            process.wait(timeout=5)
            process.stdout.close()
            process.stderr.close()

    def test_bad_tool_params_do_not_echo_payload(self):
        """Known-method validation errors also avoid echoing private fields."""
        marker = "PRIVATE_SYNTHETIC_CANARY"
        frames = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "test", "version": "1"}}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "keyleak_scan_text", "arguments": marker}},
        ]
        result = self.run_server(("\n".join(json.dumps(f) for f in frames) + "\n").encode())
        self.assertNotIn(marker.encode(), result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
