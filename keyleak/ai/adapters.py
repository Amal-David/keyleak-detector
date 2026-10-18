"""Provider-native schemas and local dispatch; no provider SDK or network calls."""

from __future__ import annotations

import json
from typing import Any

from .schemas import tool_definitions
from .service import KeyLeakTools, MAX_INPUT_BYTES, error

MAX_JSON_BYTES = MAX_INPUT_BYTES * 6 + 4096


def openai_tools() -> list[dict]:
    """Build Responses API function definitions with strict, closed input schemas."""
    return [{"type": "function", "name": t["name"], "description": t["description"], "parameters": t["inputSchema"], "strict": True} for t in tool_definitions()]


def anthropic_tools() -> list[dict]:
    """Build Anthropic Messages API tool definitions over the same service."""
    return [{"name": t["name"], "description": t["description"], "input_schema": t["inputSchema"]} for t in tool_definitions()]


def _unique_object(pairs):
    """Reject ambiguous duplicate JSON keys instead of keeping the last value."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate key.")
        result[key] = value
    return result


def parse_arguments(arguments: Any) -> dict | None:
    """Parse bounded provider arguments without reflecting malformed input."""
    if type(arguments) is not str or len(arguments) > MAX_JSON_BYTES:
        return None
    try:
        if len(arguments.encode("utf-8")) > MAX_JSON_BYTES:
            return None
        result = json.loads(arguments, object_pairs_hook=_unique_object, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, UnicodeError, RecursionError):
        return None
    return result if type(result) is dict else None


def execute_openai_call(service: KeyLeakTools, *, name: str, arguments: str, call_id: str) -> dict:
    """Dispatch one function call; the host supplies its provider-owned call ID."""
    parsed = parse_arguments(arguments)
    output = error("invalid_arguments") if parsed is None else service.call(name, parsed)
    return {"type": "function_call_output", "call_id": call_id, "output": json.dumps(output, allow_nan=False)}


def execute_anthropic_call(service: KeyLeakTools, *, name: str, arguments: Any, tool_use_id: str) -> dict:
    """Return an Anthropic tool_result block with sanitized local errors."""
    output = service.call(name, arguments)
    return {"type": "tool_result", "tool_use_id": tool_use_id, "content": json.dumps(output, allow_nan=False), "is_error": not output["ok"]}
