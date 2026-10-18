"""Shared, closed JSON Schemas for local read-only tool calls."""

from copy import deepcopy

from .service import MAX_INPUT_BYTES


def _object(properties: dict) -> dict:
    """Build a strict object accepted by OpenAI, Anthropic, and MCP clients."""
    return {"type": "object", "properties": properties, "required": list(properties), "additionalProperties": False}


TOOLS = [
    {"name": "keyleak_capabilities", "description": "Describe this local scanner's fixed safety limits and host-granted opaque file IDs. Does not enumerate files.", "inputSchema": _object({})},
    {"name": "keyleak_scan_text", "description": "Check user-supplied text for static secret-exposure patterns. Returns redacted findings only; never validates credentials or contacts a network. Do not send private file contents to a model to use this tool; prefer a host-granted file ID.", "inputSchema": _object({"text": {"type": "string", "maxLength": MAX_INPUT_BYTES, "description": "Explicitly supplied UTF-8 text; at most 128 KiB encoded."}})},
    {"name": "keyleak_scan_file", "description": "Check one host-granted UTF-8 file by its opaque ID. Returns redacted static findings only. No arbitrary paths, traversal, recursive crawling, network access, or live credential checks.", "inputSchema": _object({"file_id": {"type": "string", "maxLength": 16, "description": "An opaque ID from keyleak_capabilities, for example file_1."}})},
]

ERROR_SCHEMA = _object({"ok": {"const": False}, "error": _object({"code": {"type": "string"}, "message": {"type": "string"}})})
FINDING_SCHEMA = _object({
    "detector_id": {"type": "string"}, "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
    "line": {"type": "integer", "minimum": 1}, "value": {"const": "[redacted]"}, "remediation": {"type": "string"},
    "validation": {"const": "static_match_only"},
})
SCAN_SCHEMA = _object({
    "ok": {"const": True}, "source_id": {"type": "string"}, "input_bytes": {"type": "integer", "minimum": 0, "maximum": MAX_INPUT_BYTES},
    "complete": {"type": "boolean"}, "incomplete_reasons": {"type": "array", "items": {"type": "string"}},
    "detectors_completed": {"type": "integer", "minimum": 0}, "detectors_total": {"type": "integer", "minimum": 0},
    "findings": {"type": "array", "maxItems": 100, "items": FINDING_SCHEMA}, "finding_count": {"type": "integer", "minimum": 0, "maximum": 100},
    "assessment": {"enum": ["findings_detected", "no_findings_detected", "incomplete"]}, "notice": {"type": "string"},
})
CAPABILITIES_SCHEMA = _object({
    "ok": {"const": True}, "mode": {"const": "local_static_only"}, "input_limit_bytes": {"const": MAX_INPUT_BYTES},
    "finding_limit": {"const": 100}, "file_ids": {"type": "array", "maxItems": 32, "items": {"type": "string"}},
    "network_access": {"const": False}, "credential_validation": {"const": False}, "raw_values": {"const": False},
})


def tool_definitions() -> list[dict]:
    """Return isolated schema copies so caller mutation cannot weaken other adapters."""
    result = deepcopy(TOOLS)
    for tool in result:
        schema = CAPABILITIES_SCHEMA if tool["name"] == "keyleak_capabilities" else SCAN_SCHEMA
        tool["outputSchema"] = {"type": "object", "anyOf": [deepcopy(schema), deepcopy(ERROR_SCHEMA)]}
        tool["annotations"] = {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False}
    return result
