"""Offline native-provider example: no credentials and no model API calls."""

import json
from keyleak.ai import KeyLeakTools, anthropic_tools, openai_tools
from keyleak.ai.adapters import execute_anthropic_call, execute_openai_call


def main():
    """Show each provider's local dispatch contract using benign synthetic input."""
    with KeyLeakTools() as service:
        # In an application, provide openai_tools() to Responses API tools and
        # dispatch only its function_call items. Preserve the full response
        # history (including reasoning items) when returning tool outputs.
        assert len(openai_tools()) == len(anthropic_tools()) == 3
        print(json.dumps(execute_openai_call(service, name="keyleak_scan_text",
              arguments=json.dumps({"text": "safe synthetic input"}), call_id="demo_call")))
        # For Messages API, give anthropic_tools() as tools, then return this
        # block in a user message paired with the original tool_use block.
        print(json.dumps(execute_anthropic_call(service, name="keyleak_scan_text",
              arguments={"text": "safe synthetic input"}, tool_use_id="demo_tool")))


if __name__ == "__main__":
    main()
