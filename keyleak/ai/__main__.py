"""Run the local KeyLeak MCP server or print public tool schemas."""

import argparse
import asyncio
import json
import logging
import sys

from .adapters import anthropic_tools, openai_tools
from .schemas import tool_definitions
from .service import KeyLeakTools


class _PrivateParser(argparse.ArgumentParser):
    """Prevent command-line mistakes from reflecting private argument values."""

    def error(self, _message):
        """Print only a static setup error, never argparse's raw argument echo."""
        self.exit(2, "Invalid KeyLeak AI options; use --help for supported arguments.\n")


def main() -> int:
    """Keep startup errors static and never log request data or filesystem paths."""
    parser = _PrivateParser(description="Local, read-only KeyLeak AI tools. No HTTP/network scanning.")
    parser.add_argument("--stdio", action="store_true", help="Run the MCP stdio transport.")
    parser.add_argument("--schemas", choices=["mcp", "openai", "anthropic"], help="Print public tool schemas and exit.")
    parser.add_argument("--root", help="Trusted POSIX root for explicit file grants.")
    parser.add_argument("--allow-file", action="append", default=[], help="One relative file path; maps in order to file_1, file_2, etc.")
    args = parser.parse_args()
    if args.schemas:
        schemas = {"mcp": tool_definitions, "openai": openai_tools, "anthropic": anthropic_tools}
        print(json.dumps(schemas[args.schemas](), indent=2, allow_nan=False))
        return 0
    if not args.stdio:
        parser.print_help()
        return 2
    # The standalone transport is a no-logging process. Embedded hosts must also
    # disable argument capture, provider tracing, and request-body logging.
    logging.disable(logging.CRITICAL)
    try:
        from .mcp_server import serve_stdio
        with KeyLeakTools(root=args.root, files=tuple(args.allow_file)) as service:
            asyncio.run(serve_stdio(service))
    except ImportError:
        print("Install integrations/keyleak/requirements.txt to enable MCP.", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 0
    except Exception:
        print("KeyLeak AI server could not start or continue safely.", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
