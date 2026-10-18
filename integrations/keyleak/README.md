# KeyLeak local AI integrations

One defensive tool contract powers OpenAI function calls, Anthropic tools,
Vercel AI SDK, and local MCP clients. The scanner runs where Python runs; the
initial implementation and tests were built on an isolated VM.

## What is included

| Surface | Implementation | Scope |
| --- | --- | --- |
| OpenAI Responses API | `keyleak.ai.adapters.openai_tools` and `execute_openai_call` | Native function schemas and local dispatcher; no model request made |
| ChatGPT / Codex plugin packaging | `plugin/plugin.json` + `plugin/mcp.json` | Portable Agent Plugins 1.0 template for a compatible local desktop host |
| Claude Messages API | `anthropic_tools` and `execute_anthropic_call` | Native input schemas and local result-block dispatcher |
| Claude Code | `plugin/.claude-plugin/plugin.json`, `.mcp.json`, and safe skill | Local plugin template; no marketplace registration |
| Claude Desktop, Codex, Cursor, VS Code | `configs/` | Client-specific stdio configuration templates |
| Vercel AI SDK | `vercel/keyleak.mjs` | Actual local Node MCP tool adapter; tested against the Python service |
| Other MCP clients | Official Python MCP SDK 2.3.0 stdio transport | Same three tools; client UI support varies |

The portable/Claude plugin and client templates require replacing the absolute
Python executable placeholder. They are not installed into any user account.
A cloud-only ChatGPT session cannot reach this stdio process. A hosted
integration would need a separately reviewed authenticated remote architecture;
this package does not create a tunnel, public endpoint, OAuth grant, deployment,
or marketplace submission. Vercel AI SDK is a library: this local subprocess
adapter is **not** a Vercel Edge/serverless deployment.

## Install on a trusted local host

From this repository, using Python 3.12 or newer:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install . -r integrations/keyleak/requirements.txt
.venv/bin/python -I -m keyleak.ai --schemas openai
.venv/bin/python -I -m keyleak.ai --stdio
```

Use the absolute `.venv/bin/python` path in the selected configuration. A normal
server waits for MCP input and does not print a banner. Stop it with Ctrl-C.
MCP is an optional installation; the base scanner's lock and dependency policy
are unchanged. Review the optional transport dependencies before deployment.

For Claude Code, load `plugin/` with its supported `--plugin-dir` development
flow after editing `.mcp.json`. For a portable OpenAI/Agent Plugins host, edit
`plugin/mcp.json` and follow that host's local installation flow. The config
files use each client's actual top-level convention: `mcpServers` for
Claude/Cursor, `servers` for VS Code, and TOML `mcp_servers` for Codex. Merge
entries into existing user configs; never overwrite unrelated servers.

## Grant one file without putting its contents into model context

File reading is off by default. The **host operator**, outside model-controlled
arguments, may launch the service with a narrow root and explicit files:

```sh
/absolute/keyleak/.venv/bin/python -I -m keyleak.ai --stdio \
  --root /absolute/owned-project --allow-file src/config.ts --allow-file .env.example
```

The files map in that order to `file_1` and `file_2`. Ask the tool to scan the
appropriate opaque ID. The file names and root are not returned to the model.
A relative grant is not recursive. Symlinks in the granted path, hardlinks,
non-regular files, path traversal, and absolute grants are rejected. The trusted
root is pinned by descriptor. The supplied stdio launcher and safe file access target POSIX hosts with
descriptor-relative opens and asynchronous pipe support. Native Python text-only
dispatchers are transport-independent; Windows stdio hosts are not verified. Parent directories of the selected
root must be operator-controlled. This is not a general operating-system
sandbox; restrict process privileges and use separate instances for tenants.

## Three tools

- `keyleak_capabilities({})`: fixed limits and granted opaque file IDs.
- `keyleak_scan_text({"text": "..."})`: explicitly supplied text only.
- `keyleak_scan_file({"file_id": "file_1"})`: one host-granted text file.

No tool accepts a URL, credential-validation option, shell command, arbitrary
path, archive, recursive target, remote repository, or option to reveal values.
The server does not import or invoke the audit CLI, active validators, browser
scanner, network crawlers, account enumeration, or automatic remediation.
Existing project CLI capabilities are not exposed through this boundary.

Results contain detector ID, severity, line, `[redacted]`, and static remediation.
They omit raw values, prefixes/suffixes, surrounding snippets, paths, fingerprints,
and untrusted source-derived descriptions. Output is not evidence that a key
works or that a project is safe to ship. Treat matches as leads for human review.
Inputs stay in memory for a call; no reports or logs are persisted by the tools.

Limits: 128 KiB of UTF-8 per input, 100 returned findings, 32 explicit file
grants, one active call per instance, 50 ms of regex time per detector and a
3-second cooperative scan budget. Limit/time exhaustion makes coverage visibly
incomplete. Individual timed-out detector results may be omitted. Cancellation
signals the scan thread; it completes at the next cooperative check, bounded by
the active regex timeout. File snapshots run in a separate helper with a
3-second read budget, cancellation, and bounded cleanup. If the operating system
leaves a killed helper stuck in kernel I/O, the service refuses more work until
that single helper exits instead of starting more readers. Files use bounded
reads; NULs and invalid UTF-8 fail.
MCP frames are capped at 790,528 bytes before JSON parsing, allowing escaped
input. Oversized frames close the connection instead of consuming unbounded data.

## Native provider use

```python
from keyleak.ai import KeyLeakTools, openai_tools, anthropic_tools
from keyleak.ai.adapters import execute_openai_call, execute_anthropic_call

with KeyLeakTools(root="/absolute/owned-project", files=("src/config.ts",)) as tools:
    definitions = openai_tools()  # Pass to Responses API tools.
    output = execute_openai_call(
        tools, name="keyleak_scan_file", arguments='{"file_id":"file_1"}',
        call_id="provider-supplied-call-id",
    )
```

Use provider-owned call IDs, never private data as IDs. OpenAI tools use strict
closed schemas; the local service validates again. Handle only function calls
intended for this adapter. Keep the provider response history, including any
reasoning items, when returning function outputs. Anthropic uses
`anthropic_tools()` and `execute_anthropic_call(..., tool_use_id=...)`; append its
`tool_result` in a user message corresponding to the original `tool_use`.
The library does not create provider clients, obtain credentials, or execute an
autonomous model loop. `examples/native_tools.py` is an entirely offline example.

Prefer file IDs to text arguments for private files. Any text already supplied
to a hosted model is already in that provider's context; scanning cannot undo
that transmission. Disable tracing/argument capture and request-body logging in
your application and provider SDK. Do not insert raw files into prompts,
telemetry, exception messages, or tool-call IDs. The standalone MCP process
disables Python logging and the MCP server removes default telemetry middleware; embedded callers retain responsibility for their host.

## Vercel AI SDK

```js
import { createKeyLeakTools } from './vercel/keyleak.mjs';
const { tools, close } = await createKeyLeakTools({
  pythonExecutable: '/absolute/keyleak/.venv/bin/python',
  root: '/absolute/owned-project', files: ['src/config.ts'],
});
try {
  // Supply tools to your application's generateText/streamText call.
  // Keep tracing disabled and close only after the stream is fully consumed.
} finally {
  await close();
}
```

The adapter starts Python without a shell and with a filtered child
environment (the SDK retains its minimal HOME/PATH/USER-style defaults). Arguments and grants must be host configuration, never model input.
The Node process needs the installed Python environment and local filesystem;
this is intended for a trusted local Node application or development workflow.
Do not put `createKeyLeakTools` directly behind an untrusted multi-tenant route.

## Verify without credentials

```sh
.venv/bin/python -m unittest tests.test_ai_integrations -v
.venv/bin/python -m pip install jsonschema==4.26.0
.venv/bin/python -m unittest discover -s integrations/keyleak/tests -v
.venv/bin/python integrations/keyleak/examples/native_tools.py
cd integrations/keyleak/vercel
npm ci --ignore-scripts --no-audit --no-fund
npm test
```

All integration tests use synthetic text or temporary local fixtures. Real
OpenAI/Anthropic model calls, desktop client UIs, account installation,
marketplace review, and hosted deployments are not tested or claimed.

## Official references checked 2026-10-16

- [OpenAI function calling](https://developers.openai.com/api/docs/guides/function-calling)
- [OpenAI portable plugin packaging](https://developers.openai.com/plugins/build/plugins)
- [OpenAI desktop-only plugins](https://developers.openai.com/plugins/deploy/desktop-only)
- [Agent Plugins manifest schema](https://agent-plugins.org/schemas/1.0.0/plugin.schema.json)
- [Agent Plugins MCP schema](https://agent-plugins.org/schemas/1.0.0/mcp.schema.json)
- [Claude tool definitions](https://platform.claude.com/docs/en/agents-and-tools/tool-use/define-tools)
- [Claude Code MCP](https://code.claude.com/docs/en/mcp)
- [Claude Code plugin manifests](https://code.claude.com/docs/en/plugins-reference)
- [Official Python MCP SDK low-level server](https://py.sdk.modelcontextprotocol.io/advanced/low-level-server/)
- [Vercel AI SDK MCP](https://ai-sdk.dev/docs/ai-sdk-core/mcp-tools)
- [Codex / ChatGPT CLI MCP](https://learn.chatgpt.com/docs/extend/mcp?surface=cli)
- [VS Code MCP](https://code.visualstudio.com/docs/agent-customization/mcp-servers)
- [Cursor MCP](https://cursor.com/docs/mcp)

## Local validation receipt

The 2026-10-16 run passed 29 core integration tests, 11 MCP tests, 2 Vercel
client tests, and 49 existing extension tests. Wheel/sdist builds and the
clean-source launch gate passed. The full Python suite ran 472 tests: 470
passed, with one existing missing-Chromium error and one existing Chromium/CDP
skip. The unchanged base ran 443 tests with the same error and skip. Official
Chromium and headless-shell download attempts both produced invalid/truncated
ZIP files in this VM. See [machine-readable receipt](validation.json).

## Revalidated 2026-10-18

Restored against the unchanged `ae62056` main revision in a fresh Linux VM.
All 29 core, 11 MCP, 2 Vercel and 49 extension tests pass again. The wheel and
source distribution rebuild, and an isolated wheel install exposes all three
tool schemas and scans a granted synthetic file successfully.

The full Python suite again runs 472 tests: 470 pass, one errors because the
Playwright Chromium executable is unavailable, and one browser/CDP case skips.
A separate unmodified-main worktree runs 443 tests with the same one error and
one skip. An official Chromium installation retry again returned invalid ZIP
archives. The full suite is therefore not presented as passing; no test was
skipped or weakened to obtain a green result.

The [validation receipt](validation.json) records these checks. Live clients,
provider calls and remote hosting remain unverified and separately gated.
