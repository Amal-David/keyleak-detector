/** Local Node adapter for Vercel AI SDK tool discovery. No model API calls. */
import { createMCPClient } from '@ai-sdk/mcp';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

/** Host-controlled executable/grants only; never derive these from model input. */
export async function createKeyLeakTools({ pythonExecutable, root, files = [] }) {
  if (typeof pythonExecutable !== 'string' || !pythonExecutable.startsWith('/')) {
    throw new Error('An absolute installed Python executable is required.');
  }
  if (!Array.isArray(files) || files.length > 32 || files.some(f => typeof f !== 'string')) {
    throw new Error('Invalid file grants.');
  }
  const args = ['-I', '-m', 'keyleak.ai', '--stdio'];
  if (files.length) {
    if (typeof root !== 'string' || !root.startsWith('/')) throw new Error('An absolute root is required.');
    args.push('--root', root);
    for (const file of files) args.push('--allow-file', file);
  }
  const transport = new StdioClientTransport({
    command: pythonExecutable,
    args,
    // SDK adds only its default environment allowlist; do not pass API keys,
    // cloud credentials, Python hooks, or proxies.
    env: {},
    stderr: 'ignore',
  });
  let client;
  try {
    client = await createMCPClient({ transport });
    const discovered = await client.tools();
    const tools = Object.fromEntries(Object.entries(discovered).map(([name, definition]) => {
      const execute = definition.execute;
      return [name, {
        ...definition,
        execute: async (input, options) => {
          if (options?.abortSignal?.aborted) throw new DOMException('KeyLeak call cancelled.', 'AbortError');
          try {
            return await execute(input, options);
          } catch {
            if (options?.abortSignal?.aborted) throw new DOMException('KeyLeak call cancelled.', 'AbortError');
            // Do not leak SDK validation errors containing private tool inputs.
            throw new Error('KeyLeak local tool execution failed.');
          }
        },
      }];
    }));
    return { tools, close: () => client.close() };
  } catch {
    if (client) await client.close().catch(() => {});
    else await transport.close().catch(() => {});
    // SDK exceptions can contain request data. Do not forward them to logs.
    throw new Error('KeyLeak local MCP connection failed.');
  }
}
