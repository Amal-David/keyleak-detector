import { test } from 'node:test';
import assert from 'node:assert/strict';
import { resolve } from 'node:path';
import { createKeyLeakTools } from './keyleak.mjs';

const pythonExecutable = process.env.KEYLEAK_TEST_PYTHON || resolve('../../../.venv/bin/python');

test('Vercel MCP client discovers and calls the real local service', async () => {
  const { tools, close } = await createKeyLeakTools({ pythonExecutable });
  try {
    assert.deepEqual(Object.keys(tools).sort(), ['keyleak_capabilities', 'keyleak_scan_file', 'keyleak_scan_text']);
    const result = await tools.keyleak_scan_text.execute({ text: 'safe synthetic input' }, { toolCallId: 'test', messages: [] });
    const data = result.structuredContent || JSON.parse(result.content[0].text);
    assert.equal(data.ok, true);
    assert.equal(data.complete, true);
    assert.equal(data.finding_count, 0);
    const denied = await tools.keyleak_scan_file.execute({ file_id: 'file_1' }, { toolCallId: 'test2', messages: [] });
    const deniedData = denied.structuredContent || JSON.parse(denied.content[0].text);
    assert.equal(deniedData.ok, false);
    assert.equal(deniedData.error.code, 'file_not_granted');
    const cancelled = new AbortController();
    cancelled.abort('PRIVATE_SYNTHETIC_CANARY');
    await assert.rejects(
      () => tools.keyleak_scan_text.execute({ text: 'PRIVATE_SYNTHETIC_CANARY' }, { toolCallId: 'cancel', messages: [], abortSignal: cancelled.signal }),
      error => error.name === 'AbortError' && !error.message.includes('PRIVATE_SYNTHETIC_CANARY'),
    );
  } finally { await close(); }
});

test('model-derived commands and malformed grants are rejected', async () => {
  await assert.rejects(() => createKeyLeakTools({ pythonExecutable: 'python; anything' }), /absolute/);
  await assert.rejects(() => createKeyLeakTools({ pythonExecutable, files: 'all' }), /grants/);
});
