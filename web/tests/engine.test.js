import assert from 'node:assert/strict';
import test from 'node:test';
import { scanInputs, safeSourceName, DEFAULT_LIMITS } from '../src/engine.js';
import { PATTERN_DEFINITIONS } from '../../extension/lib/patterns.js';

// Synthetic canaries, never sent to any provider.
const KEY = 'sk-proj-Qx7R2p8M6v9N3b5K4t1H0w7Z8u6S9c2D';
const SHORT_KEY = 'AKIA7H2M9Q4V6B3N8X5K';
const text = name => ({ name, content: `OPENAI_API_KEY="${KEY}"\nAWS_ACCESS_KEY_ID=${SHORT_KEY}\nprivate_adjacent_note` });
const codes = report => report.coverage.reasons.map(reason => reason.code);

test('detects long and short credentials without emitting raw values or adjacent text', async () => {
  const progress = [];
  const report = await scanInputs([text('.env')], { onProgress: event => progress.push(event) });
  assert(report.findings.some(item => item.type === 'openai_api_key'));
  assert(report.findings.some(item => item.type === 'aws_access_key'));
  assert.equal(report.coverage.status, 'complete');
  const serialized = JSON.stringify({ report, progress });
  for (const secret of [KEY, SHORT_KEY, 'private_adjacent_note']) assert(!serialized.includes(secret));
  for (const item of report.findings) {
    assert.equal(item.evidence.redacted_value, '[redacted]');
    assert.equal(item.evidence.snippet, '');
    assert(!Object.hasOwn(item, 'raw_value'));
    assert.equal(item.validation_status, 'lead');
  }
});

test('source labels cannot trigger vendor or authentication exclusions or echo URL secrets', async () => {
  const report = await scanInputs([
    text('google-analytics.com.js'), text('Authorization Header'),
    text(`https://user:${SHORT_KEY}@example.com/app.js?token=${KEY}`),
  ]);
  assert.equal(report.coverage.text_files, 3);
  assert(report.findings.length >= 6);
  assert(!JSON.stringify(report).includes(SHORT_KEY));
  assert(!JSON.stringify(report).includes('user:'));
  assert.equal(safeSourceName(`keys/${KEY}.js`), 'Input 1');
  assert.equal(safeSourceName('password=hunter2.env'), 'Input 1');
  assert.equal(safeSourceName('password:hunter2.env'), 'Input 1');
});

test('ordinary folder and source-map provenance keeps separate path components', async () => {
  for (const name of ['src/components/Login.tsx', 'bundle.js!/src/components/Login.tsx']) {
    assert.equal(safeSourceName(name), name);
    const report = await scanInputs([text(name)]);
    assert(report.findings.every(finding => finding.source === name));
  }
  assert.equal(safeSourceName(`src/${KEY}/Login.tsx`), 'Input 1');
  const map = JSON.stringify({ version: 3, sources: ['src/components/Login.tsx'], sourcesContent: [KEY] });
  const report = await scanInputs([{ name: 'bundle.js.map', content: map }]);
  assert(report.findings.some(finding => finding.source === 'bundle.js.map!/src/components/Login.tsx'));
});

test('canonical short OTP captures produce masked unverified leads without relaxing other filters', async () => {
  const content = '{"otp":"483729","verification_code":"483729","sms_code":"A7b9","pin_code":92837461,"2fa_code":"1234AB","mfa_code":"123456789","one_time_password":"ABCDEF"}';
  const report = await scanInputs([{ name: 'fixtures/response.json', content }]);
  const otp = report.findings.filter(finding => finding.detector_id === 'appsec.otp_in_response');
  assert.equal(otp.length, 4); // Duplicate codes collapse; overlong and digit-free fields do not match.
  assert.equal(report.coverage.status, 'complete');
  for (const finding of otp) {
    assert.equal(finding.validation_status, 'lead');
    assert.equal(finding.evidence.redacted_value, '[redacted]');
    assert.match(finding.risk_reason, /fixture.*does not establish a live/);
  }
  for (const code of ['483729', 'A7b9', '92837461', '1234AB']) assert(!JSON.stringify(report).includes(code));
  const normal = await scanInputs([{ name: 'safe.txt', content: 'This text has no credential values.' }]);
  assert.equal(normal.coverage.status, 'complete');
  assert.equal(normal.verdict.status, 'NO_FINDINGS');
  const capped = await scanInputs([{ name: 'response.json', content }], { limits: { maxFindings: 1 } });
  assert.equal(capped.findings.length, 1);
  assert(codes(capped).includes('finding_limit'));
});

test('empty and non-UTF8 or binary selections do not produce a clean result', async () => {
  for (const inputs of [[], [{ name: 'asset.png', content: KEY }],
    [{ name: 'bytes.txt', bytes: new Uint8Array([0xc3, 0x28]) }],
    [{ name: 'renamed.txt', content: '%PDF-1.4 local document' }],
    [{ name: 'unknown', content: 'apparently printable', type: 'application/pdf' }]]) {
    const report = await scanInputs(inputs);
    assert.equal(report.coverage.status, 'partial');
    assert.equal(report.verdict.status, 'INCOMPLETE');
  }
});

test('low-only and partial findings never inherit a safe-to-ship verdict', async () => {
  for (const inputs of [[{ name: 'app.js', content: '//# sourceMappingURL=app.js.map' }],
    [{ name: 'app.js', content: '//# sourceMappingURL=app.js.map' }, { name: 'image.png', content: 'not scanned' }]]) {
    const report = await scanInputs(inputs);
    assert.notEqual(report.verdict.status, 'SAFE_TO_SHIP');
    assert.notEqual(report.verdict.label, 'SAFE TO SHIP');
    if (report.findings.length) assert.equal(report.verdict.status, 'REVIEW');
  }
});

test('unsupported compressed input is an explicit coverage gap', async () => {
  const report = await scanInputs([{ name: 'release.tar.gz', bytes: new Uint8Array([31, 139, 8]) }]);
  assert(codes(report).includes('unsupported_archive'));
  assert.equal(report.verdict.status, 'INCOMPLETE');
});

test('the shared analyzer cloud-storage content exclusion cannot appear clean', async () => {
  const report = await scanInputs([{ name: 'app.js', content: `${KEY}\nhttps://bucket.s3.amazonaws.com/file?X-Amz-Signature=abc` }]);
  assert(codes(report).includes('analyzer_filter'));
  assert.equal(report.coverage.status, 'partial');
});

test('file, input, and entry caps are explicit and callers cannot increase bounds', async () => {
  const file = await scanInputs([text('.env')], { limits: { maxFileBytes: 10 } });
  assert(codes(file).includes('file_byte_limit'));
  const total = await scanInputs([{ name: 'a.txt', content: 'a'.repeat(15) }, { name: 'b.txt', content: 'b'.repeat(15) }],
    { limits: { maxInputBytes: 20 } });
  assert(codes(total).includes('input_byte_limit'));
  const entries = await scanInputs([text('a.env'), text('b.env')], { limits: { maxEntries: 1 } });
  assert(codes(entries).includes('entry_limit'));
  const limits = await scanInputs([{ name: 'safe.txt', content: 'Nothing sensitive in this text.' }],
    { limits: { maxFileBytes: Number.MAX_SAFE_INTEGER } });
  assert.equal(limits.limits.maxFileBytes, DEFAULT_LIMITS.maxFileBytes);
});

test('source-map originals are reconstructed locally within shared work bounds', async () => {
  const map = JSON.stringify({ version: 3, sources: ['src/app.ts'], sourcesContent: [KEY] });
  const report = await scanInputs([{ name: 'bundle.js.map', content: map }]);
  assert.equal(report.coverage.source_map_sources, 1);
  assert(report.findings.some(item => item.source.includes('src/app.ts')));
  const capped = await scanInputs([{ name: 'bundle.js.map', content: map }],
    { limits: { maxAnalysisBytes: new TextEncoder().encode(map).length + KEY.length - 1 } });
  assert(codes(capped).includes('analysis_byte_limit'));
  assert.equal(capped.coverage.status, 'partial');
});

test('missing source-map originals and invalid JSON remain coverage gaps', async () => {
  for (const content of ['{', JSON.stringify({ version: 3, sources: ['private.js'] }),
    JSON.stringify({ version: 3, sources: ['private.js'], sourcesContent: [] })]) {
    const report = await scanInputs([{ name: 'bundle.js.map', content }]);
    assert.equal(report.coverage.status, 'partial');
  }
});

test('per-file and overall finding limits remain visible', async () => {
  const capped = await scanInputs([text('.env')], { limits: { maxFindings: 1 } });
  assert.equal(capped.findings.length, 1);
  assert(codes(capped).includes('finding_limit'));
  const content = Array.from({ length: 65 }, (_, index) => `sk-proj-${index.toString().padStart(3, '0')}-Qx7R2p8M6v9N3b5K4t1H0w7Z`).join('\n');
  const perFile = await scanInputs([{ name: 'keys.txt', content }]);
  assert(codes(perFile).includes('file_finding_limit'));
  assert.equal(perFile.coverage.status, 'partial');
});

test('invalid compiled rule coverage refuses a clean scan', async () => {
  PATTERN_DEFINITIONS.push({ id: 'test-invalid', pattern: '[', flags: 'g' });
  try {
    const report = await scanInputs([text('.env')]);
    assert(codes(report).includes('invalid_rules'));
    assert.equal(report.verdict.status, 'INCOMPLETE');
  } finally {
    PATTERN_DEFINITIONS.pop();
  }
});

test('cancellation never reports success and selected code is never run or fetched', async () => {
  const controller = new AbortController();
  controller.abort();
  const canceled = await scanInputs([text('.env')], { signal: controller.signal });
  assert(codes(canceled).includes('cancelled'));
  assert.equal(canceled.verdict.status, 'INCOMPLETE');
  const oldFetch = globalThis.fetch;
  globalThis.fetch = () => { throw new Error('Unexpected egress'); };
  try {
    const report = await scanInputs([{ name: 'script.js', content: 'globalThis.keyleakExecuted = true; fetch("https://example.com/");' }]);
    assert.equal(globalThis.keyleakExecuted, undefined);
    assert.equal(report.capabilities.network_requests, false);
    assert.equal(report.verdict.status, 'NO_FINDINGS');
  } finally {
    globalThis.fetch = oldFetch;
  }
});
