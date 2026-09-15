import assert from 'node:assert/strict';
import test from 'node:test';

import { BaaSTabState, buildBaaSFinding, testRLS } from '../lib/baas-detector.js';
import { buildReport, redactStructuredSample } from '../lib/reporting.js';

test('redactStructuredSample proves a row exists without retaining raw values', () => {
  const raw = [{
    id: '550e8400-e29b-41d4-a716-446655440000',
    email: 'owner@example.com',
    prompt: 'Write a cinematic launch script for the product',
    api_token: 'sk_live_super_secret_value_123456789',
    nested: { audience: 'founders', private_note: 'do not publish this note' },
    enabled: true,
    score: 42,
    extra_1: 'ignored',
    extra_2: 'ignored',
  }, { prompt: 'second-row-secret' }];

  const preview = redactStructuredSample(raw);

  assert.match(preview, /"prompt"/);
  assert.match(preview, /Writ… \[47 chars\]/);
  assert.match(preview, /\[email\]/);
  assert.match(preview, /\[token-like string: 36 chars\]/);
  assert.doesNotMatch(preview, /owner@example\.com|cinematic launch|super_secret|founders|42|second-row-secret/);
  assert.ok(preview.length <= 1200);
  assert.doesNotMatch(preview, /extra_2/);
});

test('Supabase table probe returns a redacted preview and two in-memory raw rows', async (t) => {
  const body = [
    { id: 'row-secret-id-1', title: 'Featured prompt one', contact: 'author@example.com' },
    { id: 'row-secret-id-2', title: 'Featured prompt two', contact: 'editor@example.com' },
    { id: 'row-secret-id-3', title: 'Featured prompt three', contact: 'third@example.com' },
  ];
  t.mock.method(globalThis, 'fetch', async () => ({
    status: 200,
    async json() { return body; },
  }));

  const result = await testRLS({
    provider: 'supabase',
    type: 'table',
    baseUrl: 'https://project.supabase.co',
    endpoint: 'featured_prompts',
    apiKey: 'anon-key',
  });

  assert.equal(result.open, true);
  assert.equal(globalThis.fetch.mock.callCount(), 1);
  assert.equal(result.rowCount, 3);
  assert.deepEqual(result.rawSampleRows, body.slice(0, 2));
  assert.match(result.sample, /"title"/);
  assert.doesNotMatch(result.sample, /Featured prompt|example\.com|row-secret-id/);

  const finding = buildBaaSFinding(
    { provider: 'supabase', type: 'table', baseUrl: 'https://project.supabase.co', endpoint: 'featured_prompts' },
    result,
  );
  assert.equal(finding.evidence.sample, result.sample);
  assert.equal(finding.evidence.raw_sample_available, true);
  assert.match(finding.risk_reason, /returned 3 rows/);

  const report = buildReport('https://fixture.example', [finding]);
  assert.equal(report.findings[0].evidence.raw_sample_available, true);
  const serialized = JSON.stringify(report);
  assert.match(serialized, /sample/);
  assert.doesNotMatch(serialized, /Featured prompt|example\.com|row-secret-id/);
});

test('raw rows live only in the bounded tab state cache', () => {
  const state = new BaaSTabState();
  const info = { provider: 'supabase', type: 'table', endpoint: 'featured_prompts' };
  const rows = [
    { id: 1, title: 'Actual row one' },
    { id: 2, title: 'Actual row two' },
    { id: 3, title: 'Must not be retained' },
  ];

  state.rememberRawSample(info, rows);
  assert.deepEqual(state.getRawSample('table:featured_prompts'), rows.slice(0, 2));
  assert.doesNotMatch(JSON.stringify(state.getRawSample('table:featured_prompts')), /Must not be retained/);

  state.clearRawSamples();
  assert.equal(state.getRawSample('table:featured_prompts'), null);
});

test('probe processing caches raw rows before emitting the safe finding', async (t) => {
  const rows = [
    { id: 1, title: 'Visible first row' },
    { id: 2, title: 'Visible second row' },
  ];
  t.mock.method(globalThis, 'fetch', async () => ({
    status: 200,
    async json() { return rows; },
  }));
  const state = new BaaSTabState();
  const info = {
    provider: 'supabase',
    type: 'table',
    baseUrl: 'https://project.supabase.co',
    endpoint: 'featured_prompts',
    apiKey: 'anon-key',
  };

  const findings = await new Promise(resolve => state.enqueueProbe(info, resolve));

  assert.equal(globalThis.fetch.mock.callCount(), 1);
  assert.equal(findings[0].evidence.raw_sample_available, true);
  assert.deepEqual(state.getRawSample('table:featured_prompts'), rows);
  assert.doesNotMatch(JSON.stringify(findings), /Visible first row|Visible second row/);
});

test('oversized rows are not retained for raw reveal', () => {
  const state = new BaaSTabState();
  state.rememberRawSample(
    { provider: 'supabase', type: 'table', endpoint: 'huge' },
    [{ body: 'x'.repeat(20_000) }],
  );
  assert.equal(state.getRawSample('table:huge'), null);

  state.rememberRawSample(
    { provider: 'supabase', type: 'table', endpoint: 'huge_unicode' },
    [{ body: '😀'.repeat(5_000) }],
  );
  assert.equal(state.getRawSample('table:huge_unicode'), null);
});

test('an empty readable table is not reported as exposed records', async (t) => {
  t.mock.method(globalThis, 'fetch', async () => ({
    status: 200,
    async json() { return []; },
  }));

  const result = await testRLS({
    provider: 'supabase',
    type: 'table',
    baseUrl: 'https://project.supabase.co',
    endpoint: 'empty_table',
    apiKey: 'anon-key',
  });

  assert.equal(result.open, false);
  assert.equal(result.empty, true);
  assert.equal(result.rowCount, 0);
  assert.equal(result.sample, '');
  assert.deepEqual(result.rawSampleRows, []);

  const finding = buildBaaSFinding(
    { provider: 'supabase', type: 'table', baseUrl: 'https://project.supabase.co', endpoint: 'empty_table' },
    result,
  );
  assert.equal(finding.type, 'baas_readable_empty_table');
  assert.equal(finding.severity, 'low');
  assert.equal(finding.validation_status, 'lead');
  assert.equal(finding.evidence.raw_sample_available, undefined);
  assert.match(finding.risk_reason, /does not prove that records are exposed/i);
});
