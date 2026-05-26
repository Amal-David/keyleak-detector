/**
 * Unit tests for BaaS real-time detector.
 * Run: node extension/tests/baas-detector.test.js
 */

import { detectBaaSRequest, classifyTable, buildBaaSFinding, BaaSTabState, MAX_PROBES_PER_TAB } from '../lib/baas-detector.js';

let passed = 0;
let failed = 0;

function assert(condition, message) {
  if (condition) {
    passed++;
  } else {
    failed++;
    console.error(`  FAIL: ${message}`);
  }
}

function test(name, fn) {
  console.log(`  ${name}`);
  fn();
}

console.log('BaaS Detector Tests');
console.log('===================');

// --- detectBaaSRequest ---

test('detects Supabase table request', () => {
  const result = detectBaaSRequest(
    'https://abcdefghijklmnopqrst.supabase.co/rest/v1/profiles?select=*&limit=1',
    [{ name: 'apikey', value: 'test-key-123' }]
  );
  assert(result !== null, 'should detect');
  assert(result.provider === 'supabase', 'provider should be supabase');
  assert(result.type === 'table', 'type should be table');
  assert(result.endpoint === 'profiles', 'endpoint should be profiles');
  assert(result.apiKey === 'test-key-123', 'should extract apikey header');
  assert(result.baseUrl === 'https://abcdefghijklmnopqrst.supabase.co', 'should extract base URL');
});

test('detects Supabase RPC request', () => {
  const result = detectBaaSRequest(
    'https://abcdefghijklmnopqrst.supabase.co/rest/v1/rpc/increment_plays',
    [{ name: 'apikey', value: 'key' }]
  );
  assert(result !== null, 'should detect');
  assert(result.type === 'rpc', 'type should be rpc');
  assert(result.endpoint === 'increment_plays', 'endpoint should be increment_plays');
});

test('detects Supabase storage request', () => {
  const result = detectBaaSRequest(
    'https://abcdefghijklmnopqrst.supabase.co/storage/v1/object/public/images/photo.jpg',
    [{ name: 'apikey', value: 'key' }]
  );
  assert(result !== null, 'should detect');
  assert(result.type === 'storage', 'type should be storage');
});

test('detects Firebase Realtime Database request', () => {
  const result = detectBaaSRequest(
    'https://my-app-default-rtdb.firebaseio.com/users.json',
    []
  );
  assert(result !== null, 'should detect');
  assert(result.provider === 'firebase', 'provider should be firebase');
  assert(result.type === 'database', 'type should be database');
});

test('detects Firebase Storage request', () => {
  const result = detectBaaSRequest(
    'https://firebasestorage.googleapis.com/v0/b/my-app.appspot.com/o/photo.jpg',
    []
  );
  assert(result !== null, 'should detect');
  assert(result.provider === 'firebase', 'provider should be firebase');
  assert(result.type === 'storage', 'type should be storage');
  assert(result.endpoint === 'my-app.appspot.com', 'endpoint should be bucket name');
});

test('returns null for non-BaaS URL', () => {
  const result = detectBaaSRequest('https://api.example.com/v1/users', []);
  assert(result === null, 'should return null for non-BaaS URL');
});

test('extracts apikey from object-style headers', () => {
  const result = detectBaaSRequest(
    'https://abcdefghijklmnopqrst.supabase.co/rest/v1/users',
    { apikey: 'my-key', Authorization: 'Bearer jwt-token' }
  );
  assert(result !== null, 'should detect');
  assert(result.apiKey === 'my-key', 'should extract from object headers');
});

// --- classifyTable ---

test('classifies payout table as critical', () => {
  assert(classifyTable('artist_payout_details') === 'critical', 'payout should be critical');
});

test('classifies admin table as critical', () => {
  assert(classifyTable('admin_settings') === 'critical', 'admin should be critical');
});

test('classifies regular table as high', () => {
  assert(classifyTable('posts') === 'high', 'posts should be high');
});

test('classifies tracks as high', () => {
  assert(classifyTable('tracks') === 'high', 'tracks should be high');
});

// --- buildBaaSFinding ---

test('builds finding for open Supabase table', () => {
  const finding = buildBaaSFinding(
    { provider: 'supabase', type: 'table', baseUrl: 'https://x.supabase.co', endpoint: 'users', apiKey: 'k' },
    { open: true, status: 200, columns: ['id', 'email', 'name'] }
  );
  assert(finding.type === 'baas_open_table', 'type should be baas_open_table');
  assert(finding.severity === 'high', 'users table should be high');
  assert(finding.validation_status === 'confirmed', 'should be confirmed');
  assert(finding.category === 'baas', 'category should be baas');
  assert(finding.evidence.snippet.includes('users'), 'snippet should mention table name');
  assert(finding.evidence.snippet.includes('id'), 'snippet should include column names');
});

test('builds critical finding for payment table', () => {
  const finding = buildBaaSFinding(
    { provider: 'supabase', type: 'table', baseUrl: 'https://x.supabase.co', endpoint: 'payment_details', apiKey: 'k' },
    { open: true, status: 200, columns: ['id', 'amount'] }
  );
  assert(finding.severity === 'critical', 'payment table should be critical');
});

test('builds finding for open Firebase DB', () => {
  const finding = buildBaaSFinding(
    { provider: 'firebase', type: 'database', baseUrl: 'https://app.firebaseio.com', endpoint: '/', apiKey: '' },
    { open: true, status: 200, keys: ['users', 'posts'] }
  );
  assert(finding.type === 'baas_open_table', 'type should be baas_open_table');
  assert(finding.severity === 'critical', 'open Firebase DB should be critical');
  assert(finding.evidence.snippet.includes('Firebase'), 'should mention Firebase');
});

test('builds finding for open RPC function', () => {
  const finding = buildBaaSFinding(
    { provider: 'supabase', type: 'rpc', baseUrl: 'https://x.supabase.co', endpoint: 'get_stats', apiKey: 'k' },
    { open: true, status: 200 }
  );
  assert(finding.type === 'baas_open_rpc', 'type should be baas_open_rpc');
  assert(finding.severity === 'medium', 'RPC should be medium');
  assert(finding.evidence.snippet.includes('get_stats'), 'snippet should mention function name');
});

test('builds finding for open storage bucket', () => {
  const finding = buildBaaSFinding(
    { provider: 'supabase', type: 'storage', baseUrl: 'https://x.supabase.co', endpoint: 'storage', apiKey: 'k' },
    { open: true, status: 200, buckets: [{ name: 'avatars', public: true }] }
  );
  assert(finding.type === 'baas_open_storage', 'type should be baas_open_storage');
  assert(finding.severity === 'high', 'storage should be high');
  assert(finding.evidence.snippet.includes('avatars'), 'snippet should include bucket name');
});

// --- BaaSTabState ---

test('BaaSTabState deduplicates endpoints', () => {
  const state = new BaaSTabState();
  const info = { provider: 'supabase', type: 'table', endpoint: 'users' };
  assert(state.shouldProbe(info) === true, 'first probe should be allowed');
  state.markTested(info);
  assert(state.shouldProbe(info) === false, 'duplicate probe should be blocked');
  assert(state.shouldProbe({ provider: 'supabase', type: 'table', endpoint: 'posts' }) === true, 'different endpoint should be allowed');
});

test('BaaSTabState uses composite dedupe key', () => {
  const state = new BaaSTabState();
  const tableInfo = { provider: 'supabase', type: 'table', endpoint: 'users' };
  const rpcInfo = { provider: 'supabase', type: 'rpc', endpoint: 'users' };
  state.markTested(tableInfo);
  assert(state.shouldProbe(rpcInfo) === true, 'same endpoint but different type should be allowed');
});

test('BaaSTabState respects probe cap', () => {
  const state = new BaaSTabState();
  for (let i = 0; i < MAX_PROBES_PER_TAB; i++) {
    state.markTested({ provider: 'supabase', type: 'table', endpoint: `table_${i}` });
  }
  assert(state.shouldProbe({ provider: 'supabase', type: 'table', endpoint: `table_${MAX_PROBES_PER_TAB}` }) === false, 'should block after cap reached');
});

// --- Summary ---
console.log('');
console.log(`${passed} passed, ${failed} failed`);
process.exit(failed > 0 ? 1 : 0);
