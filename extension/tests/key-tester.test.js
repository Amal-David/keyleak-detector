import assert from 'node:assert/strict';
import test from 'node:test';

import { TESTABLE_TYPES, testKey } from '../lib/key-tester.js';

function jwt(payload) {
  const encoded = Buffer.from(JSON.stringify(payload)).toString('base64url');
  return `synthetic.${encoded}.signature`;
}

test('only locally inspectable JWT-shaped credential types are exposed', () => {
  assert.deepEqual(
    [...TESTABLE_TYPES].sort(),
    ['bearer_token', 'jwt_token', 'supabase_anon_key', 'supabase_publishable_key'],
  );
  assert.equal(TESTABLE_TYPES.has('openai_api_key'), false);
  assert.equal(TESTABLE_TYPES.has('github_pat'), false);
  assert.equal(TESTABLE_TYPES.has('stripe_secret_key'), false);
});

test('JWT inspection never sends the credential over the network', async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = () => {
    throw new Error('network access is forbidden');
  };
  try {
    const result = await testKey('jwt_token', jwt({ role: 'admin', exp: 4102444800 }));
    assert.equal(result.status, 'decoded');
    assert.equal(result.flags.some((flag) => flag.claim === 'role'), true);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('provider credentials are unsupported rather than transmitted', async () => {
  const result = await testKey('openai_api_key', 'synthetic-provider-key');
  assert.equal(result.status, 'unsupported');
});
