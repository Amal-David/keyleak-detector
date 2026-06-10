import assert from 'node:assert/strict';
import { test } from 'node:test';

import { scrubText, scrubSnippet, normalizeFinding } from '../lib/reporting.js';

test('scrubText masks adjacent PII', () => {
  const out = scrubText('owner jane.doe@acme.com call 555-123-4567 ssn 123-45-6789');
  assert.ok(!out.includes('jane.doe@acme.com'));
  assert.ok(!out.includes('555-123-4567'));
  assert.ok(!out.includes('123-45-6789'));
  assert.ok(out.includes('[email]') && out.includes('[phone]') && out.includes('[ssn]'));
});

test('scrubText does not eat digits inside a secret token (FIX1-MF2)', () => {
  // The phone pattern must not start inside an alphanumeric token.
  assert.equal(scrubText('sk_live_4242424242424242'), 'sk_live_4242424242424242');
});

test('scrubSnippet preserves the redacted secret token', () => {
  const out = scrubSnippet('contact bob@corp.io key=sk-proj...redacted...wxyz', 'sk-proj...redacted...wxyz');
  assert.ok(out.includes('sk-proj...redacted...wxyz'));
  assert.ok(!out.includes('bob@corp.io'));
  assert.ok(out.includes('[email]'));
});

test('normalizeFinding scrubs PII in the live browser-scan path', () => {
  const finding = normalizeFinding({
    type: 'aws_access_key',
    severity: 'high',
    source: 'https://app.example.com/main.js',
    snippet: 'support=help@acme.com phone +1 555-987-6543 key=AKIAEXAMPLE1234567890',
    redacted_value: 'AKIAEX...7890',
  });
  assert.ok(!finding.evidence.snippet.includes('help@acme.com'));
  assert.ok(!finding.evidence.snippet.includes('555-987-6543'));
});
