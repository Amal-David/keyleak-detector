import assert from 'node:assert/strict';
import { test } from 'node:test';

import { isBlockedScanHost, canScanUrl } from '../lib/url-guard.js';

test('blocks loopback, private, link-local, and metadata literals', () => {
  for (const h of ['127.0.0.1', '10.1.2.3', '192.168.0.5', '172.16.9.9',
                    '169.254.169.254', '100.64.0.1', '0.0.0.0',
                    'localhost', 'db.localhost', '::1', 'fe80::1', 'fd00::1']) {
    assert.equal(isBlockedScanHost(h), true, `${h} should be blocked`);
  }
});

test('allows public hosts', () => {
  for (const h of ['8.8.8.8', '93.184.216.34', 'example.com', 'cdn.example.org', '172.32.0.1']) {
    assert.equal(isBlockedScanHost(h), false, `${h} should be allowed`);
  }
});

test('canScanUrl rejects non-http and internal cross-host targets', () => {
  assert.equal(canScanUrl('ftp://example.com/x'), false);
  assert.equal(canScanUrl('file:///etc/passwd'), false);
  // Hostile page on evil.com steering a fetch at the user's localhost → blocked.
  assert.equal(canScanUrl('http://127.0.0.1:8080/secret.js.map', 'https://evil.com/'), false);
  assert.equal(canScanUrl('http://169.254.169.254/latest/meta-data/', 'https://evil.com/'), false);
});

test('canScanUrl permits internal target that matches the page origin (localhost dev)', () => {
  // User is on their own localhost dev app; fetching its own sourcemap is fine.
  assert.equal(canScanUrl('http://localhost:3000/app.js.map', 'http://localhost:3000/'), true);
  assert.equal(canScanUrl('http://127.0.0.1:5173/main.js', 'http://127.0.0.1:5173/'), true);
  // ...but a different internal host than the page is still blocked.
  assert.equal(canScanUrl('http://192.168.1.1/admin.js', 'http://localhost:3000/'), false);
});

test('canScanUrl allows ordinary public sub-resource fetches', () => {
  assert.equal(canScanUrl('https://cdn.example.com/app.js', 'https://example.com/'), true);
});

test('blocks IPv4-mapped IPv6 (gate MF-1): loopback and cloud metadata', () => {
  // The WHATWG URL parser normalizes [::ffff:127.0.0.1] → [::ffff:7f00:1].
  assert.equal(isBlockedScanHost(new URL('http://[::ffff:127.0.0.1]/').hostname), true);
  assert.equal(isBlockedScanHost(new URL('http://[::ffff:169.254.169.254]/').hostname), true);
  assert.equal(isBlockedScanHost(new URL('http://[::ffff:10.0.0.1]/').hostname), true);
  // End to end through canScanUrl from a hostile page.
  assert.equal(canScanUrl('http://[::ffff:169.254.169.254]/latest/meta-data/', 'https://evil.com/'), false);
  assert.equal(canScanUrl('http://[::ffff:127.0.0.1]/', 'https://evil.com/'), false);
});

test('same-origin allowance is port-bound (gate MF-3)', () => {
  // A page on localhost:8080 must NOT unlock fetches to other localhost ports.
  assert.equal(canScanUrl('http://127.0.0.1:6379/', 'http://127.0.0.1:8080/'), false);
  assert.equal(canScanUrl('http://localhost:22/', 'http://localhost:3000/'), false);
  // Exact same origin (host+port) is still allowed (localhost dev sourcemap).
  assert.equal(canScanUrl('http://127.0.0.1:8080/app.js.map', 'http://127.0.0.1:8080/'), true);
  // Different protocol is a different origin → blocked.
  assert.equal(canScanUrl('https://localhost:3000/x', 'http://localhost:3000/'), false);
});
