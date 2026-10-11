import assert from 'node:assert/strict';
import test from 'node:test';

import {
  ActivityEpochs,
  isOriginPaused,
  isPagePaused,
  normalizeOrigin,
  shouldRunPrivacyMigration,
} from '../lib/privacy.js';
import { persistentSnapshot, sanitizeStoredTabData } from '../lib/reporting.js';

test('pause state applies to the owning page origin, independent of path and query', () => {
  const paused = ['https://app.example'];
  assert.equal(normalizeOrigin('https://app.example/dashboard?token=secret'), 'https://app.example');
  assert.equal(isOriginPaused('https://app.example/settings', paused), true);
  assert.equal(isOriginPaused('https://assets.example/app.js', paused), false);
  assert.equal(isPagePaused('https://frame.example/form', 'https://app.example/dashboard', paused), true);
  assert.equal(isPagePaused('https://frame.example/form', 'https://other.example', paused), false);
  assert.equal(isOriginPaused('chrome://extensions', paused), false);
  assert.equal(isOriginPaused('https://app.example', new Set(paused)), true);
});

test('a pause epoch invalidates analysis that started before pause or resume', () => {
  const epochs = new ActivityEpochs();
  const initial = epochs.current(7);
  epochs.advance(7);
  epochs.advance(7);
  assert.notEqual(epochs.current(7), initial);
});

test('persistent snapshots omit raw findings recursively while leaving the live data intact', () => {
  const secret = 'sk-live-secret-value';
  const live = {
    findings: [{ id: 'f1', raw_value: secret, redacted_value: 'sk-...alue' }],
    report: { findings: [{ id: 'f1', redacted_value: 'sk-...alue' }] },
    full_scan_report: {
      nested: { raw_value: secret },
      raw_sample_rows: [{ credential: secret }],
    },
  };

  const stored = persistentSnapshot(live);
  assert.equal(live.findings[0].raw_value, secret);
  assert.equal(JSON.stringify(stored).includes(secret), false);
  assert.equal(Object.hasOwn(stored.findings[0], 'raw_value'), false);
  assert.equal(Object.hasOwn(stored.full_scan_report.nested, 'raw_value'), false);
  assert.equal(Object.hasOwn(stored.full_scan_report, 'raw_sample_rows'), false);
  assert.equal(stored.findings[0].redacted_value, 'sk-...alue');
});

test('startup sanitation updates only persisted per-tab records that contain raw values', () => {
  const safe = { findings: [{ id: 'safe', redacted_value: '****' }] };
  const updates = sanitizeStoredTabData({
    keyleak_tab_1: { findings: [{ id: 'old', raw_value: 'legacy-secret' }] },
    keyleak_settings: { paused_origins: ['https://app.example'] },
  }, 'keyleak_tab_');

  assert.deepEqual(Object.keys(updates), ['keyleak_tab_1']);
  assert.equal(JSON.stringify(updates).includes('legacy-secret'), false);
  assert.equal(sanitizeStoredTabData({ keyleak_tab_1: safe }, 'keyleak_tab_').keyleak_tab_1, undefined);
});

test('legacy storage migration runs once for old markers and skips current markers', () => {
  assert.equal(shouldRunPrivacyMigration(undefined, 1), true);
  assert.equal(shouldRunPrivacyMigration(0, 1), true);
  assert.equal(shouldRunPrivacyMigration(1, 1), false);
});
