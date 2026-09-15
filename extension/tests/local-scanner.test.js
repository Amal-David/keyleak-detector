import assert from 'node:assert/strict';
import test from 'node:test';

import {
  checkLocalScannerHealth,
  ensureLocalScanner,
  localScannerActivity,
} from '../lib/local-scanner.js';

function runtimeWithResponse(response, lastError = null) {
  const calls = [];
  return {
    calls,
    lastError,
    sendNativeMessage(host, message, callback) {
      calls.push({ host, message });
      callback(response);
    },
  };
}

test('health check accepts only the KeyLeak loopback service', async () => {
  const response = payload => ({
    ok: true,
    async json() { return payload; },
  });

  assert.equal(await checkLocalScannerHealth({
    fetchImpl: async () => response({ status: 'ok' }),
  }), false);
  assert.equal(await checkLocalScannerHealth({
    fetchImpl: async () => response({ status: 'ok', service: 'keyleak-detector' }),
  }), true);
});

test('ensureLocalScanner starts the fixed native host when loopback is unavailable', async () => {
  const health = [false];
  const runtime = runtimeWithResponse({ ok: true, status: 'started' });

  const result = await ensureLocalScanner({
    runtime,
    checkHealth: async () => health.shift(),
  });

  assert.equal(result.status, 'started');
  assert.deepEqual(runtime.calls, [{
    host: 'com.keyleak.detector',
    message: { action: 'ensure_running' },
  }]);
});

test('ensureLocalScanner does not invoke the native host when a scanner is already running', async () => {
  const runtime = runtimeWithResponse({ ok: true });

  const result = await ensureLocalScanner({ runtime, checkHealth: async () => true });

  assert.equal(result.status, 'already_running');
  assert.equal(runtime.calls.length, 0);
});

test('missing native host reports one-time setup instead of a Docker command', async () => {
  const runtime = runtimeWithResponse(undefined, { message: 'Specified native messaging host not found.' });

  await assert.rejects(
    ensureLocalScanner({ runtime, checkHealth: async () => false }),
    error => {
      assert.match(error.message, /one-time setup/i);
      assert.match(error.message, /install-extension-host/);
      assert.doesNotMatch(error.message, /docker compose/);
      return true;
    },
  );
});

test('localScannerActivity renews and releases the helper lease around a scan', async () => {
  const runtime = runtimeWithResponse({ ok: true, owned: true });
  let heartbeat;
  let cleared = false;

  const value = await localScannerActivity(async () => 'report', {
    runtime,
    setIntervalFn(callback, delay) {
      assert.equal(delay, 60_000);
      heartbeat = callback;
      return 7;
    },
    clearIntervalFn(timer) {
      assert.equal(timer, 7);
      cleared = true;
    },
  });
  await heartbeat();

  assert.equal(value, 'report');
  assert.equal(cleared, true);
  assert.equal(runtime.calls.length, 2);
  assert.deepEqual(runtime.calls.map(call => call.message), [
    { action: 'touch' },
    { action: 'touch' },
  ]);
});
