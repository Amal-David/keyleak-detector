import assert from 'node:assert/strict';
import test from 'node:test';

import {
  checkLocalScannerHealth,
  ensureLocalScanner,
  localScannerActivity,
  scannerRequestHeaders,
} from '../lib/local-scanner.js';

const CHALLENGE = 'a'.repeat(64);
const PROOF = 'b'.repeat(64);

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
  const requests = [];
  const response = payload => ({
    ok: true,
    async json() { return payload; },
  });

  assert.equal(await checkLocalScannerHealth({ challenge: CHALLENGE, proof: PROOF }, {
    fetchImpl: async (url, options) => {
      requests.push({ url, options });
      return response({ status: 'ok', service: 'keyleak-detector' });
    },
  }), false);
  assert.equal(await checkLocalScannerHealth({ challenge: CHALLENGE, proof: PROOF }, {
    fetchImpl: async (url, options) => {
      requests.push({ url, options });
      return response({ status: 'ok', service: 'keyleak-detector', proof: PROOF });
    },
  }), true);
  assert.match(requests[0].url, new RegExp(`challenge=${CHALLENGE}`));
  assert.equal(requests[0].options.credentials, 'omit');
});

test('ensureLocalScanner authenticates the loopback service through the fixed native host', async () => {
  const healthChecks = [];
  const runtime = runtimeWithResponse({ ok: true, status: 'started', owned: true, proof: PROOF });

  const result = await ensureLocalScanner({
    runtime,
    createChallenge: () => CHALLENGE,
    checkHealth: async auth => {
      healthChecks.push(auth);
      return true;
    },
  });

  assert.equal(result.status, 'started');
  assert.deepEqual(result.auth, { challenge: CHALLENGE, proof: PROOF });
  assert.deepEqual(healthChecks, [{ challenge: CHALLENGE, proof: PROOF }]);
  assert.deepEqual(runtime.calls, [{
    host: 'com.keyleak.detector',
    message: { action: 'ensure_running', challenge: CHALLENGE },
  }]);
});

test('ensureLocalScanner rejects a loopback service that cannot prove native-host identity', async () => {
  const runtime = runtimeWithResponse({ ok: true, status: 'already_running', proof: PROOF });

  await assert.rejects(
    ensureLocalScanner({
      runtime,
      createChallenge: () => CHALLENGE,
      checkHealth: async () => false,
    }),
    /could not authenticate/i,
  );
});

test('missing native host reports one-time setup instead of a Docker command', async () => {
  const runtime = runtimeWithResponse(undefined, { message: 'Specified native messaging host not found.' });

  await assert.rejects(
    ensureLocalScanner({ runtime, createChallenge: () => CHALLENGE }),
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

  const value = await localScannerActivity(async () => {
    assert.equal(runtime.calls.length, 1);
    assert.deepEqual(runtime.calls[0].message, { action: 'touch' });
    return 'report';
  }, {
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
  assert.equal(runtime.calls.length, 3);
  assert.deepEqual(runtime.calls.map(call => call.message), [
    { action: 'touch' },
    { action: 'touch' },
    { action: 'touch' },
  ]);
});

test('scanner request headers carry only the challenge proof', () => {
  assert.deepEqual(scannerRequestHeaders({ challenge: CHALLENGE, proof: PROOF }), {
    'X-KeyLeak-Challenge': CHALLENGE,
    'X-KeyLeak-Proof': PROOF,
  });
});
