import assert from 'node:assert/strict';
import test from 'node:test';

test('service worker waits for startup privacy migration before persisting tab data', async () => {
  const stored = {
    keyleak_tab_7: {
      findings: [{ id: 'old', raw_value: 'legacy-secret', redacted_value: '****' }],
      stats: {},
    },
  };
  const listeners = {};
  const writes = [];
  let startSnapshot;
  let releaseSnapshot;
  let snapshotReleased = false;
  const snapshotStarted = new Promise(resolve => { startSnapshot = resolve; });
  const snapshotGate = new Promise(resolve => { releaseSnapshot = resolve; });
  const register = name => ({ addListener(listener) { listeners[name] = listener; } });

  globalThis.chrome = {
    storage: {
      local: {
        get(key, callback) {
          if (key === null && !snapshotReleased) {
            startSnapshot();
            snapshotGate.then(() => callback({ ...stored }));
            return;
          }
          callback(typeof key === 'string' ? { [key]: stored[key] } : { ...stored });
        },
        set(payload, callback) {
          writes.push(payload);
          Object.assign(stored, payload);
          callback?.();
        },
        remove(key, callback) {
          delete stored[key];
          callback?.();
        },
      },
    },
    runtime: { onMessage: register('message') },
    tabs: {
      onUpdated: register('updated'),
      onRemoved: register('removed'),
      get: async () => ({ url: 'https://app.example/page' }),
      sendMessage: async () => {},
    },
    webRequest: {
      onBeforeSendHeaders: register('before-headers'),
      onHeadersReceived: register('headers-received'),
    },
    action: {
      setBadgeText() {},
      setBadgeBackgroundColor() {},
    },
  };

  try {
    await import('../service-worker.js?privacy-migration-integration');
    await snapshotStarted;
    const response = new Promise(resolve => {
      listeners.message({
        action: 'analyze_content',
        data: {
          content: 'ordinary page text',
          source: 'Storage Test',
          pageUrl: 'https://app.example/page',
        },
      }, { tab: { id: 7, url: 'https://app.example/page' } }, resolve);
    });

    await new Promise(resolve => setImmediate(resolve));
    assert.equal(writes.length, 0);

    snapshotReleased = true;
    releaseSnapshot();
    const result = await response;

    assert.equal(result.ok, true, JSON.stringify(result));
    assert.equal(stored.keyleak_privacy_migration_version, 1);
    assert.equal(stored.keyleak_tab_7.stats.storage, 1);
    assert.equal(JSON.stringify(stored).includes('legacy-secret'), false);
  } finally {
    delete globalThis.chrome;
  }
});
