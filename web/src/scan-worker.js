import { scanInputs } from './engine.js';

let active = false;

self.addEventListener('message', async ({ data }) => {
  if (data?.type !== 'scan') return;
  const id = typeof data.id === 'string' && /^[A-Za-z0-9_-]{1,128}$/.test(data.id) ? data.id : '';
  if (!id || active) {
    self.postMessage({ type: 'error', id, error: 'The local scan request is invalid or another scan is still running.' });
    return;
  }
  active = true;
  try {
    const report = await scanInputs(data.inputs, {
      limits: data.options?.limits,
      onProgress: progress => self.postMessage({ type: 'progress', id, progress }),
    });
    self.postMessage({ type: 'result', id, report });
  } catch (_error) {
    // Native exceptions can include user-controlled input. Send a fixed message.
    self.postMessage({ type: 'error', id, error: 'Local analysis could not complete. The scan is incomplete.' });
  } finally {
    active = false;
  }
});
