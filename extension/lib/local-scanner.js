const LOCAL_SERVER = 'http://127.0.0.1:5002';
const NATIVE_HOST = 'com.keyleak.detector';
const HEALTH_TIMEOUT_MS = 1_500;
const HEARTBEAT_MS = 60_000;
const AUTH_VALUE = /^[a-f0-9]{64}$/;

function randomChallenge() {
  const bytes = new Uint8Array(32);
  globalThis.crypto.getRandomValues(bytes);
  return Array.from(bytes, value => value.toString(16).padStart(2, '0')).join('');
}

export function scannerRequestHeaders(auth) {
  if (!AUTH_VALUE.test(auth?.challenge || '') || !AUTH_VALUE.test(auth?.proof || '')) {
    throw new Error('The local scanner authentication session is invalid.');
  }
  return {
    'X-KeyLeak-Challenge': auth.challenge,
    'X-KeyLeak-Proof': auth.proof,
  };
}

export async function checkLocalScannerHealth(
  auth,
  { fetchImpl = globalThis.fetch } = {},
) {
  if (!AUTH_VALUE.test(auth?.challenge || '') || !AUTH_VALUE.test(auth?.proof || '')) {
    return false;
  }
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), HEALTH_TIMEOUT_MS);
  try {
    const response = await fetchImpl(
      `${LOCAL_SERVER}/healthz?challenge=${encodeURIComponent(auth.challenge)}`,
      {
        cache: 'no-store',
        credentials: 'omit',
        headers: { 'X-KeyLeak-Proof': auth.proof },
        signal: controller.signal,
      },
    );
    if (!response.ok) return false;
    const payload = await response.json();
    return payload?.status === 'ok'
      && payload?.service === 'keyleak-detector';
  } catch (_error) {
    return false;
  } finally {
    clearTimeout(timeout);
  }
}

function sendNativeMessage(runtime, message) {
  return new Promise((resolve, reject) => {
    if (typeof runtime?.sendNativeMessage !== 'function') {
      reject(new Error('Automatic startup is unavailable in this Chrome build.'));
      return;
    }

    runtime.sendNativeMessage(NATIVE_HOST, message, response => {
      if (runtime.lastError) {
        reject(new Error(runtime.lastError.message || 'Native host unavailable.'));
        return;
      }
      if (!response?.ok) {
        reject(new Error(response?.error || 'The local scanner could not be started.'));
        return;
      }
      resolve(response);
    });
  });
}

function setupError(error) {
  const detail = error?.message || String(error);
  if (/native messaging host|native host|specified native/i.test(detail)) {
    return new Error(
      'Automatic startup needs one-time setup. Run `poetry run keyleak install-extension-host`, reload the extension, then click RUN FULL SCAN again.',
    );
  }
  return error instanceof Error ? error : new Error(detail);
}

export async function ensureLocalScanner({
  runtime = globalThis.chrome?.runtime,
  checkHealth = checkLocalScannerHealth,
  createChallenge = randomChallenge,
} = {}) {
  const challenge = createChallenge();
  let result;
  try {
    result = await sendNativeMessage(runtime, { action: 'ensure_running', challenge });
  } catch (error) {
    throw setupError(error);
  }

  const auth = { challenge, proof: String(result.proof || '') };
  if (!AUTH_VALUE.test(auth.challenge) || !AUTH_VALUE.test(auth.proof)) {
    throw new Error('The native startup helper returned an invalid authentication proof.');
  }
  if (!await checkHealth(auth)) {
    throw new Error('The local scanner could not authenticate after startup.');
  }
  return {
    status: result.status || 'started',
    owned: result.owned === true,
    auth,
  };
}

async function touchLocalScanner(runtime) {
  try {
    await sendNativeMessage(runtime, { action: 'touch' });
  } catch (_error) {
    // A manually started scanner has no helper-owned lease to renew.
  }
}

export async function localScannerActivity(task, {
  runtime = globalThis.chrome?.runtime,
  setIntervalFn = globalThis.setInterval,
  clearIntervalFn = globalThis.clearInterval,
} = {}) {
  await touchLocalScanner(runtime);
  const heartbeat = setIntervalFn(() => touchLocalScanner(runtime), HEARTBEAT_MS);
  try {
    return await task();
  } finally {
    clearIntervalFn(heartbeat);
    await touchLocalScanner(runtime);
  }
}

export { LOCAL_SERVER };
