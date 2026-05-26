/**
 * Live key validation for KeyLeak Detector.
 * Tests whether a detected credential is still active by making a single
 * read-only API call to the provider. All requests are GETs that return
 * metadata (model lists, user info, scopes) — never mutating operations.
 */

const TESTERS = {
  gemini_api_key: testGemini,
  google_client_api_key: testGemini,
  openai_api_key: testOpenAI,
  anthropic_api_key: testAnthropic,
  github_pat: testGitHub,
  stripe_secret_key: testStripe,
  stripe_restricted_key: testStripe,
  openrouter_api_key: testOpenRouter,
  huggingface_token: testHuggingFace,
  sendgrid_api_key: testSendGrid,
  groq_api_key: testGroq,
  replicate_api_key: testReplicate,
};

export const TESTABLE_TYPES = new Set(Object.keys(TESTERS));

export async function testKey(type, rawValue) {
  const tester = TESTERS[type];
  if (!tester) return { status: 'unsupported', detail: 'No test available for this key type.' };
  if (!rawValue) return { status: 'error', detail: 'No raw value available. Enable Reveal mode first.' };
  try {
    return await tester(rawValue);
  } catch (err) {
    return { status: 'error', detail: err.message || 'Request failed' };
  }
}

async function probe(url, headers = {}) {
  const resp = await fetch(url, { headers, credentials: 'omit' });
  return { status: resp.status, ok: resp.ok, body: await resp.json().catch(() => null) };
}

async function testGemini(key) {
  const r = await probe(`https://generativelanguage.googleapis.com/v1beta/models?key=${encodeURIComponent(key)}`);
  if (r.ok) {
    const count = r.body?.models?.length || 0;
    return { status: 'valid', detail: `Key is active. ${count} models accessible.` };
  }
  if (r.status === 400 || r.status === 403) return { status: 'invalid', detail: `HTTP ${r.status} — key rejected or restricted.` };
  return { status: 'invalid', detail: `HTTP ${r.status}` };
}

async function testOpenAI(key) {
  const r = await probe('https://api.openai.com/v1/models', { Authorization: `Bearer ${key}` });
  if (r.ok) return { status: 'valid', detail: `Key is active. ${r.body?.data?.length || '?'} models.` };
  return { status: 'invalid', detail: `HTTP ${r.status}` };
}

async function testAnthropic(key) {
  const r = await probe('https://api.anthropic.com/v1/models', { 'x-api-key': key, 'anthropic-version': '2023-06-01' });
  if (r.ok) return { status: 'valid', detail: 'Key is active.' };
  return { status: 'invalid', detail: `HTTP ${r.status}` };
}

async function testGitHub(key) {
  const r = await probe('https://api.github.com/user', { Authorization: `token ${key}`, Accept: 'application/vnd.github+json' });
  if (r.ok) {
    const scopes = '';
    return { status: 'valid', detail: `Key is active. User: ${r.body?.login || 'unknown'}.` };
  }
  return { status: 'invalid', detail: `HTTP ${r.status}` };
}

async function testStripe(key) {
  const r = await fetch('https://api.stripe.com/v1/balance', {
    headers: { Authorization: `Basic ${btoa(key + ':')}` },
    credentials: 'omit',
  });
  if (r.ok) return { status: 'valid', detail: 'Key is active (Stripe balance endpoint accessible).' };
  return { status: 'invalid', detail: `HTTP ${r.status}` };
}

async function testOpenRouter(key) {
  const r = await probe('https://openrouter.ai/api/v1/models', { Authorization: `Bearer ${key}` });
  if (r.ok) return { status: 'valid', detail: `Key is active. ${r.body?.data?.length || '?'} models.` };
  return { status: 'invalid', detail: `HTTP ${r.status}` };
}

async function testHuggingFace(key) {
  const r = await probe('https://huggingface.co/api/whoami-v2', { Authorization: `Bearer ${key}` });
  if (r.ok) return { status: 'valid', detail: `Key is active. User: ${r.body?.name || 'unknown'}.` };
  return { status: 'invalid', detail: `HTTP ${r.status}` };
}

async function testSendGrid(key) {
  const r = await probe('https://api.sendgrid.com/v3/scopes', { Authorization: `Bearer ${key}` });
  if (r.ok) return { status: 'valid', detail: 'Key is active (SendGrid scopes accessible).' };
  return { status: 'invalid', detail: `HTTP ${r.status}` };
}

async function testGroq(key) {
  const r = await probe('https://api.groq.com/openai/v1/models', { Authorization: `Bearer ${key}` });
  if (r.ok) return { status: 'valid', detail: `Key is active. ${r.body?.data?.length || '?'} models.` };
  return { status: 'invalid', detail: `HTTP ${r.status}` };
}

async function testReplicate(key) {
  const r = await probe('https://api.replicate.com/v1/models', { Authorization: `Token ${key}` });
  if (r.ok) return { status: 'valid', detail: 'Key is active.' };
  return { status: 'invalid', detail: `HTTP ${r.status}` };
}
