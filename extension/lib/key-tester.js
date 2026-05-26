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
  bearer_token: testJWT,
  jwt_token: testJWT,
  supabase_anon_key: testJWT,
  supabase_publishable_key: testJWT,
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
    return { status: 'valid', detail: `Key is active for Gemini AI. ${count} models accessible.` };
  }
  if (r.status === 403) return { status: 'invalid', detail: 'HTTP 403 — not a Gemini key (likely a restricted Firebase/Maps key).' };
  if (r.status === 400) return { status: 'invalid', detail: 'HTTP 400 — key format rejected.' };
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

function decodeJwtPayload(token) {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  try {
    const payload = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    const padded = payload + '='.repeat((4 - payload.length % 4) % 4);
    return JSON.parse(atob(padded));
  } catch (_) {
    return null;
  }
}

const DANGEROUS_SCOPES = ['admin', 'write', 'delete', 'manage', 'superuser', 'root', 'full_access'];

function analyzeJwtClaims(claims) {
  const flags = [];

  const role = claims.role || claims.roles || '';
  const roleStr = Array.isArray(role) ? role.join(',') : String(role);
  if (/service.?role/i.test(roleStr)) {
    flags.push({ level: 'critical', claim: 'role', message: `service_role — bypasses all Row-Level Security` });
  } else if (/admin|superuser|root/i.test(roleStr)) {
    flags.push({ level: 'high', claim: 'role', message: `${roleStr} — elevated privileges` });
  }

  if (claims.is_admin === true || claims.admin === true || claims.isAdmin === true) {
    flags.push({ level: 'high', claim: 'is_admin', message: 'Admin flag is true — elevated privileges' });
  }

  const scope = claims.scope || claims.scp || claims.scopes || '';
  const scopeStr = Array.isArray(scope) ? scope.join(' ') : String(scope);
  if (scopeStr) {
    const dangerousFound = DANGEROUS_SCOPES.filter(s => scopeStr.toLowerCase().includes(s));
    if (dangerousFound.length > 0) {
      flags.push({ level: 'high', claim: 'scope', message: `Broad scope: ${dangerousFound.join(', ')}` });
    }
  }

  const now = Math.floor(Date.now() / 1000);
  if (claims.exp) {
    const remaining = claims.exp - now;
    if (remaining < 0) {
      flags.push({ level: 'info', claim: 'exp', message: `Expired ${formatDuration(-remaining)} ago` });
    } else if (remaining > 365 * 24 * 3600) {
      flags.push({ level: 'medium', claim: 'exp', message: `Expires in ${formatDuration(remaining)} — very long-lived` });
    } else {
      flags.push({ level: 'info', claim: 'exp', message: `Expires in ${formatDuration(remaining)}` });
    }
  } else {
    flags.push({ level: 'medium', claim: 'exp', message: 'No expiry set — token never expires' });
  }

  if (claims.iss) flags.push({ level: 'info', claim: 'iss', message: `Issuer: ${claims.iss}` });
  if (claims.aud) flags.push({ level: 'info', claim: 'aud', message: `Audience: ${Array.isArray(claims.aud) ? claims.aud.join(', ') : claims.aud}` });
  if (claims.sub) flags.push({ level: 'info', claim: 'sub', message: `Subject: ${claims.sub}` });
  if (claims.email) flags.push({ level: 'info', claim: 'email', message: `Email: ${claims.email}` });

  return flags;
}

function formatDuration(seconds) {
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h`;
  if (seconds < 365 * 86400) return `${Math.floor(seconds / 86400)}d`;
  return `${(seconds / (365 * 86400)).toFixed(1)}y`;
}

async function testJWT(token) {
  const claims = decodeJwtPayload(token);
  if (!claims) return { status: 'error', detail: 'Not a valid JWT — could not decode payload.' };

  const flags = analyzeJwtClaims(claims);
  const hasCritical = flags.some(f => f.level === 'critical');
  const hasHigh = flags.some(f => f.level === 'high');

  const summaryParts = [];
  if (claims.iss) summaryParts.push(`iss=${claims.iss}`);
  if (claims.role) summaryParts.push(`role=${claims.role}`);
  if (claims.sub) summaryParts.push(`sub=${String(claims.sub).slice(0, 20)}`);

  return {
    status: 'decoded',
    detail: `JWT decoded. ${summaryParts.join(', ') || 'No notable claims.'}`,
    claims,
    flags,
    severity: hasCritical ? 'critical' : hasHigh ? 'high' : 'info',
  };
}
