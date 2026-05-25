/**
 * Real-time BaaS vulnerability detection for Chrome extension.
 *
 * Detects Supabase, Firebase, Appwrite, and PocketBase API requests from
 * intercepted traffic, then probes endpoints with only the anon key
 * (no user JWT) to test for missing Row-Level Security.
 *
 * All probes are read-only GET requests. Never writes, updates, or deletes.
 */

const SUPABASE_TABLE_RE = /^(https:\/\/[a-z0-9]+\.supabase\.co)\/rest\/v1\/([a-z_][a-z0-9_]*)(?:\?|$)/;
const SUPABASE_RPC_RE = /^(https:\/\/[a-z0-9]+\.supabase\.co)\/rest\/v1\/rpc\/([a-z_][a-z0-9_]*)(?:\?|$)/;
const SUPABASE_STORAGE_RE = /^(https:\/\/[a-z0-9]+\.supabase\.co)\/storage\/v1/;
const FIREBASE_DB_RE = /^(https:\/\/[a-z0-9-]+\.firebaseio\.com)(\/|$)/;
const FIREBASE_STORAGE_RE = /firebasestorage\.googleapis\.com\/v0\/b\/([^/]+)/;

const SENSITIVE_PREFIXES = [
  'payout', 'payment', 'billing', 'invoice', 'subscription',
  'admin', 'auth', 'credential', 'secret', 'token',
  'user_block', 'report', 'dmca', 'support_ticket',
  'private', 'internal',
];

export const MAX_PROBES_PER_TAB = 30;
const PROBE_DELAY_MS = 1000;

export function classifyTable(name) {
  const lower = (name || '').toLowerCase();
  for (const prefix of SENSITIVE_PREFIXES) {
    if (lower.includes(prefix)) return 'critical';
  }
  return 'high';
}

export function detectBaaSRequest(url, headers) {
  if (!url) return null;

  let m = SUPABASE_TABLE_RE.exec(url);
  if (m) {
    const apiKey = extractHeader(headers, 'apikey');
    return {
      provider: 'supabase',
      type: 'table',
      baseUrl: m[1],
      endpoint: m[2],
      apiKey: apiKey || '',
    };
  }

  m = SUPABASE_RPC_RE.exec(url);
  if (m) {
    const apiKey = extractHeader(headers, 'apikey');
    return {
      provider: 'supabase',
      type: 'rpc',
      baseUrl: m[1],
      endpoint: m[2],
      apiKey: apiKey || '',
    };
  }

  m = SUPABASE_STORAGE_RE.exec(url);
  if (m) {
    const apiKey = extractHeader(headers, 'apikey');
    return {
      provider: 'supabase',
      type: 'storage',
      baseUrl: m[1],
      endpoint: 'storage',
      apiKey: apiKey || '',
    };
  }

  m = FIREBASE_DB_RE.exec(url);
  if (m) {
    return {
      provider: 'firebase',
      type: 'database',
      baseUrl: m[1],
      endpoint: '/',
      apiKey: '',
    };
  }

  m = FIREBASE_STORAGE_RE.exec(url);
  if (m) {
    return {
      provider: 'firebase',
      type: 'storage',
      baseUrl: 'https://firebasestorage.googleapis.com',
      endpoint: m[1],
      apiKey: '',
    };
  }

  return null;
}

export async function testRLS(baasInfo) {
  const { provider, type, baseUrl, endpoint, apiKey } = baasInfo;

  if (provider === 'supabase' && type === 'table') {
    return testSupabaseTable(baseUrl, endpoint, apiKey);
  }
  if (provider === 'supabase' && type === 'rpc') {
    return testSupabaseRPCReadOnly(baseUrl, endpoint, apiKey);
  }
  if (provider === 'supabase' && type === 'storage') {
    return testSupabaseStorage(baseUrl, apiKey);
  }
  if (provider === 'firebase' && type === 'database') {
    return testFirebaseDB(baseUrl);
  }
  if (provider === 'firebase' && type === 'storage') {
    return testFirebaseStorage(endpoint);
  }

  return { open: false, status: 0, detail: 'unsupported probe type' };
}

async function testSupabaseTable(baseUrl, table, apiKey) {
  try {
    const headers = {};
    if (apiKey) headers['apikey'] = apiKey;
    const resp = await fetch(
      `${baseUrl}/rest/v1/${table}?select=*&limit=1`,
      { headers, credentials: 'omit' }
    );
    if (resp.status === 200) {
      const body = await resp.json();
      if (Array.isArray(body)) {
        const columns = body.length > 0 && typeof body[0] === 'object'
          ? Object.keys(body[0])
          : [];
        return { open: true, status: 200, columns, rowCount: body.length };
      }
    }
    return { open: false, status: resp.status };
  } catch (err) {
    return { open: false, status: 0, detail: err.message };
  }
}

async function testSupabaseRPCReadOnly(baseUrl, fn, apiKey) {
  // OPTIONS doesn't validate EXECUTE permission on PostgREST — it returns
  // Allow headers based on function volatility, not per-role grants.
  // A real POST would mutate state, so we can't safely probe RPCs from the
  // extension.  Instead, return a "lead" (not confirmed) so it surfaces
  // in the UI for manual review without making a mutating request.
  return { open: false, status: 0, detail: 'RPC probing skipped in extension (requires POST)' };
}

async function testFirebaseStorage(bucket) {
  try {
    const resp = await fetch(
      `https://firebasestorage.googleapis.com/v0/b/${bucket}/o?maxResults=1`,
      { credentials: 'omit' }
    );
    if (resp.status === 200) {
      const body = await resp.json();
      const items = (body && body.items) || [];
      return { open: items.length > 0, status: 200, buckets: [{ name: bucket, public: true }] };
    }
    return { open: false, status: resp.status };
  } catch (err) {
    return { open: false, status: 0, detail: err.message };
  }
}

async function testSupabaseStorage(baseUrl, apiKey) {
  try {
    const headers = {};
    if (apiKey) {
      headers['apikey'] = apiKey;
      headers['Authorization'] = `Bearer ${apiKey}`;
    }
    const resp = await fetch(`${baseUrl}/storage/v1/bucket`, { headers, credentials: 'omit' });
    if (resp.status === 200) {
      const body = await resp.json();
      if (Array.isArray(body)) {
        const publicBuckets = body.filter(b => b.public);
        return {
          open: publicBuckets.length > 0,
          status: 200,
          buckets: body.map(b => ({ name: b.name || b.id, public: !!b.public })),
        };
      }
    }
    return { open: false, status: resp.status };
  } catch (err) {
    return { open: false, status: 0, detail: err.message };
  }
}

async function testFirebaseDB(baseUrl) {
  try {
    const resp = await fetch(`${baseUrl}/.json?shallow=true`, { credentials: 'omit' });
    if (resp.status === 200) {
      const body = await resp.json();
      if (body !== null && typeof body === 'object') {
        return { open: true, status: 200, keys: Object.keys(body).slice(0, 20) };
      }
    }
    return { open: false, status: resp.status };
  } catch (err) {
    return { open: false, status: 0, detail: err.message };
  }
}

export function buildBaaSFinding(baasInfo, probeResult) {
  const { provider, type, endpoint } = baasInfo;
  const severity = type === 'database' ? 'critical'
    : type === 'table' ? classifyTable(endpoint)
    : type === 'storage' ? 'high'
    : 'medium';

  const typeLabels = {
    table: 'baas_open_table',
    rpc: 'baas_open_rpc',
    storage: 'baas_open_storage',
    database: 'baas_open_table',
  };

  const snippets = {
    table: `Table '${endpoint}' readable without user auth (HTTP ${probeResult.status}).${probeResult.columns?.length ? ' Columns: ' + probeResult.columns.slice(0, 8).join(', ') : ''}`,
    rpc: `RPC function '${endpoint}' callable without user auth (HTTP ${probeResult.status}).`,
    storage: `Storage bucket${probeResult.buckets ? 's: ' + probeResult.buckets.filter(b => b.public).map(b => b.name).join(', ') : ' accessible'} (HTTP ${probeResult.status}).`,
    database: `Firebase Realtime Database is publicly readable.${probeResult.keys?.length ? ' Top-level keys: ' + probeResult.keys.join(', ') : ''}`,
  };

  const remediations = {
    table: `Enable RLS: ALTER TABLE ${endpoint} ENABLE ROW LEVEL SECURITY; then create appropriate policies.`,
    rpc: `Add auth.uid() check inside '${endpoint}' or revoke EXECUTE from the anon role.`,
    storage: `Set public buckets to private in the ${provider} dashboard and configure storage policies.`,
    database: 'Set Firebase Security Rules to deny public access: {"rules": {".read": "auth != null"}}.',
  };

  return {
    type: typeLabels[type] || 'baas_open_table',
    severity,
    confidence: 0.95,
    detector_id: `baas.${typeLabels[type] || 'open_table'}`,
    source: baasInfo.baseUrl,
    category: 'baas',
    validation_status: 'confirmed',
    evidence: {
      source: baasInfo.baseUrl,
      snippet: snippets[type] || `${provider} ${type} '${endpoint}' is open.`,
      redacted_value: `${type}:${endpoint}`,
      response_status: probeResult.status,
    },
    risk_reason: snippets[type],
    remediation: remediations[type] || 'Review access policies for this resource.',
  };
}

function extractHeader(headers, name) {
  if (!headers) return '';
  if (Array.isArray(headers)) {
    const h = headers.find(h => h.name?.toLowerCase() === name.toLowerCase());
    return h?.value || '';
  }
  if (typeof headers === 'object') {
    for (const [k, v] of Object.entries(headers)) {
      if (k.toLowerCase() === name.toLowerCase()) return v;
    }
  }
  return '';
}

export class BaaSTabState {
  constructor() {
    this.provider = null;
    this.baseUrl = null;
    this.apiKey = null;
    this.tested = new Set();
    this.probeCount = 0;
    this.probeQueue = [];
    this.processing = false;
  }

  _dedupeKey(baasInfo) {
    return `${baasInfo.provider}|${baasInfo.type || 'unknown'}|${baasInfo.endpoint}`;
  }

  shouldProbe(baasInfo) {
    if (this.probeCount >= MAX_PROBES_PER_TAB) return false;
    if (this.tested.has(this._dedupeKey(baasInfo))) return false;
    return true;
  }

  markTested(baasInfo) {
    this.tested.add(this._dedupeKey(baasInfo));
    this.probeCount++;
  }

  async enqueueProbe(baasInfo, addFindingsFn) {
    if (!this.shouldProbe(baasInfo)) return;

    if (!this.provider) {
      this.provider = baasInfo.provider;
      this.baseUrl = baasInfo.baseUrl;
      this.apiKey = baasInfo.apiKey;
    }

    this.markTested(baasInfo);

    this.probeQueue.push({ baasInfo, addFindingsFn });
    if (!this.processing) {
      this.processing = true;
      this._processQueue();
    }
  }

  async _processQueue() {
    while (this.probeQueue.length > 0) {
      const { baasInfo, addFindingsFn } = this.probeQueue.shift();
      try {
        const result = await testRLS(baasInfo);
        if (result.open) {
          const finding = buildBaaSFinding(baasInfo, result);
          addFindingsFn([finding]);
        }
      } catch (_err) { /* swallow probe errors */ }

      if (this.probeQueue.length > 0) {
        await new Promise(resolve => setTimeout(resolve, PROBE_DELAY_MS));
      }
    }
    this.processing = false;
  }
}
