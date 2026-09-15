import {
  boundedRawSampleRows,
  redactStructuredSample,
} from './reporting.js';

const CONVEX_HOST = /^[a-z0-9](?:[a-z0-9-]{1,62}[a-z0-9])?\.convex\.(cloud|site)$/;
const FUNCTION_PATH = /^[A-Za-z0-9_./-]{1,160}(?::[A-Za-z0-9_$-]{1,80})?$/;
const CONNECTION_ID = /^[A-Za-z0-9_-]{1,128}$/;
const SENSITIVE_FUNCTION = /(?:^|[/:._-])(admin|billing|credential|internal|payment|private|secret|token)(?:$|[/:._-])/i;
const MAX_RAW_SAMPLES = 300;

function parseMessage(body) {
  if (typeof body !== 'string' || !body || body.length > 2 * 1024 * 1024) return null;
  try {
    const message = JSON.parse(body);
    return message && typeof message === 'object' ? message : null;
  } catch (_error) {
    return null;
  }
}

function rowsFromValue(value) {
  if (Array.isArray(value)) return value;
  if (value && typeof value === 'object') {
    if (Array.isArray(value.page)) return value.page;
    return Object.keys(value).length > 0 ? [value] : [];
  }
  return value === null || value === undefined ? [] : [{ value }];
}

function queryKey(connectionId, queryId) {
  return `${connectionId}|${queryId}`;
}

function rawSamplePrefix(deploymentUrl, connectionId) {
  const deploymentHost = new URL(deploymentUrl).hostname;
  return `convex-query:${deploymentHost}/${connectionId}/`;
}

export function parseConvexDeployment(rawUrl) {
  try {
    const url = new URL(rawUrl);
    const match = CONVEX_HOST.exec(url.hostname.toLowerCase());
    if (!match || !['https:', 'wss:'].includes(url.protocol)) return null;
    if (match[1] === 'site' && url.protocol !== 'https:') return null;
    if (url.protocol === 'wss:' && !/\/api\/[^/]+\/sync$/.test(url.pathname)) return null;
    let surface = 'functions-api';
    if (match[1] === 'site') surface = 'http-actions';
    else if (url.protocol === 'wss:') surface = 'sync';
    return {
      provider: 'convex',
      deploymentUrl: `https://${url.hostname.toLowerCase()}`,
      surface,
    };
  } catch (_error) {
    return null;
  }
}

function buildConvexFinding(deploymentUrl, functionPath, observedRows, retainedRows, sampleKey) {
  const empty = observedRows.length === 0;
  const evidence = {
    source: deploymentUrl,
    snippet: empty
      ? `Convex query '${functionPath}' succeeded anonymously but returned no data.`
      : `Convex query '${functionPath}' returned ${observedRows.length} value${observedRows.length === 1 ? '' : 's'} to an anonymous client.`,
    redacted_value: sampleKey,
    response_status: 200,
  };
  if (!empty) {
    evidence.sample = redactStructuredSample(observedRows);
    if (retainedRows.length > 0) evidence.raw_sample_available = true;
  }

  return {
    type: empty ? 'convex_anonymous_query_empty' : 'convex_anonymous_query_data',
    severity: empty ? 'low' : SENSITIVE_FUNCTION.test(functionPath) ? 'high' : 'medium',
    confidence: empty ? 0.7 : 0.95,
    detector_id: empty ? 'baas.convex_anonymous_query_empty' : 'baas.convex_anonymous_query',
    source: deploymentUrl,
    category: 'baas',
    validation_status: empty ? 'lead' : 'confirmed',
    evidence,
    risk_reason: empty
      ? 'The query is public, but this response does not prove that application data is exposed.'
      : 'An unauthenticated Convex client received query data. Public queries are client-callable by design, so verify that this result and every returned field are intentionally public.',
    remediation: 'Require and authorize ctx.auth.getUserIdentity() for private data, validate arguments, and convert client-inaccessible helpers to internalQuery.',
    references: [
      'https://docs.convex.dev/functions/internal-functions',
      'https://docs.convex.dev/functions/query-functions',
    ],
  };
}

export class ConvexTabState {
  constructor() {
    this.authenticatedConnections = new Set();
    this.queries = new Map();
    this.rawSamples = new Map();
    this.resultSequence = 0;
  }

  observeClientMessage(url, body, connectionId) {
    const deployment = parseConvexDeployment(url);
    const message = deployment?.surface === 'sync' ? parseMessage(body) : null;
    if (!message || !CONNECTION_ID.test(String(connectionId || ''))) return [];

    if (message.type === 'Authenticate') {
      for (const key of this.queries.keys()) {
        if (key.startsWith(`${connectionId}|`)) this.queries.delete(key);
      }
      const samplePrefix = rawSamplePrefix(deployment.deploymentUrl, connectionId);
      for (const key of this.rawSamples.keys()) {
        if (key.startsWith(samplePrefix)) this.rawSamples.delete(key);
      }
      if (message.authenticated === true) {
        this.authenticatedConnections.add(connectionId);
      } else {
        this.authenticatedConnections.delete(connectionId);
      }
      return [];
    }
    if (
      message.type !== 'ModifyQuerySet'
      || message.authenticated !== false
      || this.authenticatedConnections.has(connectionId)
    ) return [];

    for (const modification of message.modifications || []) {
      if (modification?.type === 'Remove' && Number.isInteger(modification.queryId)) {
        this.queries.delete(queryKey(connectionId, modification.queryId));
        continue;
      }
      if (
        modification?.type === 'Add'
        && Number.isInteger(modification.queryId)
        && FUNCTION_PATH.test(String(modification.udfPath || ''))
      ) {
        this.queries.set(queryKey(connectionId, modification.queryId), {
          connectionId,
          deploymentUrl: deployment.deploymentUrl,
          functionPath: modification.udfPath,
          queryId: modification.queryId,
        });
      }
    }
    return [];
  }

  observeServerMessage(url, body, connectionId) {
    const deployment = parseConvexDeployment(url);
    const message = deployment?.surface === 'sync' ? parseMessage(body) : null;
    if (
      !message
      || message.type !== 'Transition'
      || !CONNECTION_ID.test(String(connectionId || ''))
      || this.authenticatedConnections.has(connectionId)
    ) return [];

    const findings = [];
    for (const modification of message.modifications || []) {
      if (modification?.type === 'QueryRemoved' && Number.isInteger(modification.queryId)) {
        this.queries.delete(queryKey(connectionId, modification.queryId));
        continue;
      }
      if (modification?.type !== 'QueryUpdated' || !Number.isInteger(modification.queryId)) continue;
      const query = this.queries.get(queryKey(connectionId, modification.queryId));
      if (!query) continue;
      const observedRows = rowsFromValue(modification.value);
      const rows = boundedRawSampleRows(observedRows);
      this.resultSequence += 1;
      const sampleKey = rawSamplePrefix(query.deploymentUrl, query.connectionId) + [
        query.queryId,
        encodeURIComponent(query.functionPath),
        this.resultSequence,
      ].join('/');
      const finding = buildConvexFinding(
        query.deploymentUrl,
        query.functionPath,
        observedRows,
        rows,
        sampleKey,
      );
      if (rows.length > 0) {
        this.rawSamples.set(sampleKey, rows);
        if (this.rawSamples.size > MAX_RAW_SAMPLES) {
          this.rawSamples.delete(this.rawSamples.keys().next().value);
        }
      }
      findings.push(finding);
    }
    return findings;
  }

  getRawSample(sampleKey) {
    const rows = this.rawSamples.get(sampleKey);
    return rows ? structuredClone(rows) : null;
  }
}
