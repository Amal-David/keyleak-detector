/**
 * Service worker for KeyLeak Detector.
 * Coordinates analysis, stores normalized findings per tab, and builds launch-gate reports.
 */

import { analyzeContent, analyzeHeaders, analyzeUrl } from './lib/analyzer.js';
import {
  buildReport,
  formatMarkdownReport,
  formatSarifReport,
  normalizeFinding,
  severityRank,
} from './lib/reporting.js';
import { detectBaaSRequest, BaaSTabState } from './lib/baas-detector.js';
import { buildLibraryFindings } from './lib/library-cves.js';
import { testKey } from './lib/key-tester.js';

const STORAGE_PREFIX = 'keyleak_tab_';
const SETTINGS_KEY = 'keyleak_settings';
const MAX_FINDINGS_PER_TAB = 300;
const MAX_REMOTE_BODY_SIZE = 2 * 1024 * 1024;
const LOCAL_SERVER = 'http://127.0.0.1:5002';
const START_SERVER_COMMAND = 'poetry run python app.py';
const DEFAULT_PACKS = ['leak', 'appsec', 'access-control', 'baas'];

const baasTabStates = new Map();

const EMPTY_STATS = {
  requests: 0,
  bodies: 0,
  scripts: 0,
  dataAttrs: 0,
  metaTags: 0,
  externalScripts: 0,
  sourceMaps: 0,
  storage: 0,
  websockets: 0,
  eventStreams: 0,
  devtoolsBodies: 0,
  fullScans: 0,
  libraries: 0,
};

const tabCache = new Map();

function storageKey(tabId) {
  return `${STORAGE_PREFIX}${tabId}`;
}

function storageGet(key) {
  return new Promise(resolve => chrome.storage.local.get(key, resolve));
}

function storageSet(payload) {
  return new Promise(resolve => chrome.storage.local.set(payload, resolve));
}

function storageRemove(key) {
  return new Promise(resolve => chrome.storage.local.remove(key, resolve));
}

function cloneStats(stats = {}) {
  return { ...EMPTY_STATS, ...stats };
}

async function readSettings() {
  const stored = await storageGet(SETTINGS_KEY);
  return {
    suppressed_ids: [],
    ...(stored[SETTINGS_KEY] || {}),
  };
}

async function writeSettings(settings) {
  await storageSet({ [SETTINGS_KEY]: settings });
}

function emptyTabData(pageUrl = '') {
  const data = {
    findings: [],
    url: pageUrl,
    stats: cloneStats(),
    report: null,
    full_scan_report: null,
    full_scan_error: '',
    last_updated: Date.now(),
  };
  data.report = buildReport(pageUrl, [], data.stats, { profile: 'launch-gate', packs: DEFAULT_PACKS });
  return data;
}

async function readTabData(tabId, pageUrl = '') {
  if (!Number.isInteger(tabId) || tabId < 0) {
    return emptyTabData(pageUrl);
  }
  if (tabCache.has(tabId)) {
    const cached = tabCache.get(tabId);
    if (pageUrl) cached.url = pageUrl;
    return cached;
  }

  const stored = await storageGet(storageKey(tabId));
  const data = stored[storageKey(tabId)] || emptyTabData(pageUrl);
  data.stats = cloneStats(data.stats);
  data.findings = (data.findings || []).map(finding => normalizeFinding(finding));
  data.url = pageUrl || data.url || '';
  data.report = buildReport(data.url, data.findings, data.stats, {
    profile: 'launch-gate',
    packs: DEFAULT_PACKS,
    full_scan_report: data.full_scan_report || null,
  });
  tabCache.set(tabId, data);
  return data;
}

async function persistTabData(tabId, data) {
  if (!Number.isInteger(tabId) || tabId < 0) return;
  data.last_updated = Date.now();
  data.report = buildReport(data.url, data.findings, data.stats, {
    profile: 'launch-gate',
    packs: DEFAULT_PACKS,
    full_scan_report: data.full_scan_report || null,
  });
  tabCache.set(tabId, data);
  await storageSet({ [storageKey(tabId)]: data });
  updateBadge(tabId, data);
}

function updateBadge(tabId, data = tabCache.get(tabId)) {
  if (!Number.isInteger(tabId) || tabId < 0) return;
  if (!data || !data.findings || data.findings.length === 0) {
    chrome.action.setBadgeText({ text: '', tabId });
    return;
  }

  const count = data.findings.length;
  const hasBlocker = data.findings.some(finding => ['critical', 'high'].includes(finding.severity));

  chrome.action.setBadgeText({ text: count > 99 ? '99+' : String(count), tabId });
  chrome.action.setBadgeBackgroundColor({
    color: hasBlocker ? '#DC2626' : '#F59E0B',
    tabId,
  });
}

async function addFindings(tabId, newFindings, pageUrl = '') {
  if (!Number.isInteger(tabId) || tabId < 0 || !newFindings || newFindings.length === 0) {
    return emptyTabData(pageUrl);
  }

  const data = await readTabData(tabId, pageUrl);
  const settings = await readSettings();
  const suppressedIds = new Set(settings.suppressed_ids || []);
  if (pageUrl) data.url = pageUrl;

  const existing = new Set(data.findings.map(finding => finding.id));
  for (const rawFinding of newFindings) {
    const finding = normalizeFinding(rawFinding);
    if (suppressedIds.has(finding.id)) continue;
    if (!existing.has(finding.id)) {
      existing.add(finding.id);
      data.findings.push(finding);
    }
  }

  data.findings.sort((left, right) => severityRank(right.severity) - severityRank(left.severity));
  if (data.findings.length > MAX_FINDINGS_PER_TAB) {
    data.findings = data.findings.slice(0, MAX_FINDINGS_PER_TAB);
  }

  await persistTabData(tabId, data);
  return data;
}

async function suppressFinding(tabId, findingId) {
  if (!findingId) return { ok: false, error: 'Missing finding id.' };
  const settings = await readSettings();
  const suppressedIds = new Set(settings.suppressed_ids || []);
  suppressedIds.add(findingId);
  settings.suppressed_ids = Array.from(suppressedIds).slice(-1000);
  await writeSettings(settings);

  const data = await readTabData(tabId);
  data.findings = (data.findings || []).filter(finding => finding.id !== findingId);
  await persistTabData(tabId, data);
  return { ok: true, data };
}

function isTextContent(contentType) {
  if (!contentType) return true;
  const type = contentType.toLowerCase();
  return type.includes('text/')
    || type.includes('application/json')
    || type.includes('application/javascript')
    || type.includes('application/xml')
    || type.includes('application/x-javascript')
    || type.includes('application/x-www-form-urlencoded')
    || type.includes('source-map');
}

function canScanUrl(url) {
  try {
    const parsed = new URL(url);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:';
  } catch (_error) {
    return false;
  }
}

function resolveUrl(url, baseUrl) {
  try {
    return new URL(url, baseUrl || undefined).toString();
  } catch (_error) {
    return '';
  }
}

function sourceMapUrlsFromBody(body, baseUrl) {
  const urls = [];
  const re = /sourceMappingURL=([^\s'"<>]+)/g;
  let match;
  while ((match = re.exec(body)) !== null) {
    const resolved = resolveUrl(match[1], baseUrl);
    if (resolved) urls.push(resolved);
  }
  return Array.from(new Set(urls)).slice(0, 5);
}

async function fetchAndAnalyzeRemote(tabId, { url, source, pageUrl, captureType = 'remote', depth = 0 }) {
  const resolvedUrl = resolveUrl(url, pageUrl);
  if (!canScanUrl(resolvedUrl)) return { ok: false, skipped: true, reason: 'unsupported_url' };

  const response = await fetch(resolvedUrl, {
    cache: 'force-cache',
    credentials: 'omit',
    redirect: 'follow',
  });

  const contentType = response.headers.get('content-type') || '';
  const contentLength = Number(response.headers.get('content-length') || 0);
  if (!isTextContent(contentType) || contentLength > MAX_REMOTE_BODY_SIZE) {
    return { ok: false, skipped: true, reason: 'unsupported_content' };
  }

  const body = await response.text();
  if (!body || body.length > MAX_REMOTE_BODY_SIZE) {
    return { ok: false, skipped: true, reason: 'too_large' };
  }

  const data = await readTabData(tabId, pageUrl);
  if (captureType === 'source-map') data.stats.sourceMaps += 1;
  else if (captureType === 'devtools') data.stats.devtoolsBodies += 1;
  else data.stats.externalScripts += 1;

  const findings = analyzeContent(body, source || resolvedUrl, {
    url: resolvedUrl,
    status: response.status,
    contentType,
    capture_type: captureType,
  });

  await addFindings(tabId, findings, pageUrl || data.url);

  if (depth < 1 && captureType !== 'source-map') {
    for (const mapUrl of sourceMapUrlsFromBody(body, resolvedUrl)) {
      await fetchAndAnalyzeRemote(tabId, {
        url: mapUrl,
        source: `Source Map: ${mapUrl}`,
        pageUrl: pageUrl || data.url,
        captureType: 'source-map',
        depth: depth + 1,
      }).catch(() => {});
    }
  }

  return { ok: true, findings: findings.length };
}

async function runFullScan(tabId, targetUrl) {
  if (!canScanUrl(targetUrl)) {
    return { ok: false, error: 'Full scan requires an http:// or https:// URL.', command: START_SERVER_COMMAND };
  }

  const data = await readTabData(tabId, targetUrl);
  data.stats.fullScans += 1;
  data.full_scan_error = '';

  try {
    const response = await fetch(`${LOCAL_SERVER}/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        url: targetUrl,
        scan_mode: 'basic',
        launch_profile: 'launch-gate',
        packs: DEFAULT_PACKS,
      }),
    });

    if (!response.ok) {
      throw new Error(`Local KeyLeak server returned HTTP ${response.status}`);
    }

    const payload = await response.json();
    data.full_scan_report = payload.report || payload;
    await persistTabData(tabId, data);
    return { ok: true, report: data.full_scan_report };
  } catch (error) {
    data.full_scan_error = `${error.message || error}. Start the local scanner with \`${START_SERVER_COMMAND}\` or \`docker compose up -d\`.`;
    await persistTabData(tabId, data);
    return { ok: false, error: data.full_scan_error, command: START_SERVER_COMMAND };
  }
}

async function exportReport(tabId, format = 'json') {
  const data = await readTabData(tabId);
  const report = data.report || buildReport(data.url, data.findings, data.stats, {
    profile: 'launch-gate',
    packs: DEFAULT_PACKS,
    full_scan_report: data.full_scan_report || null,
  });

  if (format === 'markdown') {
    return { ok: true, format, content: formatMarkdownReport(report), report };
  }
  if (format === 'sarif') {
    return { ok: true, format, content: formatSarifReport(report), report };
  }
  return { ok: true, format: 'json', content: JSON.stringify(report, null, 2), report };
}

async function clearTab(tabId) {
  tabCache.delete(tabId);
  baasTabStates.delete(tabId);
  await storageRemove(storageKey(tabId));
  chrome.action.setBadgeText({ text: '', tabId });
  return { ok: true };
}

async function handleAnalyzeIntercepted(tabId, data = {}) {
  const { url, body, headers, pageUrl, status, contentType, source, captureType } = data;
  const tabData = await readTabData(tabId, pageUrl);
  if (captureType === 'websocket') tabData.stats.websockets += body ? 1 : 0;
  else if (captureType === 'eventstream') tabData.stats.eventStreams += body ? 1 : 0;
  else tabData.stats.bodies += body ? 1 : 0;
  await persistTabData(tabId, tabData);

  const findings = [];
  findings.push(...analyzeUrl(url, { url, status, contentType, capture_type: 'url' }));
  if (headers) findings.push(...analyzeHeaders(headers, 'Response Header', { url, status, contentType, capture_type: 'header' }));
  if (body) {
    findings.push(...analyzeContent(body, source ? `${source} Body` : 'Response Body', {
      url,
      status,
      contentType,
      capture_type: captureType || 'fetch-xhr',
    }));
  }

  await addFindings(tabId, findings, pageUrl);

  // BaaS real-time detection: check if this request targets a BaaS provider
  const requestHeaders = headers || [];
  const baasInfo = detectBaaSRequest(url, requestHeaders);
  if (baasInfo && (baasInfo.apiKey || baasInfo.provider === 'firebase')) {
    if (!baasTabStates.has(tabId)) baasTabStates.set(tabId, new BaaSTabState());
    const baasState = baasTabStates.get(tabId);
    baasState.enqueueProbe(baasInfo, (baasFindings) => {
      addFindings(tabId, baasFindings, pageUrl).catch(() => {});
    });
  }

  return { ok: true, findings: findings.length };
}

async function handleAnalyzeContent(tabId, data = {}) {
  const { content, source, pageUrl, url, status, contentType, captureType } = data;
  const tabData = await readTabData(tabId, pageUrl);

  if (source && source.includes('Inline Script')) tabData.stats.scripts += 1;
  else if (source && source.includes('data attribute')) tabData.stats.dataAttrs += 1;
  else if (source && source.includes('Meta tag')) tabData.stats.metaTags += 1;
  else if (source && source.includes('Storage')) tabData.stats.storage += 1;
  else if (captureType === 'websocket') tabData.stats.websockets += 1;
  else if (captureType === 'eventstream') tabData.stats.eventStreams += 1;

  await persistTabData(tabId, tabData);

  const findings = analyzeContent(content, source, {
    url,
    status,
    contentType,
    capture_type: captureType || 'content',
  });
  await addFindings(tabId, findings, pageUrl);
  return { ok: true, findings: findings.length };
}

async function handleAnalyzeLibraries(tabId, data = {}) {
  const { libraries, pageUrl } = data;
  if (!Array.isArray(libraries) || libraries.length === 0) {
    return { ok: true, findings: 0 };
  }
  // Count coverage from the scan itself: the library surface was inspected
  // regardless of whether any version turned out to be vulnerable, so a page
  // running only safe libraries still reports "JS library versions" covered.
  const tabData = await readTabData(tabId, pageUrl);
  tabData.stats.libraries += 1;
  await persistTabData(tabId, tabData);

  const findings = buildLibraryFindings(libraries, pageUrl);
  await addFindings(tabId, findings, pageUrl);
  return { ok: true, findings: findings.length };
}

async function handleMessage(message, sender) {
  const senderTabId = sender.tab?.id;
  const targetTabId = Number.isInteger(message.tabId) ? message.tabId : senderTabId;

  if (message.action === 'get_findings') {
    if (!Number.isInteger(targetTabId)) return emptyTabData();
    return readTabData(targetTabId);
  }

  if (message.action === 'clear_findings') {
    if (!Number.isInteger(targetTabId)) return { ok: false, error: 'No tab selected.' };
    return clearTab(targetTabId);
  }

  if (message.action === 'export_report') {
    if (!Number.isInteger(targetTabId)) return { ok: false, error: 'No tab selected.' };
    return exportReport(targetTabId, message.format || 'json');
  }

  if (message.action === 'suppress_finding') {
    if (!Number.isInteger(targetTabId)) return { ok: false, error: 'No tab selected.' };
    return suppressFinding(targetTabId, message.findingId);
  }

  if (message.action === 'test_key') {
    const { type, raw_value } = message;
    if (!type || !raw_value) return { ok: false, error: 'Missing type or raw_value.' };
    try {
      const result = await testKey(type, raw_value);
      return { ok: true, ...result };
    } catch (err) {
      return { ok: false, status: 'error', detail: err.message || 'Test failed.' };
    }
  }

  if (message.action === 'run_full_scan') {
    if (!Number.isInteger(targetTabId)) return { ok: false, error: 'No tab selected.', command: START_SERVER_COMMAND };
    return runFullScan(targetTabId, message.url || message.data?.url);
  }

  if (!Number.isInteger(senderTabId) && !Number.isInteger(targetTabId)) {
    return { ok: false, error: 'No sender tab available.' };
  }

  const analysisTabId = Number.isInteger(senderTabId) ? senderTabId : targetTabId;

  if (message.action === 'analyze_intercepted') {
    return handleAnalyzeIntercepted(analysisTabId, message.data);
  }

  if (message.action === 'analyze_content') {
    return handleAnalyzeContent(analysisTabId, message.data);
  }

  if (message.action === 'analyze_libraries') {
    return handleAnalyzeLibraries(analysisTabId, message.data);
  }

  if (message.action === 'analyze_remote_url') {
    return fetchAndAnalyzeRemote(analysisTabId, message.data || {});
  }

  if (message.action === 'analyze_devtools_content') {
    const data = message.data || {};
    const tabData = await readTabData(analysisTabId, data.pageUrl || data.url);
    tabData.stats.devtoolsBodies += 1;
    await persistTabData(analysisTabId, tabData);
    const findings = analyzeContent(data.body || '', data.source || data.url || 'DevTools Network Body', {
      url: data.url,
      status: data.status,
      contentType: data.contentType,
      capture_type: 'devtools',
    });
    await addFindings(analysisTabId, findings, data.pageUrl || data.url);
    return { ok: true, findings: findings.length };
  }

  return { ok: false, error: `Unknown action: ${message.action}` };
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  handleMessage(message, sender)
    .then(sendResponse)
    .catch(error => sendResponse({ ok: false, error: error.message || String(error) }));
  return true;
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === 'loading' && changeInfo.url) {
    clearTab(tabId).catch(() => {});
    baasTabStates.delete(tabId);
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  tabCache.delete(tabId);
  baasTabStates.delete(tabId);
  storageRemove(storageKey(tabId)).catch(() => {});
});

chrome.webRequest.onBeforeSendHeaders.addListener(
  (details) => {
    if (!details.tabId || details.tabId < 0 || !details.requestHeaders) return;
    const tabId = details.tabId;
    readTabData(tabId, details.url)
      .then((data) => {
        data.stats.requests += 1;
        return persistTabData(tabId, data);
      })
      .then(() => {
        const headers = details.requestHeaders.map(h => ({ name: h.name, value: h.value || '' }));
        const findings = [
          ...analyzeHeaders(headers, 'Request Header', { url: details.url, capture_type: 'header' }),
          ...analyzeUrl(details.url, { url: details.url, capture_type: 'url' }),
        ];

        // BaaS detection from outgoing request headers
        const baasInfo = detectBaaSRequest(details.url, headers);
        if (baasInfo && (baasInfo.apiKey || baasInfo.provider === 'firebase')) {
          if (!baasTabStates.has(tabId)) baasTabStates.set(tabId, new BaaSTabState());
          const baasState = baasTabStates.get(tabId);
          baasState.enqueueProbe(baasInfo, (baasFindings) => {
            addFindings(tabId, baasFindings, details.url).catch(() => {});
          });
        }

        return addFindings(tabId, findings, details.url);
      })
      .catch(() => {});
  },
  { urls: ['<all_urls>'] },
  ['requestHeaders'],
);

chrome.webRequest.onHeadersReceived.addListener(
  (details) => {
    if (!details.tabId || details.tabId < 0 || !details.responseHeaders) return;
    const headers = details.responseHeaders.map(h => ({ name: h.name, value: h.value || '' }));
    const findings = analyzeHeaders(headers, 'Response Header', {
      url: details.url,
      status: details.statusCode,
      capture_type: 'header',
    });
    addFindings(details.tabId, findings, details.url).catch(() => {});
  },
  { urls: ['<all_urls>'] },
  ['responseHeaders'],
);

console.log('[KeyLeak] Service worker started - launch-gate monitoring active');
