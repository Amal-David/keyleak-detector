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
  persistentSnapshot,
  sanitizeStoredTabData,
  severityRank,
} from './lib/reporting.js';
import {
  ActivityEpochs,
  isOriginPaused,
  isPagePaused,
  normalizeOrigin,
  shouldRunPrivacyMigration,
} from './lib/privacy.js';
import { detectBaaSRequest, BaaSTabState } from './lib/baas-detector.js';
import { ConvexTabState, parseConvexDeployment } from './lib/convex-detector.js';
import { buildLibraryFindings } from './lib/library-cves.js';
import { testKey } from './lib/key-tester.js';
import { canScanUrl } from './lib/url-guard.js';
import {
  ensureLocalScanner,
  localScannerActivity,
  LOCAL_SERVER,
  scannerRequestHeaders,
} from './lib/local-scanner.js';

const STORAGE_PREFIX = 'keyleak_tab_';
const SETTINGS_KEY = 'keyleak_settings';
const PRIVACY_MIGRATION_KEY = 'keyleak_privacy_migration_version';
const PRIVACY_MIGRATION_VERSION = 1;
const MAX_FINDINGS_PER_TAB = 300;
const MAX_REMOTE_BODY_SIZE = 2 * 1024 * 1024;
const DEFAULT_PACKS = ['leak', 'appsec', 'access-control', 'baas'];

const baasTabStates = new Map();
const convexTabStates = new Map();

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
const activityEpochs = new ActivityEpochs();
const tabObservedOrigins = new Map();
const topLevelUrls = new Map();
let pausedOriginsCache = null;
let pausedOriginsLoading = null;
let pausedOriginsRevision = 0;

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
    paused_origins: [],
    ...(stored[SETTINGS_KEY] || {}),
  };
}

async function writeSettings(settings) {
  await storageSet({ [SETTINGS_KEY]: settings });
  pausedOriginsRevision += 1;
  pausedOriginsCache = new Set(settings.paused_origins || []);
}

async function pageIsPaused(pageUrl, topLevelUrl = '') {
  if (!pausedOriginsCache) {
    if (!pausedOriginsLoading) {
      const revision = pausedOriginsRevision;
      pausedOriginsLoading = readSettings().then((settings) => {
        if (revision === pausedOriginsRevision) {
          pausedOriginsCache = new Set(settings.paused_origins || []);
        }
      }).finally(() => {
        pausedOriginsLoading = null;
      });
    }
    await pausedOriginsLoading;
  }
  return isPagePaused(pageUrl, topLevelUrl, pausedOriginsCache);
}

async function topLevelUrlForTab(tabId) {
  if (topLevelUrls.has(tabId)) return topLevelUrls.get(tabId);
  const tab = await chrome.tabs.get(tabId).catch(() => null);
  if (tab?.url) topLevelUrls.set(tabId, tab.url);
  return tab?.url || '';
}

async function activityIsPaused(tabId, expectedEpoch, pageUrl, topLevelUrl = '') {
  const paused = await pageIsPaused(pageUrl, topLevelUrl);
  return activityEpochs.current(tabId) !== expectedEpoch || paused;
}

function rememberTabOrigins(tabId, ...urls) {
  if (!Number.isInteger(tabId)) return;
  const origins = tabObservedOrigins.get(tabId) || new Set();
  for (const url of urls) {
    const origin = normalizeOrigin(url);
    if (origin) origins.add(origin);
  }
  const topLevelUrl = urls[urls.length - 1];
  if (normalizeOrigin(topLevelUrl)) topLevelUrls.set(tabId, topLevelUrl);
  tabObservedOrigins.set(tabId, origins);
}

async function sanitizePersistedFindings() {
  const migration = await storageGet(PRIVACY_MIGRATION_KEY);
  if (!shouldRunPrivacyMigration(migration[PRIVACY_MIGRATION_KEY], PRIVACY_MIGRATION_VERSION)) return;
  const stored = await storageGet(null);
  const updates = sanitizeStoredTabData(stored, STORAGE_PREFIX);
  updates[PRIVACY_MIGRATION_KEY] = PRIVACY_MIGRATION_VERSION;
  await storageSet(updates);
}

async function setOriginPaused(originValue, paused) {
  const origin = normalizeOrigin(originValue);
  if (!origin) return { ok: false, error: 'Pause controls require an http:// or https:// page.' };
  const settings = await readSettings();
  const origins = new Set(settings.paused_origins || []);
  if (paused) origins.add(origin);
  else origins.delete(origin);
  settings.paused_origins = [...origins];
  await writeSettings(settings);
  const nextPaused = origins.has(origin);
  const tabs = await chrome.tabs.query({ url: `${origin}/*` });
  const affectedTabIds = new Set();
  for (const tab of tabs) {
    if (!Number.isInteger(tab.id)) continue;
    if (tab.url) topLevelUrls.set(tab.id, tab.url);
    if (normalizeOrigin(tab.url) === origin) {
      affectedTabIds.add(tab.id);
      chrome.tabs.sendMessage(tab.id, {
        action: 'origin_pause_changed',
        origin,
        paused: nextPaused,
      }, () => { void chrome.runtime.lastError; });
    }
  }
  for (const [tabId, observedOrigins] of tabObservedOrigins) {
    if (observedOrigins.has(origin)) affectedTabIds.add(tabId);
  }
  for (const tabId of affectedTabIds) activityEpochs.advance(tabId);
  return { ok: true, origin, paused: nextPaused };
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
  const storedData = stored[storageKey(tabId)] || emptyTabData(pageUrl);
  const data = persistentSnapshot(storedData);
  if (JSON.stringify(data) !== JSON.stringify(storedData)) {
    await storageSet({ [storageKey(tabId)]: data });
  }
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

async function persistTabData(tabId, data, expectedEpoch = null) {
  if (!Number.isInteger(tabId) || tabId < 0) return;
  if (expectedEpoch !== null && activityEpochs.current(tabId) !== expectedEpoch) {
    tabCache.delete(tabId);
    return false;
  }
  data.last_updated = Date.now();
  data.report = buildReport(data.url, data.findings, data.stats, {
    profile: 'launch-gate',
    packs: DEFAULT_PACKS,
    full_scan_report: data.full_scan_report || null,
  });
  tabCache.set(tabId, data);
  await storageSet({ [storageKey(tabId)]: persistentSnapshot(data) });
  updateBadge(tabId, data);
  return true;
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

async function addFindings(tabId, newFindings, pageUrl = '', expectedEpoch = activityEpochs.current(tabId)) {
  if (!Number.isInteger(tabId) || tabId < 0 || !newFindings || newFindings.length === 0) {
    return emptyTabData(pageUrl);
  }

  const data = await readTabData(tabId, pageUrl);
  const settings = await readSettings();
  if (activityEpochs.current(tabId) !== expectedEpoch) return data;
  const suppressedIds = new Set(settings.suppressed_ids || []);
  if (pageUrl) data.url = pageUrl;

  const existing = new Map(data.findings.map((finding, index) => [finding.id, index]));
  for (const rawFinding of newFindings) {
    const finding = normalizeFinding(rawFinding);
    if (suppressedIds.has(finding.id)) continue;
    if (!existing.has(finding.id)) {
      existing.set(finding.id, data.findings.length);
      data.findings.push(finding);
    } else {
      const index = existing.get(finding.id);
      if (!data.findings[index].raw_value && finding.raw_value) data.findings[index] = finding;
    }
  }

  data.findings.sort((left, right) => severityRank(right.severity) - severityRank(left.severity));
  if (data.findings.length > MAX_FINDINGS_PER_TAB) {
    data.findings = data.findings.slice(0, MAX_FINDINGS_PER_TAB);
  }

  await persistTabData(tabId, data, expectedEpoch);
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

async function fetchAndAnalyzeRemote(tabId, { url, source, pageUrl, captureType = 'remote', depth = 0 }, expectedEpoch = activityEpochs.current(tabId)) {
  const resolvedUrl = resolveUrl(url, pageUrl);
  if (!canScanUrl(resolvedUrl, pageUrl)) return { ok: false, skipped: true, reason: 'unsupported_url' };

  // redirect: 'manual' — a service worker cannot read a cross-origin redirect's
  // Location to re-validate it, so we refuse to follow redirects at all rather
  // than let a guard-approved public host 302 the fetch into an internal target
  // (gate MF-2). Legit sub-resources are served directly, not via redirects.
  const response = await fetch(resolvedUrl, {
    cache: 'force-cache',
    credentials: 'omit',
    redirect: 'manual',
  });

  if (response.type === 'opaqueredirect' || (response.status >= 300 && response.status < 400)) {
    return { ok: false, skipped: true, reason: 'redirect_not_followed' };
  }
  // Defense in depth: if the final URL somehow differs and is internal, drop it.
  if (response.url && !canScanUrl(response.url, pageUrl)) {
    return { ok: false, skipped: true, reason: 'redirected_to_blocked_host' };
  }

  const contentType = response.headers.get('content-type') || '';
  const contentLength = Number(response.headers.get('content-length') || 0);
  if (!isTextContent(contentType) || contentLength > MAX_REMOTE_BODY_SIZE) {
    return { ok: false, skipped: true, reason: 'unsupported_content' };
  }

  const body = await response.text();
  if (!body || body.length > MAX_REMOTE_BODY_SIZE) {
    return { ok: false, skipped: true, reason: 'too_large' };
  }
  if (await activityIsPaused(tabId, expectedEpoch, pageUrl)) {
    return { ok: true, skipped: true, reason: 'origin_paused' };
  }

  const data = await readTabData(tabId, pageUrl);
  if (activityEpochs.current(tabId) !== expectedEpoch) return { ok: true, skipped: true, reason: 'origin_paused' };
  if (captureType === 'source-map') data.stats.sourceMaps += 1;
  else if (captureType === 'devtools') data.stats.devtoolsBodies += 1;
  else data.stats.externalScripts += 1;

  const findings = analyzeContent(body, source || resolvedUrl, {
    url: resolvedUrl,
    status: response.status,
    contentType,
    capture_type: captureType,
  });

  await addFindings(tabId, findings, pageUrl || data.url, expectedEpoch);

  if (await activityIsPaused(tabId, expectedEpoch, pageUrl)) {
    return { ok: true, skipped: true, reason: 'origin_paused' };
  }
  if (depth < 1 && captureType !== 'source-map') {
    for (const mapUrl of sourceMapUrlsFromBody(body, resolvedUrl)) {
      await fetchAndAnalyzeRemote(tabId, {
        url: mapUrl,
        source: `Source Map: ${mapUrl}`,
        pageUrl: pageUrl || data.url,
        captureType: 'source-map',
        depth: depth + 1,
      }, expectedEpoch).catch(() => {});
    }
  }

  return { ok: true, findings: findings.length };
}

async function runFullScan(tabId, targetUrl) {
  // The user explicitly chose to scan their current tab, so its own host is
  // always in scope (passed as both target and page origin).
  if (!canScanUrl(targetUrl, targetUrl)) {
    return { ok: false, error: 'Full scan requires an http:// or https:// URL.' };
  }
  const expectedEpoch = activityEpochs.current(tabId);
  if (await activityIsPaused(tabId, expectedEpoch, targetUrl, targetUrl)) {
    return { ok: false, error: 'Scanning is paused for this site.' };
  }

  const data = await readTabData(tabId, targetUrl);
  if (activityEpochs.current(tabId) !== expectedEpoch) return { ok: false, skipped: true, reason: 'origin_paused' };
  data.stats.fullScans += 1;
  data.full_scan_error = '';

  try {
    const scanner = await ensureLocalScanner();
    const response = await localScannerActivity(() => fetch(`${LOCAL_SERVER}/extension/scan`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...scannerRequestHeaders(scanner.auth),
      },
      body: JSON.stringify({
        url: targetUrl,
        scan_mode: 'basic',
        launch_profile: 'launch-gate',
        packs: DEFAULT_PACKS,
      }),
    }));

    if (!response.ok) {
      throw new Error(`Local KeyLeak server returned HTTP ${response.status}`);
    }

    const payload = await response.json();
    if (await activityIsPaused(tabId, expectedEpoch, targetUrl, targetUrl)) {
      tabCache.delete(tabId);
      return { ok: false, skipped: true, reason: 'origin_paused' };
    }
    data.full_scan_report = persistentSnapshot(payload.report || payload);
    if (!await persistTabData(tabId, data, expectedEpoch)) {
      return { ok: false, skipped: true, reason: 'origin_paused' };
    }
    return { ok: true, report: data.full_scan_report };
  } catch (error) {
    if (activityEpochs.current(tabId) !== expectedEpoch) {
      tabCache.delete(tabId);
      return { ok: false, skipped: true, reason: 'origin_paused' };
    }
    data.full_scan_error = error.message || String(error);
    if (!await persistTabData(tabId, data, expectedEpoch)) {
      return { ok: false, skipped: true, reason: 'origin_paused' };
    }
    return { ok: false, error: data.full_scan_error };
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
  convexTabStates.delete(tabId);
  await storageRemove(storageKey(tabId));
  chrome.action.setBadgeText({ text: '', tabId });
  return { ok: true };
}

async function handleAnalyzeIntercepted(tabId, data = {}, expectedEpoch = activityEpochs.current(tabId)) {
  const {
    url,
    body,
    headers,
    pageUrl,
    status,
    contentType,
    source,
    captureType,
    connectionId,
  } = data;
  const tabData = await readTabData(tabId, pageUrl);
  if (await activityIsPaused(tabId, expectedEpoch, pageUrl)) {
    return { ok: true, skipped: true, reason: 'origin_paused' };
  }
  if (captureType === 'websocket') tabData.stats.websockets += body ? 1 : 0;
  else if (captureType === 'eventstream') tabData.stats.eventStreams += body ? 1 : 0;
  else tabData.stats.bodies += body ? 1 : 0;
  if (!await persistTabData(tabId, tabData, expectedEpoch)) {
    return { ok: true, skipped: true, reason: 'origin_paused' };
  }
  if (await activityIsPaused(tabId, expectedEpoch, pageUrl)) {
    return { ok: true, skipped: true, reason: 'origin_paused' };
  }

  const findings = [];
  const convexDeployment = parseConvexDeployment(url);
  if (convexDeployment?.surface === 'sync') {
    if (!convexTabStates.has(tabId)) convexTabStates.set(tabId, new ConvexTabState());
    const convexState = convexTabStates.get(tabId);
    const convexFindings = captureType === 'convex-client'
      ? convexState.observeClientMessage(url, body, connectionId)
      : captureType === 'websocket'
        ? convexState.observeServerMessage(url, body, connectionId)
        : [];
    findings.push(...convexFindings);
  }
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

  await addFindings(tabId, findings, pageUrl, expectedEpoch);
  if (await activityIsPaused(tabId, expectedEpoch, pageUrl)) {
    return { ok: true, skipped: true, reason: 'origin_paused' };
  }

  // BaaS real-time detection: check if this request targets a BaaS provider
  const requestHeaders = headers || [];
  const baasInfo = detectBaaSRequest(url, requestHeaders);
  if (baasInfo && (baasInfo.apiKey || baasInfo.provider === 'firebase')) {
    if (!baasTabStates.has(tabId)) baasTabStates.set(tabId, new BaaSTabState());
    const baasState = baasTabStates.get(tabId);
    baasState.enqueueProbe(baasInfo, (baasFindings) => {
      addFindings(tabId, baasFindings, pageUrl, expectedEpoch).catch(() => {});
    });
  }

  return { ok: true, findings: findings.length };
}

async function handleAnalyzeContent(tabId, data = {}, expectedEpoch = activityEpochs.current(tabId)) {
  const { content, source, pageUrl, url, status, contentType, captureType } = data;
  const tabData = await readTabData(tabId, pageUrl);
  if (await activityIsPaused(tabId, expectedEpoch, pageUrl)) {
    return { ok: true, skipped: true, reason: 'origin_paused' };
  }

  if (source && source.includes('Inline Script')) tabData.stats.scripts += 1;
  else if (source && source.includes('data attribute')) tabData.stats.dataAttrs += 1;
  else if (source && source.includes('Meta tag')) tabData.stats.metaTags += 1;
  else if (source && source.includes('Storage')) tabData.stats.storage += 1;
  else if (captureType === 'websocket') tabData.stats.websockets += 1;
  else if (captureType === 'eventstream') tabData.stats.eventStreams += 1;

  if (!await persistTabData(tabId, tabData, expectedEpoch)) {
    return { ok: true, skipped: true, reason: 'origin_paused' };
  }
  if (await activityIsPaused(tabId, expectedEpoch, pageUrl)) {
    return { ok: true, skipped: true, reason: 'origin_paused' };
  }

  const findings = analyzeContent(content, source, {
    url,
    status,
    contentType,
    capture_type: captureType || 'content',
  });
  await addFindings(tabId, findings, pageUrl, expectedEpoch);
  return { ok: true, findings: findings.length };
}

async function handleAnalyzeLibraries(tabId, data = {}, expectedEpoch = activityEpochs.current(tabId)) {
  const { libraries, pageUrl } = data;
  if (!Array.isArray(libraries) || libraries.length === 0) {
    return { ok: true, findings: 0 };
  }
  // Count coverage from the scan itself: the library surface was inspected
  // regardless of whether any version turned out to be vulnerable, so a page
  // running only safe libraries still reports "JS library versions" covered.
  const tabData = await readTabData(tabId, pageUrl);
  if (await activityIsPaused(tabId, expectedEpoch, pageUrl)) {
    return { ok: true, skipped: true, reason: 'origin_paused' };
  }
  tabData.stats.libraries += 1;
  if (!await persistTabData(tabId, tabData, expectedEpoch)) {
    return { ok: true, skipped: true, reason: 'origin_paused' };
  }
  if (await activityIsPaused(tabId, expectedEpoch, pageUrl)) {
    return { ok: true, skipped: true, reason: 'origin_paused' };
  }

  const findings = buildLibraryFindings(libraries, pageUrl);
  await addFindings(tabId, findings, pageUrl, expectedEpoch);
  return { ok: true, findings: findings.length };
}

async function handleMessage(message, sender) {
  const senderTabId = sender.tab?.id;
  const targetTabId = Number.isInteger(message.tabId) ? message.tabId : senderTabId;

  if (message.action === 'get_findings') {
    if (!Number.isInteger(targetTabId)) return emptyTabData();
    const data = await readTabData(targetTabId);
    return {
      ...data,
      raw_values_available: data.findings.some(finding => Boolean(finding.raw_value)),
    };
  }

  if (message.action === 'get_origin_state') {
    const pageUrl = message.pageUrl || sender.tab?.url || '';
    const topLevelUrl = sender.tab?.url || pageUrl;
    await pageIsPaused(pageUrl, topLevelUrl);
    const ownerOrigin = normalizeOrigin(pageUrl);
    const topOrigin = normalizeOrigin(topLevelUrl);
    const ownerPaused = isOriginPaused(pageUrl, pausedOriginsCache);
    const topPaused = isOriginPaused(topLevelUrl, pausedOriginsCache);
    return {
      ok: Boolean(ownerOrigin),
      origin: ownerOrigin,
      topOrigin,
      paused: ownerPaused || topPaused,
      ownerPaused,
      topPaused,
    };
  }

  if (message.action === 'set_origin_paused') {
    const result = await setOriginPaused(message.pageUrl || sender.tab?.url || '', Boolean(message.paused));
    return result;
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

  if (message.action === 'reveal_backend_sample') {
    if (!Number.isInteger(targetTabId)) return { ok: false, error: 'No tab selected.' };
    const sampleKey = String(message.sampleKey || '');
    const data = await readTabData(targetTabId);
    const finding = data.findings.find(item => (
      item.evidence?.raw_sample_available === true
      && item.evidence?.redacted_value === sampleKey
    ));
    if (!finding) return { ok: false, error: 'This finding has no raw sample to reveal.' };
    const rows = baasTabStates.get(targetTabId)?.getRawSample(sampleKey)
      || convexTabStates.get(targetTabId)?.getRawSample(sampleKey);
    if (!rows) {
      return { ok: false, error: 'The in-memory sample expired. Refresh the page to capture it again.' };
    }
    return { ok: true, rows };
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
    if (!Number.isInteger(targetTabId)) return { ok: false, error: 'No tab selected.' };
    return runFullScan(targetTabId, message.url || message.data?.url);
  }

  if (!Number.isInteger(senderTabId) && !Number.isInteger(targetTabId)) {
    return { ok: false, error: 'No sender tab available.' };
  }

  const analysisTabId = Number.isInteger(senderTabId) ? senderTabId : targetTabId;

  if ([
    'analyze_intercepted', 'analyze_content', 'analyze_libraries',
    'analyze_remote_url', 'analyze_devtools_content',
  ].includes(message.action)) {
    message.data = message.data || {};
    const expectedEpoch = activityEpochs.current(analysisTabId);
    let pageUrl = message.data?.pageUrl;
    let topLevelUrl = sender.tab?.url || '';
    if (!pageUrl && message.action === 'analyze_devtools_content' && Number.isInteger(targetTabId)) {
      topLevelUrl = (await chrome.tabs.get(targetTabId)).url;
      pageUrl = topLevelUrl;
    }
    if (!normalizeOrigin(pageUrl) || await activityIsPaused(analysisTabId, expectedEpoch, pageUrl, topLevelUrl)) {
      return { ok: true, skipped: true, reason: 'origin_paused_or_unknown' };
    }
    rememberTabOrigins(analysisTabId, pageUrl, topLevelUrl);
    message.expectedEpoch = expectedEpoch;
    message.data.pageUrl = pageUrl;
  }

  if (message.action === 'analyze_intercepted') {
    return handleAnalyzeIntercepted(analysisTabId, message.data, message.expectedEpoch);
  }

  if (message.action === 'analyze_content') {
    return handleAnalyzeContent(analysisTabId, message.data, message.expectedEpoch);
  }

  if (message.action === 'analyze_libraries') {
    return handleAnalyzeLibraries(analysisTabId, message.data, message.expectedEpoch);
  }

  if (message.action === 'analyze_remote_url') {
    return fetchAndAnalyzeRemote(analysisTabId, message.data || {}, message.expectedEpoch);
  }

  if (message.action === 'analyze_devtools_content') {
    const data = message.data || {};
    if (await activityIsPaused(analysisTabId, message.expectedEpoch, data.pageUrl)) {
      return { ok: true, skipped: true, reason: 'origin_paused' };
    }
    const tabData = await readTabData(analysisTabId, data.pageUrl || data.url);
    tabData.stats.devtoolsBodies += 1;
    if (!await persistTabData(analysisTabId, tabData, message.expectedEpoch)) {
      return { ok: true, skipped: true, reason: 'origin_paused' };
    }
    if (await activityIsPaused(analysisTabId, message.expectedEpoch, data.pageUrl)) {
      return { ok: true, skipped: true, reason: 'origin_paused' };
    }
    const findings = analyzeContent(data.body || '', data.source || data.url || 'DevTools Network Body', {
      url: data.url,
      status: data.status,
      contentType: data.contentType,
      capture_type: 'devtools',
    });
    await addFindings(analysisTabId, findings, data.pageUrl || data.url, message.expectedEpoch);
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
  if (changeInfo.url) topLevelUrls.set(tabId, changeInfo.url);
  if (changeInfo.status === 'loading') {
    activityEpochs.advance(tabId);
    tabObservedOrigins.delete(tabId);
    clearTab(tabId).catch(() => {});
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  tabCache.delete(tabId);
  baasTabStates.delete(tabId);
  convexTabStates.delete(tabId);
  tabObservedOrigins.delete(tabId);
  topLevelUrls.delete(tabId);
  activityEpochs.clear(tabId);
  storageRemove(storageKey(tabId)).catch(() => {});
});

chrome.webRequest.onBeforeSendHeaders.addListener(
  async (details) => {
    if (!Number.isInteger(details.tabId) || details.tabId < 0 || !details.requestHeaders) return;
    const pageOwner = details.documentUrl || details.initiator;
    const tabId = details.tabId;
    if (!normalizeOrigin(pageOwner)) return;
    const expectedEpoch = activityEpochs.current(tabId);
    const topLevelUrl = await topLevelUrlForTab(tabId);
    if (await activityIsPaused(tabId, expectedEpoch, pageOwner, topLevelUrl)) return;
    rememberTabOrigins(tabId, pageOwner, topLevelUrl);
    readTabData(tabId, pageOwner)
      .then((data) => {
        data.stats.requests += 1;
        return persistTabData(tabId, data, expectedEpoch);
      })
      .then(() => {
        if (activityEpochs.current(tabId) !== expectedEpoch) return;
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
            addFindings(tabId, baasFindings, pageOwner, expectedEpoch).catch(() => {});
          });
        }

        return addFindings(tabId, findings, pageOwner, expectedEpoch);
      })
      .catch(() => {});
  },
  { urls: ['<all_urls>'] },
  ['requestHeaders'],
);

chrome.webRequest.onHeadersReceived.addListener(
  async (details) => {
    if (!Number.isInteger(details.tabId) || details.tabId < 0 || !details.responseHeaders) return;
    const pageOwner = details.documentUrl || details.initiator;
    if (!normalizeOrigin(pageOwner)) return;
    const expectedEpoch = activityEpochs.current(details.tabId);
    const topLevelUrl = await topLevelUrlForTab(details.tabId);
    if (await activityIsPaused(details.tabId, expectedEpoch, pageOwner, topLevelUrl)) return;
    rememberTabOrigins(details.tabId, pageOwner, topLevelUrl);
    const headers = details.responseHeaders.map(h => ({ name: h.name, value: h.value || '' }));
    const findings = analyzeHeaders(headers, 'Response Header', {
      url: details.url,
      status: details.statusCode,
      capture_type: 'header',
    });
    addFindings(details.tabId, findings, pageOwner, expectedEpoch).catch(() => {});
  },
  { urls: ['<all_urls>'] },
  ['responseHeaders'],
);

console.log('[KeyLeak] Service worker started - launch-gate monitoring active');
sanitizePersistedFindings().catch(() => {});
