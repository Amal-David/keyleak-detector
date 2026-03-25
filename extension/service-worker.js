/**
 * Service worker for KeyLeak Detector.
 * Coordinates analysis, stores findings per tab, updates badge.
 */

import { analyzeContent, analyzeHeaders, analyzeUrl } from './lib/analyzer.js';

// Per-tab findings storage
const tabFindings = new Map(); // tabId -> { findings: [], url: '' }

// --- Badge Management ---

function updateBadge(tabId) {
  const data = tabFindings.get(tabId);
  if (!data || data.findings.length === 0) {
    chrome.action.setBadgeText({ text: '', tabId });
    return;
  }

  const count = data.findings.length;
  const hasHigh = data.findings.some(f => f.severity === 'high');

  chrome.action.setBadgeText({ text: String(count), tabId });
  chrome.action.setBadgeBackgroundColor({
    color: hasHigh ? '#DC2626' : '#F59E0B', // red for high, amber for medium
    tabId,
  });
}

function addFindings(tabId, newFindings, pageUrl) {
  if (!newFindings || newFindings.length === 0) return;

  if (!tabFindings.has(tabId)) {
    tabFindings.set(tabId, { findings: [], url: pageUrl || '' });
  }

  const data = tabFindings.get(tabId);
  if (pageUrl) data.url = pageUrl;

  // Deduplicate by type+value
  const existing = new Set(data.findings.map(f => `${f.type}:${f.value}`));
  for (const finding of newFindings) {
    const key = `${finding.type}:${finding.value}`;
    if (!existing.has(key)) {
      existing.add(key);
      data.findings.push(finding);
    }
  }

  // Sort by severity
  const sevOrder = { high: 0, medium: 1, low: 2 };
  data.findings.sort((a, b) => (sevOrder[a.severity] ?? 3) - (sevOrder[b.severity] ?? 3));

  // Cap at 200 findings per tab
  if (data.findings.length > 200) {
    data.findings = data.findings.slice(0, 200);
  }

  updateBadge(tabId);
}

// --- Message Handler ---

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const tabId = sender.tab?.id;
  if (!tabId) return;

  if (message.action === 'analyze_intercepted') {
    const { url, body, headers, pageUrl } = message.data;
    const findings = [];

    // Analyze URL
    findings.push(...analyzeUrl(url));

    // Analyze response headers
    if (headers) {
      findings.push(...analyzeHeaders(headers, 'Response Header'));
    }

    // Analyze response body
    if (body) {
      findings.push(...analyzeContent(body, 'Response Body'));
    }

    addFindings(tabId, findings, pageUrl);
  }

  if (message.action === 'analyze_content') {
    const { content, source, pageUrl } = message.data;
    const findings = analyzeContent(content, source);
    addFindings(tabId, findings, pageUrl);
  }

  if (message.action === 'get_findings') {
    const data = tabFindings.get(message.tabId || tabId) || { findings: [], url: '' };
    sendResponse(data);
    return true; // async response
  }

  if (message.action === 'clear_findings') {
    const targetTabId = message.tabId || tabId;
    tabFindings.delete(targetTabId);
    updateBadge(targetTabId);
    sendResponse({ ok: true });
    return true;
  }
});

// --- Tab Lifecycle ---

// Clear findings when a tab navigates to a new page
chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === 'loading' && changeInfo.url) {
    tabFindings.delete(tabId);
    updateBadge(tabId);
  }
});

// Clean up when tabs are closed
chrome.tabs.onRemoved.addListener((tabId) => {
  tabFindings.delete(tabId);
});

// --- Header Analysis via webRequest ---

// Analyze request headers for leaked secrets
chrome.webRequest.onBeforeSendHeaders.addListener(
  (details) => {
    if (!details.tabId || details.tabId < 0) return;
    if (!details.requestHeaders) return;

    const headers = details.requestHeaders.map(h => ({ name: h.name, value: h.value || '' }));
    const findings = analyzeHeaders(headers, 'Request Header');
    const urlFindings = analyzeUrl(details.url);

    addFindings(details.tabId, [...findings, ...urlFindings], details.url);
  },
  { urls: ['<all_urls>'] },
  ['requestHeaders']
);

// Analyze response headers
chrome.webRequest.onHeadersReceived.addListener(
  (details) => {
    if (!details.tabId || details.tabId < 0) return;
    if (!details.responseHeaders) return;

    const headers = details.responseHeaders.map(h => ({ name: h.name, value: h.value || '' }));
    const findings = analyzeHeaders(headers, 'Response Header');

    addFindings(details.tabId, findings, details.url);
  },
  { urls: ['<all_urls>'] },
  ['responseHeaders']
);

console.log('[KeyLeak] Service worker started — passive monitoring active');
