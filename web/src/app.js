import { openReportStore, reportSnapshot } from './storage.js';
import { exportReport } from './exports.js';
import { fetchPublicResource, discoverSubdomains } from './network.js';

const $ = id => document.getElementById(id);
const MAX_INPUTS = 500;
const MAX_INPUT_BYTES = 20 * 1024 * 1024;
const MAX_TEXT_BYTES = 2 * 1024 * 1024; // The engine's per-file byte limit.
const WORKER_DEADLINE_MS = 25_000;
const labels = { files: 'Scan selected files', text: 'Scan pasted text', url: 'Fetch and scan resource', dns: 'Discover DNS names' };
let selectedTab = 'files';
let selectedFiles = [];
let currentReport = null;
let reportStore = null;
let activeJob = null;
let nextJobId = 0;

function node(tag, text, className) {
  const element = document.createElement(tag);
  if (text !== undefined) element.textContent = String(text);
  if (className) element.className = className;
  return element;
}
function safeMessage(error, fallback) {
  // Messages emitted by our modules are fixed strings. Never display platform
  // errors containing a target URL, credential, or user-supplied file path.
  if (error?.safeMessage) return error.safeMessage;
  if (error?.name === 'NetworkAcquisitionError') return error.message;
  return fallback;
}
function userError(message) { const error = new Error(message); error.safeMessage = message; return error; }
function setStatus(message) { $('scan-status').textContent = message; }
function setError(message = '') { $('scan-error').textContent = message; $('scan-error').hidden = !message; }
function setBusy(value) {
  $('scan-button').disabled = value;
  $('cancel-button').hidden = !value;
  for (const button of document.querySelectorAll('[role=tab]')) button.disabled = value;
  for (const id of ['files', 'folder', 'source-text', 'target-url', 'target-domain', 'load-example', 'empty-example']) $(id).disabled = value;
}
function selectTab(tab) {
  if (activeJob || !Object.hasOwn(labels, tab)) return;
  selectedTab = tab;
  for (const button of document.querySelectorAll('[role=tab]')) {
    const selected = button.dataset.tab === tab;
    button.setAttribute('aria-selected', String(selected));
    button.tabIndex = selected ? 0 : -1;
    $(`panel-${button.dataset.tab}`).hidden = !selected;
  }
  $('scan-button').textContent = labels[tab];
  setError();
}
for (const button of document.querySelectorAll('[role=tab]')) {
  button.addEventListener('click', () => selectTab(button.dataset.tab));
  button.addEventListener('keydown', event => {
    const tabs = [...document.querySelectorAll('[role=tab]')];
    const index = tabs.indexOf(button);
    let target;
    if (event.key === 'ArrowRight') target = tabs[(index + 1) % tabs.length];
    if (event.key === 'ArrowLeft') target = tabs[(index + tabs.length - 1) % tabs.length];
    if (event.key === 'Home') target = tabs[0];
    if (event.key === 'End') target = tabs.at(-1);
    if (target) { event.preventDefault(); selectTab(target.dataset.tab); target.focus(); }
  });
}

function setFiles(files) {
  if (activeJob) return;
  selectedFiles = Array.from(files);
  const bytes = selectedFiles.reduce((total, file) => total + file.size, 0);
  $('selection-status').textContent = selectedFiles.length ? `${selectedFiles.length} file${selectedFiles.length === 1 ? '' : 's'} selected · ${(bytes / (1024 * 1024)).toFixed(2)} MiB` : 'No files selected.';
  setError();
}
$('files').addEventListener('change', event => setFiles(event.target.files));
$('folder').addEventListener('change', event => setFiles(event.target.files));
for (const type of ['dragenter', 'dragover']) $('drop-zone').addEventListener(type, event => { event.preventDefault(); if (!activeJob) $('drop-zone').classList.add('dragging'); });
for (const type of ['dragleave', 'drop']) $('drop-zone').addEventListener(type, event => { event.preventDefault(); $('drop-zone').classList.remove('dragging'); });
$('drop-zone').addEventListener('drop', event => {
  if (activeJob) return;
  const items = [...(event.dataTransfer?.items || [])];
  if (items.some(item => item.webkitGetAsEntry?.()?.isDirectory)) {
    setError('Use Choose folder to inspect a directory, or drop a ZIP. Dragged directories are not read.');
    return;
  }
  setFiles(event.dataTransfer?.files || []);
});
function loadExample() {
  selectTab('text');
  $('source-text').value = ['// Synthetic example only. This is not a usable credential.', `const leakedKey = "sk-proj-${'a'.repeat(24)}";`, 'element.innerHTML = location.hash;'].join('\n');
  $('source-text').focus();
}
$('load-example').addEventListener('click', loadExample);
$('empty-example').addEventListener('click', loadExample);

function isCurrent(job) { return activeJob?.id === job.id && !job.controller.signal.aborted; }
function finish(job) {
  if (activeJob?.id !== job.id) return;
  clearTimeout(job.timer);
  job.worker?.terminate();
  activeJob = null;
  setBusy(false);
}
function clearResults() {
  currentReport = null;
  $('report-content').hidden = true;
  $('discovery-content').hidden = true;
  $('empty-results').hidden = false;
  $('report-state').textContent = 'Working…';
}
async function collectInputs(job) {
  if (selectedTab === 'text') {
    const content = $('source-text').value;
    if (!content.trim()) throw userError('Paste some text before starting a scan.');
    if (new TextEncoder().encode(content).byteLength > MAX_TEXT_BYTES) throw userError('Pasted input exceeds the 2 MiB per-file limit. Paste a smaller excerpt or split the text into files no larger than 2 MiB each.');
    return [{ name: 'Pasted text.txt', content }];
  }
  if (selectedTab === 'url') {
    if (!$('authorized').checked) throw userError('Confirm that you have permission to inspect this target.');
    setStatus('Requesting one HTTPS resource directly from this browser…');
    const resource = await fetchPublicResource($('target-url').value, { signal: job.controller.signal });
    // Keep URLs, query strings and response headers out of durable reports.
    // The acquired bytes alone enter the same analysis path as a selected file.
    return [{ name: 'Fetched resource.txt', content: resource.content, type: resource.type }];
  }
  if (!selectedFiles.length) throw userError('Choose at least one file or ZIP to scan.');
  if (selectedFiles.length > MAX_INPUTS) throw userError('More than 500 files were selected. Choose a smaller folder or file set. No files were scanned.');
  if (selectedFiles.reduce((sum, file) => sum + file.size, 0) > MAX_INPUT_BYTES) throw userError('Selected inputs exceed 20 MiB. Choose a smaller file set. No files were scanned.');
  const inputs = [];
  for (let index = 0; index < selectedFiles.length; index += 1) {
    if (!isCurrent(job)) throw userError('Scan canceled.');
    const file = selectedFiles[index];
    setStatus(`Reading local file ${index + 1} of ${selectedFiles.length}…`);
    let bytes;
    try { bytes = await file.arrayBuffer(); } catch (_) { throw userError('A selected file could not be read. Select the files again. No complete result was produced.'); }
    inputs.push({ name: file.webkitRelativePath || file.name, bytes, type: file.type });
  }
  return inputs;
}
function scanInWorker(job, inputs) {
  return new Promise((resolve, reject) => {
    const worker = new Worker(new URL('./scan-worker.js', import.meta.url), { type: 'module' });
    job.worker = worker;
    job.reject = reject;
    job.timer = setTimeout(() => {
      worker.terminate();
      reject(userError('The scan reached its time limit and was stopped. Coverage is incomplete. Try smaller inputs.'));
    }, WORKER_DEADLINE_MS);
    worker.onerror = () => reject(userError('The local scan worker failed. No complete result was produced.'));
    worker.onmessage = event => {
      if (!isCurrent(job) || event.data?.id !== job.id) return;
      const message = event.data;
      if (message.type === 'progress') {
        const progress = message.progress || {};
        const completed = Number(progress.completed ?? progress.processed ?? progress.files ?? 0);
        setStatus(Number.isFinite(completed) ? `Analyzing locally · ${completed} inputs processed…` : 'Analyzing locally…');
      }
      if (message.type === 'result') { clearTimeout(job.timer); resolve(message.report); }
      if (message.type === 'error') reject(userError('The input could not be analyzed. Coverage is incomplete; try a smaller supported file.'));
    };
    const transfers = inputs.flatMap(input => input.bytes instanceof ArrayBuffer ? [input.bytes] : []);
    worker.postMessage({ type: 'scan', id: job.id, inputs }, transfers);
  });
}

$('scan-button').addEventListener('click', async () => {
  if (activeJob) return;
  const job = { id: String(++nextJobId), controller: new AbortController() };
  activeJob = job;
  setError();
  clearResults();
  setBusy(true);
  try {
    if (selectedTab === 'dns') {
      if (!$('dns-authorized').checked) throw userError('Confirm permission and the DNS resolver disclosure before discovery.');
      setStatus('Querying Google Public DNS for a bounded set of candidate names…');
      const result = await discoverSubdomains($('target-domain').value, { signal: job.controller.signal });
      if (!isCurrent(job)) return;
      finish(job);
      renderDiscovery(result);
      setStatus(result.complete ? 'DNS discovery finished. No websites were fetched or scanned.' : 'DNS discovery is partial. Review unavailable queries and wildcard checks.');
      return;
    }
    const inputs = await collectInputs(job);
    if (!isCurrent(job)) return;
    setStatus('Analyzing locally in a dedicated worker…');
    const report = reportSnapshot(await scanInWorker(job, inputs));
    if (!isCurrent(job)) return;
    const acquisition = selectedTab === 'url' ? 'direct-cors-fetch' : 'local-input';
    report.acquisition = { method: acquisition, uploaded: false };
    finish(job);
    renderReport(report);
    setStatus('Analysis finished. Review findings and coverage below.');
    if ($('save-history').checked && reportStore) {
      try { await reportStore.save(report); await renderHistory(); }
      catch (_) { $('storage-state').textContent = 'This report could not be saved. Export it to keep a copy.'; }
    }
  } catch (error) {
    if (!isCurrent(job)) return;
    finish(job);
    $('report-state').textContent = 'Incomplete';
    setStatus('No complete result was produced.');
    setError(safeMessage(error, 'The operation could not complete. No clean result was produced.'));
  }
});
$('cancel-button').addEventListener('click', () => {
  const job = activeJob;
  if (!job) return;
  job.controller.abort();
  job.worker?.terminate();
  job.reject?.(userError('Scan canceled.'));
  finish(job);
  $('report-state').textContent = 'Canceled';
  setStatus('Canceled. No complete result was produced or saved.');
});

function renderReport(report) {
  currentReport = report;
  $('empty-results').hidden = true;
  $('discovery-content').hidden = true;
  $('report-content').hidden = false;
  $('report-state').textContent = 'Local report';
  $('verdict').dataset.status = report.verdict.status;
  $('verdict-label').textContent = report.verdict.label;
  $('verdict-reason').textContent = report.verdict.reason;
  const metrics = [ ['Findings', report.findings.length, 'total'], ['Critical', report.summary?.critical_severity || 0, 'critical'], ['High', report.summary?.high_severity || 0, 'high'], ['Other', report.findings.filter(f => !['critical', 'high'].includes(f.severity)).length, 'other'] ];
  $('metrics').replaceChildren(...metrics.map(([label, value, level]) => {
    const metric = node('div', undefined, 'metric'); metric.dataset.level = level;
    metric.append(node('strong', value), node('span', label)); return metric;
  }));
  const coverage = report.coverage;
  $('coverage-status').textContent = coverage.status || coverage.level;
  $('coverage-description').textContent = `${coverage.completed ?? 0} completed · ${coverage.skipped ?? 0} skipped · ${coverage.failed ?? 0} failed. Selected browser checks only.`;
  $('coverage-reasons').replaceChildren(...(coverage.reasons || []).map(reason => node('li', typeof reason === 'string' ? reason : reason.message || reason.code)));
  $('findings-list').replaceChildren(...report.findings.map(finding => {
    const details = node('details', undefined, 'finding');
    const summary = node('summary');
    const severity = node('span', String(finding.severity).toUpperCase(), 'severity'); severity.dataset.level = finding.severity;
    summary.append(severity, node('span', String(finding.type).replaceAll('_', ' '), 'finding-name'));
    const body = node('div', undefined, 'finding-detail');
    const add = (label, value) => { const p = node('p'); p.append(node('strong', `${label}: `), document.createTextNode(String(value || 'Unknown'))); body.append(p); };
    add('Detector', finding.detector_id);
    add('Source', finding.source);
    add('Evidence', finding.evidence?.redacted_value || '[redacted]');
    add('Assessment', finding.risk_reason);
    add('Remediation', finding.remediation);
    add('Validation', finding.validation_status);
    details.append(summary, body);
    return details;
  }));
  if (!report.findings.length) $('findings-list').append(node('p', 'No findings in the selected checks. Review coverage before relying on this result.', 'no-findings'));
}
function renderDiscovery(result) {
  $('empty-results').hidden = true;
  $('report-content').hidden = true;
  $('discovery-content').hidden = false;
  $('report-state').textContent = result.complete ? 'DNS observations' : 'Partial DNS observations';
  const wildcardNotice = result.wildcardDetected
    ? 'Wildcard DNS detected; listed names may not represent distinct services.'
    : result.wildcardStatus === 'inconclusive' ? 'The wildcard DNS check was inconclusive; candidate names need manual review.' : '';
  $('discovery-notice').textContent = `${result.notice || ''} ${result.stats?.requests || 0} requests. ${wildcardNotice}`;
  $('discovery-list').replaceChildren(...result.subdomains.map(record => {
    const li = node('li', record.hostname);
    li.append(node('span', `${(record.recordTypes || []).join(', ')} · ${(record.addresses || []).join(', ')}`));
    return li;
  }));
  if (!result.subdomains.length) $('discovery-list').append(node('li', 'No resolving names were observed in this bounded candidate set.'));
  $('discovery-errors').replaceChildren(...(result.errors || []).map(error => node('li', `${error.hostname || 'Discovery'}: ${error.message || error.code}`)));
}

for (const button of document.querySelectorAll('[data-export]')) button.addEventListener('click', () => {
  if (!currentReport) return;
  try {
    const exported = exportReport(currentReport, button.dataset.export);
    const blob = new Blob([exported.content], { type: `${exported.type};charset=utf-8` });
    const url = URL.createObjectURL(blob);
    const link = node('a'); link.href = url; link.download = `keyleak-report.${exported.extension}`;
    document.body.append(link); link.click(); link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1_000);
  } catch (_) { setError('This report could not be exported. Try JSON or run the scan again.'); }
});

async function renderHistory() {
  if (!reportStore) return;
  const records = await reportStore.list();
  $('history-list').replaceChildren(...records.map(record => {
    const li = node('li', undefined, 'history-item');
    const open = node('button', undefined, 'history-open'); open.type = 'button';
    open.append(node('strong', `${record.report.findings.length} findings · ${record.report.verdict.label}`), node('span', new Date(record.createdAt).toLocaleString()));
    open.addEventListener('click', () => { if (!activeJob) renderReport(reportSnapshot(record.report)); });
    const remove = node('button', 'Delete', 'history-delete'); remove.type = 'button';
    remove.addEventListener('click', async () => {
      try { await reportStore.remove(record.id); await renderHistory(); }
      catch (_) { $('storage-state').textContent = 'The report could not be deleted. Try again.'; }
    });
    li.append(open, remove); return li;
  }));
  if (!records.length) $('history-list').append(node('li', 'Your saved scans will appear here.', 'empty-note'));
}
$('clear-history').addEventListener('click', async () => {
  if (!reportStore) return;
  try { await reportStore.clear(); await renderHistory(); $('storage-state').textContent = 'Saved reports cleared. Inputs and the current report remain in memory until you close or reload this page.'; }
  catch (_) { $('storage-state').textContent = 'History could not be cleared. Use your browser’s site-data controls.'; }
});
$('persist-storage').addEventListener('click', async () => {
  try {
    const persisted = await navigator.storage?.persist?.();
    $('storage-state').textContent = persisted ? 'Persistent storage granted. Clearing site data still removes history; keep exports of important reports.' : 'Persistent storage was not granted. Keep exports of important reports.';
  } catch (_) { $('storage-state').textContent = 'Persistent storage is unavailable. Keep exports of important reports.'; }
});
async function initHistory() {
  try {
    reportStore = await openReportStore();
    await renderHistory();
    $('storage-state').textContent = 'Up to 50 redacted reports, stored only in this browser. Export important reports; site data can be cleared.';
  } catch (_) {
    $('save-history').checked = false;
    $('save-history').disabled = true;
    $('persist-storage').disabled = true;
    $('storage-state').textContent = 'Local history is unavailable. You can still scan and export reports.';
  }
}
async function initOffline() {
  if (!('serviceWorker' in navigator)) { $('offline-state').textContent = 'Offline caching unavailable'; return; }
  try {
    const registration = await navigator.serviceWorker.register(new URL('../sw.js', import.meta.url), { scope: new URL('../', import.meta.url).pathname });
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('Offline cache setup timed out.')), 15_000);
      navigator.serviceWorker.ready.then(value => { clearTimeout(timer); resolve(value); }, error => { clearTimeout(timer); reject(error); });
    });
    $('offline-state').textContent = 'Ready for offline file scans';
    registration.addEventListener('updatefound', () => {
      const installing = registration.installing;
      installing?.addEventListener('statechange', () => {
        if (installing.state === 'installed' && navigator.serviceWorker.controller) $('offline-state').textContent = 'Update ready · close other tabs and reopen';
      });
    });
  } catch (_) { $('offline-state').textContent = 'Online assets · offline cache unavailable'; }
}
void initHistory();
void initOffline();
