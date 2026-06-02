import { DETECTOR_INFO, getDetectorInfo } from '../lib/detector-info.js';
import { renderLearnPanel, LEARN_PANEL_CSS } from '../lib/learn-panel.js';
import { mountReferenceView, REFERENCE_VIEW_CSS } from '../lib/reference-view.js';

const content = document.getElementById('content');
const stats = document.getElementById('stats');
const clearBtn = document.getElementById('clearBtn');
const filtersEl = document.getElementById('filters');
const verdictBadge = document.getElementById('verdictBadge');
const verdictReason = document.getElementById('verdictReason');
const coverageEl = document.getElementById('coverage');
const statusEl = document.getElementById('status');
const copyJsonBtn = document.getElementById('copyJsonBtn');
const copyMarkdownBtn = document.getElementById('copyMarkdownBtn');
const tabstripEl = document.getElementById('tabstrip');
const findingsViewEl = document.getElementById('findingsView');
const referenceViewEl = document.getElementById('referenceView');

const activeFilters = new Set(['critical', 'high', 'medium', 'low']);
const MAX_DEVTOOLS_BODY = 2 * 1024 * 1024;
let pollInterval = null;
let latestData = null;
let referenceMounted = false;

const sharedStyle = document.createElement('style');
sharedStyle.textContent = `${LEARN_PANEL_CSS}\n${REFERENCE_VIEW_CSS}`;
document.head.appendChild(sharedStyle);

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text || '';
  return div.innerHTML;
}

function formatType(type) {
  return (type || 'unknown').replace(/_/g, ' ').toUpperCase();
}

function updateStats(report) {
  const summary = report.summary || {};
  stats.innerHTML = `
    <span class="stat stat-total">${summary.total_findings || 0} total</span>
    ${summary.critical_severity > 0 ? `<span class="stat stat-critical">${summary.critical_severity} critical</span>` : ''}
    ${summary.high_severity > 0 ? `<span class="stat stat-high">${summary.high_severity} high</span>` : ''}
    ${summary.medium_severity > 0 ? `<span class="stat stat-medium">${summary.medium_severity} med</span>` : ''}
    ${summary.low_severity > 0 ? `<span class="stat stat-low">${summary.low_severity} low</span>` : ''}
  `;
}

function updateVerdict(report) {
  const verdict = report.verdict || {};
  verdictBadge.textContent = verdict.label || 'SAFE TO SHIP';
  verdictBadge.className = 'verdict-badge';
  if (verdict.status === 'BLOCK_SHIP') {
    verdictBadge.classList.add('verdict-block');
  } else if (verdict.status === 'SAFE_TO_SHIP') {
    verdictBadge.classList.add('verdict-safe');
  } else {
    verdictBadge.classList.add('verdict-review');
  }
  verdictReason.textContent = verdict.reason || '';

  const coverage = report.coverage || {};
  const covered = coverage.covered || [];
  const packs = report.packs || [];
  coverageEl.textContent = covered.length
    ? `coverage: ${coverage.level || 'partial'} | packs: ${packs.join(', ') || 'none'} | ${covered.join(', ')}`
    : `coverage: waiting for browser activity | packs: ${packs.join(', ') || 'none'}`;
}

function renderFindings(findings) {
  const filtered = findings.filter(f => activeFilters.has(f.severity));

  if (filtered.length === 0) {
    content.innerHTML = '<div class="empty">No findings for the active filters.</div>';
    return;
  }

  content.innerHTML = `
    <table>
      <thead>
        <tr>
          <th>Severity</th>
          <th>Type</th>
          <th>Evidence</th>
          <th>Source</th>
          <th>Fix</th>
        </tr>
      </thead>
      <tbody>
        ${filtered.map(f => {
          const evidence = f.evidence || {};
          return `
            <tr data-severity="${escapeHtml(f.severity)}" data-finding-id="${escapeHtml(f.id)}">
              <td><span class="severity-badge sev-${escapeHtml(f.severity)}">${escapeHtml(f.severity)}</span></td>
              <td class="type-cell">${escapeHtml(formatType(f.type))}<br><span style="color:#64748b;font-size:10px;">${escapeHtml(f.category || 'unknown')} | ${escapeHtml(f.detector_id)}</span></td>
              <td class="value-cell">${escapeHtml(evidence.redacted_value || f.redacted_value || '[redacted]')}</td>
              <td class="source-cell">${escapeHtml(evidence.source || f.source || '')}<br>${escapeHtml(evidence.request_url || f.url || '')}</td>
              <td class="context-cell">
                <button class="row-learn-btn" data-id="${escapeHtml(f.id)}" data-detector="${escapeHtml(f.detector_id || '')}">LEARN</button>
                ${escapeHtml(f.remediation || '')}
              </td>
            </tr>
          `;
        }).join('')}
      </tbody>
    </table>
  `;
}

function loadFindings() {
  const tabId = chrome.devtools.inspectedWindow.tabId;
  chrome.runtime.sendMessage({ action: 'get_findings', tabId }, (data) => {
    if (chrome.runtime.lastError || !data) return;
    latestData = data;
    const report = data.report || { findings: data.findings || [] };
    updateStats(report);
    updateVerdict(report);
    renderFindings(report.findings || data.findings || []);
  });
}

function exportReport(format) {
  const tabId = chrome.devtools.inspectedWindow.tabId;
  chrome.runtime.sendMessage({ action: 'export_report', tabId, format }, async (response) => {
    if (chrome.runtime.lastError || !response?.ok) {
      statusEl.textContent = response?.error || 'Unable to export report.';
      return;
    }
    try {
      await navigator.clipboard.writeText(response.content);
      statusEl.textContent = `Copied ${format.toUpperCase()} report with redacted evidence.`;
    } catch (_error) {
      statusEl.textContent = 'Clipboard permission denied.';
    }
  });
}

filtersEl.addEventListener('click', (event) => {
  const btn = event.target.closest('.filter-btn');
  if (!btn) return;
  const sev = btn.dataset.severity;
  if (activeFilters.has(sev)) {
    activeFilters.delete(sev);
    btn.classList.remove('active');
    btn.classList.add('inactive');
  } else {
    activeFilters.add(sev);
    btn.classList.remove('inactive');
    btn.classList.add('active');
  }
  const report = latestData?.report || {};
  renderFindings(report.findings || latestData?.findings || []);
});

clearBtn.addEventListener('click', () => {
  const tabId = chrome.devtools.inspectedWindow.tabId;
  chrome.runtime.sendMessage({ action: 'clear_findings', tabId }, () => loadFindings());
});

copyJsonBtn.addEventListener('click', () => exportReport('json'));
copyMarkdownBtn.addEventListener('click', () => exportReport('markdown'));

content.addEventListener('click', (event) => {
  const btn = event.target.closest('.row-learn-btn');
  if (!btn) return;
  const row = btn.closest('tr[data-finding-id]');
  if (!row) return;
  const findingId = btn.dataset.id;
  const detectorId = btn.dataset.detector;
  const next = row.nextElementSibling;
  if (next && next.classList.contains('learn-row') && next.dataset.for === findingId) {
    next.remove();
    btn.textContent = 'LEARN';
    return;
  }
  const findings = latestData?.report?.findings || latestData?.findings || [];
  const finding = findings.find(f => f.id === findingId);
  const info = getDetectorInfo(detectorId) || (finding && getDetectorInfo(finding.type)) || null;
  // Version-based detectors (vulnerable_js_library) and active probes (BaaS)
  // have no DETECTOR_INFO entry but carry their own risk/fix/references, so
  // render from the finding itself rather than showing an empty panel.
  const html = (info || finding)
    ? renderLearnPanel(finding || null, info)
    : '<div class="learn-panel"><div class="learn-body">No reference content for this detector yet.</div></div>';
  const learnRow = document.createElement('tr');
  learnRow.className = 'learn-row';
  learnRow.dataset.for = findingId;
  learnRow.innerHTML = `<td colspan="5">${html}</td>`;
  row.parentNode.insertBefore(learnRow, row.nextSibling);
  btn.textContent = 'HIDE';
});

tabstripEl.addEventListener('click', (event) => {
  const btn = event.target.closest('.tab-btn');
  if (!btn) return;
  tabstripEl.querySelectorAll('.tab-btn').forEach(b => b.classList.toggle('active', b === btn));
  if (btn.dataset.view === 'reference') {
    findingsViewEl.style.display = 'none';
    referenceViewEl.style.display = 'block';
    if (!referenceMounted) {
      mountReferenceView(referenceViewEl, DETECTOR_INFO);
      referenceMounted = true;
    }
  } else {
    findingsViewEl.style.display = '';
    referenceViewEl.style.display = 'none';
  }
});

chrome.devtools.network.onRequestFinished.addListener((request) => {
  request.getContent((body) => {
    if (!body || body.length > MAX_DEVTOOLS_BODY) return;
    const contentTypeHeader = (request.response.headers || []).find(header => header.name.toLowerCase() === 'content-type');
    const tabId = chrome.devtools.inspectedWindow.tabId;
    chrome.runtime.sendMessage({
      action: 'analyze_devtools_content',
      tabId,
      data: {
        body,
        source: `DevTools Network Body: ${request.request.url}`,
        url: request.request.url,
        status: request.response.status,
        contentType: contentTypeHeader?.value || '',
      },
    }, () => loadFindings());
  });
});

loadFindings();
pollInterval = setInterval(loadFindings, 2000);

window.addEventListener('unload', () => {
  if (pollInterval) clearInterval(pollInterval);
});
