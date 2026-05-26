import { DETECTOR_INFO, getDetectorInfo } from '../lib/detector-info.js';
import { renderLearnPanel, LEARN_PANEL_CSS } from '../lib/learn-panel.js';
import { mountReferenceView, REFERENCE_VIEW_CSS } from '../lib/reference-view.js';
import { TESTABLE_TYPES } from '../lib/key-tester.js';

const content = document.getElementById('content');
const findingCount = document.getElementById('findingCount');
const clearBtn = document.getElementById('clearBtn');
const filtersEl = document.getElementById('filters');
const scanStatsEl = document.getElementById('scanStats');
const verdictBadge = document.getElementById('verdictBadge');
const verdictReason = document.getElementById('verdictReason');
const targetUrl = document.getElementById('targetUrl');
const coverageEl = document.getElementById('coverage');
const actionStatus = document.getElementById('actionStatus');
const fullScanBtn = document.getElementById('fullScanBtn');
const copyJsonBtn = document.getElementById('copyJsonBtn');
const copyMarkdownBtn = document.getElementById('copyMarkdownBtn');
const revealBtn = document.getElementById('revealBtn');
const tabstripEl = document.getElementById('tabstrip');
const findingsViewEl = document.getElementById('findingsView');
const referenceViewEl = document.getElementById('referenceView');

const activeFilters = new Set(['critical', 'high', 'medium', 'low']);
let activeTab = null;
let latestData = null;
let revealRaw = false;
let referenceMounted = false;

const sharedStyle = document.createElement('style');
sharedStyle.textContent = `${LEARN_PANEL_CSS}\n${REFERENCE_VIEW_CSS}`;
document.head.appendChild(sharedStyle);

async function currentTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab || null;
}

async function loadFindings() {
  activeTab = await currentTab();
  if (!activeTab) return;

  chrome.runtime.sendMessage({ action: 'get_findings', tabId: activeTab.id }, (data) => {
    if (chrome.runtime.lastError || !data) {
      showStatus('Unable to read extension findings yet.');
      return;
    }

    latestData = data;
    render(data);
  });
}

function render(data) {
  const findings = data.findings || [];
  const stats = data.stats || {};
  const report = data.report || {};

  updateVerdict(report, data.url || activeTab?.url || '');
  updateCount(findings);
  renderCoverage(report.coverage || {}, stats, report.packs || []);
  renderStats(stats, findings.length);

  if (findings.length === 0) {
    filtersEl.style.display = 'none';
    content.innerHTML = `
      <div class="status">
        <strong>${escapeHtml(report.verdict?.label || 'SAFE TO SHIP')}</strong><br>
        No findings detected in covered browser surfaces. Run the full local scan before release.
      </div>`;
    return;
  }

  filtersEl.style.display = 'flex';
  renderFindings(findings);
}

function updateVerdict(report, url) {
  const verdict = report.verdict || {
    label: 'SAFE TO SHIP',
    status: 'SAFE_TO_SHIP',
    reason: 'No findings detected in covered browser surfaces.',
  };

  verdictBadge.textContent = verdict.label || 'REVIEW';
  verdictBadge.className = 'verdict-badge';
  if (verdict.status === 'BLOCK_SHIP') {
    verdictBadge.classList.add('verdict-block');
  } else if (verdict.status === 'SAFE_TO_SHIP') {
    verdictBadge.classList.add('verdict-safe');
  } else {
    verdictBadge.classList.add('verdict-review');
  }
  verdictReason.textContent = verdict.reason || '';
  targetUrl.textContent = url || '';
}

function renderCoverage(coverage, stats, packs = []) {
  const covered = coverage.covered || [];
  const totalScanned = Object.values(stats || {}).reduce((sum, value) => sum + (Number(value) || 0), 0);
  const pills = covered.length
    ? covered.map(item => `<span class="pill">${escapeHtml(item)}</span>`).join('')
    : '<span class="pill">waiting for browser activity</span>';
  coverageEl.innerHTML = `
    <div class="section-label">coverage: ${escapeHtml(coverage.level || (totalScanned ? 'partial' : 'waiting'))}</div>
    <div class="pill-row">${pills}</div>
    <div class="pill-row">${packs.map(pack => `<span class="pill">${escapeHtml(pack)}</span>`).join('')}</div>
    <div class="finding-detail">${escapeHtml(coverage.note || 'Run the full local scan for attack-surface coverage.')}</div>
  `;
}

function renderStats(stats, findingsCount) {
  const lines = [];
  const labels = {
    requests: 'headers/URLs',
    bodies: 'fetch/XHR bodies',
    scripts: 'inline scripts',
    externalScripts: 'external scripts',
    sourceMaps: 'source maps',
    dataAttrs: 'data attributes',
    metaTags: 'meta tags',
    storage: 'browser storage',
    websockets: 'WebSocket messages',
    eventStreams: 'SSE messages',
    devtoolsBodies: 'DevTools bodies',
    fullScans: 'full scans',
  };

  for (const [key, label] of Object.entries(labels)) {
    if (stats[key] > 0) lines.push({ count: stats[key], label });
  }

  if (lines.length === 0) {
    scanStatsEl.style.display = 'none';
    return;
  }

  scanStatsEl.style.display = 'block';
  scanStatsEl.innerHTML = `
    <div class="section-label">scan activity</div>
    ${lines.map(l => `<div><span style="color:#34d399;font-weight:700;">${l.count}</span> ${escapeHtml(l.label)}</div>`).join('')}
    ${findingsCount === 0 ? '<div style="color:#34d399;margin-top:5px;">all clean in covered surfaces</div>' : ''}
  `;
}

function updateCount(findings) {
  const count = findings.length;
  findingCount.textContent = count;
  findingCount.className = 'count';

  if (count === 0) {
    findingCount.classList.add('count-zero');
  } else if (findings.some(f => ['critical', 'high'].includes(f.severity))) {
    findingCount.classList.add('count-danger');
  } else {
    findingCount.classList.add('count-warn');
  }
}

function renderFindings(findings) {
  const filtered = findings.filter(f => activeFilters.has(f.severity));

  if (filtered.length === 0) {
    content.innerHTML = '<div class="status">All findings filtered out.</div>';
    return;
  }

  // Group findings with identical key values
  const groups = new Map();
  for (const f of filtered) {
    const key = `${f.type}:${f.evidence?.redacted_value || f.redacted_value || ''}`;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(f);
  }

  content.innerHTML = Array.from(groups.values()).map(group => {
    const f = group[0]; // Representative finding (highest severity first since findings are sorted)
    const evidence = f.evidence || {};
    const value = revealRaw && f.raw_value ? f.raw_value : evidence.redacted_value || f.redacted_value || '[redacted]';

    let locationsHtml = '';
    if (group.length > 1) {
      const locationItems = group.map(g => {
        const src = g.evidence?.source || g.source || 'unknown';
        const url = g.url || g.evidence?.request_url || '';
        const isClickable = url && url.startsWith('http');
        return `<li>${isClickable ? `<a class="source-link" href="#" data-url="${escapeHtml(url)}" data-source="${escapeHtml(src)}">${escapeHtml(src)}</a>` : escapeHtml(src)}</li>`;
      }).join('');
      locationsHtml = `<div class="finding-locations"><strong>Found in ${group.length} locations:</strong><ul>${locationItems}</ul></div>`;
    }

    const sourceDisplay = group.length === 1
      ? `<a class="source-link" href="#" data-url="${escapeHtml(f.url || evidence.request_url || '')}" data-source="${escapeHtml(evidence.source || f.source)}">${escapeHtml(evidence.source || f.source)}</a>`
      : `${group.length} locations`;

    return `
      <div class="finding" data-severity="${escapeHtml(f.severity)}">
        <div class="finding-header">
          <span class="severity-badge sev-${escapeHtml(f.severity)}">${escapeHtml(f.severity)}</span>
          <span class="finding-type">${escapeHtml(formatType(f.type))}</span>
        </div>
        <div class="finding-value">${escapeHtml(value)}</div>
        <div class="finding-detail"><strong>source:</strong> ${sourceDisplay}</div>
        ${locationsHtml}
        <div class="finding-detail"><strong>pack:</strong> ${escapeHtml(f.category || 'unknown')}</div>
        <div class="finding-detail"><strong>confidence:</strong> ${escapeHtml(String(f.confidence || 'n/a'))} | <strong>status:</strong> ${escapeHtml(f.validation_status || 'detected')}</div>
        <div class="finding-detail">${escapeHtml(f.risk_reason || '')}</div>
        <div class="fix"><strong>fix:</strong> ${escapeHtml(f.remediation || 'Review and remove exposed sensitive data.')}</div>
        <div class="finding-actions">
          ${TESTABLE_TYPES.has(f.type) && f.raw_value ? `<button class="test-btn primary" data-id="${escapeHtml(f.id)}" data-type="${escapeHtml(f.type)}" data-raw="${escapeHtml(f.raw_value)}">TEST</button>` : ''}
          <button class="learn-btn" data-id="${escapeHtml(f.id)}" data-detector="${escapeHtml(f.detector_id || '')}">LEARN</button>
          <button class="suppress-btn" data-id="${escapeHtml(f.id)}">SUPPRESS ID</button>
        </div>
        <div class="test-result" data-test-for="${escapeHtml(f.id)}"></div>
        <div class="learn-mount" data-mount-for="${escapeHtml(f.id)}"></div>
      </div>
    `;
  }).join('');
}

function formatType(type) {
  return (type || 'unknown').replace(/_/g, ' ').toUpperCase();
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text || '';
  return div.innerHTML;
}

function showStatus(message) {
  actionStatus.style.display = 'block';
  actionStatus.textContent = message;
}

async function copyReport(format) {
  if (!activeTab) return;
  chrome.runtime.sendMessage({ action: 'export_report', tabId: activeTab.id, format }, async (response) => {
    if (chrome.runtime.lastError || !response?.ok) {
      showStatus(response?.error || 'Unable to export report.');
      return;
    }
    try {
      await navigator.clipboard.writeText(response.content);
      showStatus(`Copied ${format.toUpperCase()} report with redacted evidence.`);
    } catch (_error) {
      showStatus('Clipboard permission was denied. Open DevTools panel and export from there.');
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

  if (latestData) renderFindings(latestData.findings || []);
});

content.addEventListener('click', (event) => {
  const sourceLink = event.target.closest('.source-link');
  if (sourceLink) {
    event.preventDefault();
    const url = sourceLink.dataset.url;
    if (url && url.startsWith('http')) {
      chrome.tabs.create({ url });
    }
    return;
  }

  const testBtn = event.target.closest('.test-btn');
  if (testBtn) {
    const findingId = testBtn.dataset.id;
    const type = testBtn.dataset.type;
    const rawValue = testBtn.dataset.raw;
    const resultEl = content.querySelector(`.test-result[data-test-for="${CSS.escape(findingId)}"]`);
    if (!resultEl) return;
    testBtn.disabled = true;
    testBtn.textContent = 'TESTING...';
    resultEl.innerHTML = '<span class="test-pending">Testing key...</span>';
    chrome.runtime.sendMessage({ action: 'test_key', type, raw_value: rawValue }, (response) => {
      testBtn.disabled = false;
      testBtn.textContent = 'TEST';
      if (!response) {
        resultEl.innerHTML = '<span class="test-error">Test failed — no response.</span>';
        return;
      }
      if (response.status === 'valid') {
        resultEl.innerHTML = `<span class="test-valid">VALID — ${escapeHtml(response.detail)}</span>`;
      } else if (response.status === 'invalid') {
        resultEl.innerHTML = `<span class="test-invalid">INVALID — ${escapeHtml(response.detail)}</span>`;
      } else {
        resultEl.innerHTML = `<span class="test-error">${escapeHtml(response.detail || 'Unknown result')}</span>`;
      }
    });
    return;
  }

  const learnBtn = event.target.closest('.learn-btn');
  if (learnBtn) {
    const findingId = learnBtn.dataset.id;
    const detectorId = learnBtn.dataset.detector;
    const mount = content.querySelector(`.learn-mount[data-mount-for="${CSS.escape(findingId)}"]`);
    if (!mount) return;
    if (mount.dataset.open === '1') {
      mount.innerHTML = '';
      mount.dataset.open = '0';
      learnBtn.textContent = 'LEARN';
      return;
    }
    const finding = (latestData?.findings || []).find(f => f.id === findingId);
    const info = getDetectorInfo(detectorId) || (finding && getDetectorInfo(finding.type)) || null;
    if (!info) {
      mount.innerHTML = '<div class="learn-panel"><div class="learn-body">No reference content for this detector yet.</div></div>';
    } else {
      mount.innerHTML = renderLearnPanel(finding || null, info);
    }
    mount.dataset.open = '1';
    learnBtn.textContent = 'HIDE';
    return;
  }

  const button = event.target.closest('.suppress-btn');
  if (!button || !activeTab) return;
  chrome.runtime.sendMessage({
    action: 'suppress_finding',
    tabId: activeTab.id,
    findingId: button.dataset.id,
  }, (response) => {
    if (chrome.runtime.lastError || !response?.ok) {
      showStatus(response?.error || 'Unable to suppress finding.');
      return;
    }
    showStatus('Suppressed this finding ID for future extension reports.');
    loadFindings();
  });
});

tabstripEl.addEventListener('click', (event) => {
  const btn = event.target.closest('.tab-btn');
  if (!btn) return;
  const view = btn.dataset.view;
  tabstripEl.querySelectorAll('.tab-btn').forEach(b => b.classList.toggle('active', b === btn));
  if (view === 'reference') {
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

clearBtn.addEventListener('click', async () => {
  activeTab = activeTab || await currentTab();
  if (!activeTab) return;
  chrome.runtime.sendMessage({ action: 'clear_findings', tabId: activeTab.id }, () => {
    loadFindings();
  });
});

fullScanBtn.addEventListener('click', async () => {
  activeTab = activeTab || await currentTab();
  if (!activeTab) return;
  showStatus('Running full local scan through http://127.0.0.1:5002 ...');
  chrome.runtime.sendMessage({ action: 'run_full_scan', tabId: activeTab.id, url: activeTab.url }, (response) => {
    if (chrome.runtime.lastError || !response?.ok) {
      showStatus(response?.error || 'Start the local scanner with `poetry run python app.py` or `docker compose up -d`.');
      loadFindings();
      return;
    }
    showStatus('Full local scan completed. Results are attached to this tab report.');
    loadFindings();
  });
});

copyJsonBtn.addEventListener('click', () => copyReport('json'));
copyMarkdownBtn.addEventListener('click', () => copyReport('markdown'));

revealBtn.addEventListener('click', () => {
  revealRaw = !revealRaw;
  revealBtn.textContent = revealRaw ? 'HIDE RAW' : 'REVEAL';
  if (latestData) renderFindings(latestData.findings || []);
});

loadFindings();
