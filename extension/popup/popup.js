const content = document.getElementById('content');
const findingCount = document.getElementById('findingCount');
const clearBtn = document.getElementById('clearBtn');
const filtersEl = document.getElementById('filters');
const scanStatsEl = document.getElementById('scanStats');

const activeFilters = new Set(['high', 'medium', 'low']);

async function loadFindings() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab) return;

  chrome.runtime.sendMessage({ action: 'get_findings', tabId: tab.id }, (data) => {
    if (chrome.runtime.lastError || !data) return;

    const findings = data.findings || [];
    const stats = data.stats || { requests: 0, bodies: 0, scripts: 0, dataAttrs: 0, metaTags: 0 };

    updateCount(findings);
    renderStats(stats, findings.length);

    if (findings.length === 0) {
      const totalScanned = stats.requests + stats.bodies + stats.scripts + stats.dataAttrs + stats.metaTags;
      if (totalScanned > 0) {
        content.innerHTML = `
          <div class="status">
            <div class="icon">&#x2714;</div>
            <div>No secrets detected</div>
          </div>`;
      } else {
        content.innerHTML = `
          <div class="status">
            <div class="icon">&#x2714;</div>
            <div>Monitoring active. Browse normally.</div>
          </div>`;
      }
      filtersEl.style.display = 'none';
      return;
    }

    filtersEl.style.display = 'flex';
    renderFindings(findings);
  });
}

function renderStats(stats, findingsCount) {
  const totalScanned = stats.requests + stats.bodies + stats.scripts + stats.dataAttrs + stats.metaTags;
  if (totalScanned === 0) {
    scanStatsEl.style.display = 'none';
    return;
  }

  scanStatsEl.style.display = 'block';

  const lines = [];
  if (stats.requests > 0) lines.push({ count: stats.requests, label: 'network requests' });
  if (stats.bodies > 0)   lines.push({ count: stats.bodies, label: 'response bodies' });
  if (stats.scripts > 0)  lines.push({ count: stats.scripts, label: 'inline scripts' });
  if (stats.dataAttrs > 0) lines.push({ count: stats.dataAttrs, label: 'data attributes' });
  if (stats.metaTags > 0) lines.push({ count: stats.metaTags, label: 'meta tags' });

  const statsHtml = lines.map(l =>
    `<div class="stat-line"><span class="stat-count">${l.count}</span><span class="stat-label">${l.label}</span></div>`
  ).join('');

  const cleanLine = findingsCount === 0
    ? '<div class="all-clean">all clean</div>'
    : '';

  scanStatsEl.innerHTML = `
    <div class="stats-header">scan activity</div>
    ${statsHtml}
    ${cleanLine}
  `;
}

function updateCount(findings) {
  const count = findings.length;
  findingCount.textContent = count;
  findingCount.className = 'count';

  if (count === 0) {
    findingCount.classList.add('count-zero');
  } else if (findings.some(f => f.severity === 'high')) {
    findingCount.classList.add('count-danger');
  } else {
    findingCount.classList.add('count-warn');
  }
}

function renderFindings(findings) {
  const filtered = findings.filter(f => activeFilters.has(f.severity));

  if (filtered.length === 0) {
    content.innerHTML = `
      <div class="status">
        <div style="color: #475569;">All findings filtered out.</div>
      </div>`;
    return;
  }

  content.innerHTML = filtered.map(f => `
    <div class="finding" data-severity="${f.severity}">
      <div class="finding-header">
        <span class="severity-badge sev-${f.severity}">${f.severity}</span>
        <span class="finding-type">${formatType(f.type)}</span>
      </div>
      <div class="finding-value">${escapeHtml(f.value)}</div>
      <div class="finding-source">${escapeHtml(f.source)}</div>
    </div>
  `).join('');
}

function formatType(type) {
  return (type || 'unknown').replace(/_/g, ' ').toUpperCase();
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text || '';
  return div.innerHTML;
}

// Filter toggles
filtersEl.addEventListener('click', (e) => {
  const btn = e.target.closest('.filter-btn');
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

  loadFindings();
});

// Clear button
clearBtn.addEventListener('click', async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab) return;
  chrome.runtime.sendMessage({ action: 'clear_findings', tabId: tab.id }, () => {
    loadFindings();
  });
});

// Load on open
loadFindings();
