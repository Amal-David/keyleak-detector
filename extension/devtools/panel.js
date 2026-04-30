const content = document.getElementById('content');
const stats = document.getElementById('stats');
const clearBtn = document.getElementById('clearBtn');
const filtersEl = document.getElementById('filters');
const activeFilters = new Set(['high', 'medium', 'low']);

let pollInterval = null;

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text || '';
  return div.innerHTML;
}

function formatType(type) {
  return (type || 'unknown').replace(/_/g, ' ').toUpperCase();
}

function updateStats(findings) {
  const high = findings.filter(f => f.severity === 'high').length;
  const medium = findings.filter(f => f.severity === 'medium').length;
  const low = findings.filter(f => f.severity === 'low').length;
  const total = findings.length;

  stats.innerHTML = `
    <span class="stat stat-total">${total} total</span>
    ${high > 0 ? `<span class="stat stat-high">${high} high</span>` : ''}
    ${medium > 0 ? `<span class="stat stat-medium">${medium} med</span>` : ''}
    ${low > 0 ? `<span class="stat stat-low">${low} low</span>` : ''}
  `;
}

function renderFindings(findings) {
  const filtered = findings.filter(f => activeFilters.has(f.severity));

  if (filtered.length === 0) {
    content.innerHTML = '<div class="empty">No findings yet. Browse a page to start scanning.</div>';
    return;
  }

  content.innerHTML = `
    <table>
      <thead>
        <tr>
          <th class="sev-cell">Severity</th>
          <th>Type</th>
          <th>Value</th>
          <th>Source</th>
          <th>Context</th>
        </tr>
      </thead>
      <tbody>
        ${filtered.map(f => `
          <tr data-severity="${f.severity}">
            <td class="sev-cell"><span class="severity-badge sev-${f.severity}">${f.severity}</span></td>
            <td class="type-cell">${escapeHtml(formatType(f.type))}</td>
            <td class="value-cell">${escapeHtml(f.value)}</td>
            <td class="source-cell">${escapeHtml(f.source)}</td>
            <td class="context-cell" title="${escapeHtml(f.context || '')}">${escapeHtml(f.context || '')}</td>
          </tr>
        `).join('')}
      </tbody>
    </table>
  `;
}

function loadFindings() {
  const tabId = chrome.devtools.inspectedWindow.tabId;
  chrome.runtime.sendMessage({ action: 'get_findings', tabId }, (data) => {
    if (chrome.runtime.lastError || !data) return;
    const findings = data.findings || [];
    updateStats(findings);
    renderFindings(findings);
  });
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

// Clear
clearBtn.addEventListener('click', () => {
  const tabId = chrome.devtools.inspectedWindow.tabId;
  chrome.runtime.sendMessage({ action: 'clear_findings', tabId }, () => {
    loadFindings();
  });
});

// Poll for updates every 2 seconds
loadFindings();
pollInterval = setInterval(loadFindings, 2000);
