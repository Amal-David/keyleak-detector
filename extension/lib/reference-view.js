/**
 * Reference library tab. Renders every detector grouped by pack with a
 * search filter, and reuses `renderLearnPanel` so the educational content
 * stays consistent with the per-finding Learn panel.
 */

import { renderLearnPanel } from './learn-panel.js';

const PACK_ORDER = ['leak', 'appsec', 'access-control', 'correctness', 'housekeeping'];

const PACK_BLURB = {
  leak: 'Secrets, credentials, source maps, and other concrete browser-visible leaks.',
  appsec: 'SQL injection, XSS, and auth-bypass leads found by pattern.',
  'access-control': 'IDOR and tenant-check leads. Validate with a two-user scan.',
  correctness: 'N+1, regressions, off-by-one, timezone, and config-risk leads.',
  housekeeping: 'Missing tests, dead code, stale documentation leads.',
};

function escapeHtml(value) {
  if (value === null || value === undefined) return '';
  const div = document.createElement('div');
  div.textContent = String(value);
  return div.innerHTML;
}

function formatType(value) {
  return (value || '').replace(/_/g, ' ').toUpperCase();
}

function groupByPack(detectors) {
  const groups = new Map();
  for (const detector of detectors) {
    const pack = detector.pack || 'leak';
    if (!groups.has(pack)) groups.set(pack, []);
    groups.get(pack).push(detector);
  }
  for (const list of groups.values()) {
    list.sort((a, b) => {
      const sevOrder = ['critical', 'high', 'medium', 'low', 'info'];
      const aSev = sevOrder.indexOf(a.severity || 'low');
      const bSev = sevOrder.indexOf(b.severity || 'low');
      if (aSev !== bSev) return aSev - bSev;
      return String(a.id).localeCompare(String(b.id));
    });
  }
  return groups;
}

function filterDetectors(detectors, query) {
  const term = query.trim().toLowerCase();
  if (!term) return detectors;
  return detectors.filter((d) => {
    const haystack = [
      d.id,
      d.detector_id,
      d.pack,
      d.severity,
      d.description,
      d.remediation,
      d.attack_scenario,
      ...(d.categories || []),
    ]
      .filter(Boolean)
      .join(' ')
      .toLowerCase();
    return haystack.includes(term);
  });
}

function renderEntry(detector) {
  const severity = (detector.severity || 'low').toLowerCase();
  return `
    <details class="ref-entry" data-id="${escapeHtml(detector.id)}">
      <summary>
        <span class="severity-badge sev-${escapeHtml(severity)}">${escapeHtml(severity)}</span>
        <span class="ref-type">${escapeHtml(formatType(detector.id))}</span>
        <span class="ref-summary-desc">${escapeHtml(detector.description || '')}</span>
      </summary>
      <div class="ref-body" data-ref-body="${escapeHtml(detector.id)}"></div>
    </details>`;
}

function renderGroup(pack, detectors) {
  if (!detectors.length) return '';
  const blurb = PACK_BLURB[pack] || '';
  return `
    <section class="ref-group">
      <h3 class="ref-group-title">${escapeHtml(pack)} <span class="ref-group-count">(${detectors.length})</span></h3>
      <div class="ref-group-blurb">${escapeHtml(blurb)}</div>
      <div class="ref-group-list">${detectors.map(renderEntry).join('')}</div>
    </section>`;
}

export const REFERENCE_VIEW_CSS = `
.ref-toolbar {
  padding: 10px 16px;
  border-bottom: 1px solid #1e293b;
  background: #0f172a;
}
.ref-search {
  width: 100%;
  background: #0c1222;
  border: 1px solid #334155;
  color: #e2e8f0;
  padding: 6px 10px;
  border-radius: 4px;
  font-family: inherit;
  font-size: 12px;
}
.ref-search:focus { outline: none; border-color: #34d399; }
.ref-empty { padding: 24px 16px; color: #64748b; text-align: center; font-size: 11px; }
.ref-group { padding: 10px 16px; border-bottom: 1px solid #1e293b; }
.ref-group-title { color: #34d399; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 2px; }
.ref-group-count { color: #475569; font-weight: 500; }
.ref-group-blurb { color: #64748b; font-size: 10px; margin-bottom: 6px; line-height: 1.4; }
.ref-entry { border: 1px solid #1e293b; border-radius: 4px; margin: 4px 0; background: #0c1222; }
.ref-entry > summary {
  list-style: none;
  cursor: pointer;
  padding: 6px 8px;
  display: flex;
  gap: 6px;
  align-items: center;
  font-size: 11px;
}
.ref-entry > summary::-webkit-details-marker { display: none; }
.ref-entry > summary:hover { background: #1e293b; }
.ref-type { color: #e2e8f0; font-weight: 700; }
.ref-summary-desc { color: #94a3b8; font-size: 10px; flex: 1; }
.ref-body { padding: 6px 8px 8px; }
`;

/**
 * Mounts the reference view into `rootEl`. Idempotent: calling it twice will
 * replace existing content. The hosting view is expected to render this once
 * the user opens the Reference tab.
 */
export function mountReferenceView(rootEl, detectorInfoMap) {
  if (!rootEl) return;
  const detectors = Object.values(detectorInfoMap || {});

  rootEl.innerHTML = `
    <div class="ref-toolbar">
      <input type="search" class="ref-search" id="refSearch" placeholder="Search detectors, packs, remediation..." autocomplete="off">
    </div>
    <div class="ref-results" id="refResults"></div>`;

  const searchEl = rootEl.querySelector('#refSearch');
  const resultsEl = rootEl.querySelector('#refResults');

  function paint(query) {
    const filtered = filterDetectors(detectors, query);
    if (filtered.length === 0) {
      resultsEl.innerHTML = '<div class="ref-empty">No detectors match this filter.</div>';
      return;
    }
    const groups = groupByPack(filtered);
    const ordered = PACK_ORDER.filter((pack) => groups.has(pack)).concat(
      [...groups.keys()].filter((pack) => !PACK_ORDER.includes(pack)),
    );
    resultsEl.innerHTML = ordered.map((pack) => renderGroup(pack, groups.get(pack))).join('');
  }

  // Lazy-fill Learn content when a detector is expanded so we only pay the
  // rendering cost for things the user actually opens.
  resultsEl.addEventListener('toggle', (event) => {
    const details = event.target;
    if (!(details instanceof HTMLDetailsElement) || !details.open) return;
    const body = details.querySelector('.ref-body');
    if (!body || body.dataset.populated === '1') return;
    const id = details.dataset.id;
    const info = detectorInfoMap[id];
    if (!info) {
      body.textContent = 'No details available.';
      return;
    }
    body.innerHTML = renderLearnPanel(null, info);
    body.dataset.populated = '1';
  }, true);

  searchEl.addEventListener('input', () => paint(searchEl.value));
  paint('');
}
