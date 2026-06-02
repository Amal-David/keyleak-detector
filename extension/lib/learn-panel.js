/**
 * Shared educational panel used by the popup and the DevTools panel.
 *
 * `renderLearnPanel` returns an HTML string for a self-contained panel
 * that explains a finding in user-facing terms. It is XSS-safe: every
 * value coming from a finding or detector record is escaped before it
 * is interpolated into the markup.
 */

function escapeHtml(value) {
  if (value === null || value === undefined) return '';
  const div = document.createElement('div');
  div.textContent = String(value);
  return div.innerHTML;
}

function escapeAttribute(value) {
  return escapeHtml(value).replace(/"/g, '&quot;');
}

function safeUrl(value) {
  const text = String(value || '').trim();
  if (!/^https?:\/\//i.test(text)) return null;
  return text;
}

function formatType(type) {
  return (type || 'unknown').replace(/_/g, ' ').toUpperCase();
}

function renderReferences(references) {
  if (!Array.isArray(references) || references.length === 0) return '';
  const items = references
    .map((ref) => {
      const url = safeUrl(ref);
      if (url) {
        return `<li><a href="${escapeAttribute(url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(url)}</a></li>`;
      }
      return `<li>${escapeHtml(ref)}</li>`;
    })
    .join('');
  return `
    <div class="learn-section">
      <div class="learn-label">References</div>
      <ul class="learn-references">${items}</ul>
    </div>`;
}

function renderSection(label, body) {
  if (!body) return '';
  return `
    <div class="learn-section">
      <div class="learn-label">${escapeHtml(label)}</div>
      <div class="learn-body">${escapeHtml(body)}</div>
    </div>`;
}

/**
 * @param {object} finding   May be empty when the panel renders inside the Reference tab.
 * @param {object} info      Detector info record (from DETECTOR_INFO[id]).
 */
export function renderLearnPanel(finding, info) {
  const detector = info || {};
  const type = finding?.type || detector.finding_type || detector.id || 'detector';
  const severity = (finding?.severity || detector.severity || 'low').toLowerCase();
  const pack = finding?.category || detector.pack || 'leak';
  const detectorId = finding?.detector_id || detector.detector_id || detector.id || '';
  const description = detector.description || finding?.risk_reason || '';
  const attackScenario = detector.attack_scenario || '';
  const remediation = detector.remediation || finding?.remediation || '';
  const riskReason = finding?.risk_reason || '';

  const why = [riskReason, attackScenario && riskReason ? '' : null]
    .filter(Boolean)
    .join(' ');

  const heading = `
    <div class="learn-header">
      <span class="severity-badge sev-${escapeHtml(severity)}">${escapeHtml(severity)}</span>
      <span class="learn-title">${escapeHtml(formatType(type))}</span>
      <span class="learn-detector-id">${escapeHtml(detectorId)}</span>
    </div>`;

  const packLine = `
    <div class="learn-meta">
      pack: <strong>${escapeHtml(pack)}</strong>
      &nbsp;&middot;&nbsp; severity: <strong>${escapeHtml(severity)}</strong>
      ${detector.validation_status ? `&nbsp;&middot;&nbsp; status: <strong>${escapeHtml(detector.validation_status)}</strong>` : ''}
    </div>`;

  return `
    <div class="learn-panel" data-detector-id="${escapeAttribute(detectorId)}">
      ${heading}
      ${packLine}
      ${renderSection('What this is', description)}
      ${renderSection('Why it matters in this app', why || null)}
      ${renderSection('Attack scenario', attackScenario)}
      ${renderSection('Fix', remediation)}
      ${renderReferences(detector.references && detector.references.length ? detector.references : finding?.references)}
    </div>`;
}

/**
 * Shared CSS for the panel. Both popup.html and panel.html link this in via
 * a <link rel="stylesheet"> so the visual treatment stays consistent and we
 * avoid duplicating the rules in two HTML files.
 */
export const LEARN_PANEL_CSS = `
.learn-panel {
  margin-top: 8px;
  padding: 10px 12px;
  border: 1px solid #1e3a5f;
  border-radius: 6px;
  background: #0b1326;
  color: #cbd5e1;
  font-size: 11px;
  line-height: 1.55;
}
.learn-header {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 6px;
  flex-wrap: wrap;
}
.learn-title { color: #e2e8f0; font-weight: 700; font-size: 12px; }
.learn-detector-id { color: #64748b; font-size: 10px; }
.learn-meta { color: #64748b; font-size: 10px; margin-bottom: 8px; }
.learn-section { margin-top: 8px; }
.learn-label {
  color: #475569;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  font-size: 9px;
  margin-bottom: 3px;
}
.learn-body { color: #cbd5e1; }
.learn-references { margin: 4px 0 0 16px; padding: 0; color: #93c5fd; }
.learn-references li { margin: 2px 0; word-break: break-all; }
.learn-references a { color: #93c5fd; text-decoration: none; }
.learn-references a:hover { text-decoration: underline; }
`;
