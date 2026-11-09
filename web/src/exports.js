import { formatSarifReport } from '../../extension/lib/reporting.js';
import { reportSnapshot } from './storage.js';

const escapeHtml = value => String(value ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
// Escaping also prevents untrusted paths/metadata becoming active Markdown HTML.
const escapeMarkdown = value => String(value ?? '').replace(/[\\`*_{}\[\]()#+.!|<>]/g, '\\$&').replace(/[\r\n]/g, ' ');

export function reportMarkdown(report) {
  const text = escapeMarkdown;
  const lines = ['# KeyLeak browser report', '', `**${text(report.verdict.label)}**`, '', text(report.verdict.reason), '',
    `Generated: ${text(report.generated_at)}`, '', '## Coverage', '',
    `Status: ${text(report.coverage.status || report.coverage.level)}`, '',
    ...((report.coverage.reasons || []).map(reason => `- ${text(typeof reason === 'string' ? reason : reason.message || reason.code)}`)), '',
    'Selected browser checks only. Native browser capture and procedural CLI checks are not included.', '', '## Findings', ''];
  for (const finding of report.findings) {
    lines.push(`### ${text(finding.severity)} — ${text(finding.type)}`, '', `Detector: ${text(finding.detector_id)}`, '',
      `Source: ${text(finding.source)}`, '', 'Credential value: [redacted]', '', text(finding.risk_reason), '', `Remediation: ${text(finding.remediation)}`, '');
  }
  if (!report.findings.length) lines.push('No findings in the selected checks. See coverage for incomplete or unsupported inputs.');
  return lines.join('\n');
}

export function reportHtml(report) {
  const html = escapeHtml;
  const findings = report.findings.map(f => `<article><h2>${html(f.severity)} · ${html(f.type)}</h2><p>Detector: ${html(f.detector_id)}</p><p>Source: ${html(f.source)}</p><p>Credential value: [redacted]</p><p>${html(f.risk_reason)}</p><p><strong>Remediation:</strong> ${html(f.remediation)}</p></article>`).join('');
  const reasons = (report.coverage.reasons || []).map(r => `<li>${html(typeof r === 'string' ? r : r.message || r.code)}</li>`).join('');
  return `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"><title>KeyLeak browser report</title><style>body{font:16px/1.6 system-ui,sans-serif;max-width:900px;margin:40px auto;padding:0 24px;color:#182b25}h1{font-size:32px}article{border-top:1px solid #ccd7d0;padding:20px 0}h2{font-size:19px}p,li{overflow-wrap:anywhere}</style><h1>KeyLeak browser report</h1><h2>${html(report.verdict.label)}</h2><p>${html(report.verdict.reason)}</p><p>Generated: ${html(report.generated_at)}</p><h2>Coverage: ${html(report.coverage.status || report.coverage.level)}</h2><ul>${reasons}</ul><p>Selected browser checks only. Native browser capture and procedural CLI checks are not included.</p>${findings || '<p>No findings in the selected checks. See coverage for incomplete or unsupported inputs.</p>'}</html>`;
}

export function exportReport(report, format) {
  const safe = reportSnapshot(report);
  if (format === 'json') return { content: JSON.stringify(safe, null, 2), extension: 'json', type: 'application/json' };
  if (format === 'sarif') {
    const sarif = JSON.parse(formatSarifReport(safe));
    const run = sarif.runs[0];
    run.tool.driver.name = 'KeyLeak Browser';
    for (let index = 0; index < run.results.length; index += 1) {
      const location = run.results[index].locations[0].physicalLocation;
      location.artifactLocation.uri = String(safe.findings[index].source || 'input').split('/').map(encodeURIComponent).join('/');
      if (!Number.isInteger(safe.findings[index].evidence?.line) || safe.findings[index].evidence.line < 1) delete location.region;
    }
    run.properties = { coverage: safe.coverage, verdict: safe.verdict, acquisition: safe.acquisition || {method:'local-input', uploaded:false} };
    const complete = safe.coverage.status === 'complete';
    const reasons = safe.coverage.reasons || [];
    run.invocations = [{
      executionSuccessful: complete,
      toolExecutionNotifications: complete ? [] : (reasons.length ? reasons : [{message:'Selected inputs were not completely analyzed.'}]).map(reason => ({
        level: 'warning', message: { text: typeof reason === 'string' ? reason : reason.message || reason.code || 'Incomplete coverage.' },
      })),
    }];
    return { content: JSON.stringify(sarif, null, 2), extension: 'sarif', type: 'application/sarif+json' };
  }
  if (format === 'markdown') return { content: reportMarkdown(safe), extension: 'md', type: 'text/markdown' };
  if (format === 'html') return { content: reportHtml(safe), extension: 'html', type: 'text/html' };
  throw new Error('Unsupported export format.');
}
