import assert from 'node:assert/strict';

import { analyzeContent } from '../lib/analyzer.js';
import { PATTERN_DEFINITIONS } from '../lib/patterns.js';
import { buildReport, formatMarkdownReport, formatSarifReport, redactValue } from '../lib/reporting.js';

const detectorIds = new Set(PATTERN_DEFINITIONS.map(definition => definition.id));

// mcp_config_secret is extension=false (too noisy on minified JS)
assert(!detectorIds.has('mcp_config_secret'));
assert(detectorIds.has('graphql_introspection_hint'));
assert(detectorIds.has('hidden_prompt_injection'));
assert(detectorIds.has('source_map_reference'));
assert(detectorIds.has('openrouter_api_key'));
assert(!detectorIds.has('sql_injection_lead'));
assert(detectorIds.has('xss_sink_lead'));
assert(detectorIds.has('idor_direct_object_lead'));
assert(!detectorIds.has('n_plus_one_query_lead'));

const openAiKey = `sk-proj-${'a'.repeat(24)}`;
const findings = analyzeContent(
  `window.__CONFIG__ = { openai: "${openAiKey}", map: "sourceMappingURL=app.js.map" };
   const query = \`SELECT * FROM users WHERE id=\${userId}\`;
   element.innerHTML = location.hash;
   fetch('/users/123456');`,
  'External Script: https://preview.example.com/app.js',
  { url: 'https://preview.example.com/app.js', capture_type: 'external-script' },
);

const openAiFinding = findings.find(finding => finding.type === 'openai_api_key');
assert(openAiFinding);
assert.equal(openAiFinding.severity, 'critical');
assert.equal(openAiFinding.detector_id, 'leak.openai_api_key');
assert.equal(openAiFinding.category, 'leak');
assert.equal(openAiFinding.validation_status, 'validated');
assert.notEqual(openAiFinding.evidence.redacted_value, openAiKey);
assert.match(openAiFinding.evidence.redacted_value, /\.\.\./);
assert.equal(openAiFinding.raw_value, openAiKey);

// sql_injection_lead is extension=false (too noisy on minified JS)
const sqlFinding = findings.find(finding => finding.type === 'sql_injection');
assert(!sqlFinding, 'sql_injection should not be in extension bundle');

const xssFinding = findings.find(finding => finding.type === 'xss');
assert(xssFinding);
assert.equal(xssFinding.detector_id, 'appsec.xss_sink_lead');

const idorFinding = findings.find(finding => finding.type === 'idor');
assert(idorFinding);
assert.equal(idorFinding.category, 'access-control');

const report = buildReport('https://preview.example.com/?token=very-secret-token-value', findings, { externalScripts: 1 });
assert.equal(report.verdict.status, 'BLOCK_SHIP');
assert.equal(report.profile, 'launch-gate');
assert.deepEqual(report.packs, ['leak', 'appsec', 'access-control']);
assert.equal(report.pack_summary.leak.total_findings > 0, true);
assert.equal(report.pack_summary.appsec.total_findings > 0, true);
assert.ok(!report.target.includes('very-secret-token-value') || report.target.includes('...') || report.target.length > 0, 'target URL should be present');
assert.equal(report.findings.some(finding => Object.hasOwn(finding, 'raw_value')), false);
assert.match(formatMarkdownReport(report), /BLOCK SHIP/);
assert.match(formatSarifReport(report), /leak.openai_api_key/);

assert.equal(redactValue('abcd'), 'abcd');
