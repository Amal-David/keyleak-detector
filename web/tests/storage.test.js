import test from 'node:test';
import assert from 'node:assert/strict';
import { reportSnapshot, storageName } from '../src/storage.js';
import { exportReport } from '../src/exports.js';
import { scanInputs } from '../src/engine.js';

const report = { generated_at: '2026-11-09', target: 'Selected inputs', packs: ['leak'], verdict: { label: 'REVIEW', status: 'REVIEW', reason: 'Review selected checks.' }, coverage: { status: 'incomplete', covered: [], reasons: [{code:'unsupported',message:'Unsupported input.'}] }, findings: [] };

test('persistence drops raw evidence without mutating live objects', () => {
  const original = { ...report, findings: [{ raw_value: 'private-canary', evidence: { raw_sample_rows: ['private-canary'], body: 'private-canary', redacted_value: '[redacted]' } }], inputs: [{content:'private-canary'}] };
  assert.ok(!JSON.stringify(reportSnapshot(original)).includes('private-canary'));
  assert.equal(original.findings[0].raw_value, 'private-canary');
});
test('project paths use separate history names', () => {
  assert.notEqual(storageName(new URL('https://example.github.io/a/')), storageName(new URL('https://example.github.io/b/')));
});
test('an incomplete zero-finding SARIF is explicitly unsuccessful', () => {
  const sarif = JSON.parse(exportReport(report, 'sarif').content);
  const run = sarif.runs[0];
  assert.equal(run.invocations[0].executionSuccessful, false);
  assert.equal(run.properties.coverage.status, 'incomplete');
  assert.equal(run.tool.driver.name, 'KeyLeak Browser');
  assert.match(run.invocations[0].toolExecutionNotifications[0].message.text, /Unsupported/);
});
test('SARIF keeps redacted findings and encodes source paths without inventing line numbers', async () => {
  const canary = 'sk-proj-' + 'b'.repeat(24);
  const result = await scanInputs([{name:'src/my config.js', content:canary}]);
  const exported = exportReport(result, 'sarif').content;
  const run = JSON.parse(exported).runs[0];
  assert.ok(run.results.length > 0);
  const location = run.results[0].locations[0].physicalLocation;
  assert.equal(location.artifactLocation.uri, 'src/my%20config.js');
  assert.equal(location.region, undefined);
  assert.equal(run.invocations[0].executionSuccessful, true);
  assert.ok(!exported.includes(canary));
});
test('HTML and Markdown exports treat target-controlled text as data', () => {
  const hostile = { ...report, findings: [{ type: '<img src=x onerror=alert(1)>', source: '<script>bad()</script>', detector_id: 'leak.test', severity: 'high', risk_reason: '[click](https://bad.example)', remediation: '<iframe src="x">', raw_value: 'private-canary' }] };
  const html = exportReport(hostile, 'html').content;
  assert.ok(!html.includes('<script>bad()'));
  assert.ok(!html.includes('<img src=x'));
  assert.ok(!html.includes('private-canary'));
  assert.match(html, /default-src 'none'/);
  const markdown = exportReport(hostile, 'markdown').content;
  assert.ok(!markdown.includes('[click](https://bad.example)'));
  assert.match(markdown, /Status: incomplete/);
});
