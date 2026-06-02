import assert from 'node:assert/strict';
import { test } from 'node:test';

import { parseVersion, matchLibraryCves, buildLibraryFindings } from '../lib/library-cves.js';

test('parseVersion tolerates loose strings and rejects malformed ones', () => {
  assert.deepEqual(parseVersion('1.7.2'), [1, 7, 2]);
  assert.deepEqual(parseVersion('v3.4.0-beta'), [3, 4, 0]);
  assert.deepEqual(parseVersion('2'), [2, 0, 0]);
  assert.equal(parseVersion('3..5'), null);
  assert.equal(parseVersion('.5'), null);
  assert.equal(parseVersion(''), null);
  assert.equal(parseVersion(null), null);
});

test('jQuery below 1.9 matches the full vulnerability cascade as high', () => {
  const matched = matchLibraryCves('jquery', '1.7.2');
  const cves = matched.flatMap(rule => rule.cves);
  assert.ok(cves.includes('CVE-2012-6708'));
  assert.ok(cves.includes('CVE-2020-11022'));
  assert.equal(matched.length, 4);
});

test('jQuery 3.4.1 only matches the htmlPrefilter rules', () => {
  const cves = matchLibraryCves('jquery', '3.4.1').flatMap(rule => rule.cves);
  assert.deepEqual(new Set(cves), new Set(['CVE-2020-11022', 'CVE-2020-11023']));
});

test('safe and unknown libraries produce no matches', () => {
  assert.equal(matchLibraryCves('jquery', '3.7.1').length, 0);
  assert.equal(matchLibraryCves('bootstrap', '5.3.0').length, 0);
  assert.equal(matchLibraryCves('react', '17.0.2').length, 0);
});

test('Bootstrap 4.6.2 is flagged for the carousel XSS CVE', () => {
  const cves = matchLibraryCves('bootstrap', '4.6.2').flatMap(rule => rule.cves);
  assert.ok(cves.includes('CVE-2024-6531'));
});

test('buildLibraryFindings emits one deduped finding with NVD references', () => {
  const findings = buildLibraryFindings(
    [
      { name: 'jquery', version: '1.7.2', source: 'global' },
      { name: 'jquery', version: '1.7.2', source: 'global' },
      { name: 'jquery', version: '3.7.1', source: 'global' },
    ],
    'https://example.test/',
  );
  assert.equal(findings.length, 1);
  const finding = findings[0];
  assert.equal(finding.type, 'vulnerable_js_library');
  assert.equal(finding.detector_id, 'appsec.vulnerable_js_library');
  assert.equal(finding.severity, 'high');
  assert.equal(finding.validation_status, 'lead');
  assert.ok(finding.references.every(ref => ref.startsWith('https://nvd.nist.gov/vuln/detail/CVE-')));
  assert.ok(finding.references.length >= 1);
});

test('buildLibraryFindings ignores entries missing a name or version', () => {
  assert.equal(buildLibraryFindings([{ name: 'jquery' }, { version: '1.0.0' }, {}]).length, 0);
});
