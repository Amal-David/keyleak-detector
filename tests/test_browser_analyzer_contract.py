"""Run the browser's actual analyzer call without a browser or network access."""

import json
import shutil
import subprocess
import unittest

from keyleak.browser_scanner import _RUN_ANALYZER_SCRIPT


@unittest.skipUnless(shutil.which("node"), "Node is required to exercise the analyzer JavaScript")
class BrowserAnalyzerContractTests(unittest.TestCase):
    def test_missing_or_invalid_analyzer_fails_but_clean_empty_result_is_valid(self):
        harness = r"""
const vm = require('node:vm');
const fs = require('node:fs');
const script = JSON.parse(fs.readFileSync(0, 'utf8'));
(async () => {
const cases = {
  missing: {},
  non_callable: {__keyleak_run: true},
  invalid_result: {__keyleak_run: () => ({})},
  async_invalid: {__keyleak_run: async () => ({})},
  async_failure: {__keyleak_run: async () => { throw new Error('analyzer failed'); }},
  clean: {__keyleak_run: () => []},
  async_clean: {__keyleak_run: async () => []},
  finding: {__keyleak_run: () => [{type: 'fixture'}]},
};
const results = {};
for (const [name, window] of Object.entries(cases)) {
  try {
    results[name] = {findings: await vm.runInNewContext('(' + script + ')()', {window}, {timeout: 1000})};
  } catch (error) {
    results[name] = {error: error.message};
  }
}
process.stdout.write(JSON.stringify(results));
})().catch(error => { console.error(error); process.exitCode = 1; });
"""
        result = subprocess.run(
            [shutil.which("node"), "-e", harness], input=json.dumps(_RUN_ANALYZER_SCRIPT),
            text=True, capture_output=True, check=True, timeout=10,
        )
        cases = json.loads(result.stdout)
        for name in ("missing", "non_callable", "invalid_result", "async_invalid"):
            self.assertIn("scan is incomplete", cases[name]["error"])
        self.assertEqual(cases["clean"], {"findings": []})
        self.assertEqual(cases["async_clean"], {"findings": []})
        self.assertEqual(cases["async_failure"], {"error": "analyzer failed"})
        self.assertEqual(cases["finding"], {"findings": [{"type": "fixture"}]})
