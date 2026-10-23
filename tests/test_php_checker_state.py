import json
from pathlib import Path
import subprocess
import unittest


class PhpCheckerStateTests(unittest.TestCase):
    def test_newer_actions_keep_their_result_and_loading_state(self):
        harness = r"""
const vm = require('node:vm');
const fs = require('node:fs');
const source = fs.readFileSync(process.argv[1], 'utf8');
function setup() {
  const ids = ['result', 'error', 'url-form', 'version-form', 'version', 'url',
    'authorized', 'check-url', 'result-title', 'result-version', 'result-reason'];
  const nodes = Object.fromEntries(ids.map(id => [id, {value: '', textContent: '',
    hidden: false, disabled: false, checked: true, scrollIntoView() {},
    addEventListener(event, handler) { this[event] = handler; }}]));
  const requests = [];
  vm.runInNewContext(source, {document: {getElementById: id => nodes[id]},
    location: {hostname: 'keyleakdetector.com'}, AbortController,
    setTimeout: () => 0, clearTimeout() {},
    fetch: (_url, options) => new Promise((resolve, reject) => requests.push({resolve, reject, signal: options.signal}))});
  nodes.url.value = 'https://owned.example.test/';
  nodes.version.value = '8.3.36';
  return {nodes, requests};
}
const event = {preventDefault() {}};
const response = status => ({ok: true, json: async () => ({status, version: '', reason: 'Fixture response.'})});
(async () => {
  const results = [];
  for (const outcome of ['response', 'failure']) {
    const {nodes, requests} = setup();
    const pending = nodes['url-form'].submit(event);
    nodes['version-form'].submit(event);
    if (outcome === 'response') requests[0].resolve(response('unknown'));
    else requests[0].reject(new Error('Old request failed.'));
    await pending;
    results.push({name: outcome, title: nodes['result-title'].textContent,
      error: nodes.error.textContent, disabled: nodes['check-url'].disabled,
      aborted: requests[0].signal.aborted});
  }
  const {nodes, requests} = setup();
  const first = nodes['url-form'].submit(event);
  const second = nodes['url-form'].submit(event);
  requests[0].resolve(response('unknown'));
  await first;
  const stillLoading = nodes['check-url'].disabled;
  requests[1].resolve(response('patched_version_reported'));
  await second;
  results.push({name: 'newer-url', title: nodes['result-title'].textContent,
    error: nodes.error.textContent, disabled: nodes['check-url'].disabled,
    aborted: requests[0].signal.aborted, stillLoading});
  console.log(JSON.stringify(results));
})().catch(error => {console.error(error); process.exitCode = 1;});
"""
        script = Path(__file__).resolve().parents[1] / "site/php-check/checker.js"
        result = subprocess.run(["node", "-e", harness, str(script)], check=True,
                                capture_output=True, text=True, timeout=10)
        for state in json.loads(result.stdout):
            with self.subTest(case=state["name"]):
                self.assertEqual(state["title"], "Patched version reported")
                self.assertEqual(state["error"], "")
                self.assertFalse(state["disabled"])
                self.assertTrue(state["aborted"])
                if state["name"] == "newer-url":
                    self.assertTrue(state["stillLoading"])
