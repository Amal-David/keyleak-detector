"""Guard: the Chrome extension's hand-ported library-CVE table must stay in
sync with the Python source of truth (keyleak/js_library_cves.py).

The extension cannot import the Python module, so VULN_TABLE is duplicated in
extension/lib/library-cves.js. This test fails loudly if a CVE or library is
added/removed on one side but not the other — the most likely drift.
"""

import re
import unittest
from pathlib import Path

from keyleak.js_library_cves import VULN_TABLE

EXT_JS = Path(__file__).resolve().parents[1] / "extension" / "lib" / "library-cves.js"
CVE_RE = re.compile(r"CVE-\d{4}-\d+")


def _python_cves():
    cves = set()
    for rules in VULN_TABLE.values():
        for rule in rules:
            cves.update(rule["cves"])
    return cves


class ExtensionLibraryCveSyncTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(EXT_JS.exists(), f"missing ported module: {EXT_JS}")
        self.js = EXT_JS.read_text(encoding="utf-8")

    def test_cve_set_matches_python(self):
        js_cves = set(CVE_RE.findall(self.js))
        py_cves = _python_cves()
        self.assertEqual(
            js_cves,
            py_cves,
            "extension/lib/library-cves.js CVE list drifted from "
            "keyleak/js_library_cves.py VULN_TABLE",
        )

    def test_every_python_library_is_present(self):
        for name in VULN_TABLE:
            self.assertIn(
                f"{name}:",
                self.js,
                f"library '{name}' is in the Python VULN_TABLE but not the ported JS table",
            )

    def test_finding_contract_is_preserved(self):
        # The finding type / detector id are what the service worker and report
        # pipeline key on; pin them so a rename can't silently break dedup.
        self.assertIn("type: 'vulnerable_js_library'", self.js)
        self.assertIn("detector_id: 'appsec.vulnerable_js_library'", self.js)


if __name__ == "__main__":
    unittest.main()
