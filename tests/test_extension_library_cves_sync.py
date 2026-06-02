"""Guard: the Chrome extension's hand-ported library-CVE table must stay in
sync with the Python source of truth (keyleak/js_library_cves.py).

The extension cannot import the Python module, so VULN_TABLE is duplicated in
extension/lib/library-cves.js. This test parses the JS table and compares the
full rule set (library, introduced/below version bounds, severity, and CVEs) so
drift in *any* of those fields — not just the flattened CVE list — fails loudly.
"""

import re
import unittest
from pathlib import Path

from keyleak.js_library_cves import VULN_TABLE

EXT_JS = Path(__file__).resolve().parents[1] / "extension" / "lib" / "library-cves.js"
CVE_RE = re.compile(r"CVE-\d{4}-\d+")
TRIPLE_RE = re.compile(r"\[(\d+),\s*(\d+),\s*(\d+)\]")
SEVERITY_RE = re.compile(r"severity:\s*'([^']+)'")
BELOW_RE = re.compile(r"below:\s*\[(\d+),\s*(\d+),\s*(\d+)\]")
INTRODUCED_RE = re.compile(r"introduced:\s*\[(\d+),\s*(\d+),\s*(\d+)\]")
CVES_RE = re.compile(r"cves:\s*\[([^\]]*)\]")


def _balanced(text, open_ch, close_ch, start):
    """Return the inner content of the first balanced open_ch..close_ch run
    at/after start. Summaries in the table contain parentheses but no braces or
    square brackets, so single-character depth counting is unambiguous here."""
    i = text.index(open_ch, start)
    depth = 0
    for j in range(i, len(text)):
        if text[j] == open_ch:
            depth += 1
        elif text[j] == close_ch:
            depth -= 1
            if depth == 0:
                return text[i + 1 : j], j
    raise AssertionError("unbalanced block in library-cves.js")


def _rule_tuple(rule_src):
    below = BELOW_RE.search(rule_src)
    assert below, f"rule missing 'below': {rule_src!r}"
    introduced = INTRODUCED_RE.search(rule_src)
    intro = tuple(int(x) for x in introduced.groups()) if introduced else (0, 0, 0)
    severity = SEVERITY_RE.search(rule_src)
    assert severity, f"rule missing 'severity': {rule_src!r}"
    cves = tuple(sorted(CVE_RE.findall(CVES_RE.search(rule_src).group(1))))
    return (intro, tuple(int(x) for x in below.groups()), severity.group(1), cves)


def parse_js_vuln_table(js):
    body, _ = _balanced(js, "{", "}", js.index("const VULN_TABLE"))
    key_re = re.compile(r"(\w+):\s*\[")
    table = {}
    pos = 0
    # Walk only the top level: after consuming each library's [...] block we
    # resume past it, so nested rule fields (below:/cves:/introduced:) are never
    # mistaken for library keys.
    while True:
        match = key_re.search(body, pos)
        if not match:
            break
        name = match.group(1)
        rules_src, end = _balanced(body, "[", "]", match.start())
        rules = []
        inner = 0
        while True:
            brace = rules_src.find("{", inner)
            if brace == -1:
                break
            rule_src, rule_end = _balanced(rules_src, "{", "}", brace)
            rules.append(_rule_tuple(rule_src))
            inner = rule_end + 1
        table[name] = sorted(rules)
        pos = end + 1
    return table


def _python_table():
    table = {}
    for name, rules in VULN_TABLE.items():
        table[name] = sorted(
            (
                tuple(rule.get("introduced", (0, 0, 0))),
                tuple(rule["below"]),
                rule["severity"],
                tuple(sorted(rule["cves"])),
            )
            for rule in rules
        )
    return table


class ExtensionLibraryCveSyncTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(EXT_JS.exists(), f"missing ported module: {EXT_JS}")
        self.js = EXT_JS.read_text(encoding="utf-8")

    def test_full_rule_table_matches_python(self):
        # Compares libraries, version bounds, severities, and CVE lists — so a
        # change to any rule field in either file fails this guard.
        self.assertEqual(
            parse_js_vuln_table(self.js),
            _python_table(),
            "extension/lib/library-cves.js VULN_TABLE drifted from "
            "keyleak/js_library_cves.py (library/version-bound/severity/CVE)",
        )

    def test_cve_set_matches_python(self):
        js_cves = set(CVE_RE.findall(self.js))
        py_cves = {cve for rules in VULN_TABLE.values() for rule in rules for cve in rule["cves"]}
        self.assertEqual(js_cves, py_cves)

    def test_finding_contract_is_preserved(self):
        # The finding type / detector id are what the service worker and report
        # pipeline key on; pin them so a rename can't silently break dedup.
        self.assertIn("type: 'vulnerable_js_library'", self.js)
        self.assertIn("detector_id: 'appsec.vulnerable_js_library'", self.js)


if __name__ == "__main__":
    unittest.main()
