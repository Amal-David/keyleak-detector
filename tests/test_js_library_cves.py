"""Tests for known-vulnerable JS library detection (keyleak/js_library_cves.py)."""

from __future__ import annotations

import unittest

from keyleak.js_library_cves import (
    _library_cve_findings,
    match_library_cves,
    parse_version,
)


class ParseVersionTests(unittest.TestCase):
    def test_parses_common_shapes(self):
        self.assertEqual(parse_version("1.10.2"), (1, 10, 2))
        self.assertEqual(parse_version("v3.7.1"), (3, 7, 1))
        self.assertEqual(parse_version("3.5.0-beta"), (3, 5, 0))
        self.assertEqual(parse_version("2"), (2, 0, 0))
        self.assertEqual(parse_version("4.6"), (4, 6, 0))

    def test_rejects_garbage(self):
        self.assertIsNone(parse_version(""))
        self.assertIsNone(parse_version(None))
        self.assertIsNone(parse_version("not-a-version"))


class MatchLibraryCvesTests(unittest.TestCase):
    def _cves(self, name, version):
        return sorted({c for r in match_library_cves(name, version) for c in r["cves"]})

    def test_old_jquery_flags_the_expected_cves(self):
        # jQuery 1.10.2 is >= 1.9 so CVE-2012-6708 does not apply, but the
        # cross-domain AJAX, prototype-pollution, and htmlPrefilter XSS CVEs do.
        self.assertEqual(
            self._cves("jquery", "1.10.2"),
            ["CVE-2015-9251", "CVE-2019-11358", "CVE-2020-11022", "CVE-2020-11023"],
        )

    def test_ancient_jquery_includes_selector_cve(self):
        self.assertIn("CVE-2012-6708", self._cves("jquery", "1.8.3"))

    def test_current_jquery_is_clean(self):
        self.assertEqual(match_library_cves("jquery", "3.7.1"), [])

    def test_bootstrap4_flags_xss_and_carousel(self):
        cves = self._cves("bootstrap", "4.0.0")
        self.assertIn("CVE-2019-8331", cves)
        self.assertIn("CVE-2024-6531", cves)

    def test_modern_bootstrap_is_clean(self):
        self.assertEqual(match_library_cves("bootstrap", "5.3.2"), [])

    def test_unknown_library_and_bad_version_are_safe(self):
        self.assertEqual(match_library_cves("leftpad", "1.0.0"), [])
        self.assertEqual(match_library_cves("jquery", "garbage"), [])


class LibraryFindingTests(unittest.TestCase):
    def test_builds_appsec_lead_finding(self):
        findings = _library_cve_findings(
            [{"name": "jquery", "version": "1.10.2", "source": "global"}],
            "https://app.example.test/",
        )
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.type, "vulnerable_js_library")
        self.assertEqual(f.detector_id, "appsec.vulnerable_js_library")
        self.assertEqual(f.category, "appsec")
        self.assertEqual(f.validation_status, "lead")
        self.assertEqual(f.severity, "high")
        self.assertEqual(f.evidence.redacted_value, "jquery 1.10.2")
        self.assertTrue(any("CVE-2020-11022" in r for r in f.references))

    def test_dedupes_and_skips_safe_libraries(self):
        findings = _library_cve_findings(
            [
                {"name": "jquery", "version": "1.10.2"},
                {"name": "jquery", "version": "1.10.2"},  # duplicate
                {"name": "react", "version": "18.2.0"},   # safe
            ],
            "u",
        )
        self.assertEqual(len(findings), 1)

    def test_empty_input_is_safe(self):
        self.assertEqual(_library_cve_findings([], "u"), [])
        self.assertEqual(_library_cve_findings([{"name": "jquery"}], "u"), [])


if __name__ == "__main__":
    unittest.main()
