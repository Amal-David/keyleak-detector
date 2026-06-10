"""Tests for the attack-vector correlation engine (keyleak.attack_chains).

Each chain has a positive and a negative case, so a test fails if the chain fires
when it shouldn't (false attack vector) or fails to fire when it should.
"""

import unittest

from keyleak.attack_chains import SEED_CHAINS, correlate
from keyleak.models import Evidence, Finding


def mk(ftype, host="https://app.example.com", *, detector_id=None, severity="high",
       status="confirmed", request_url=None) -> Finding:
    url = request_url if request_url is not None else host
    return Finding(
        type=ftype, severity=severity, confidence=0.9,
        detector_id=detector_id or f"baas.{ftype}", source=host,
        evidence=Evidence(source=host, snippet="x", redacted_value=ftype, request_url=url),
        risk_reason="x", remediation="x", validation_status=status, category="baas",
    )


class RlsAnonFulldbTests(unittest.TestCase):
    def test_fires_on_anon_key_plus_open_table_same_host(self):
        findings = [mk("supabase_publishable_key"), mk("baas_open_table")]
        vectors = correlate(findings)
        rls = [v for v in vectors if v.rule_id == "rls-anon-fulldb"]
        self.assertEqual(len(rls), 1)
        self.assertEqual(rls[0].severity, "critical")          # escalated
        self.assertEqual(len(rls[0].member_finding_ids), 2)    # both legs cited

    def test_does_not_fire_with_only_open_table(self):
        vectors = correlate([mk("baas_open_table")])
        self.assertEqual([v for v in vectors if v.rule_id == "rls-anon-fulldb"], [])

    def test_does_not_fire_across_different_hosts(self):
        findings = [mk("supabase_publishable_key", host="https://a.example.com"),
                    mk("baas_open_table", host="https://b.other.com")]
        self.assertEqual([v for v in correlate(findings) if v.rule_id == "rls-anon-fulldb"], [])


class HostFallbackTests(unittest.TestCase):
    def test_realistic_single_url_chains_only_with_target(self):
        # Production single-URL shape: anon key on the PAGE host, but baas_open_table
        # is emitted with the SUPABASE project host. They are different network hosts.
        anon = mk("supabase_publishable_key", host="https://myapp.com")
        tbl = mk("baas_open_table", host="https://abcxyz.supabase.co",
                 request_url="https://abcxyz.supabase.co/rest/v1/users")
        # Without a target, the two legs are on different hosts -> must NOT chain.
        self.assertFalse(any(v.rule_id == "rls-anon-fulldb" for v in correlate([anon, tbl])))
        # With the scan target, both anchor to the target host -> the chain fires.
        vectors = correlate([anon, tbl], target="https://myapp.com")
        rls = [v for v in vectors if v.rule_id == "rls-anon-fulldb"]
        self.assertEqual(len(rls), 1)
        self.assertEqual(rls[0].hosts, ["myapp.com"])

    def test_bare_filename_source_is_not_treated_as_a_host(self):
        # Findings whose source/request_url are bare strings (no scheme) must not be
        # grouped by a bogus 'host' -> no false same-host chain.
        anon = mk("supabase_publishable_key", host="app.js", request_url="app.js")
        tbl = mk("baas_open_table", host="bundle.js", request_url="bundle.js")
        self.assertEqual([v for v in correlate([anon, tbl]) if v.rule_id == "rls-anon-fulldb"], [])

    def test_provenance_map_is_used_when_present(self):
        anon = mk("supabase_publishable_key", host="x", request_url="")  # no host on the finding
        tbl = mk("baas_open_table", host="x", request_url="")
        prov = {anon.id: ["https://app.example.com/a"], tbl.id: ["https://app.example.com/b"]}
        vectors = correlate([anon, tbl], provenance=prov)
        rls = [v for v in vectors if v.rule_id == "rls-anon-fulldb"]
        self.assertEqual(len(rls), 1)
        self.assertEqual(rls[0].hosts, ["app.example.com"])


class ServiceRoleTests(unittest.TestCase):
    def test_single_leg_fires_regardless_of_host(self):
        vectors = correlate([mk("baas_service_role_exposed", severity="critical")])
        sr = [v for v in vectors if v.rule_id == "service-role-leak"]
        self.assertEqual(len(sr), 1)
        self.assertEqual(sr[0].severity, "critical")

    def test_no_service_role_no_vector(self):
        self.assertEqual([v for v in correlate([mk("baas_open_table")]) if v.rule_id == "service-role-leak"], [])


class OtherChainsTests(unittest.TestCase):
    def test_cors_wildcard_open_table(self):
        findings = [mk("baas_cors_wildcard", severity="low"), mk("baas_open_table")]
        self.assertTrue(any(v.rule_id == "cors-wildcard-open-table" for v in correlate(findings)))

    def test_sourcemap_plus_secret(self):
        findings = [mk("source_map_reference", detector_id="leak.source_map_reference"),
                    mk("openai_api_key", detector_id="leak.openai_api_key")]
        self.assertTrue(any(v.rule_id == "sourcemap-secret-recovery" for v in correlate(findings)))

    def test_sourcemap_alone_does_not_fire(self):
        vectors = correlate([mk("source_map_reference", detector_id="leak.source_map_reference")])
        self.assertEqual([v for v in vectors if v.rule_id == "sourcemap-secret-recovery"], [])

    def test_write_takeover_fires(self):
        findings = [mk("supabase_url"), mk("baas_writable_table")]
        self.assertTrue(any(v.rule_id == "rls-anon-write-takeover" for v in correlate(findings)))

    def test_write_takeover_negative_without_anon_key(self):
        self.assertEqual(
            [v for v in correlate([mk("baas_writable_table")]) if v.rule_id == "rls-anon-write-takeover"], [])

    def test_cors_alone_does_not_fire(self):
        self.assertEqual(
            [v for v in correlate([mk("baas_cors_wildcard", severity="low")])
             if v.rule_id == "cors-wildcard-open-table"], [])


class SeverityCapTests(unittest.TestCase):
    def test_lead_only_chain_is_capped_at_high(self):
        # an enumerated-only / maybe-public open table is a LEAD; it must not alone
        # produce a BLOCK-SHIP critical vector.
        findings = [mk("supabase_publishable_key", severity="medium", status="lead"),
                    mk("baas_open_table", severity="high", status="lead")]
        rls = [v for v in correlate(findings) if v.rule_id == "rls-anon-fulldb"][0]
        self.assertEqual(rls.confidence, "lead")
        self.assertEqual(rls.severity, "high")  # capped, not critical

    def test_confirmed_member_yields_critical(self):
        findings = [mk("supabase_publishable_key", status="lead"),
                    mk("baas_open_table", status="confirmed")]
        rls = [v for v in correlate(findings) if v.rule_id == "rls-anon-fulldb"][0]
        self.assertEqual(rls.confidence, "confirmed")
        self.assertEqual(rls.severity, "critical")  # real missing-RLS finding


class EngineSemanticsTests(unittest.TestCase):
    def test_confidence_is_lead_when_no_member_confirmed(self):
        findings = [mk("supabase_publishable_key", status="lead"), mk("baas_open_table", status="lead")]
        rls = [v for v in correlate(findings) if v.rule_id == "rls-anon-fulldb"][0]
        self.assertEqual(rls.confidence, "lead")

    def test_confidence_confirmed_when_a_member_is_confirmed(self):
        findings = [mk("supabase_publishable_key", status="lead"), mk("baas_open_table", status="confirmed")]
        rls = [v for v in correlate(findings) if v.rule_id == "rls-anon-fulldb"][0]
        self.assertEqual(rls.confidence, "confirmed")

    def test_no_duplicate_vectors_for_same_member_set(self):
        findings = [mk("supabase_publishable_key"), mk("baas_open_table")]
        ids = [v.id for v in correlate(findings) if v.rule_id == "rls-anon-fulldb"]
        self.assertEqual(len(ids), len(set(ids)))

    def test_empty_findings_yields_no_vectors(self):
        self.assertEqual(correlate([]), [])

    def test_every_seed_rule_has_real_legs(self):
        # guard: a chain whose legs reference no finding type AND no detector glob is dead
        for rule in SEED_CHAINS:
            for leg in rule.legs:
                self.assertTrue(leg.types or leg.detector_globs, f"{rule.id} has an empty leg")


class BuildReportWiringTests(unittest.TestCase):
    """B1: correlate() must actually run inside build_report and surface in output
    (it was dead code — defined and tested but never called by any scan path)."""

    def _findings(self):
        return [
            mk("supabase_url", severity="info", status="lead"),
            mk("baas_open_table", severity="high", status="confirmed"),
        ]

    def test_build_report_emits_attack_chains(self):
        from keyleak.reporting import build_report
        report = build_report("https://app.example.com", self._findings(), scan_mode="browser")
        chains = report.extra.get("attack_chains")
        self.assertTrue(chains, "build_report did not surface attack chains")
        self.assertEqual(chains[0]["rule_id"], "rls-anon-fulldb")

    def test_chains_render_in_all_serializers(self):
        from keyleak.reporting import build_report, format_markdown, format_html, format_json
        report = build_report("https://app.example.com", self._findings(), scan_mode="browser")
        self.assertIn("## Attack chains", format_markdown(report))
        self.assertIn("Attack chains", format_html(report))
        self.assertIn("attack_chains", format_json(report))

    def test_no_chains_no_section(self):
        from keyleak.reporting import build_report, format_markdown
        report = build_report("https://app.example.com", [mk("openai_api_key")], scan_mode="browser")
        self.assertNotIn("attack_chains", report.extra)
        self.assertNotIn("## Attack chains", format_markdown(report))

    def test_chains_roundtrip_through_scanreport_from_dict(self):
        from keyleak.reporting import build_report
        from keyleak.models import ScanReport
        report = build_report("https://app.example.com", self._findings(), scan_mode="browser")
        restored = ScanReport.from_dict(report.to_dict())
        self.assertEqual(restored.extra.get("attack_chains"), report.extra.get("attack_chains"))


if __name__ == "__main__":
    unittest.main()
