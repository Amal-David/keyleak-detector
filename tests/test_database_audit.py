"""Database metadata audits never connect to or change a database."""

import copy
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from keyleak.database_audit import audit_supabase_catalog, load_catalog
from keyleak.local_scanner import scan_path
from keyleak.reporting import build_report, format_html, format_markdown, format_sarif, report_to_text


def catalog():
    return {
        "version": 1,
        "provider": "supabase",
        "schemas": ["public"],
        "relations": [],
        "functions": [],
    }


def relation(kind="table", **overrides):
    item = {
        "schema": "public", "name": "profiles", "kind": kind,
        "rls_enabled": True, "security_invoker": True,
        "columns": ["id", "role"], "write_roles": [], "destructive_roles": [],
        "grants": {role: {p: False for p in ("select", "insert", "update", "delete", "truncate")}
                   for role in ("anon", "authenticated")},
    }
    item.update(overrides)
    return item


class SupabaseAuditTests(unittest.TestCase):
    def test_writable_definer_view_reports_the_delete_risk_and_review_sql(self):
        data = catalog()
        view = relation("view", security_invoker=False)
        view["grants"]["anon"]["delete"] = True
        data["relations"] = [view]
        with patch("socket.socket", side_effect=AssertionError("no network")):
            findings, summary = audit_supabase_catalog(data)
        by_type = {f.type: f for f in findings}
        self.assertIn("supabase_writable_view", by_type)
        self.assertIn("supabase_definer_view", by_type)
        self.assertIn('REVOKE INSERT, UPDATE, DELETE ON TABLE "public"."profiles" FROM PUBLIC, anon, authenticated;',
                      by_type["supabase_writable_view"].remediation)
        self.assertIn("DELETE", by_type["supabase_writable_view"].risk_reason)
        self.assertEqual(summary["status"], "complete")

    def test_rls_off_and_effective_grants_are_independent(self):
        data = catalog()
        table = relation(rls_enabled=False)
        table["grants"]["anon"].update(select=True, delete=True, truncate=True)
        data["relations"] = [table]
        findings, _ = audit_supabase_catalog(data)
        by_type = {f.type: f for f in findings}
        self.assertIn("supabase_rls_disabled", by_type)
        self.assertIn("supabase_anon_destructive_grant", by_type)
        self.assertIn("does not apply", by_type["supabase_anon_destructive_grant"].risk_reason)

    def test_safe_objects_and_quoted_names(self):
        data = catalog()
        data["relations"] = [relation(), relation("view", name="profile_view")]
        original = copy.deepcopy(data)
        self.assertEqual(audit_supabase_catalog(data)[0], [])
        self.assertEqual(data, original)
        data["relations"][1]["name"] = 'a"; DROP TABLE profiles;--'
        data["relations"][1]["grants"]["anon"]["update"] = True
        finding = audit_supabase_catalog(data)[0][0]
        self.assertIn('"a""; DROP TABLE profiles;--"', finding.remediation)

    def test_security_definer_effective_execute_and_search_path(self):
        data = catalog()
        data["functions"] = [{
            "schema": "public", "name": "delete_profiles", "security_definer": True,
            "identity_arguments": "uuid", "search_path": None,
            "execute_roles": [],
            "execute": {"anon": True, "authenticated": True},
        }]
        findings, _ = audit_supabase_catalog(data)
        self.assertEqual({f.type for f in findings}, {
            "supabase_definer_executable", "supabase_function_search_path",
        })
        for finding in findings:
            self.assertIn('"public"."delete_profiles"(uuid)', finding.remediation)
        self.assertIn("PUBLIC, anon, authenticated", findings[0].remediation)

    def test_incomplete_or_hostile_metadata_is_rejected(self):
        for data in ({}, {**catalog(), "relations": None},
                     {**catalog(), "relations": [relation(grants={})]},
                     {**catalog(), "functions": [{"schema": "public", "name": "x"}]},
                     {**catalog(), "functions": [{
                         "schema": "public", "name": "x", "security_definer": True,
                         "identity_arguments": "uuid); DROP TABLE profiles;--",
                         "search_path": "", "execute": {"anon": True, "authenticated": True},
                     }]}):
            with self.subTest(data=data), self.assertRaises(ValueError):
                audit_supabase_catalog(data)

    def test_missing_booleans_are_not_interpreted_as_safe(self):
        for key in ("rls_enabled", "security_invoker"):
            data = catalog()
            item = relation("view" if key == "security_invoker" else "table")
            del item[key]
            data["relations"] = [item]
            with self.assertRaises(ValueError):
                audit_supabase_catalog(data)

    def test_column_grants_and_inherited_roles_are_included_in_review_fixes(self):
        data = catalog()
        view = relation("view", name="shared_view", write_roles=['client"writers'])
        view["grants"]["anon"]["update"] = True
        data["relations"] = [view]
        fix = audit_supabase_catalog(data)[0][0].remediation
        self.assertIn('UPDATE ("id", "role")', fix)
        self.assertIn('"client""writers"', fix)

    def test_load_is_bounded_and_refuses_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            path = root / "catalog.json"
            path.write_text(json.dumps(catalog()))
            self.assertEqual(load_catalog(path), catalog())
            link = root / "link.json"
            link.symlink_to(path)
            with self.assertRaises(ValueError):
                load_catalog(link)
            path.write_text("x" * (5 * 1024 * 1024 + 1))
            with self.assertRaises(ValueError):
                load_catalog(path)

    def test_local_scan_automatically_consumes_catalog_and_convex_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / ".keyleak").mkdir()
            data = catalog()
            data["relations"] = [relation("view", security_invoker=False)]
            (root / ".keyleak/database-audit.json").write_text(json.dumps(data))
            (root / "convex").mkdir()
            (root / "convex/profiles.ts").write_text('''import { mutation } from "./_generated/server";
export const wipe = mutation({handler: async (ctx,args) => ctx.db.delete(args.id)});''')
            with patch("socket.socket", side_effect=AssertionError("no network")):
                report = scan_path(str(root))
            types = {f.type for f in report.findings}
            self.assertIn("supabase_definer_view", types)
            self.assertIn("convex_public_function_review", types)
            self.assertEqual(report.extra["database_audits"][0]["status"], "complete")

    def test_missing_catalog_is_visible_in_every_report_format(self):
        from keyleak.models import Evidence, Finding
        signal = Finding(type="supabase_url", severity="info", confidence=1.0,
                         detector_id="baas.supabase_url", source="app.js",
                         evidence=Evidence(source="app.js"), risk_reason="Public project URL", remediation="Audit grants")
        report = build_report("test-project", [signal])
        self.assertEqual(report.extra["database_audits"][0]["status"], "metadata_required")
        self.assertEqual(report.verdict["label"], "REVIEW")
        for output in (format_markdown(report), format_html(report), report_to_text(report), format_sarif(report)):
            self.assertIn("metadata_required", output)

    def test_corrupt_automatic_metadata_fails_coverage_loudly(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / ".keyleak").mkdir()
            (root / ".keyleak/database-audit.json").write_text('{"password":"never-print-this"}')
            report = scan_path(str(root))
            self.assertNotEqual(report.extra["coverage"]["status"], "complete")
            self.assertEqual(report.extra["database_audits"][0]["status"], "failed")
            self.assertNotIn("never-print-this", json.dumps(report.to_dict()))

    def test_cli_audits_metadata_and_exports_read_only_collector(self):
        from keyleak.cli import main
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "catalog.json"
            data = catalog()
            data["relations"] = [relation(rls_enabled=False)]
            path.write_text(json.dumps(data))
            output = io.StringIO()
            with patch("socket.socket", side_effect=AssertionError("no network")), contextlib.redirect_stdout(output):
                self.assertEqual(main(["database-audit", str(path), "--json"]), 0)
            self.assertIn("supabase_rls_disabled", output.getvalue())
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(main(["database-audit", "--export-sql"]), 0)
        self.assertIn("BEGIN READ ONLY", output.getvalue())
        self.assertIn("has_any_column_privilege", output.getvalue())

    def test_cli_invalid_metadata_never_prints_input_or_clean_report(self):
        from keyleak.cli import main
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "bad.json"
            path.write_text('{"secret":"do-not-log"}')
            output, error = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
                self.assertEqual(main(["database-audit", str(path), "--json"]), 1)
            self.assertEqual(output.getvalue(), "")
            self.assertNotIn("do-not-log", error.getvalue())

    def test_unused_proxy_is_not_contacted_and_offline_policy_is_enforced(self):
        from keyleak.cli import main
        for offline, expected in ((False, 0), (True, 1)):
            with self.subTest(offline=offline), patch("keyleak.cli.preflight") as preflight, \
                    patch("socket.socket", side_effect=AssertionError("no network")), \
                    contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                args = (["--offline"] if offline else []) + [
                    "--proxy", "http://203.0.113.10:8080", "database-audit", "--export-sql",
                ]
                self.assertEqual(main(args), expected)
                preflight.assert_not_called()


if __name__ == "__main__":
    unittest.main()
