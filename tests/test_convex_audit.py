"""Static Convex results are authorization leads, never live exploit proof."""

import unittest
import tempfile
from pathlib import Path

from keyleak.convex_audit import audit_convex_source


class ConvexAuditTests(unittest.TestCase):
    def test_public_destructive_function_without_identity_is_a_lead(self):
        source = '''import { mutation } from "./_generated/server";
export const wipe = mutation({handler: async (ctx, args) => {
  await ctx.db.delete(args.id);
}});'''
        findings = audit_convex_source(source, "convex/profiles.ts")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].type, "convex_public_function_review")
        self.assertEqual(findings[0].validation_status, "lead")
        self.assertIn("internalMutation", findings[0].remediation)

    def test_internal_functions_and_comments_are_not_public_functions(self):
        source = '''import { internalMutation } from "./_generated/server";
// export const fake = mutation({handler: async ctx => ctx.db.delete(id)});
export const wipe = internalMutation({handler: async ctx => { return null; }});'''
        self.assertEqual(audit_convex_source(source, "convex/private.ts"), [])

    def test_sibling_identity_does_not_authorize_a_different_function(self):
        source = '''import { mutation as m } from "./_generated/server";
export const safe = m({handler: async (ctx) => {
 const identity = await ctx.auth.getUserIdentity();
 if (!identity) throw new Error("unauthenticated"); return null;
}});
export const wipe = m({handler: async (ctx,args) => {await ctx.db.delete(args.id);}});'''
        findings = audit_convex_source(source, "convex/profiles.ts")
        wipe = [f for f in findings if "wipe" in f.evidence.redacted_value]
        self.assertEqual(len(wipe), 1)
        self.assertIn("No recognized identity lookup", wipe[0].risk_reason)

    def test_identity_lookup_does_not_prove_ownership(self):
        source = '''import { mutation } from "./_generated/server";
export const update = mutation({handler: async (ctx,args) => {
 const identity = await ctx.auth.getUserIdentity();
 return ctx.db.patch(args.id, {role: args.role});
}});'''
        finding = audit_convex_source(source, "convex/profiles.ts")[0]
        self.assertIn("ownership", finding.risk_reason)
        self.assertEqual(finding.validation_status, "lead")

    def test_unrecognized_wrappers_never_produce_a_clean_authorization_verdict(self):
        from keyleak.local_scanner import scan_path
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "convex").mkdir()
            (root / "convex/tasks.ts").write_text("export const update = customMutation({handler: doUpdate});")
            report = scan_path(str(root))
            self.assertEqual(report.extra["database_audits"][0]["status"], "source_review")
            self.assertEqual(report.verdict["label"], "REVIEW")


if __name__ == "__main__":
    unittest.main()
