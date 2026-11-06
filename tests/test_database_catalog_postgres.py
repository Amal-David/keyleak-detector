"""Optional local PostgreSQL proof; no third-party database or TCP listener."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from keyleak.database_audit import audit_supabase_catalog


@unittest.skipUnless(all(shutil.which(name) for name in ("initdb", "pg_ctl", "psql")) and getattr(os, "geteuid", lambda: 0)() != 0,
                     "local PostgreSQL binaries and a non-root user are required")
class PostgresCatalogTests(unittest.TestCase):
    def test_collector_is_read_only_and_fixes_cover_public_inherited_and_column_grants(self):
        with tempfile.TemporaryDirectory(prefix="keyleak-pg-") as directory:
            root = Path(directory).resolve()
            data = root / "data"
            subprocess.run(["initdb", "-D", str(data), "-A", "trust", "--no-locale", "-E", "UTF8"],
                           check=True, capture_output=True, timeout=30)
            subprocess.run(["pg_ctl", "-D", str(data), "-l", str(root / "server.log"),
                            "-o", f"-k {root} -h '' -p 55439", "-w", "start"],
                           check=True, capture_output=True, timeout=30)
            try:
                def sql(statement):
                    return subprocess.run(["psql", "-X", "-qAt", "-v", "ON_ERROR_STOP=1", "-h", str(root),
                                           "-p", "55439", "-d", "postgres"],
                                          input=statement, text=True, check=True,
                                          capture_output=True, timeout=15).stdout.strip()

                sql('''CREATE ROLE anon; CREATE ROLE authenticated; CREATE ROLE inherited_clients;
                    GRANT inherited_clients TO anon;
                    CREATE TABLE public.profiles(id integer, role text);
                    INSERT INTO public.profiles VALUES (1, 'user'), (2, 'user');
                    ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
                    CREATE VIEW public.unsafe_profiles AS SELECT * FROM public.profiles;
                    GRANT SELECT, DELETE ON public.unsafe_profiles TO PUBLIC;
                    GRANT UPDATE(role) ON public.unsafe_profiles TO inherited_clients;
                    CREATE VIEW public.safe_profiles WITH (security_invoker=on) AS SELECT * FROM public.profiles;
                    CREATE FUNCTION public.wipe(integer) RETURNS void LANGUAGE sql SECURITY DEFINER
                      AS 'DELETE FROM public.profiles WHERE id = $1';
                    CREATE FUNCTION public.helper() RETURNS text LANGUAGE sql SECURITY DEFINER SET search_path=''
                      AS $$SELECT 'catalog-private-canary'::text$$;
                    REVOKE EXECUTE ON FUNCTION public.helper() FROM PUBLIC;
                    CREATE TABLE public.unprotected(id integer);
                    GRANT SELECT ON public.unprotected TO anon;
                ''')
                collector = (Path(__file__).parents[1] / "keyleak/supabase_catalog.sql").read_text()
                snapshot = json.loads(sql(collector))
                self.assertNotIn("catalog-private-canary", json.dumps(snapshot))
                view = next(item for item in snapshot["relations"] if item["name"] == "unsafe_profiles")
                self.assertTrue(view["grants"]["anon"]["delete"])
                self.assertTrue(view["grants"]["anon"]["update"])
                self.assertIn("inherited_clients", view["write_roles"])
                safe = next(item for item in snapshot["relations"] if item["name"] == "safe_profiles")
                self.assertTrue(safe["security_invoker"])
                findings, _ = audit_supabase_catalog(snapshot)
                self.assertIn("supabase_rls_disabled", {f.type for f in findings})
                self.assertFalse(any("helper" in f.evidence.snippet for f in findings))
                self.assertEqual(sql("SELECT count(*) FROM public.profiles"), "2")

                # Exercise proposed SQL only against disposable test objects and
                # roll it back; production auditing never executes remediation.
                fix = next(f.remediation.split("\n", 1)[1] for f in findings if f.type == "supabase_writable_view")
                remaining = sql("BEGIN;\n" + fix + "\nSELECT has_table_privilege('anon', 'public.unsafe_profiles', 'DELETE') "
                                "OR has_any_column_privilege('anon', 'public.unsafe_profiles', 'UPDATE');\nROLLBACK;")
                self.assertEqual(remaining, "f")
                function_fix = next(f.remediation.split("\n", 1)[1] for f in findings if f.type == "supabase_definer_executable")
                remaining = sql("BEGIN;\n" + function_fix + "\nSELECT has_function_privilege('anon','public.wipe(integer)','EXECUTE');\nROLLBACK;")
                self.assertEqual(remaining, "f")
            finally:
                subprocess.run(["pg_ctl", "-D", str(data), "-m", "fast", "-w", "stop"],
                               check=True, capture_output=True, timeout=30)


if __name__ == "__main__":
    unittest.main()
