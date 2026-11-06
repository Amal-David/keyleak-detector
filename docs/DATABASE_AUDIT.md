# Database permission audits


Normal `keyleak local <project>` scans automatically audit Supabase metadata at
`<project>/.keyleak/database-audit.json` and inspect JavaScript/TypeScript functions
under `convex/`, including nested projects. The audit never connects to a database,
invokes Convex functions, or applies a proposed fix.

For Supabase, export a catalog snapshot using an owner-authorized connection:

```bash
keyleak database-audit --export-sql > /tmp/keyleak-catalog.sql
mkdir -p .keyleak
# Use an existing psql service configuration; keep credentials out of shell history.
PGSERVICE=your-project psql -XqAt -v ON_ERROR_STOP=1 \
  -f /tmp/keyleak-catalog.sql > .keyleak/database-audit.json
keyleak local . --json > report.json
# Or audit the snapshot directly; Markdown with proposed SQL is the default.
keyleak database-audit .keyleak/database-audit.json
```

The collector uses a read-only transaction and a ten-second statement timeout. It
reads catalog metadata, including effective privileges inherited through roles or
`PUBLIC` and column-specific grants. It does not read application rows or function
bodies. The default schema scope is `public`; add every other Data API schema to
the collector's `audit_schemas` list before exporting. Keep the snapshot private
and re-export after schema or permission changes.

Supabase checks cover:

- Views with client write privileges, including inherited and column grants.
- Views without `security_invoker`, and client-readable materialized views.
- Table RLS state, effective client grants, and anonymous DELETE/TRUNCATE grants.
- Client-executable `SECURITY DEFINER` functions and functions without a fixed
  `search_path`. Overloaded function signatures are preserved.

Every finding explains the possible impact and includes SQL **for review only**.
Revocations can affect legitimate access or policy helpers. Re-export to verify
effective permissions after applying reviewed changes; ownership and role
membership may require additional changes. `security_invoker` requires PostgreSQL
15 or later. A TRUNCATE grant is a SQL privilege, not a REST table operation.

Convex uses function authorization rather than SQL views or RLS. Local scans find
standard public `query`, `mutation`, and `action` registrations, including named
import aliases, and emit authorization review leads with code guidance. They
inspect at most 200 matched registrations per file, under the existing 5 MiB file
limit. Identity lookup alone does not prove ownership checks or rejection of
anonymous requests. Custom wrappers, namespace imports, HTTP actions, helpers, and
runtime control flow need owner review; internal registrations are not flagged as
public functions. These checks never call a query, mutation, action, or guessed
function name.

Reports include `database_audits` in JSON/SARIF and a visible status in text,
Markdown, and HTML. Detected Supabase projects without metadata are
`metadata_required`; Convex authorization remains `source_review` or
`source_required`. These states produce a REVIEW verdict, not a clean permission
audit. Malformed metadata fails scan coverage and exits with code 1. Threshold
violations exit with code 2; REVIEW alone follows the selected severity threshold.
Firebase, Appwrite, and PocketBase retain their existing exposure checks and report
configuration auditing as `not_supported` when detected. The extension retains
its existing passive Convex observations; catalog and source audits run in Python
local scans. URL scans can identify missing owner inputs but cannot collect them
using a public key.

This mode does not verify policy semantics, function-body authorization, default
privileges for future objects, cascades, backups, or Supabase Security Advisor.
Catalog findings describe the supplied snapshot; they do not prove current live
exploitability or a complete application security audit.
