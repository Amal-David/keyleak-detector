# Supabase / BaaS RLS — deep-dive + UI design (D8, primary theme)

The seed bug (CBSE-class): a public site ships its Supabase **project URL + anon
key** in the JS bundle (by design — they're public), but one or more tables have
**Row-Level Security (RLS) disabled or written with a permissive `USING (true)`
policy**. Because Supabase exposes every table over PostgREST at
`/rest/v1/<table>`, anyone with the anon key can `select *` (and sometimes
insert/update/delete) **every row** — no auth bypass needed, just the published
key plus a missing policy. This generalizes to Firebase (open security rules),
Appwrite (open collection permissions), PocketBase (open list rules), and Hasura
(permissive permissions / exposed admin secret).

## What KeyLeak already does (reuse)

`baas_validator.py` already extracts config from the running page and probes —
**read-only by default after review R1**: the one mutating probe
(`_probe_write_access`, a `POST /rest/v1/{table}` insert that relies on
`Prefer: tx=rollback`, which not every PostgREST deployment honors) is now gated
behind an explicit `allow_write_probe=True` and is **off** for the default scan
and every built-in bundle. The read-only probes:
- `extract_baas_config()` — provider, `project_url`, anon `api_key`, `tables[]`,
  `rpc_functions[]`, `storage_buckets[]` from browser-scan findings + injected JS.
- Supabase probes: `_probe_tables` (`GET /rest/v1/{t}?select=*&limit=1`),
  `_probe_storage` (`GET /storage/v1/bucket` for public-flagged buckets, then
  `GET /storage/v1/object/list/{bucket}`), `_probe_rpcs` (surfaces client-referenced
  RPCs as **leads without calling them** — POSTing would execute the function),
  `_probe_write_access` (a POST insert — **opt-in only**, see
  above), `_probe_auth_config`, `_analyze_realtime`. Caps: TABLE 50 / BUCKET 10 /
  RPC 20 / WRITE 20. `prober` is injectable (testable). Result:
  `BaaSValidation{key_valid, open_tables[], protected_tables[], accessible_buckets[],
  callable_rpcs[], writable_tables[], cors_open}`.

This deep-dive **extends** that into a complete RLS evaluation surface + a UI.

## Full RLS/BaaS misconfiguration taxonomy (what to detect)

Each maps to a `baas` detector or an active probe result. Severity in (), probe type.

1. **Open table read** — anon `select *` returns rows. (critical, active read)
   Signal: `GET /rest/v1/{t}?select=*&limit=1` → 200 + non-empty array / row.
2. **RLS disabled vs permissive policy** — distinguish *no RLS* from
   `USING (true)`. (critical) Signal: open read **and** the table appears in the
   OpenAPI root (`GET /rest/v1/`) definitions. Report which, since the fix differs.
3. **Open table write (insert/update/delete)** — anon mutation accepted.
   (critical) **Detection is off by default** because the only way to confirm a
   write is to attempt one. The current `_probe_write_access` POSTs a row relying
   on `Prefer: tx=rollback` (not universally honored) → gated behind
   `allow_write_probe=True`. **Preferred safe path (M5):** infer write capability
   *without mutating* — a no-body `POST` (expect `400`/`415` schema error if writes
   are allowed vs `401`/`403`/`42501` if RLS blocks), or read the PostgREST OpenAPI
   root / `Allow` header for the table. Only fall back to the real insert under
   explicit opt-in. Signal (inference): `401/403/42501` ⇒ protected; non-auth
   error ⇒ likely writable.
4. **Service-role key exposure** — the `service_role` JWT (RLS-bypassing) leaked
   in bundle/storage/headers. (critical, passive) Signal: JWT with
   `"role":"service_role"`. This is game-over; flag distinctly from anon key.
5. **Open storage bucket** — anon can list/download objects. (high, active read)
   Signal: `GET /storage/v1/bucket` returns buckets with `public: true`, and/or
   `GET /storage/v1/object/list/{bucket}` → 200 with a non-empty object list.
6. **Public storage upload** — anon upload allowed. (critical) Signal:
   bucket `public=true` + permissive policy; infer from bucket metadata, don't upload.
7. **Callable RPC with side effects** — some RPCs wrap privileged SQL.
   **Current behavior:** KeyLeak surfaces client-referenced RPCs as a **lead
   without execution**. It does not POST to `/rest/v1/rpc/{fn}` or `/rpc/{fn}`,
   does not pass crafted args, and does not attempt to run functions by default.
   **Future opt-in confirmation:** an explicit RPC execution mode may POST to
   `/rest/v1/rpc/{fn}` or `/rpc/{fn}` and compare 200/204 versus 404/401 response
   signals, but that must remain a separate, flagged workflow.
8. **Exposed auth settings / signup enabled** — `GET /auth/v1/settings` reveals
   external providers, `mailer_autoconfirm`, `disable_signup=false`. (medium)
   Open signup + open tables = account-driven data harvesting.
9. **Realtime channel subscription** — anon can subscribe to table-change streams
   (`/realtime/v1`), leaking rows as they change. (high, passive analysis of
   channel config; do not open sockets by default).
10. **CORS wide-open on the data API** — `Access-Control-Allow-Origin: *` on
    `/rest/v1`. (medium) Amplifies anon read into any-origin exfiltration.
11. **Permissive policy patterns** — when policies are observable (rare), flag
    `USING (true)`, `auth.role() = 'anon'`, missing `WITH CHECK`. (high)
12. **JWT secret / weak signing** — Supabase `JWT_SECRET` leaked, or anon key not
    rotated. (critical, passive)
13. **GraphQL (pg_graphql) exposure** — `/graphql/v1` introspection + unguarded
    resolvers mirror the table exposure. (high)
14. **Firebase parallels** — open Firestore/RTDB rules (`.read:true`), open Storage
    rules, web API key with no App Check. (critical/high)
15. **Appwrite/PocketBase parallels** — collection read/list permission = `any`,
    open document rules. (critical/high)

## Detection / evaluation / test flow (per target)

1. **Discover (passive):** extract provider + URL + anon key + table/rpc/bucket
   names from the bundle/DOM/storage (existing `extract_baas_config`). Expand the
   table-name source: also parse `GET /rest/v1/` OpenAPI root (PostgREST publishes
   every exposed table's schema there) — this finds tables the JS never named.
2. **Evaluate (classify, read-only active):** for each table/bucket/rpc, run the
   capped read-only probe and classify `open | protected | error`. Diff anon vs
   (optional) authenticated key to separate "public by design" from "leaking".
3. **Test (confirm, opt-in):** a one-click "confirm" that re-runs the single probe
   live and shows the actual (redacted) row count / columns returned, so the user
   sees proof. Always read-only, anon-key only, rate-limited, in-scope.

Safety rails (mandatory): anon key only by default; never the service_role key for
mutation; read-only; never commit writes; honor caps + `offline_guard` + `--proxy`;
redact returned row values (show shape/count, not data); scope to the target host.

## UI design (extension panel + web report)

A dedicated **"BaaS / RLS"** view, because it's a matrix, not a flat finding list.

- **Header:** provider badge (Supabase/Firebase/…), project URL (redacted), key
  type detected (anon vs **service_role** — red), key-valid check, CORS flag.
- **Table matrix** (the core): rows = tables (from JS + OpenAPI root), columns =
  `Read | Insert | Update | Delete | RLS`. Each cell: ✅ protected / 🔴 open /
  ⚪ untested / ⚠️ error. Open cells expand to the probe evidence (status, redacted
  row count, columns). Sort by risk. A "Test" button per row re-runs that probe live.
- **Storage / RPC / Realtime** sub-sections with the same protected/open treatment.
- **Verdict + remediation card:** count of open tables; one-click copy of the fix
  (`ALTER TABLE x ENABLE ROW LEVEL SECURITY;` + a least-privilege policy template;
  for Firebase, a rules snippet). Link to Supabase RLS docs.
- **Severity rollup:** any open table → BLOCK SHIP; service_role leak → critical
  banner. Feeds the launch-gate verdict and the `baas` bundle.
- **Discoverability affordance:** if an anon key is found but no tables were named
  in the bundle, surface "anon key present — run RLS probe to enumerate exposed
  tables" as a primary CTA (this is the CBSE case: the key is there, the tables
  aren't in the JS, but PostgREST will list them).

## Gaps in current `baas_validator` → proposed enhancements (P7)

- **Enumerate tables from the PostgREST OpenAPI root** (`GET /rest/v1/`), not only
  from JS-named tables — catches the CBSE case where tables aren't referenced in
  the bundle. (biggest coverage win)
- **Distinguish RLS-disabled from permissive-policy** in `open_tables` results.
- **Detect `service_role` key** explicitly and escalate (separate from anon).
- **Auth-settings probe** → signup-enabled + provider list (`_probe_auth_config`
  already hits `/auth/v1/settings`; classify the body).
- **GraphQL (`/graphql/v1`) introspection probe** for pg_graphql.
- **Per-table read/write/RLS matrix** in the result model (extend `BaaSValidation`)
  to drive the UI matrix above.
- **Authenticated-diff mode:** optional second key (a real user JWT) to separate
  "public by design" from "leaking", reducing false positives.

This deep-dive is the anchor for the `baas` bundle and the highest-confidence,
highest-impact runtime class KeyLeak detects today.
