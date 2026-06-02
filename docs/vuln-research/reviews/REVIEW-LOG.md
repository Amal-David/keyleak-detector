# Adversarial Review Log

Each step's review gate: lenses, scores (0-100), must-fixes, and what changed.
Bar: every lens >= 85 (or 3 rounds + recorded residual risk).

## Step: Designs (D5–D8) + M1 bundles

### Round 1 (scores: security 72, architecture 72, code-quality 62, product 74 — all < 85)
Blocking findings (all verified true against source):
- **SEC**: "read-only invariant" was false — `_probe_write_access` POSTs a real row.
- **SEC**: correlation engine matched on `canonical_class`, which does not exist.
- **SEC**: provenance mis-attributed to `build_report`; single-URL chains would never fire.
- **ARCH**: reused `build_report`'s fixed-shape `attack_vectors` arg; wrong `blast_radius` signature.
- **CQ**: bundles referenced packs `normalize_packs` rejects; muddy passive/active semantics; tautological deep test; global-mutation test; no budget/scope validation.
- **PROD**: bundles unwired (no `--bundle`/subcommand).

Fixes applied (commits 17556ba, f2a16ad, 7f3abf5):
- Safety: `allow_write_probe` (default OFF) gates the POST; browser_scanner default now read-only; spy-prober test proves no POST by default.
- Registered 6 program packs in `DETECTOR_PACKS`; bundles now resolve through `normalize_packs` (tested).
- Explicit passive/navigation/probing taxonomy; `validate_bundles(bundles=...)` enforces budget/rate/scope/probing + no global mutation; de-tautologized tests.
- Docs: real `finding.type`/`detector_id` matching; corrected `build_report`/provenance (+ single-URL fallback)/`blast_radius`; accurate read-only/write-probe + storage signals.
- CLI: `keyleak bundles` + `scan/local --bundle` (skip-loudly on unpopulated packs / un-orchestrated phases).
- 88 tests pass. **Round 2 launched to verify (bar: every lens ≥ 85).**

### Round 2 (scores: security 88, architecture 90, code-quality 90, product 86 — ALL >= 85 ✅ GATE CLEARED)
All 10 round-1 items verified resolved at code/test level. Residual nits (fixed in f34d571):
- docs called `_probe_rpcs` a POST and `_probe_write_access` "read-only" — corrected (rpcs surface leads without executing; write-probe is mutating/opt-in).
- `validate_bundles` now enforces rate>0 for all request-sending bundles; `runnable_packs()` added.
- CLI warns loudly when a `--bundle` resolves to zero runnable detectors (e.g. `injection` today).
- scan-bundles.md CLI section split into "implemented now (scan/local)" vs "planned".
Outcome: design + M1 foundation accepted. Proceeding to M5 (RLS flagship) under the same gate.

## Step: M5 OpenAPI-root table enumeration

### Round 3 (fp-and-safety 62, code-quality 68, design-alignment 78 — below bar)
Ship-blocking false positives the gate caught:
- `200 []` flagged as an OPEN table at HIGH — but it's the EXPECTED anon response for a CORRECTLY RLS-protected table (a pre-existing bug M5 amplified).
- Views + by-design-public tables flagged HIGH with invalid `ALTER TABLE <view> ENABLE RLS`.
- "code-invisible" annotation overclaimed; parser dropped `rpc_*` tables; `_table_severity` escalated `authors` via substring; M5 mutated caller config; cap could starve enumerated tables.
Fixes (d390184): 200-[] floor → protected/empty; enumerated-only → leads (downgraded, softened); view-aware remediation; path-only RPC exclusion; token-boundary severity; no mutation; sensitive-first ordering. +4 tests.

### Round 3b (fp-and-safety 94 PASS; code-quality 78 — one regression)
fp-and-safety: all 4 R3 items verified resolved by independent adversarial probing. code-quality found a NEW regression: view detection by ABSENCE of POST mislabeled base tables as views on definitions-only OpenAPI bodies.
Fix (69781b9): `_view_relations` requires POSITIVE evidence (in paths, ops present, no post); unknown insertability defaults to table. Regression test added; fails if reverted.
Outcome: M5 accepted (fp/safety 94; the single code-quality must-fix resolved + test-guarded). 40 baas tests pass.

