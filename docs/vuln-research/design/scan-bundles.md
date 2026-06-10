# Scan Bundles — design (D6)

Goal: let users invoke **named bundles** of checks (not just "everything" or each
detector independently), and let the **deep scan** run all bundles plus the
active phases (subdomain enum, crawl + download, MITM/proxy). This extends the
*existing* `pack` + `profile` model rather than inventing a parallel concept.

## What already exists (grounding)

- `Detector.pack` groups detectors. `DETECTOR_PACKS` currently includes
  `leak, appsec, access-control, baas` (+ correctness/housekeeping).
- `PROFILE_PACKS` maps a `--launch-profile` to a tuple of packs:
  `launch-gate → (leak,)`, `bug-bounty → (leak, appsec, access-control, baas)`,
  `full → all`. `normalize_packs(packs, profile, surface)` resolves them, with
  surface-specific maps for `extension`/`web`/`local`.
- CLI already accepts `--packs` (comma-separated) and `--launch-profile`.

So a "bundle" is really **a named set of packs (+ active phases + probe policy)**.
We formalize that.

## Bundle model

A **Bundle** = `{ id, title, description, packs[], phases[], probe_policy }`
(as implemented in `keyleak/bundles.py`).

- `packs[]` — which detector packs run (reuses the existing pack system; the new
  packs below are registered in `DETECTOR_PACKS`).
- `phases[]` — subset of `{passive, crawl, subdomain, probe, forms, fuzz,
  authz_diff, baas_probe, mitm}`, in three classes: **passive** (zero new
  requests), **navigation** (`crawl`/`subdomain` — real read-only GETs / CT logs),
  and **probing** (everything else — crafted requests).
- `probe_policy` = `ProbePolicy{ probing: bool, allow_write_probe: bool=False,
  max_requests, rate_per_sec, scope }`. Probing is **read-only by default**: the
  single mutating probe (`baas_validator._probe_write_access`) only runs when a
  bundle sets `allow_write_probe=True`, which **no built-in bundle does**.
  `validate_bundles` enforces budget/rate/scope and that probing phases carry a
  probing policy. All requests stay rate-limited, in-scope, and behind
  `net_guard`/`offline_guard`/`--proxy`.

### New detector packs (populated from the ranked catalog in P3)

| pack | covers |
|------|--------|
| `leak` (exists) | secrets, keys, tokens, source maps |
| `baas` (exists) | Supabase/Firebase/Appwrite RLS + config |
| `access-control` (exists) | IDOR/BOLA, BFLA, tenant checks |
| `appsec` (exists) | XSS/SSTI leads, auth bypass leads |
| `injection` (new) | SQLi/NoSQLi/SSTI/cmd/XXE/SSRF/redirect/traversal (fuzz-discoverable) |
| `authn` (new) | JWT/OAuth/session/password-reset/OTP-in-response/2FA-bypass |
| `client` (new) | DOM XSS, prototype pollution, postMessage, CORS, CSP, clickjacking |
| `api` (new) | excessive data exposure, BOPLA, rate-limit, enumeration, GraphQL |
| `recon` (new) | subdomain takeover, debug/admin endpoints, default creds, header/cookie audit, info disclosure |
| `headers` (new, lightweight) | security-header + cookie-flag audit (cheap, passive) |

### Named bundles (composition over packs)

| bundle id | packs | active_phases | use case |
|-----------|-------|---------------|----------|
| `secrets` | leak | passive | "just find leaked keys" (today's launch-gate) |
| `quick` | leak, headers, client | passive, crawl | fast hygiene pass, no crafted requests |
| `authz` | access-control, authn, api, baas | passive, authz_diff, baas_probe | needs 2 users / anon key; RLS + IDOR focus |
| `injection` | injection, api | passive, crawl, forms, fuzz | planned active input fuzzing; currently skip-loudly until packs/phases land |
| `recon` | recon, leak, headers | passive, subdomain, crawl | external attack-surface mapping |
| `baas` | baas | passive, baas_probe | Supabase/Firebase RLS deep probe |
| `deep` (everything) | ALL packs | ALL phases incl. mitm | the full deep scan + correlation engine |

`deep` = run every bundle, then run the **correlation engine** (D7) over the
union of findings to surface chained attack vectors.

## CLI / UX

**Implemented now (M1):**
- `keyleak bundles` — lists every bundle, its packs/phases, and flags bundles with
  no runnable detectors yet.
- `keyleak scan <url> --bundle <id>` and `keyleak local <path> --bundle <id>` —
  resolve the bundle's runtime packs into the scan (`--bundle` **overrides**
  `--packs`), printing the implied phases and skipping-loudly on unpopulated packs.

**Planned (later milestones):**
- `--bundle` on `site-scan`/`browser-scan` and full **phase orchestration** (crawl,
  subdomain, probe, fuzz, authz_diff, baas_probe, mitm). Today `--bundle` selects
  packs; the active phases a bundle declares are not yet executed by the CLI.
- `keyleak scan <url> --bundle deep --bearer $A --bearer-b $B --proxy warp` — the
  planned full active run once phase orchestration lands. Today this selects the
  runnable detector packs and prints the declared phases; active phases that are
  not yet wired degrade loudly (no silent coverage loss).

## Implementation shape (P7)

1. `keyleak/bundles.py` — `Bundle` dataclass + `BUNDLES` registry +
   `resolve_bundle(id)` / `bundle_packs` / `runnable_packs` / `validate_bundles`.
   Pure data + resolution; unit tested. **(done — M1)**
2. Register new packs in `DETECTOR_PACKS` **(done)** and populate detectors
   (catalog-driven, M2–M7).
3. `cli.py` — `--bundle` flag on `scan`/`local` + `bundles` subcommand **(done)**;
   extend to `site-scan`/`browser-scan` later. Reuses `normalize_packs`.
4. `site_scanner.py` deep mode — sequence active phases per the resolved bundle's
   `phases`, honoring `probe_policy` + guards. **(later — M3+)**
5. Reporting — group findings by bundle/pack; append the correlation section.

## Open questions for the human (flagged, defaults chosen)

- Default `deep` scan: MITM phase **off by default**, opt-in via `--active`/proxy
  (legal/scope safety). Chosen default: off-unless-asked.
- New pack names above are provisional; final names follow the ranked catalog (P3).
