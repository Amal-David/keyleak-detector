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

A **Bundle** = `{ id, title, description, packs[], active_phases[], probe_policy }`.

- `packs[]` — which detector packs run (reuses the existing pack system; we add
  new packs below).
- `active_phases[]` — subset of `{passive, crawl, subdomain, forms, authz_diff,
  baas_probe, mitm, fuzz}`. Passive-only bundles send no crafted requests.
- `probe_policy` — `{ active: bool, max_requests, rate_per_sec, read_only: true,
  scope: same-registrable-domain }`. Active probing stays read-only, rate-limited,
  in-scope, and behind `net_guard`/`offline_guard`/`--proxy` (never destructive).

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
| `authz` | access-control, authn, api | passive, authz_diff, baas_probe | needs 2 users / anon key; RLS + IDOR focus |
| `injection` | injection, api | crawl, forms, fuzz | active input fuzzing (opt-in) |
| `recon` | recon, leak, headers | passive, subdomain, crawl | external attack-surface mapping |
| `baas` | baas | passive, baas_probe | Supabase/Firebase RLS deep probe |
| `deep` (everything) | ALL packs | ALL phases incl. mitm | the full deep scan + correlation engine |

`deep` = run every bundle, then run the **correlation engine** (D7) over the
union of findings to surface chained attack vectors.

## CLI / UX

- `keyleak scan <url> --bundle authz` (new `--bundle` flag; resolves to packs +
  phases + probe policy). `--bundle` composes with existing `--packs`/`--profile`.
- `keyleak scan <url> --bundle deep --bearer $A --bearer-b $B --proxy warp`
  runs the whole thing (active phases enabled because the bundle declares them;
  still read-only + rate-limited).
- `keyleak bundles` (new subcommand) lists bundles + what each runs.
- Active phases require explicit opt-in: a bundle that declares `fuzz`/`mitm`/
  `authz_diff` only runs them when the needed inputs (two bearers, proxy, or an
  explicit `--active` ack) are present; otherwise it degrades to passive and
  reports the skipped phase loudly (no silent reduction in coverage).

## Implementation shape (P7)

1. `keyleak/bundles.py` — `Bundle` dataclass + `BUNDLES` registry +
   `resolve_bundle(id) -> (packs, phases, policy)`. Pure data + resolution; unit
   tested.
2. Add new packs to `DETECTOR_PACKS` and populate detectors (catalog-driven).
3. `cli.py` — `--bundle` flag on `scan`/`site-scan`/`browser-scan`; `bundles`
   subcommand. Reuses `normalize_packs`.
4. `site_scanner.py` deep mode — sequence active phases per the resolved bundle's
   `active_phases`, honoring `probe_policy` + guards.
5. Reporting — group findings by bundle/pack; append the correlation section.

## Open questions for the human (flagged, defaults chosen)

- Default `deep` scan: MITM phase **off by default**, opt-in via `--active`/proxy
  (legal/scope safety). Chosen default: off-unless-asked.
- New pack names above are provisional; final names follow the ranked catalog (P3).
