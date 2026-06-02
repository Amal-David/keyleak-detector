# Integration + implementation plan (D5)

How the ~Top-51 (+ extended) runtime vulnerabilities become real KeyLeak coverage,
grounded in the existing architecture (see `architecture-map.md`). The specific
catalog→detector mapping table is appended after P3 (ranking) lands.

## 1. Detector taxonomy → extension point

Every catalog entry maps to exactly one of four implementation shapes:

| shape | what | KeyLeak home |
|-------|------|--------------|
| **A. passive pattern** | regex/heuristic over response bodies, headers, JS, storage | a `Detector` in `detectors.py` (browser-eligible → `extension=True`, flows through `extension_pattern_payload`) |
| **B. active probe** | send a crafted read-only request, classify the response (actuator/`/h2-console`/`.git`/`.env`/CORS preflight/security-header audit/open-redirect/SSTI-marker/error-trace) | a new **ActiveCheck** (see §3), registered + selected by bundle phase |
| **C. auth-differential** | compare two authenticated users (IDOR/BOLA/BFLA/tenant) | extend `access_control.py` (already does 2-user IDOR); generalize to BFLA + object-property |
| **D. config-extract + probe** | extract config from the page, then probe the backend (BaaS RLS, GraphQL introspection, Firebase rules) | extend `baas_validator.py` + a GraphQL probe sibling |

Most entries are B or A; the highest-impact (RLS, IDOR) are C/D and already have
scaffolding.

## 2. New detector packs

Add to `DETECTOR_PACKS`: `injection, authn, client, api, recon, headers` (joining
`leak, appsec, access-control, baas, correctness, housekeeping`). Each Top-51 item
gets a `suggested_pack` from P3. Packs compose into bundles (`bundles.py`, D6).

## 3. Active-check registry (new abstraction)

Active probes today are hardcoded (baas_validator, access_control). To add ~30
active checks cleanly, introduce a small registry mirroring the injectable-`prober`
pattern already proven in `baas_validator`/`blast_radius`:

```python
class ActiveCheck(Protocol):
    id: str            # "recon.actuator", "headers.cors", "injection.ssti-marker"
    pack: str
    phase: str         # which bundle active_phase enables it: "probe"|"forms"|"fuzz"|"authz_diff"|"baas_probe"|"crawl"
    def run(self, target: Target, http: Prober, budget: Budget) -> list[Finding]: ...

ACTIVE_CHECKS: list[ActiveCheck] = [...]   # registered like DETECTORS
def active_checks_for(packs, phases) -> list[ActiveCheck]
```

- `http` is the injectable prober (routes through `proxy.py`, honors
  `offline_guard`, read-only). `budget` carries per-check caps + global rate limit.
- Checks are pure + unit-testable with a fake prober (no network), exactly like the
  BaaS probes today.
- This is the single seam where 100+ active checks plug in without touching the
  orchestrator.

## 4. Deep-scan orchestration (`site_scanner` deep mode)

`scan_site(..., bundle="deep")` resolves the bundle (D6) → `(packs, active_phases,
probe_policy)` then sequences phases (parallel within a phase where safe):

1. **subdomain** (if phase enabled): existing discovery (crt.sh + subfinder + DNS).
2. **crawl + download**: existing BFS; keep page bodies for analysis + provenance.
3. **passive**: run pack-A detectors over every downloaded page/response/header.
4. **probe**: run pack-B `ActiveCheck`s (actuator, .git/.env, CORS, headers,
   open-redirect, SSTI markers, error-trace) per host, capped + rate-limited.
5. **forms/fuzz** (opt-in `--active`): discover forms/params; send benign
   validation-probe payloads (marker-based reflection, error-based) — never
   destructive; read-only-by-intent.
6. **authz_diff** (needs `--bearer A --bearer-b B`): `access_control` IDOR/BFLA.
7. **baas_probe**: `baas_validator` RLS matrix (D8).
8. **mitm** (opt-in, off by default): tool proxy interception to capture traffic
   the crawler misses (xhr/fetch/websocket) for passive analysis.
9. **correlate**: run `attack_chains.correlate()` over the merged findings (D7) and
   attach the Attack-Vectors section.

Every active phase honors: read-only default, per-check caps, global rate limit,
scope = same registrable domain, `offline_guard`, optional `--proxy`. Phases that
need inputs they don't have (2nd bearer, proxy, `--active` ack) **skip loudly** and
the report records the skipped coverage (no silent reduction).

## 5. Reporting

- Group findings by pack/bundle; add the **Attack vectors** section (D7) above
  per-finding detail; add the **BaaS/RLS matrix** view (D8).
- Verdict escalation: any critical finding or critical attack-vector → BLOCK SHIP.
- `--bundle` + `bundles` subcommand (D6) surfaced in CLI + extension.

## 6. Staged P7 roadmap (each milestone independently shippable + tested)

- **M1 — bundles core.** `keyleak/bundles.py` (Bundle model + registry + resolve)
  + `--bundle`/`bundles` CLI + tests. *(no behavior change to detectors)*
- **M2 — new packs + high-value passive detectors.** Add `headers/client/api`
  passive `Detector`s (security headers, cookie flags, CORS-reflected, mixed
  content, sensitive-data-in-response markers, GraphQL introspection hint, verbose
  error/stack-trace, open-redirect reflection) + regenerate extension bundle + tests.
- **M3 — active-check registry + recon checks.** `ActiveCheck` protocol + registry;
  recon probes (actuator/`/env`, `/h2-console`, `.git`/`.env`/backup, default-cred
  ping, debug endpoints) wired into deep-scan `probe` phase + tests (fake prober).
- **M4 — auth-diff generalization.** Extend `access_control` to BFLA + object-
  property (BOPLA); CLI 2-bearer wiring; tests.
- **M5 — BaaS/RLS enhancements (D8).** OpenAPI-root table enumeration, RLS-disabled
  vs permissive, service_role detection, auth-settings classify, GraphQL probe,
  per-table matrix in `BaaSValidation` + UI matrix + tests.
- **M6 — correlation engine (D7).** `attack_chains.py` + `SEED_CHAINS` + wire into
  `build_report` + report section + verdict escalation + per-rule pos/neg tests.
- **M7 — fuzz/forms + MITM phases (opt-in).** benign input-validation probing +
  proxy-capture passive analysis; documented, off by default, scope-guarded.

Order rationale: M1/M2 are pure-additive + low-risk (ship first); M3–M6 add the
active + meta-analysis value; M7 (the most sensitive: fuzzing/MITM) is last and
strictly opt-in. Catalog Top-51 items are assigned to M2–M6 in the post-P3 mapping.

## 7. Catalog → detector mapping

*(Appended after P3 reconcile: each Top-51 cluster → {shape A/B/C/D, pack,
milestone, detector id}. Until then, M1 (bundles) is unblocked and starts now.)*
