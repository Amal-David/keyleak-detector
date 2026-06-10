# KeyLeak active-scan architecture — extension points (D5 grounding)

Condensed from a full-codebase map. File:line refs are approximate.

## Pipeline (single URL → site → report)

- `browser_scanner.run_browser_scan(url, ...)` — injects `_INIT_SCRIPT_TEMPLATE`
  via Playwright `addInitScript`; scans DOM/localStorage/sessionStorage/IndexedDB/
  CacheStorage/SW; extracts BaaS config; `_to_finding()` → `Finding`. Optional
  `_run_baas_validation()` when `baas_validate=True`.
- `site_scanner.scan_site(domain, depth, max_pages, max_subdomains)` — subdomain
  discovery (crt.sh + optional subfinder + DNS brute of `COMMON_SUBDOMAINS`, cap 25)
  → BFS crawl via Playwright (cap 100, depth 3) → `run_browser_scan` per URL →
  `_merge_findings` (dedupe by (type, redacted_value), **provenance**: finding.id →
  [urls] in `report.extra["provenance"]`).
- `reporting.build_report(target, findings, scan_mode, attack_vectors, profile,
  packs)` — normalizes findings, **already calls `_attack_vector_findings(attack_vectors)`**
  and folds them in as `category="access-control"` findings. Sorts by severity,
  computes verdict/summary. Serializers: json/markdown/html/sarif.

## Active probing already present (reuse, don't reinvent)

- `baas_validator.py` — `BaaSConfig`, `BaaSProbeResult`, `BaaSValidation`;
  `validate_baas_config(config, prober, js_extraction)`. Per-provider probes:
  Supabase (`_probe_tables` GET `/rest/v1/{t}?select=*&limit=1`, `_probe_storage`,
  `_probe_rpcs` (surfaces RPCs as leads WITHOUT calling them — POSTing would
  execute the function), `_probe_write_access` (mutating insert probe — opt-in via
  `allow_write_probe`, OFF by default), `_probe_auth_config`,
  `_analyze_realtime`), Firebase, Appwrite, PocketBase. Caps: TABLE 50 / BUCKET 10
  / RPC 20 / WRITE 20. `prober` is an injectable Callable (testable).
- `access_control.compare_access_control_urls(urls, user_a_auth, user_b_auth,
  fetch, max_urls)` — two-user IDOR: object-id URL regex, fetch with A vs B,
  body-similarity > 0.85 + both 2xx → `type="idor"`. `fetch` injectable.
- `blast_radius.compute_blast_radius(finding, raw_value=None, *, probes: dict[str, Prober])`
  — read-only scope probes for GitHub PAT / Stripe / OpenAI / Gemini / JWT-claim
  decode. NOTE the real shape: a `{detector_id: Prober}` dict + the raw token, not
  a single callable. (This is the pattern the new ActiveCheck `http` should follow.)

## Guards every active phase must respect

- `offline_guard.install_socket_block()` — blocks non-loopback when `--offline`;
  `KEYLEAK_OFFLINE_ALLOW_HOSTS` allowlist.
- `proxy.resolve_proxy/requests_proxies/playwright_proxy` — `warp`/`tor` aliases,
  http/https/socks5. All active HTTP should route through these.
- Probe caps + rate limits per probe type. Read-only by default.

## Detector model

- `Detector` frozen dataclass: `id, pattern, severity, categories, pack,
  validation_status, attack_scenario, finding_type, remediation, references,
  extension, min_entropy, ...`; `canonical_id = f"{pack}.{id}"`.
- Built-in `DETECTORS` list (~43). Dynamic: `detectors_dynamic.load_dynamic_detectors`
  (IOC manifest → Detector), `detectors_fuzzy` (worm fingerprints), `detectors_ast`,
  `detectors_splittoken`. Packs/profiles: `DETECTOR_PACKS`, `PROFILE_PACKS`,
  `normalize_packs`, `detectors_for_packs`.
- `Finding`/`Evidence`/`ScanReport` in `models.py`. `ScanReport.extra` carries
  scan-mode metadata + provenance. **No attack-chain concept yet.**

## Chosen extension points (this program)

1. **Pattern/runtime detectors** → add `Detector`s (new packs `injection/authn/
   client/api/recon/headers`); browser-eligible ones get `extension=True` and flow
   through `extension_pattern_payload()` into the injected scanner.
2. **Active checks** (fuzz probes, header/CORS audit, auth-diff, enumeration) →
   new prober modules following the `baas_validator`/`access_control` injectable-
   `prober`/`fetch` pattern, with their own caps + guard compliance. Registered in
   an **active-check registry** keyed by the bundle `active_phases`.
3. **Correlation / attack-vector chaining** → new `keyleak/attack_chains.py`:
   `@dataclass ChainRule {id, name, requires:[detector_id/type globs], when:Callable,
   produce:Callable→Finding/AttackVector, severity}`; `ATTACK_CHAINS` registry;
   `correlate(findings, context) -> List[AttackVector]`. Hook it into
   `build_report` via a NEW `attack_chains` param + a dedicated section — NOT the
   existing `attack_vectors` arg, whose `_attack_vector_findings` only understands
   `{"subdomains":[{host,findings}]}` and would flatten/lose the AttackVector model.
   `report.extra["provenance"]` (set by `site_scanner._merge_findings`, absent on
   single-URL scans) provides host co-location, with a fallback to the host parsed
   from `evidence.request_url`/`source` so single-URL RLS chains still fire.
4. **Bundles** → `keyleak/bundles.py` (Bundle = packs + active_phases + probe_policy);
   current `--bundle` CLI support selects runnable packs and prints the declared
   phases; phase orchestration and `deep` correlation remain planned extension
   work rather than shipped behavior.

## Reconciliation note

The map suggested a `DetectorBundle = [detector_ids] + tags` selector. We keep the
**packs + active_phases** Bundle as primary (matches "deep scan runs subdomain +
crawl + MITM" = phases, not just detector lists); detector-id/tag selection can be
an optional secondary filter later.
