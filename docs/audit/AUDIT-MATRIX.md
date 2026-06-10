# KeyLeak Detector — Code Audit: Strengths / Weaknesses Matrix

Audit date: 2026-06-10. Method: 6 parallel adversarial auditors over real source
(`keyleak-vuln-program` worktree, off `origin/main`) + a 6-month threat-landscape
researcher. Every claim below was required to cite `file:line`; the three
highest-stakes claims (S0 SSRF, dead correlation engine, unexecuted bundle phases)
were independently re-verified by hand against the source before this matrix was
written. Per-subsystem full reports live in `docs/audit/raw/01..06`.

## Headline

KeyLeak is **a strong detection/data core wrapped in a control plane that
overclaims.** Five of six subsystems scored 58–62/100, clustering on the same
structural fault: capabilities that are *declared, tested in isolation, and
advertised* but **not wired into any path a user actually runs** — plus one
exploitable **S0 SSRF** in the active BaaS prober. The single most common failure
mode is "the tool says something it doesn't actually do."

| Subsystem | Health | One-line verdict |
|---|---|---|
| Detector engine | 58 | Strong IOC/secret core; 3 detection surfaces (CLI/browser/extension) **disagree** — FP guards are CLI-only. |
| Active probing & safety | 58 | Good primitives, but SSRF-scope, rate-limit, and PII-redaction promises are **not enforced** on the probe path. **1× S0.** |
| Orchestration & reporting | 58 | Excellent data plane (crawl/dedupe/provenance); ~40% of advertised control plane (correlation + phases) is **inert**. |
| CLI / UX / extension | 58 | No honest "is my app safe?" front door; extension flashes "SAFE TO SHIP" before inspecting anything. |
| Tests / quality / CI | 62 | Test *content* above average, but **zero CI**, 4 suites silently disabled by a missing dep, half the modules untested. |
| 6-month threat currency | — | Static secret/IOC coverage is current; **active deployed-surface probing is the missing class** (the trend of the window). |

## Strengths (keep, build on)

- **S-1. Supply-chain IOC pack is genuinely good** and lands on the window's
  dominant attack family (Shai-Hulud lineage): `npm_optional_dep_git_ref`,
  `gh_actions_pull_request_target`, `shai_hulud_c2_domain`, `npm_prepare_bun_payload`.
- **S-2. Read-only-by-default invariant actually holds** for the one mutating
  probe: `baas_validator._probe_write_access` is gated by `allow_write_probe=False`
  (`baas_validator.py:285`) and is unreachable from every live caller. Asserted by
  `tests/test_baas_validator.py:455`.
- **S-3. Crawl / dedupe / provenance data plane is well-engineered and tested** —
  `site_scanner._merge_findings` provenance, BFS crawl caps, severity sort.
- **S-4. `net_guard` cloud-metadata SSRF block is correct in isolation** and tested
  (`test_net_guard.py:28`) — the primitive exists; it's just not called everywhere.
- **S-5. CLI false-positive suppression is evidence-driven and thoughtful**
  (entropy, placeholder, public-prefix, local-dev, client-key downgrade) — *on the
  CLI path*.
- **S-6. Supabase RLS active probe** is real, tested, FP-hardened (R3→R3b), and
  matches the most-reported breach class of the window (RANKED #3 / CVE-2025-48757).
- **S-7. Structured remediation contract** (`remediation_v2` fix/verify card) and a
  prepared adversarial-review culture (`docs/vuln-research/reviews/`).

## Weaknesses (ranked; S0 = critical → S3 = minor)

| # | Sev | Weakness | Evidence (file:line) | Verified |
|---|-----|----------|----------------------|----------|
| W1 | **S0** | **SSRF / scope bypass in BaaS probe.** Probe target = `config.project_url` taken verbatim from the scanned page's JS; `validate_baas_config` receives no scope guard and the default prober does raw `requests.request(url)`. Attacker page → server fetches `169.254.169.254`/internal hosts when `baas_validate=True`. | `browser_scanner.py:468`, `baas_validator.py:280,468`, `make_default_prober` (no guard), `app.py:1428` | ✅ by hand |
| W2 | S1 | **Detection surfaces disagree.** FP guards + `min_entropy` + client-key downgrade are CLI-only; `extension_pattern_payload` never serializes them and browser/extension do no post-filter → same secret, different verdict per surface. | `extension_bundle.py:71-89`, `browser_scanner.py:71-80` | ✅ |
| W3 | S1 | **Flagship correlation engine is dead code.** `attack_chains.correlate()` is called by nothing outside its own tests; the meta-analysis "chain findings like an attacker" feature produces zero user output. | `attack_chains.py:251` (no importers) | ✅ by hand |
| W4 | S1 | **Bundle phases declared but never executed.** `--bundle deep/recon/injection` print "not yet orchestrated … selecting pack detectors for now" and silently run passive-only; `injection` bundle has zero detectors → runs nothing. | `cli.py:607`, `bundles.py:101-145` | ✅ by hand |
| W5 | S1 | **No CI; 4 test suites silently disabled.** `.github/workflows/` absent; the dev environment lacked installed deps so `test_site_scanner{,_ssrf}`, `test_subdomain_takeover`, `test_dangerous_url_params` aborted on `import tldextract` before running — so crawler scope/SSRF enforcement was **untested in practice**. *(Correction after re-verify: `tldextract` IS declared in `requirements.txt`; the genuinely-missing declarations were `PyYAML`/`PySocks` (requirements.txt) and the whole `[project].dependencies` table — see W8. Root cause was no CI to install deps + run the suite.)* | no workflow dir; suite: `errors=4` | ✅ (ran suite) |
| W6 | S1 | **No honest "scan before I ship" front door.** `keyleak local` defaults to `launch-gate` (leak pack only) while `demo` uses `ci` (4 packs); 16 subcommands, no single coverage-aware command; extension shows green "SAFE TO SHIP" with ~zero coverage. | `cli.py:334`, `demo.py:32`, `popup.js:66-72` | ✅ |
| W7 | S1 | **Safety promises not enforced on probe path:** `ProbePolicy.rate_per_sec`/`max_requests` ignored everywhere; PII scrubber runs only on local-file path, never on browser/BaaS findings; `allow_write_probe` flag is dead-wired. | `bundles.py:50` (no limiter), `privacy_filter.py:61` (1 call site), `browser_scanner.py:468` | ✅ |
| W8 | S1 | **`[project]` install is broken / deps undeclared.** PEP 621 table has no `dependencies` key → `pip install .` ships zero runtime deps. | `pyproject.toml:47-69` | ✅ |
| W9 | S2 | **Browser scan ignores capture groups + emits one match per pattern per blob** — grouped detectors report the wrong span; ten keys → one finding. | `browser_scanner.py:75-79` | ✅ |
| W10 | S2 | **Verdict isn't confidence/validation-aware** but its reason text claims a "high-confidence gate." An unconfirmed lead blocks ship identically to a confirmed critical. | `models.py:213-220` | ✅ |
| W11 | S2 | **Extension `fetchAndAnalyzeRemote` SSRF** — fetches any forwarded URL with only an http/https check under `<all_urls>`. | `service-worker.js:201-237` | ✅ |
| W12 | S2 | **SARIF output is CI-hostile** — `artifactLocation.uri` set to runtime labels (`localStorage:foo`), `startLine` defaults to 1; GitHub Code Scanning rejects/mis-pins. HTML/SARIF/text ignore the `remediation_v2` contract. | `reporting.py:304-309`, `models.py:25-33` | ✅ |
| W13 | S2 | **~18/36 modules untested**, incl. all 4 detector engines (`detectors_ast/fuzzy/splittoken/dynamic`), `self_audit`, `privacy_filter`, `chain_of_custody`. Serializer tests are tautological (`assertIn("sarif", …)`, no XSS-escape check on attacker-controlled fields). | suite coverage map; `test_core_reporting.py:38` | ✅ |
| W14 | S2 | **Threat-currency gaps** (last 6 months): no live `/.env`+`/.git` probe (RANKED #2), no dep lifecycle-hook scanner, no Spring-actuator/unauth-LLM/Next.js-middleware probes, stale Shai-Hulud IOCs (no 2.0/Miasma), no GH-Actions hardening detectors, 2-entry JS-CVE table. | `docs/audit/raw/06` (sourced) | ✅ |
| W15 | S3 | Split-token reassembly detector is tautological/dead; name-only IOC match emits hardcoded critical; `doctor` network check is theater; `watch` re-scans whole tree; `feed sync` may emit empty manifests. | `detectors_splittoken.py:144`, `detectors_dynamic.py:57`, `doctor.py:142`, `watch.py:86`, `feeds.py:91` | ⚠️ reported |

## The through-line

Three of the worst weaknesses (W3, W4, W6) are the **same disease**: *features that
exist as code + tests + docs but are never executed by a real user path.* The tool
is more capable on paper than in the hands of someone running it. The highest-value
work is therefore less "write new detectors" and more **"make what's already built
actually run, honestly, and safely"** — then extend toward the 6-month gaps.

See `IMPLEMENTATION-PLAN.md` for the ranked remediation roadmap.
