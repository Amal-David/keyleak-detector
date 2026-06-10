# Audit 03 — Scan-Orchestration & Reporting Subsystem

Scope: `keyleak/site_scanner.py`, `browser_scanner.py`, `local_scanner.py`, `reporting.py`,
`models.py`, `bundles.py`, `attack_chains.py`, `watch.py`. Tests skimmed:
`test_site_scanner.py`, `test_core_reporting.py`, `test_attack_chains.py`, `test_bundles.py`.

Verdict up front: the *data plane* (crawl → scan → merge → report serialize) is solid and
well-tested. The *control plane* is half-built theater: two of the subsystem's headline
capabilities — **attack-chain correlation** and **bundle phase orchestration** — are
declared, documented, and unit-tested, but **never executed by any real scan path**. A user
running `keyleak scan --bundle deep` or `keyleak site-scan` gets none of the meta-analysis or
active phases the bundle/chain code advertises.

---

## Strengths

- **Crawl correctness is genuinely careful.** `crawl_pages` (site_scanner.py:350) does BFS
  with normalized dedup (`_normalize_url`, :309), same-registrable-domain scoping
  (`_filter_links`, :316), a global `max_pages` cap, per-context cleanup in a `finally`
  (:407-414) so a failed host can't leak browser contexts, and a budget-aware `remaining`
  computation (:425) that accounts for the in-flight queue. This is above-average crawler
  hygiene.
- **Provenance merge is the right design.** `_merge_findings` (site_scanner.py:436) keys on
  `(type, redacted_value)`, keeps one canonical Finding, and returns a `finding.id -> [urls]`
  map so the report can show *which pages* a leak appeared on. Backfilling
  `evidence.request_url` only when empty (:450) is correct.
- **Subdomain source-priority ordering is deliberate and correct.** `discover_subdomains`
  (:261-275) places apex → subfinder → amass → crt.sh → dns-brute so the `max_subdomains`
  cap can't drop a real CT-log hit in favor of a brute-force guess that merely sorts earlier.
  Per-source attribution (`sources_out`) is a nice provenance touch.
- **SSRF guard is threaded consistently** through discovery, crawl roots, link-following,
  and per-URL scan (site_scanner.py:584-599, :372, :423, :638), and never re-adds a host the
  guard just rejected (:594-599).
- **Redaction-before-leave is enforced** in the browser path (`_to_finding`, browser_scanner.py
  :472-488) with salted HMAC redaction, and the comment documents the historical cleartext leak
  it fixes. `format_html` HTML-escapes every interpolated field (reporting.py:114, :144-153).
- **Bundle invariants are validated at import** (`validate_bundles`, bundles.py:160-188,
  invoked at :188) — probing phases require a probing policy, request-sending bundles require a
  budget, scope is allowlisted. The `unpopulated_packs`/`runnable_packs` "skip loudly" split
  (:83-93) is honest about empty packs.
- **Parallel takeover check is correctly lifecycle-managed** — submitted to a 1-worker pool and
  shut down in a `finally` that wraps the whole crawl+scan body (site_scanner.py:604-672).

---

## Weaknesses

| id | sev | file:line | evidence | fix |
|----|-----|-----------|----------|-----|
| W1 | **S1** | attack_chains.py:251 (`correlate`); grep: no non-test caller | ⚠️ **DEAD CODE.** `correlate()` / `SEED_CHAINS` are *never* called by `build_report`, `site_scanner`, `browser_scanner`, `local_scanner`, or `cli.py`. The module's own docstring (:22-28) admits "It is NOT yet called by any scan path." The 5 seed chains (RLS+anon key, service_role leak, sourcemap+secret, etc.) — the subsystem's flagship "ethical-hacker" value — produce **zero user-visible output**. Only `tests/test_attack_chains.py` exercises it. | Wire it into `build_report` (add an `attack_chains` param) and pass `provenance` from `site_scanner` (:674) and `target=url` from `browser_scanner` (:438). Render a "Attack Chains" section in all 4 serializers + a `verdict` contribution. |
| W2 | **S1** | bundles.py:101-145; cli.py:606-607 | ⚠️ **DECLARED-NOT-EXECUTED PHASES = silent coverage loss.** Bundles declare phases `crawl/subdomain/probe/forms/fuzz/authz_diff/baas_probe/mitm`, but `_apply_bundle_selection` (cli.py:589) only maps the bundle's *packs* into `args.packs` and prints (cli.py:607) "active phases ... are **not yet orchestrated** by the CLI ... selecting pack detectors for now." So `--bundle recon` (declares `subdomain,crawl,probe`) and `--bundle deep` (declares everything + "attack-vector correlation") run **only passive pack detectors on whatever target mode the user chose** — no crawl, no subdomain enum, no probing, no correlation. The `injection` bundle declares `crawl/forms/fuzz` against packs (`injection`,`api`) that have *zero* detectors → it runs literally nothing. | Either (a) route probing/navigation bundles through `scan_site`/active probers so declared phases execute, or (b) until then, make `--bundle` reject probing bundles with a hard error instead of a stderr note silently downgrading to passive. A "deep" bundle that probes nothing is worse than no bundle. |
| W3 | **S2** | models.py:213-220 | **Verdict ignores confidence and conflates severity with confidence.** `verdict` returns `BLOCK_SHIP` on *any* critical/high finding with reason text "Critical or **high-confidence** exposures" — but the logic never reads `finding.confidence` or `validation_status`. A `validation_status="lead"` high (e.g. `dangerous_url_parameter` at high, site_scanner.py:499) BLOCKS SHIP identically to a `confirmed` critical. The reason text claims a confidence gate that does not exist. `attack_chains` carefully caps unconfirmed chains at "high" (:297-301) precisely to avoid this — but since correlation is unwired (W1), the verdict gets no benefit. | Have `verdict` weigh `validation_status`/`confidence`: leads → REVIEW, confirmed highs/criticals → BLOCK. At minimum fix the reason string so it doesn't assert a nonexistent confidence check. |
| W4 | **S2** | site_scanner.py:633-634 | **Dangerous-param findings can be dropped by the merge dedup.** `_dangerous_param_findings` keys distinct findings by `(netloc, path, hits)`, but `_merge_findings` re-keys on `(type, redacted_value)` where `redacted_value` is just the comma-joined param *names* (site_scanner.py:510, :488). Two different endpoints sharing the same param name (`/a?cmd=` and `/b?cmd=`) collapse to **one** finding; the second host/path survives only as a provenance URL, losing its distinct severity (one could be `high` server-exec, the other `medium`). | Include path/host in the dangerous-param `redacted_value` or give these findings a merge key that preserves location. |
| W5 | **S2** | reporting.py:251 vs :64; :88-103 | **HTML report drops packs and remediation_v2; format inconsistency across serializers.** `format_html` reads a local `packs` var (:113 `payload.get("packs")`) which works, but it renders **only** `risk_reason`+`remediation` — it never surfaces the structured `remediation_v2` card (what-leaked / why / fix-steps / verify) that Markdown renders (:88-100) and that models.py:25-33 calls a cross-emitter "contract." HTML also shows **no provenance, no source URL per finding, no attack chains**. SARIF and text likewise ignore `remediation_v2`. The "every emitter renders the same four-field card" contract is violated by 3 of 4 emitters. | Render `remediation_v2` in HTML/SARIF/text, or drop the contract comment. Add per-finding `source` to HTML cards. |
| W6 | **S2** | reporting.py:304-309 | **SARIF locations are semantically wrong for CI consumers.** `artifactLocation.uri` is set to `item["source"]`, which for browser/site scans is a label like `localStorage:foo`, `Inline Script #1`, or a full `https://…` URL — none of which are repo-relative file URIs. `region.startLine` defaults to `1` when `evidence.line` is absent (the common case for runtime scans). GitHub Code Scanning will either reject these or pin every runtime finding to line 1 of a bogus "file," making the SARIF noise rather than signal. | For runtime scans, emit findings without a `physicalLocation` (or use a `logicalLocation`/`properties.url`); only emit `artifactLocation` when `source` is a real relative path (local scan). |
| W7 | **S3** | reporting.py:23, 363-374; site_scanner.py:686 | **`attack_vectors` param is a vestigial, near-dead second correlation path.** `build_report(attack_vectors=...)` converts `attack_vectors["subdomains"][].findings` into findings (:363). Only `cli.py:499` (a JSON re-emit path) ever passes it; no scanner does. Meanwhile `site_scanner` stores a *different* `subdomains` (a `List[str]`) into `report.extra` (:686). Two unrelated "subdomains" concepts and two unrelated "attack vector" concepts coexist — confusing and a latent bug magnet. | Remove `attack_vectors` param or unify it with `attack_chains` (W1). Pick one correlation surface. |
| W8 | **S3** | site_scanner.py:382, browser_scanner.py:379 | **Playwright-absent degradation is silent and inconsistent.** `crawl_pages` silently returns host roots when Playwright is missing (:382) — a "full site scan" quietly becomes "fetch N homepages," with no flag in the report telling the user coverage collapsed. `run_browser_scan` instead *raises* ImportError. Same dependency, opposite failure mode, and the site path hides the degradation. | Record `extra["crawl_degraded"]=true` (or emit an info finding) when Playwright is unavailable so the report doesn't imply coverage it didn't achieve. |
| W9 | **S3** | watch.py:87 | **`watch` ignores user pack/profile selection.** `_write_scan` hardcodes `profile="ci"` and never threads `--bundle`/`--packs`, so the live SARIF in the editor can disagree with what `keyleak local` reports for the same tree. Also re-scans the *entire* root on any single-file change (:79) — fine for small repos, O(repo) per save on large ones. | Pass through the user's profile/packs; optionally scan only changed files. |
| W10 | **S3** | reporting.py:24 | **Severity sort is not deterministic within a severity tier.** `normalized.sort(key=severity_rank, reverse=True)` is stable, so order within a tier depends on detector iteration order, which varies across crawl runs (page order, threads). Two scans of the same site can emit findings in different order → noisy diffs in committed SARIF/JSON artifacts. | Add a stable secondary sort key (`finding.id`, then `source`). |

---

## Ranked Improvements (highest leverage first)

1. **Wire `attack_chains.correlate()` into the scan path (W1).** This is the single biggest
   usefulness unlock. The engine, rules, host-correlation, severity-capping, and tests already
   exist (attack_chains.py); only the ~15-line wiring (a `build_report` param + two call sites
   passing `provenance`/`target` + a report section) is missing. Today the product's marquee
   "we chain findings like a real attacker" capability ships **off**. Highest ROI.

2. **Make declared bundle phases either execute or hard-fail (W2).** A `deep`/`recon`/`injection`
   bundle that silently runs passive-only is a trust bug: the user believes they probed and they
   did not. Minimum viable fix: route probing/navigation bundles through `scan_site` + active
   probers; interim fix: refuse to run a probing bundle in passive mode instead of a stderr note.

3. **Make the verdict confidence-aware and fix the reason text (W3).** The verdict is the
   "run-this-before-you-ship" output. Right now an unconfirmed high lead BLOCKS SHIP exactly
   like a confirmed critical, and the reason text *claims* a confidence gate that isn't in the
   code. Folding `validation_status`/confidence (and W1's capped chains) into the verdict makes
   the ship/no-ship signal trustworthy.

4. **Honor the `remediation_v2` contract in all emitters (W5)** and **fix SARIF locations (W6).**
   These directly affect whether output is *actionable* (the four-field fix card) and whether CI
   ingestion works (SARIF that GitHub won't reject/misplace). Medium effort, high day-to-day value.

5. **Surface degraded coverage and de-duplicate the correlation surfaces (W7, W8, W10).**
   Cleanup that prevents the report from overstating what it checked and from producing noisy,
   non-deterministic artifacts.

---

### Coverage-loss summary (the key usefulness question)

- `attack_chains.correlate` — **declared + tested, never executed.** ⚠️ DEAD.
- Bundle phases `crawl/subdomain/probe/forms/fuzz/authz_diff/baas_probe/mitm` — **declared per
  bundle, never orchestrated by the bundle/CLI path.** ⚠️ DECLARED-NOT-EXECUTED. (Note: `scan_site`
  *does* crawl+subdomain, but it is reached via the `site-scan` command, not via `--bundle recon`.)
- `injection` bundle — declares fuzz phases against packs with **zero detectors** → runs nothing.
- `build_report(attack_vectors=...)` — a second, near-orphaned correlation path used by one
  re-emit call site, conflicting in naming with the real provenance/chains data.
