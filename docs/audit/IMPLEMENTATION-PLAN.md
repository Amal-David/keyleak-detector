# KeyLeak Detector — Audit Remediation Implementation Plan

Derived from `AUDIT-MATRIX.md`. Ordered by **(safety × value × honesty) ÷ effort**.
Every item ships test-first and passes the Adversarial Review Gate (reviewers ≥85)
before it's marked done. Theme of the plan: **make what's built actually run —
honestly and safely — then extend toward the last-6-months threat gaps.**

Legend: effort S(<2h) / M(half-day) / L(day+). Status ⬜ todo · 🔄 doing · ✅ done.

## Tier 0 — Safety (a security tool must not be exploitable)

| ID | Item | Fixes | Effort | Status |
|----|------|-------|--------|--------|
| **A1** | **Fix S0 SSRF in BaaS probe.** Wrap every prober so each request URL is validated through `net_guard.scan_target_block_reason` (block loopback/link-local/private/metadata) **and** scope-checked to the scanned page's registrable domain. Applies whether the prober is default or injected. Thread the same guard from `app.py`/`browser_scanner` → `validate_baas_config`. | W1 | M | ✅ |
| A2 | **Extension remote-fetch SSRF guard** — private/link-local/loopback block in `service-worker.js fetchAndAnalyzeRemote`. | W11 | S | ✅ |
| A3 | **Single PII-scrub chokepoint** — redact in `Finding` construction so the privacy promise holds on browser/BaaS findings, not just local-file. | W7 | S | ✅ |

## Tier 1 — Make the marquee features real (stop overclaiming)

| ID | Item | Fixes | Effort | Status |
|----|------|-------|--------|--------|
| **B1** | **Wire `correlate()` into `build_report`** (new `attack_chains` param) + render an "Attack chains" section in md/html/json; pass `provenance` from site_scanner and `target` from browser_scanner. Turns the flagship meta-analysis from dead code into output. (= prior program M6b.) | W3 | M | ✅ |
| B2 | **Bundle phases: execute or fail loud.** `--bundle` must either run its declared navigation/probe phases (route through existing `scan_site`/probers) or hard-error — never silently downgrade to passive. `injection` (0 detectors) must skip loudly with a non-zero notice. | W4 | M | ✅ |
| B3 | **Confidence/validation-aware verdict** + truthful reason string (don't claim a high-confidence gate that isn't there). | W10 | S | ✅ |

## Tier 2 — Usefulness: the honest "scan before you ship" experience

| ID | Item | Fixes | Effort | Status |
|----|------|-------|--------|--------|
| **C1** | **One front door:** `keyleak check [path|url]` — runs a real multi-pack profile, prints which packs ran/skipped, emits a **coverage-aware** verdict. Align `local`/`demo` defaults. | W6 | M | ⬜ |
| C2 | **Surface unification** — shared evaluator so browser/extension apply the same FP guards + `min_entropy` + client-key downgrade + capture-group/multi-match as the CLI. Coverage-gate the extension verdict (no "SAFE TO SHIP" before real inspection). | W2, W9 | L | ⬜ |

## Tier 3 — Threat currency (the last-6-months "protect yourself" checks)

| ID | Item | Source | Effort | Status |
|----|------|--------|--------|--------|
| **D1** | **Live deployed-surface probe** — read-only marker-confirmed GETs for `/.env`, `/.git/config`, `/.git/HEAD`, Spring `/actuator/env|heapdump`, unauth LLM `/api/tags`,`/v1/models`. Behind scope guard + caps. "Run this before you deploy." | gap #1,#3,#4 | M | ⬜ |
| D2 | **Dependency lifecycle-hook scanner** — walk `node_modules/*/package.json` (+ root) for `pre/post/install`+`prepare` hooks invoking bun/curl/base64/git-ref; operationalizes this repo's CLAUDE.md supply-chain rules. | gap #2 | M | ⬜ |
| D3 | **Refresh Shai-Hulud IOCs** to 2.0 / Miasma (new C2 hosts, `environment_source.js`/`bun_installer.js`, repo-description markers). | gap #6 | S | ⬜ |
| D4 | **GitHub Actions hardening detectors** — unpinned `uses:@tag`, `permissions: write-all`, secret echoed in `run:`. | gap #7 | S | ✅ |
| D5 | **CORS Origin-reflection probe** (generic, not just BaaS `*`) + expanded vulnerable-JS-library table (lodash/axios/Next.js incl. CVE-2026-44575/-29927/Angular/Vue). | gap #9,#10 | M | ⬜ |

## Tier 4 — Foundation (quality / CI / packaging)

| ID | Item | Fixes | Effort | Status |
|----|------|-------|--------|--------|
| **E1** | **Add `pull_request` CI** (SHA-pinned actions): unittest suite (fails on collection errors), `cd extension && node --test`, and the launch-gate. | W5 | S | ✅ |
| E2 | **Fix dependency declarations** — add `tldextract`/`PyYAML`/`PySocks` to `requirements.txt`, add `[project].dependencies`, parity test. Unblocks the 4 disabled suites + `pip install .`. | W5, W8 | S | ✅ |
| E3 | **Harden serializer tests** — real SARIF-2.1.0 schema assert + HTML XSS-escaping assert on attacker-controlled finding fields; tests for the untested detector engines. | W12, W13 | M | ⬜ |

## Sequencing & safety rails

1. **A1 first** — it's an exploitable hole in a security tool. Nothing ships before it.
2. Tiers run roughly in order, but each item is independently committable and gated.
3. All active probing stays **read-only, opt-in, rate-limited, scope-bound, behind
   `net_guard`/`offline_guard`/`--proxy`** — the audit's #1 lesson is that these
   promises must be *enforced at the call site*, not just declared.
4. Each completed item: tests green → Adversarial Review Gate ≥85 → commit → update
   this table. Residual risk logged in `docs/audit/reviews/`.

## Status log

- 2026-06-10: Audit complete (6 reports, matrix written). Plan locked. Starting A1.
