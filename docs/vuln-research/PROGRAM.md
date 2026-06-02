# KeyLeak Runtime-Vulnerability Expansion Program

Autonomous program kicked off 2026-06-02. Branch: `feat/runtime-vuln-program`
(worktree `/Users/amal/experiments/keyleak-vuln-program`, off `origin/main`).

## My interpretation of the goal (correct me if wrong)

The goal was dictated by voice and is paraphrased. Here is what I understood as
the concrete, checkable deliverables. **If any of this is wrong, edit this file
and I'll re-plan from it.**

- **D1 — Research.** Build a comprehensive catalog of the top ~100–200 *runtime /
  dynamically discoverable* vulnerability use cases a tool like KeyLeak can detect
  — i.e. things found by interacting with a *running* app (form-filling, input
  validation probing, observing responses, crawling, auth probing), **not only**
  static or runtime *code* analysis. Seeded by the CBSE / Supabase-RLS class of bug.
- **D2 — Per-framework + agnostic.** Top ~10 per framework/stack (Java/Spring,
  Node/Express, React, Next.js, Flask, Django, Rails, Laravel/PHP, ASP.NET, Go,
  FastAPI, Angular/Vue, mobile/API backends) → can reach ~200, plus a
  framework-agnostic set and an "ethical-hacker top 15 scripted recon" set.
- **D3 — Rank.** Rank by prevalence ("done-to-death"), impact, and runtime
  detectability. Produce a curated **Top 51** core set (+ an extended Top 100/200).
- **D4 — Adversarial review.** 2–3 independent agents adversarially review,
  re-rank, and modify the catalog before it's locked.
- **D5 — Integration plan.** A concrete plan for how to add these into KeyLeak's
  existing detector/scan pipeline (the analyzer + deep/site scan), grounded in the
  real architecture (see "Architecture facts" below).
- **D6 — Implement (staged).** Add detectors as part of the deep scan; let users
  invoke **bundles** of scans (not just everything or each one independently); the
  deep scan runs all of them — subdomain enumeration, crawl + page download +
  data analysis, and MITM/proxy interception.
- **D7 — Meta-analysis rule book.** The missing piece: correlate individual
  findings into **chained attack vectors** (finding 1 + 2 + 3 → a real attack
  path), the way an ethical hacker mixes signals from different places.
- **D8 — Supabase RLS deep-dive.** It's the primary current theme: a dedicated
  deep-dive + a UI design for how to *discover, evaluate, and test* RLS vulns.
- **D9 — Autonomy.** Run independently for ~10–15 hours, parallel where possible,
  sequential where required, committing working states; no user actions needed.

## Decisions I'm taking (the goal delegated these to me)

- **Meta-analysis engine = deterministic rule-based first.** KeyLeak is
  offline/privacy-first (`offline_guard`, `net_guard`, `privacy_filter`). A
  transparent, dependency-free, testable correlation **rule engine** fits that
  stance and is reproducible in CI. I'll design it with an **optional pluggable
  LLM-assist hook** (local Qwen via an offline-friendly interface) for fuzzy
  correlations rules can't express — but the default path needs no LLM. Rules
  first; LLM is opt-in and never required.
- **Bundles = extend the existing `pack` + `profile` model** rather than invent a
  parallel concept. New packs (e.g. `injection`, `authz`, `client`, `recon`,
  `api`) + named bundles/profiles that compose them; deep scan = the `full`/all
  bundle plus active phases (subdomain enum, crawl, MITM).
- **Safety/authorization.** KeyLeak is an authorized security tool. Active probing
  (RLS reads, MITM, fuzzing) stays opt-in, read-only by default, rate-limited,
  scoped to the target, and behind existing guards (`net_guard`, `offline_guard`,
  `--proxy`). No destructive payloads. MITM = the tool's own proxy interception.
- **Implementation is staged + test-backed**, committed incrementally on this
  branch. No giant unreviewed dump. A PR is prepared at the end for human review.

## Architecture facts (grounding)

- `keyleak/detectors.py`: `@dataclass(frozen=True) Detector` — `id, pattern,
  severity, categories, pack, validation_status, attack_scenario, finding_type,
  remediation, references, id_aliases, ...`. `DETECTOR_PACKS`, `PROFILE_PACKS`
  (`launch-gate`/`local-dev`/`bug-bounty`/`ci`/`full`), `normalize_packs`,
  `detectors_for_packs`.
- Dynamic/active surface already exists: `detectors_dynamic.py`,
  `detectors_fuzzy.py`, `detectors_ast.py`, `detectors_splittoken.py`,
  `browser_scanner.py`, `site_scanner.py` (deep/site scan, crawl + subdomain),
  `baas_validator.py` (active RLS probing), `access_control.py`,
  `blast_radius.py`, `subdomain_takeover.py`, `proxy.py`, `net_guard.py`,
  `offline_guard.py`, `privacy_filter.py`, `models.py` (`Finding`/`Evidence`),
  `reporting.py`.
- CLI subcommands: `scan, local, site-scan, browser-scan, self-audit, explain,
  diff, feed, archive, watch, doctor, demo, disclose, allowlist-diff`.

## Standing process: Adversarial Review Gate (every step)

Every completed artifact (research output, design doc, code milestone) passes
through an adversarial review gate before it's considered done:
1. Spawn N reviewers (parallel, distinct critical lenses) that **question,
   validate, demand proof, and find gaps** — harshly. Each returns a score
   (0–100) + `must_fix` + `unsupported_claims` + `evidence_gaps`.
2. If any reviewer scores < 85 or raises a must-fix, **revise** and re-review.
3. Repeat until all reviewers ≥ 85 (or 3 rounds, then record residual risk).
4. Log the outcome in `reviews/REVIEW-LOG.md` (round, scores, what changed).
Proof, not assertion: code must show passing tests; designs must cite real
`file:line` grounding and feasible probes.

## Phase plan

- **P1 Research** (multi-agent, parallel) → raw catalog per slice. *(in progress)*
- **P2 Dedupe + normalize** → master catalog (`catalog/master.json`).
- **P3 Adversarial rank/review** (2–3 agents) → Top 51 + extended list, scored.
- **P4 Meta-analysis rule book** → chaining ruleset + engine design.
- **P5 Integration plan** → how each maps to detectors/packs/deep-scan/bundles.
- **P6 Supabase RLS deep-dive + UI design.**
- **P7 Implementation** (staged, tested, committed): catalog-as-data, runtime
  detectors, scan bundles, correlation engine + ruleset, deep-scan wiring.
- **P8 Prepare PR** for human review.

## Progress log

- 2026-06-02: Program set up. Worktree + research dirs created. Architecture
  oriented. Wrote this anchor + scan-bundles design (D6).
  - P1 research workflow launched (18 parallel slices, Sonnet) — running in bg.
  - Architecture-map agent launched (active-scan internals for D5/D7) — running.
  - Decision recorded: meta-analysis = rule-based first, optional LLM hook.
  - Next on completion: P2 dedupe → write catalog/master.json → P3 adversarial rank.
- 2026-06-02 (cont.): P1 research landed (269 entries). P2 normalized + per-slice.
  D6/D5/D8/D7 designs written. **M1 shipped**: bundles.py + 12 passing tests.
  P3 ranking landed: 66 clusters → Top 51 (29 crit/18 high/4 med) + 7 adversarial
  additions (req-smuggling, web-cache-deception, deser, ATO chain, ws-auth,
  exposed-.git, open-bucket) + 16 extended → master.json/RANKED.md/mapping.
  Milestone load: M2=13, M3=24, M4=5, M5=4, M7=12.
  Adversarial Review Gate R1 running over designs + M1 (gates M2).
  - Next: apply R1 fixes → M2 (passive detectors) under the gate → M3..M7.
