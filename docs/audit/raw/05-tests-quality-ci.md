# Audit 05 — Tests, Quality Posture, Packaging & CI

Auditor stance: adversarial QA / release engineering. A green suite that doesn't
verify intent is worse than no suite. All claims grounded in real files under
`<repo>`.

## Real suite state (measured)

Command:
```
PYTHONPATH=. python3 -m unittest discover -s tests -v
```
Result: **`Ran 169 tests ... FAILED (errors=4, skipped=2)`**.

- The 4 errors are NOT logic failures — they are `ModuleNotFoundError: No module
  named 'tldextract'` collection errors that abort 4 entire test modules before a
  single test runs:
  - `tests/test_dangerous_url_params.py`
  - `tests/test_site_scanner.py`
  - `tests/test_site_scanner_ssrf.py`
  - `tests/test_subdomain_takeover.py`
- `tldextract` IS a declared dependency (`pyproject.toml:32`, `5.1.2`) but is
  **absent from `requirements.txt`** (which lists 9 packages and stops at
  `tldextract`? — see note) and absent from the local interpreter. The default,
  documented run command silently drops ~35 tests including the two most
  safety-relevant modules (SSRF scope enforcement, subdomain takeover).
- Extension JS tests: `cd extension && node --test` → **46 + 9 pass, 0 fail**.
  But `node --test extension/tests/` from repo root reports `fail 1 / pass 0`
  ("test failed", 0 discovered) — the runner only works from the `extension/`
  CWD. A CI job that runs it from root would go green-then-red confusingly or
  red with zero signal.

Net: the suite is unittest-based (no pytest config present), mostly green, but
the **headline run is misleading** — 4 modules never execute in a clean checkout
that follows `requirements.txt`, and the most dangerous code paths are inside
those modules.

## Strengths

- **Safety gates that matter ARE asserted at the intent level.** The two highest
  business-risk behaviors have real, falsifiable tests:
  - `tests/test_baas_validator.py:455` `test_write_probe_skipped_by_default_sends_no_post`
    asserts `"POST" not in methods` for a default scan — the single most
    important safety invariant (read-only by default) is genuinely guarded.
  - `tests/test_baas_validator.py:279` asserts RPCs are never POST-probed
    (`"RPC should not be probed via POST"`).
  - `tests/test_net_guard.py:28-31` asserts cloud metadata (`169.254.169.254`)
    stays blocked **even with `allow_private=True`** — a test that would fail if
    the opt-in were wired too broadly. This is intent verification, not a smoke
    test.
- **SSRF scope enforcement is well-modeled** in `tests/test_site_scanner_ssrf.py`
  — it asserts blocked hosts don't reach crawl/takeover AND that blocked links
  don't consume crawl budget (`:42-53`). Strong intent coverage… that currently
  doesn't run (tldextract).
- **Reporting/serializer round-trip and falsy-preservation** are tested with
  teeth: `tests/test_core_reporting.py:72-81` (forward-compat round-trip keeps
  unknown keys), `:83+` (legacy falsy values preserved), `:36/:39` (verdict +
  profile). 126 assertions across 37 tests is the densest file.
- **Cross-language contract tests** exist: `tests/test_extension_library_cves_sync.py`
  asserts the JS extension CVE table matches the Python `VULN_TABLE`, preventing
  silent drift between the two detector implementations.
- Correlation logic is tested for the right failure mode:
  `tests/test_attack_chains.py:44-53` asserts two findings on different hosts do
  NOT chain without a target and DO chain with one — encodes *why* correlation
  matters, not just that it returns a list.

## Weaknesses

| id | sev | file:line | evidence | fix |
|----|-----|-----------|----------|-----|
| W1 | S0 | (absent) `.github/workflows/` | **No CI at all.** Only `.github/secret_scanning.yml` exists (a GitHub native push-protection `paths-ignore` config, not a workflow). Tests, launch-gate, and extension tests never run on PR. Nothing prevents a merge that breaks the suite. | Add a `pull_request`-triggered workflow running the Python suite + `node --test` (from `extension/`) + `keyleak local . --launch-profile launch-gate --fail-on high`, actions pinned to SHAs. |
| W2 | S1 | `requirements.txt:1-9` vs `pyproject.toml:32-34` | `requirements.txt` omits `tldextract`, `PyYAML`, `PySocks` that `pyproject.toml` declares. A `pip install -r requirements.txt` checkout cannot run 4 test modules and breaks YAML allowlists / SOCKS proxy at runtime. This is the direct cause of the 4 suite errors. | Regenerate `requirements.txt` from the locked deps, or delete it and document `pip install .` / poetry. Add a test asserting parity between the two files. |
| W3 | S1 | `pyproject.toml:47-69` | The PEP 621 `[project]` table (used by `uv`/`pip`) has **no `dependencies` key**. `pip install .` / `uv pip install .` installs the package with ZERO runtime deps. Only the poetry `[tool.poetry.dependencies]` block carries them. | Add `dependencies = [...]` to `[project]` mirroring the poetry list, or drive both from one source. |
| W4 | S1 | suite run (tldextract) | The documented run command green-washes: 4 modules error out, but a skim of `OK`-heavy `-v` output or a `grep -c ok` looks healthy. The two modules covering **scope/SSRF enforcement** (`test_site_scanner_ssrf`) and **takeover** are exactly the ones suppressed. Safety coverage exists on paper but does not execute. | Fix deps (W2); add a CI gate that fails on ANY collection error (`unittest` returns non-zero, so `python -m unittest` in CI already would — but there's no CI, W1). |
| W5 | S2 | `extension/package.json:5` + root invocation | `"test": "node --test"` only discovers tests when CWD is `extension/`. From repo root the glob finds nothing and reports failure. A naive CI `npm test` at root, or a contributor running from root, gets a false red/zero-signal. | Pin the test glob (`node --test tests/`) and document/run from `extension/`; add the npm test to CI with correct `working-directory`. |
| W6 | S2 | `keyleak/` (18 modules) | 18 of 36 non-`__init__` modules (~2,840 LoC) have **no direct test and are not imported by any test** — including `sourcemaps.py`, `blast_radius.py`, `diff.py`, `disclose.py`, `privacy_filter.py`, `chain_of_custody.py`, `self_audit.py` (437 LoC, the largest untested module), and 4 detector engines (`detectors_ast/fuzzy/splittoken/dynamic`). See untested list below. | Prioritize tests for the detector engines (false-positive/negative risk) and `privacy_filter`/`disclose`/`chain_of_custody` (these touch data handling and responsible-disclosure correctness). |
| W7 | S2 | `tests/test_core_reporting.py:38` | `self.assertIn("sarif", format_sarif(report).lower())` is a near-tautology — any string containing the substring "sarif" passes. It does not validate the SARIF schema (`version`, `runs[].tool.driver.rules`, `results[].ruleId`, `level` mapping). A malformed SARIF that no SARIF consumer (GitHub code scanning) accepts would pass. | Assert `json.loads` succeeds and check `$schema`/`version == "2.1.0"`, presence of `runs[0].results`, and that finding severity maps to SARIF `level`. |
| W8 | S2 | `tests/test_core_reporting.py:179-234` | HTML serializer tests only assert `assertIn("<!DOCTYPE html>", output)` and a few substrings. They do not assert findings actually render, no XSS-escaping check on attacker-controlled `redacted_value`/`risk_reason` injected into HTML. A report that drops all findings but keeps the doctype passes. | Assert finding count rendered, and that a `"<script>"` in a finding field is HTML-escaped in output (the report ingests untrusted scanned content). |
| W9 | S3 | `tests/test_core_reporting.py:310-312` | `assertTrue(detector.result_type)` / `description` / `remediation` are truthiness checks — they pass for any non-empty string, including `"x"`. They assert presence, not correctness/quality of metadata. | Acceptable as a registry-completeness guard, but pair with a content lint (min length, no placeholder text). Low priority. |
| W10 | S3 | `keyleak/cli.py` | CLI is only partially covered (`_apply_bundle_selection`, `_print_bundles`, `_scan_request_payload`). `main()` argument parsing, exit codes, and `--fail-on` threshold→exit-code mapping for the launch-gate path are not unit-tested end to end. The exit-code contract is what CI/users depend on. | Add a subprocess/`main()` test asserting exit code 1 on high findings and 0 on clean, for `keyleak local`. |

Notes on `requirements.txt`: it ends at `tldextract==5.1.2` on line 9 in the
listing but the live file read showed only 9 entries stopping before `PyYAML`
and `PySocks`; treat the deps-parity gap (W2) as the load-bearing finding.

## Safety-critical coverage verdict

- **Read-only / `allow_write_probe` gate: COVERED and asserted at intent.**
  `keyleak/baas_validator.py:285,380-381` (default `False`, mutating POST gated)
  is verified by `tests/test_baas_validator.py:455` (no POST by default) and the
  opt-in paths `:450/:485`. This is the suite's best work.
- **Scope / SSRF enforcement: TESTED BUT NOT EXECUTING.**
  `keyleak/net_guard.py` is well covered and runs (`tests/test_net_guard.py`),
  but the higher-level scope enforcement inside `scan_site`
  (`tests/test_site_scanner_ssrf.py`) is suppressed by the tldextract import
  error. Right now, in the standard run, **scope enforcement for the crawler is
  effectively untested** even though the test exists.
- **Correlation: COVERED** (`tests/test_attack_chains.py`), 21 tests.
- **Report serializers: PARTIALLY COVERED** — round-trip/verdict strong; SARIF
  schema and HTML escaping weak (W7, W8).

## Untested modules (no direct test, not imported by any test)

```
keyleak/self_audit.py            (437 LoC)
keyleak/blast_radius.py          (230)
keyleak/allowlist_diff.py        (217)
keyleak/disclose.py              (213)
keyleak/detectors_fuzzy.py       (211)
keyleak/doctor.py                (205)
keyleak/sourcemaps.py            (189)
keyleak/detectors_splittoken.py  (182)
keyleak/detectors_ast.py         (170)
keyleak/feeds.py                 (168)
keyleak/chain_of_custody.py      (121)
keyleak/archive_scanner.py       (114)
keyleak/watch.py                 (105)
keyleak/offline_guard.py         (104)
keyleak/diff.py                  (94)
keyleak/privacy_filter.py        (80)
keyleak/detectors_dynamic.py
keyleak/demo.py
```
18 modules, ~2,840+ LoC. Highest-risk untested: the 4 detector engines
(`detectors_ast/fuzzy/splittoken/dynamic` — directly govern false-pos/neg
rates), `privacy_filter.py` + `chain_of_custody.py` + `disclose.py` (data
handling and disclosure correctness), `sourcemaps.py` + `blast_radius.py`
(feed the report's severity/impact claims).

## CI / packaging

- **CI: none.** No `.github/workflows/`. `.github/secret_scanning.yml` is a
  native secret-scanning `paths-ignore`, not a workflow. The repo's own
  `CLAUDE.md` mandates `keyleak local . --launch-profile launch-gate --fail-on
  high` before merging dependency/workflow changes — nothing enforces it.
- **Launch-gate runs clean locally:** `keyleak local . --launch-profile
  launch-gate --fail-on high` → `SAFE TO SHIP: 0/0/0/0`, exit 0. It only loads
  the `leak` pack, so it is a narrow gate (secrets/IOCs), not a full-suite gate.
- **Supply-chain hygiene of declared deps:** versions are pinned exactly in both
  `pyproject.toml` and `requirements.txt` (good). No `poetry.lock` is present in
  this checkout root, so transitive deps are not hash-locked. Heavy attack
  surface (`mitmproxy 12.2.3`, `playwright 1.55.0`, `Flask 3.1.3`) with no
  automated `pip-audit`/dependabot. The repo's CLAUDE.md preaches a 7-day
  cooldown and SHA-pinned Actions, but with zero workflows there are no Actions
  to pin and no automation to enforce the policy.
- **Packaging gap (W3):** `[project]` table ships no dependencies → `pip install
  .` produces a broken install. Only poetry users get a working dependency set.

## Improvements (ranked, highest leverage first)

1. **Add CI** (`pull_request`-triggered, actions SHA-pinned) running: Python
   `unittest` suite (fails on collection errors → catches the tldextract class of
   bug), `cd extension && node --test`, and the launch-gate. Single highest
   leverage: today nothing stops a red-suite merge. (Fixes W1, surfaces W4/W5.)
2. **Fix dependency declarations** — add `tldextract`/`PyYAML`/`PySocks` to
   `requirements.txt`, add `dependencies` to `[project]`, add a parity test
   between the two manifests. Makes the documented run actually exercise the
   safety-critical SSRF/takeover modules and makes `pip install .` work. (W2/W3.)
3. **Harden the report serializers** — JSON-parse + SARIF 2.1.0 schema assertions
   and an HTML-escaping/XSS test for attacker-controlled finding fields. The
   report is the product's output and ingests untrusted scanned content. (W7/W8.)
4. (Then) seed tests for the 4 detector engines and `privacy_filter` /
   `chain_of_custody` / `disclose` — the largest untested, correctness-sensitive
   surface. (W6.)

## Subsystem health score

**62 / 100.**

Justification: the *content* of the existing tests is above average for an OSS
security tool — the two genuinely dangerous behaviors (read-only-by-default BaaS
probing, cloud-metadata SSRF block) are asserted at intent and would fail if the
logic regressed (`test_baas_validator.py:455`, `test_net_guard.py:28-31`). That
earns real credit. It is dragged down hard by: (a) **zero CI** — none of this is
enforced (S0); (b) the **documented run silently suppresses the SSRF/scope/
takeover modules** via an undeclared-in-requirements dependency, so the best
safety tests don't actually execute in a standard checkout (S1); (c) a **broken
`[project]` dependency table** that yields a non-functional `pip install .` (S1);
and (d) **half the codebase (~2,840 LoC, incl. all detector engines) untested**
(S2). The intent quality is ~75; the enforcement and execution reality is ~45.
Weighted toward release risk, 62.
