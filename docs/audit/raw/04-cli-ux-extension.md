# Audit 04 — CLI / UX / Extension (Usability + Security)

Scope: `keyleak/cli.py`, `doctor.py`, `demo.py`, `disclose.py`, `diff.py`, `feeds.py`,
`archive_scanner.py`, `suppressions.py`, `allowlist_diff.py`, `chain_of_custody.py`,
`self_audit.py`, `watch.py`; extension `injector.js`, `content-script.js`,
`service-worker.js`, `lib/analyzer.js`, `devtools/panel.js`, `popup/popup.js`,
`manifest.json`; `README.md`, `docs/DETECTOR_AUTHORING.md`.

Lens: "does this actually help a normal developer protect themselves before they ship?"

---

## Strengths

- **Real "first finding in 60s" path exists.** `keyleak demo` (`demo.py:21`) scans a
  bundled vulnerable fixture and prints a remediation report with explicit next steps
  (`demo.py:38-43`). `keyleak doctor` (`doctor.py:178-205`) gives a green/yellow/red
  checklist with copy-paste fixes for every red. This is genuinely good onboarding
  scaffolding that most scanners lack.
- **Structured, actionable remediation contract.** Findings carry `what_leaked`,
  `why_it_matters`, `fix_steps`, and `verify_command` (`cli.py:113-130`,
  `explain` command). The popup/panel surface a per-finding `fix:` line and a `LEARN`
  panel (`popup.js:208-211`, `panel.js:99-102`). When populated, this answers
  "how do I fix it / how do I verify".
- **Extension/CLI detector parity is enforced by generation, not copy-paste.**
  `extension/lib/patterns.js` is generated from `keyleak.detectors.DETECTORS`
  (`extension_bundle.py`, header in `patterns.js:1-5`). Supply-chain IOC detectors
  (`npm_optional_dep_git_ref`, `gh_actions_pull_request_target`,
  `gh_actions_secrets_tojson`, `shai_hulud_c2_domain`, `npm_prepare_bun_payload`)
  exist in BOTH the CLI registry (`detectors.py:442-548`) and the extension bundle
  (`patterns.js:754-879`). Same regexes, same IDs.
- **"Never break the page" discipline in the injector.** Every monkey-patch in
  `injector.js` (fetch/XHR/WebSocket/EventSource/Worker) is wrapped in try/catch and
  preserves prototype + static constants (`injector.js:133-138`, `157-159`). The
  content script guards against invalidated extension context
  (`content-script.js:10-17`). This is the right instinct for a passive monitor.
- **Default fixture suppressions are evidence-driven.** The 130-entry default
  suppression list (`suppressions.py:45-138`) is justified by a 313-repo dogfood
  (82% of criticals were in fixture paths) and is opt-out, not opt-in. This is the
  difference between "useful" and "wall of noise on first run".
- **Self-shielding-PR gate is a genuinely novel defense.** `allowlist_diff.py`
  detects the "ship a payload + grant it a waiver in the same PR" pattern
  (`allowlist_diff.py:149-178`) and has a path-traversal guard on changed files
  (`_is_safe_under_root`, `allowlist_diff.py:115-120`).

---

## Weaknesses

| id | sev | file:line | evidence | fix |
|----|-----|-----------|----------|-----|
| W1 | S1 | `cli.py:334-340` + `demo.py:32,40` | **First real scan silently drops 75% of detectors.** `keyleak local` defaults to `--launch-profile launch-gate`, which expands to only the `leak` pack (`normalize_packs(None,'launch-gate') -> ('leak',)`). But `keyleak demo` scans with `profile="ci"` (`leak,appsec,access-control,baas`) AND its next-step tells users to run `--launch-profile ci` (`demo.py:40`). So the demo shows MORE findings than the command a user actually defaults to. A dev who runs `keyleak local .` after the demo gets a quieter report and may believe they're clean when appsec/access-control/baas findings were never run. | Make `local`/`scan` default to the same profile the demo uses, or make the demo scan with `launch-gate` so the first finding count matches the default workflow. At minimum, print which packs ran. |
| W2 | S1 | `tests/test_core_reporting.py:383-394` | **No guard that the committed `patterns.js` equals the generated bundle.** The "parity" test only asserts `extension_patterns_js()` *output* contains certain substrings and that the committed file *looks* generated. It never compares the committed file's bytes to `extension_patterns_js()`. The extension can silently drift from the core registry (someone hand-edits `patterns.js`, or forgets to regenerate after adding a detector) and CI stays green. The headline claim "extension catches what the CLI catches" is unverified. | Add a test: `assertEqual(Path('extension/lib/patterns.js').read_text(), extension_patterns_js())` (same for `detector-info.js`). Fail CI on drift. |
| W3 | S1 | `cli.py:35-79` | **16 subcommands, no single obvious "scan my app before I ship" command, and most are launch-tooling not user tooling.** Of the 16 (`bundles, scan, local, self-audit, explain, diff, feed, archive, watch, doctor, site-scan, demo, browser-scan, disclose, allowlist-diff`), at least 6 (`feed`, `archive`, `disclose`, `allowlist-diff`, `self-audit`, `bundles`) are operator/CI plumbing a normal dev will never touch. There is no `keyleak scan-my-app`/`keyleak check` that auto-picks local-vs-URL. README leads with `browser-scan` but the most-documented command is `local` (23 mentions). | Add one front-door command (e.g. `keyleak check [path-or-url]`) that dispatches. Group the plumbing subcommands under a `keyleak ci ...` / `keyleak advanced ...` namespace or hide from top-level `--help`. |
| W4 | S2 | `cli.py:42-71,296-304` | **Global flags (`--proxy`, `--offline`, `--no-default-suppressions`) must precede the subcommand**, an argparse ergonomic trap. `keyleak local . --proxy tor` silently fails (argparse attaches `--proxy` to the subparser-less position) — the help even has to say "Must precede the subcommand" (`cli.py:302`). Users will hit this constantly. | Re-declare these flags on each subparser (or use a parent parser via `parents=[...]`) so they work in either position. |
| W5 | S2 | `cli.py:382-392` (`archive`) | **`archive` ignores all output-format flags.** Unlike every other report-emitting command, `archive` has no `_add_format_flags` and hardcodes JSON envelope output, yet still accepts `--fail-on`. A user who learned `--markdown`/`--sarif`/`--html` everywhere else gets no error and no honored flag. Same inconsistency: `feed sync` and `disclose` also bypass `_emit_report` and print raw JSON only. | Either route archive/feed/disclose through `_emit_report`, or document that these are envelope-only. Reject unknown format flags loudly. |
| W6 | S2 | `cli.py:537-560` vs `allowlist_diff.py:186-213` | **`allowlist-diff` has two divergent code paths.** The CLI dispatch (`cli.py:261-278`) builds inputs then calls `_emit_report` (which applies default fixture suppressions + baseline/allowlist again), while `allowlist_diff.cli_main` is a second standalone parser that prints directly. The two can produce different verdicts for the same inputs, and the `_emit_report` path will run `default_fixture_suppressions` over a *self-shield* report — potentially suppressing a critical self-shield finding if its path contains `/tests/` etc. | Delete the dead `cli_main` or make it call the same path. Skip default fixture suppressions for `scan_mode=="allowlist-diff"` (and `self-audit`). |
| W7 | S2 | `diff.py:36-71` | **SARIF→ScanReport roundtrip drops `redacted_value` (sets `""`, `diff.py:66`) and uses `partialFingerprints.findingId` for identity.** `diff` keys findings by `id` (`diff.py:86-87`); if either report is SARIF and lacks `findingId` fingerprints, every finding gets `id=""` and is treated as identical → diff returns nothing (false "no new findings"). And a diff report can't be fed to `keyleak disclose` because the redacted value is gone (`disclose.py:75`). | Synthesize a stable `id` from detector+source+line when fingerprint missing; carry `redacted_value` through SARIF (it's already in the KeyLeak SARIF `properties`). |
| W8 | S2 | `service-worker.js:229-237` | **Extension full-scan/remote-fetch uses the page's ambient network with `credentials:'omit'` but `<all_urls>` host perms and no SSRF guard on `analyze_remote_url`.** `fetchAndAnalyzeRemote` will fetch any URL the content script forwards (script src, source maps), including internal/loopback URLs resolved against the page origin. A malicious page can point the extension at `http://localhost:5002` or `http://169.254.169.254/` and read the body into findings storage. `canScanUrl` only checks http/https (`service-worker.js:201-208`). | Block private/loopback/link-local hosts in `fetchAndAnalyzeRemote`; cap to same-eTLD+1 as the page or require explicit user action. |
| W9 | S2 | `doctor.py:135-147` | **`check_network_egress` always returns OK regardless of result.** It connects to `127.0.0.1:1`, swallows `ConnectionRefusedError`/`OSError`, and unconditionally returns `_ok("network", "Loopback connectivity OK.")` (`doctor.py:142-147`). The check is theater — it can never warn or fail, so it gives false confidence. | Either make it a meaningful check (e.g. can it reach the local scanner port, or OSV.dev when not `--offline`) or remove it. |
| W10 | S2 | `feeds.py:91-94` | **`feed sync` queries OSV for the WHOLE ecosystem and filters `MAL-` client-side.** `query_osv_malicious` sends `{"query":{"package":{"ecosystem":"npm"}}}` to `/querybatch` (`feeds.py:92`) — OSV's querybatch does not accept an ecosystem-only query that returns every malicious advisory; in practice this returns nothing or errors, and `_parse_osv_response` then yields zero `MAL-` entries. The "signed IOC feed" likely produces an empty manifest. | Use OSV's `MAL-` export/feed endpoint (the `ecosystems/<eco>/all.zip` or the malicious-packages OSV dump), not a per-package querybatch. Add a test asserting non-empty output against a recorded fixture. |
| W11 | S2 | `popup.js:54-72,381-394` | **Extension verdict says "SAFE TO SHIP" before any meaningful coverage.** With zero browser activity the popup shows the green `SAFE TO SHIP` badge and "No findings detected in covered browser surfaces" (`popup.js:66-72`). Passive monitoring only sees traffic that happened *while the popup was open on that tab*; a freshly opened tab with no XHR shows green. A normal dev reads this as "my app is safe", which it does not establish. | Gate the SAFE verdict behind a minimum coverage threshold; show "INSUFFICIENT COVERAGE — run full scan" until real surfaces were inspected. The "Run the full local scan" hint exists but is buried under a green badge. |
| W12 | S3 | `watch.py:86-88` | **`keyleak watch` re-scans the ENTIRE tree on every change, defeating "incremental".** `_write_scan` calls `scan_path(root)` over the whole directory regardless of which file changed (`watch.py:77-79`). On a large repo, save-to-feedback latency will be seconds, and the module docstring's "incremental" claim is false. | Scan only changed files and merge into the existing SARIF, or document it as full-rescan-on-save. |
| W13 | S3 | `cli.py:355-360` | **`explain` is undiscoverable and lossy.** It requires a canonical id the user has to already know (`leak.openai_api_key`); there's no `keyleak explain --list` and the text output drops `attack_scenario`/`references` that `detectors.py` carries (only `what_leaked/why/fix_steps/verify`). A dev seeing a finding in `local` text output gets `detector_id` but no nudge that `explain` exists. | Print "run `keyleak explain <id>`" in the text report footer; add `explain --list`. |
| W14 | S3 | `doctor.py:150-162` | **`doctor` allowlist check only looks in CWD** (`keyleak-allowlist.yaml`), not the scanned path, and silently reports OK if absent. Combined with `check_poetry`/`check_node` warnings that are irrelevant to a `pip install` end-user, the doctor output is noisy for the target persona (a dev scanning their app, not a KeyLeak contributor). | Split "user doctor" vs "contributor doctor"; only show poetry/node/CODEOWNERS-style checks under a `--dev` flag. |
| W15 | S3 | `chain_of_custody.py:71-76` | **CoC silently downgrades to unsigned when `KEYLEAK_COC_KEY` is unset** (`signature_mode="none"`). `archive`/`disclose` advertise a "legally defensible" envelope, but the default produces an unsigned one with no warning to stderr. A user shipping this as evidence won't know it's unsigned. | Warn loudly when downgrading to `none`; or refuse and tell the user to set the key. |
| W16 | S3 | `content-script.js:145-162` | **Storage scan regex can false-positive on benign config and forwards full values.** `scanBrowserStorage` forwards any localStorage entry whose key/value matches `(key|token|...|config|jwt)` and is >20 chars (`content-script.js:152`), sending the *raw value* to the service worker for analysis. Feature-flag blobs, analytics configs, etc. will be shipped through the pipeline. Redaction happens later, but the raw value transits postMessage/sendMessage first. | Tighten the trigger to value-shape (looks-like-a-secret) rather than key-name; redact before forwarding where possible. |

---

## Extension parity assessment

- **Detector parity: structurally good, operationally unverified.** `patterns.js` is
  generated from the same `DETECTORS` registry the CLI uses, and the supply-chain
  IOCs are present in both. But there is **no test proving the committed file matches
  the generator** (W2), so the parity is a build-time intention, not a guarantee.
- **Surface parity gap (by design, but undocumented in-UI):** the extension is passive
  (sees only live traffic on the open tab) while `local`/`archive`/`watch` scan files
  at rest. The popup's green verdict (W11) hides this from the user.
- **Repo-only packs correctly excluded** from the extension bundle
  (`test_core_reporting.py:396-401`), so the extension won't surface `correctness`/
  `housekeeping` leads that need source — that's correct.

---

## Ranked usefulness improvements (highest leverage first)

1. **One front-door command + honest default coverage (fixes W1, W3, W11).**
   Add `keyleak check [path|url]` that auto-detects target type, runs a sensible
   multi-pack profile (not just `leak`), and prints which packs ran and what was
   skipped. Align `demo` and `local` defaults so the first real scan matches the demo.
   This is the single biggest lever: today a user's first independent scan is quieter
   than the tutorial, which actively misleads.
2. **Enforce extension↔CLI parity in CI (fixes W2).** A two-line byte-equality test
   converts the strongest marketing claim ("extension catches what the CLI catches")
   from aspiration to fact and prevents silent drift.
3. **Make the extension verdict coverage-aware (fixes W11) + add SSRF guard (W8).**
   Never show "SAFE TO SHIP" until real surfaces were inspected; block private-network
   fetches. These are the two things that make the extension trustworthy for the
   "is my app safe?" question it implicitly answers.
4. **Surface `explain`/remediation from the text report (fixes W13).** Print
   `keyleak explain <detector_id>` and the `verify_command` directly in `local`/`scan`
   text output so the fix/verify loop is one copy-paste away.
5. **Reconcile or hide the plumbing subcommands (W3, W5, W6).** Namespace
   `feed/archive/disclose/allowlist-diff/self-audit` under `keyleak ci`/`advanced`,
   give them consistent format handling, and delete the dead `allowlist_diff.cli_main`.
6. **Fix `feed sync` to actually return IOCs (W10)** and warn on unsigned CoC envelopes
   (W15) — otherwise the "signed feed" and "legally defensible" features are hollow.

---

## Subsystem health score: 58 / 100

Justification:
- **+** Strong onboarding scaffolding (`demo`, `doctor`), evidence-driven default
  suppressions, generation-based extension parity, and a real remediation contract.
  The bones of a tool a developer *would* run before shipping are here.
- **−** The two things that matter most for the target persona are broken or
  misleading: the first independent scan is quieter than the tutorial (W1), and the
  extension shows a green "SAFE TO SHIP" with effectively no coverage (W11). Both
  actively undermine "does this protect me?".
- **−** Parity — the headline differentiator — is unguarded (W2); `feed sync` likely
  emits empty manifests (W10); `doctor`'s network check is theater (W9); `watch` isn't
  incremental (W12); and there's a plausible SSRF in the extension's remote fetch (W8).
- **−** CLI coherence is weak: 16 subcommands, no front door, position-sensitive global
  flags (W4), and three commands that ignore the format flags users learned elsewhere.

The subsystem is above "prototype" but below "a normal developer can trust the green
light". Fixing W1, W2, W8, and W11 alone would move it into the 75+ range.
