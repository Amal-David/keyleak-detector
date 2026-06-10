# Detector / Pattern Engine Audit — KeyLeak Detector

Scope: `keyleak/detectors.py`, `detectors_dynamic.py`, `detectors_fuzzy.py`,
`detectors_ast.py`, `detectors_splittoken.py`, `js_library_cves.py`,
`sourcemaps.py`, `extension_bundle.py`, `redaction.py`, plus the consuming
glue in `local_scanner.py` / `browser_scanner.py` and the test suite.

Auditor stance: adversarial. Claims below cite real code read in
`/Users/amal/experiments/keyleak-vuln-program`. Line numbers are from the files
as read on 2026-06-10.

---

## Strengths (proven, not assumed)

- **Supply-chain IOC pack is genuinely good and current.** `detectors.py:441-549`
  ships `npm_optional_dep_git_ref`, `gh_actions_pwn_request_head_ref`,
  `gh_actions_secrets_tojson`, `shai_hulud_c2_domain`, `npm_prepare_bun_payload`.
  These encode the Mini Shai-Hulud (TanStack 2026) TTPs with references and
  real attack scenarios. The `pull_request_target`-alone detector was correctly
  *downgraded to info* (`detectors.py:457-478`) and the true Pwn Request shape
  (`pull_request_target` + `checkout … head.ref`) split into a separate `high`
  detector (`detectors.py:479-501`). This is the kind of FP-driven tuning most
  scanners never do.
- **Behavioral worm-shape detector** (`detectors_ast.py`) is string-rotation
  resilient: it requires the env-read + net-egress + persistence-write triad
  within a 200-line window (`detectors_ast.py:102-130`) rather than matching a
  fixed hostname. This is real defense-in-depth over the string IOCs.
- **Layered FP suppression in the CLI** (`local_scanner.py:247-286`): placeholder
  gate, dev-default DB URL gate, loopback/.local guard, Shannon-entropy gate,
  basic-auth localhost guard, template-marker guard, public-prefix guard, and an
  AIza client-key severity downgrade. The reasoning comments (Q.1, Q.6–Q.12, L.2–L.4)
  show these were added in response to dogfood FPs, not invented.
- **Source-map fetch sandbox** (`sourcemaps.py:120-141`): same-origin check, no
  redirects, 8 MiB cap, no chained `.map` references. The SSRF threat model is
  explicitly documented and the same-origin check is correct.
- **Salted-HMAC redaction by default on the browser path** (`browser_scanner.py:480-482`,
  `redaction.py:82-84`) closes a real cleartext-leak hole; diff-resistance is a
  thoughtful touch.
- **`js_library_cves.parse_version`** is defensively written — rejects `.5`,
  `3..5`, `1.2.` instead of silently coercing (`js_library_cves.py:114-128`).

---

## Critical theme: the three detection surfaces do NOT agree

KeyLeak has three places where the *same* detector pack runs, but only one of
them applies the FP-suppression and capture-group logic:

| Surface | Entry point | Placeholder gate | Entropy gate | public-prefix / local-dev / template guards | `capture_group` honored |
|---|---|---|---|---|---|
| CLI `local` | `local_scanner.scan_text` (`local_scanner.py:234-319`) | yes | yes | yes | yes (l.246) |
| Browser scan | injected JS `scanString` (`browser_scanner.py:71-80`) + `_to_finding` | **no** | **no** | **no** | **no** (emits `m[0]`) |
| Chrome extension | `extension/lib/patterns.js` via `extension_pattern_payload` | **no** | **no** | **no** | min-len only, no entropy |

The entropy field, placeholder list, public-prefix list, and AIza downgrade live
**only** in `local_scanner.py`. `extension_pattern_payload` (`extension_bundle.py:71-89`)
serializes `min_match_length` and `capture_group` but **omits `min_entropy`,
`id_aliases`, and `remediation_v2` entirely**, and the extension/browser runtimes
implement none of the Python-side guards. Net effect: the *same key* that the CLI
correctly suppresses (`sk-indigo-twilight-color-1`, a Skeleton-UI class name —
the literal example in the code comment at `detectors.py:164-167`) will be
reported as a **critical OpenAI key** by the browser scan and the extension.
This is the single most important weakness in the engine.

---

## Weaknesses

| id | sev | file:line | evidence | fix |
|---|---|---|---|---|
| W1 | S0 | `extension_bundle.py:71-89`; `browser_scanner.py:71-80`, `505-523` | Entropy/placeholder/public-prefix/local-dev/template/AIza guards are CLI-only. `extension_pattern_payload` never serializes `min_entropy`; the injected JS `scanString` does `text.match(d.regex)` and emits `m[0]` with zero post-filtering; `evaluate_findings_payload`→`_to_finding` adds no gating. The browser/extension surfaces over-report exactly the matches the CLI suppresses. | Port the guards into a shared evaluation layer (Python: run browser raw-hits through a `scan_text`-equivalent post-filter; JS: re-implement min_entropy + placeholder + public-prefix in `patterns.js`/analyzer). At minimum, serialize `min_entropy` and gate on it in JS. |
| W2 | S1 | `browser_scanner.py:60-80` | Injected JS ignores `capture_group`. For `aws_secret_key` (`detectors.py:254`, group 1), `bearer_token` (`detectors.py:387`, group 1), `mcp_config_secret`, `otp_in_response`, `http_basic_auth`, the emitted value is `m[0]` — the entire match including the `aws…secret…=` lead-in or `bearer ` prefix — not the captured secret. Redaction then hashes the wrong span and the dedup key is wrong. | Read `definition.capture_group` in JS and emit the captured group; mirror the CLI's `match.group(detector.capture_group)` selection. |
| W3 | S1 | `browser_scanner.py:75-79` | `scanString` uses `text.match(d.regex)` with a `g`-flagged regex, then only reads `m[0]`. With the global flag `String.match` returns an array of *full matches* and discards groups; the code emits a single `emit(... m[0] ...)`. Result: at most **one** finding per pattern per scanned string blob — a page that bundles ten distinct AWS keys in one JS file yields one finding. | Iterate `regex.exec` in a loop (like the BaaS extractors already do at `browser_scanner.py:300`,`344`) to emit every occurrence with its capture group. |
| W4 | S1 | `detectors_splittoken.py:144-181` | The split-token reassembly is logically inert. `is_lead_candidate` is true only when `text.startswith(prefix)` (l.144-145). The match condition is `(fa.text + fb.text).startswith(prefix)` (l.170-172). If `fa` already starts with the prefix, the concatenation *always* starts with it regardless of `fb` — so every cross-file fragment pairs with any lead and the "reassembly" proves nothing. The documented goal (`gh` + `p_aBcD…` → `ghp_…`, l.123-126) is never implemented; partial-prefix leads are explicitly excluded. Also gated off by default (`KEYLEAK_ENABLE_SPLIT_TOKEN`), so it ships dead. | Implement true prefix-bridging: a lead is any fragment that is a *strict prefix of* a key prefix OR ends mid-prefix; require the concatenation to additionally satisfy the full token shape (length + charset) before flagging, else this is pure noise. |
| W5 | S1 | `detectors.py:188`, `804`, `317` (`browser_scanner.py`) | `gemini_api_key` is `AIza[0-9A-Za-z\-_]{35}` — exactly 35 trailing chars. Google `AIza` keys are 39 chars total (`AIza` + 35) which fits, but the pattern has no entropy gate and the client-key downgrade (`local_scanner.py:285`) is CLI-only. On the browser surface every Firebase/Maps client key (designed to be public) is reported at full `critical` severity. High-volume FP on every SPA that uses Firebase. | Apply the AIza client-key downgrade on all surfaces, or split a dedicated `firebase_client_config`-style medium detector for browser scans. |
| W6 | S1 | `detectors.py:158` | `openai_api_key` = `\bsk-(?!(?:ant|or)-)(?:proj-)?[A-Za-z0-9_-]{20,}\b`. This matches a huge space of `sk-…` strings (Sass map keys, Stripe-style `sk_` is excluded by the dash but `sk-` prefixes abound in CSS/JS). The only thing saving it is the entropy gate — which (per W1) does not run on browser/extension. Modern OpenAI keys are `sk-proj-…`/`sk-svcacct-…`/`sk-admin-…` ~164 chars; the `{20,}` lower bound is fine but the lack of an upper structure makes it the single biggest FP generator. | Tighten to the documented OpenAI shapes (`sk-proj-`, `sk-svcacct-`, `sk-admin-`, legacy `sk-[A-Za-z0-9]{48}`) and make the entropy gate cross-surface. |
| W7 | S2 | `detectors.py:171` | `anthropic_api_key` requires `{80,}` chars after `sk-ant-`. Real Anthropic keys are `sk-ant-api03-<95 chars>`. `{80,}` likely holds today but is brittle and undocumented; no entropy gate set (unlike OpenAI). A future shorter admin/key variant silently misses. | Anchor on the documented `sk-ant-api03-` / `sk-ant-admin01-` infixes and add `min_entropy`. |
| W8 | S2 | `detectors.py:297-303` | `slack_token` requires the legacy 3-segment `xox[baprs]-N-N-hash`. Modern Slack **`xoxe-`/`xapp-`/`xoxe.xoxp-` rotation & app-level tokens** and the `xoxb-` newer formats with different segmenting are not matched. Token-leak coverage for Slack is partial. | Add `xapp-`, `xoxe-`, refresh-token shapes; loosen segment counts. |
| W9 | S2 | `detectors.py` (whole registry) | **Missing common modern providers**: no Azure (`AccountKey=`, SAS `sig=`), no GCP `ya29.` OAuth access tokens, no Twilio `SK…`/`AC…`+auth-token, no DigitalOcean `dop_v1_`, no Cloudflare API tokens, no Datadog/`dd`-key, no Mailgun `key-…`, no Postmark, no Square `sq0…`, no Shopify `shpat_/shpss_`, no Linear/Notion (`secret_…`/`ntn_`), no Supabase **service_role** JWT specifically, no Telegram bot tokens, no Discord bot tokens/webhooks, no Algolia admin keys, no Doppler, no HashiCorp Vault `hvs.`/`s.`, no generic high-entropy fallback. For a tool that gates launches this is a large coverage hole. | Add a provider batch (ranked in Improvements) and a guarded generic-high-entropy detector. |
| W10 | S2 | `local_scanner.py:246` | Capture-group selection: `match.group(detector.capture_group) if detector.capture_group and match.groups() else match.group(1) if match.groups() else match.group(0)`. When `capture_group == 0` (default) but the pattern *happens* to contain a group (e.g. an alternation wrapped in `(...)`), this falls through to `match.group(1)`, which may be `None` (unmatched optional branch) → downstream `_is_placeholder(None)`/entropy on `"None"`. The `github_pat` pattern (`detectors.py:236`) uses an alternation `(?:…)` (non-capturing, safe) but any future grouped pattern with default `capture_group=0` silently changes which span is evaluated. | Make the rule explicit: only use `group(capture_group)` when `capture_group>0`; otherwise always `group(0)`. Never fall back to `group(1)` implicitly. |
| W11 | S2 | `detectors.py:280` | `stripe_secret_key` = `sk_(?:live|test)_[0-9A-Za-z]{24,}` but `openai_api_key` excludes only `sk-ant`/`sk-or`. Stripe uses `sk_` (underscore); OpenAI uses `sk-` (dash). They don't collide, but the **restricted/secret Stripe key also now appears as `rk_`/`sk_` with longer bodies and `_…` infixes**; `{24,}` is fine, but there is no upper bound and no entropy gate, so a `sk_live_` followed by a long base64 blob in minified JS over-captures across token boundaries (`[0-9A-Za-z]` won't stop at `_`-free runs). | Bound the body or add `\b`-safe terminators; add entropy gate. |
| W12 | S2 | `detectors.py:343` (`mcp_config_secret`) and `567` (`secret_in_logs_lead`) | These use `.{0,80}` / `[\s\S]{0,120}` proximity windows with case-insensitive matching against generic words (`token`, `secret`, `password`, `key`). On minified bundles and config files these over-fire heavily; `mcp_config_secret` is `extension=False` (good) but `secret_in_logs_lead` ships to `code` category and will flag any `logger.info("api_key rotated")`-style benign log. Validation_status is `lead`, which mitigates blocking but inflates noise. | Require a value-shaped capture (entropy/length) adjacent to the keyword, not just the keyword presence. |
| W13 | S2 | `detectors.py:743` (`dead_code_lead`) | Matches bare `console.log(` and `debugger;`. On any real JS codebase this fires thousands of times. Severity `info` + `lead` limits blast radius, but it pollutes reports and trains users to ignore output. | Drop `console.log(` from this detector (it overlaps `secret_in_logs_lead`) or require a TODO/dead-code marker. |
| W14 | S2 | `detectors_dynamic.py:83` | When an IOC entry has no versions, the fallback pattern is `"{pkg}"\s*:\s*"` — matches the package name as a JSON key in *any* file, including the project's own `package.json` listing the package as a legitimate (patched) dependency. Severity is hardcoded `critical` (l.57). A benign post-fix dependency on a once-compromised package name throws a critical. | Require a version match or lockfile-integrity context; never emit `critical` on name-only matches — downgrade to `lead`/`medium`. |
| W15 | S2 | `detectors_fuzzy.py:80-83`,`183` | `shingle_set` over an 8-char window on `normalize_for_fingerprint` output, which **replaces every string literal with `""`** (`detectors_fuzzy.py:63`). Two unrelated minified bundles with similar boilerplate (webpack runtime, the same UI framework) can exceed Jaccard 0.70 against a fingerprint that is itself mostly framework boilerplate, producing FP "worm payload" criticals. There is no minimum-distinctiveness or payload-size floor. | Gate fuzzy hits on a minimum normalized length and a distinctiveness/IDF weighting; raise the default threshold or require the exact hash for `validated`. |
| W16 | S2 | `js_library_cves.py:34-90` | CVE table covers **only jQuery and Bootstrap**. No Angular, AngularJS, lodash (prototype pollution CVE-2019-10744), moment, handlebars, DOMPurify, React (rare but exists), Next.js, Vue 2 XSS, three.js, axios SSRF (CVE-2024-…), serialize-javascript, etc. "retire.js-style" but with ~2 libraries is a thin coverage claim. | Expand the table; consider importing the retire.js JSON dataset (with the 7-day cooldown rule) rather than hand-curating two libraries. |
| W17 | S3 | `extension_bundle.py:101-103`,`178-180` | Generated JS headers reference `python3 scripts/generate_extension_patterns.py`, but **no `scripts/` directory exists in the repo** (`find` confirms absence). The documented regeneration entrypoint is dangling — drift risk: whoever edits `DETECTORS` has no runnable generator and may hand-edit `patterns.js`, desyncing CLI vs extension. | Restore the generator script (or fix the header to the real command) and add a CI test asserting `extension/lib/patterns.js` equals `extension_patterns_js()`. |
| W18 | S3 | `extension_bundle.py:35-51` | The JS-incompat guard blocks `(?P<…>)`, inline-flag groups, `\A`,`\Z`, etc. — good — but does **not** catch JS-incompatible *lookbehind length* differences, named groups in the newer `(?<name>…)` (valid in modern JS but the guard's `(?P[<=!]` check won't flag a Python `(?<=…)` lookbehind that JS supports differently), or possessive quantifiers. `secret_in_logs_lead` uses a variable-length lookbehind `(?<![a-z0-9_])` (`detectors.py:568`) — Python allows it, JS allows fixed only in older engines. Since that detector is `code`-category and not extension-shipped it's currently safe, but the guard gives false confidence. | Add an explicit lookbehind/lookahead compatibility check, and actually run each pattern through a JS engine (node) in CI rather than a Python-side denylist. |
| W19 | S3 | `redaction.py:86-91` | Non-salted redaction reveals the first 6 and last 4 chars for values longer than `keep_start+keep_end+6`. For an `AKIA…` access key ID (20 chars) that exposes `AKIAEX…` + last 4 — enough to fingerprint the account/region prefix. Browser path always salts (good), but any CLI/report path that calls `redact_value` without a salt leaks structure. | Default `redact_value` to require a salt; make the prefix/suffix mode opt-in only. |
| W20 | S3 | `detectors.py:1006` (`hardcoded_credential_in_bundle`) | `min_entropy=3.5` is set, but the regex requires a keyword like `password`/`secret_key` adjacent. Many real hardcoded creds use names like `apiSecret`, `auth`, `clientSecret`, `connectionPassword`, `db_pass` — `pass`/`pwd`/`passwd` are covered but `apiSecret`/`clientSecret` are only matched via `secret[_-]?key` (won't match `clientSecret`). Narrow. | Broaden the credential-name alternation; this is the catch-all and should be generous (entropy gate already bounds FPs). |

---

## Coverage map (what's caught vs missing)

**Caught well:** OpenAI/Anthropic/OpenRouter/Gemini/HF/Replicate/Perplexity/
Anyscale/Groq LLM keys; GitHub PAT; AWS access key ID + secret-near-keyword;
GCP service-account JSON; Firebase server key + client config; Stripe sk/rk;
Slack legacy token + webhook; GitLab; npm; SendGrid; PyPI; DB URLs; .NET/JDBC
conn strings; private keys; JWT/bearer; basic-auth-in-URL; the full Shai-Hulud
supply-chain IOC set; BaaS (Supabase/Firebase/Appwrite/PocketBase) surface;
OTP-in-response; source-map references.

**Missing / thin (see W8, W9, W16):** Azure, GCP OAuth `ya29.`, Twilio,
DigitalOcean, Cloudflare, Datadog, Mailgun, Square, Shopify, Notion/Linear,
Telegram/Discord, Vault, Algolia, Doppler; modern Slack app tokens; generic
high-entropy fallback; lodash/Angular/handlebars/axios CVEs; Kubernetes
kubeconfig/service-account tokens; `.npmrc`/`.netrc` credential lines;
JWT *with sensitive-claim* analysis (current JWT detector is `medium` and
purely structural).

---

## Maintainability / drift

- **No checked-in generator** (W17): the data-flow `DETECTORS → extension_bundle.py
  → extension JS` is half-wired. `extension_bundle.extension_patterns_js()` exists
  and `test_extension_library_cves_sync.py` exists, but the headers point at a
  missing script and there is no test asserting `patterns.js` content equals the
  generated output for the *secret* detectors (only library-CVE sync is tested).
- **Logic duplication across surfaces** (W1/W2/W3): the FP guards and capture-group
  logic are reimplemented (or absent) per surface instead of sharing one evaluator.
  Every new guard added to `local_scanner.py` silently fails to protect the
  browser/extension surfaces. This is the dominant long-term drift risk.
- **Field omission in serialization**: `extension_pattern_payload` drops
  `min_entropy`/`id_aliases`/`remediation_v2` — a new detector author who sets
  `min_entropy` reasonably assumes it applies everywhere; it does not.
- **Test coverage of the in-scope modules is near-zero in this tree.** The only
  detector-adjacent tests present are `test_js_library_cves.py`,
  `test_extension_library_cves_sync.py`, `test_browser_redaction.py`. There are
  **no** unit tests for `detectors.py` regex correctness, the entropy gate,
  `detectors_fuzzy`, `detectors_ast`, `detectors_splittoken`, or `sourcemaps`.
  Per the repo's own "tests verify intent" rule, the highest-FP-risk code is the
  least tested.

---

## Correctness bug summary (the load-bearing ones)

1. **Split-token detector is tautological** (W4, `detectors_splittoken.py:144-172`):
   leads must already start with the full prefix, so the concatenation always
   matches — it can never demonstrate cross-file *reassembly*. Dead + wrong.
2. **Browser scan emits one finding per pattern per blob and ignores capture
   groups** (W2/W3, `browser_scanner.py:75-79`): under-reports multi-key bundles
   and reports the wrong span for grouped detectors.
3. **Entropy/placeholder/public-prefix guards are CLI-only** (W1): same input,
   different verdict across surfaces — the worst property a security scanner can
   have (inconsistent truth).
4. **Name-only IOC match emits `critical`** (W14, `detectors_dynamic.py:57,83`).
5. **Implicit `group(1)` fallback** (W10, `local_scanner.py:246`) can evaluate
   `None`/wrong span for any future grouped pattern with default capture_group.

---

## Ranked Improvements (highest leverage first)

1. **Unify detection into one shared evaluator across CLI / browser / extension.**
   Move the FP guards (entropy, placeholder, public-prefix, local-dev, template,
   AIza downgrade) and the capture-group + multi-match iteration into a single
   code path the three surfaces call. Fixes W1, W2, W3, W5, W6, W10 at once. This
   is the single highest-value change: today the same secret gets three different
   verdicts.
2. **Fix the browser/extension match loop and capture groups** (W2, W3):
   `regex.exec` loop, honor `capture_group`, serialize `min_entropy`. Without
   this the browser/extension product over- and under-reports simultaneously.
3. **Expand provider coverage** (W9, W8): add Azure / GCP `ya29.` / Twilio /
   Cloudflare / DigitalOcean / Shopify / Vault `hvs.` / Discord+Telegram /
   modern Slack `xapp-`/`xoxe-`, plus a guarded generic-high-entropy fallback
   (entropy ≥ 4.5, length ≥ 32, keyword-adjacent). Biggest coverage delta for a
   secret scanner.
4. **Either delete or correctly implement the split-token detector** (W4). As
   shipped it is dead code that, if enabled, produces meaningless pairs.
5. **Add regex/intent unit tests for the whole in-scope set** (maintainability):
   a positive+negative corpus per detector, an entropy-gate test, a fuzzy-FP test
   on framework boilerplate, and a generator-sync test asserting `patterns.js`
   equals `extension_patterns_js()`. The highest-FP modules currently have no tests.
6. **Restore/repair the generator script** referenced by `extension_bundle.py`
   headers and gate it in CI (W17).
7. **Harden the fuzzy fingerprint** with a distinctiveness floor and minimum
   payload size (W15); require exact-hash for `validated`, fuzzy only ever `lead`.
8. **Tighten the highest-FP regexes** (W6 OpenAI, W11 Stripe, W12 proximity
   detectors, W13 dead_code) with bounded bodies / value-shaped captures.
9. **Expand the JS-library CVE table** beyond jQuery+Bootstrap (W16), ideally by
   ingesting the retire.js dataset under the repo's 7-day-cooldown rule.
10. **Make `redact_value` salt-mandatory** (W19) so no report path can leak
    `AKIA…`/`AIza…` structural prefixes.
