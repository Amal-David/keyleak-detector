# Audit 02 — Active-Probing & Safety/Guard Subsystem

**Scope:** `keyleak/baas_validator.py`, `access_control.py`, `blast_radius.py`,
`subdomain_takeover.py`, `proxy.py`, `net_guard.py`, `offline_guard.py`,
`privacy_filter.py`, plus the live call sites in `browser_scanner.py`,
`site_scanner.py`, `bundles.py`, and the web bridge `app.py`.

**Posture claimed by the tool:** authorized, defensive, read-only-by-default,
opt-in, scoped, rate-limited.

**Verdict:** The read-only-by-default invariant for the *one* mutating probe
holds in practice (it is dead-gated OFF in every live path). But three of the
five safety promises — **SSRF/scope containment of probe targets**, **rate
limiting**, and **PII redaction before emission** — are *not actually enforced
on the active-probing path*. One of these (SSRF) is a concrete, exploitable
safety-invariant violation. Details below, every claim cited to real code.

---

## Strengths

- **Single mutating probe is gated and dead-OFF in production.**
  `_probe_write_access` (`baas_validator.py:699`) is the only POST-insert. It is
  called only from `_validate_supabase` behind `if allow_write_probe:`
  (`baas_validator.py:381`), and `validate_baas_config`'s parameter defaults to
  `allow_write_probe=False` (`baas_validator.py:285`). The live caller
  `_run_baas_validation` (`browser_scanner.py:468`) never passes the argument, so
  it is structurally impossible to reach the write probe from any current scan
  entry point. Belt-and-suspenders, even if imperfectly wired (see W3).
- **RPCs are surfaced as leads, never executed.** `_probe_rpcs`
  (`baas_validator.py:658`) deliberately does not POST to `/rpc/<fn>`; the
  docstring explicitly reasons about side effects. Correct and conservative.
- **Per-category probe caps are real slices, not decoration.** `TABLE_PROBE_CAP`
  (`:466`), `BUCKET_PROBE_CAP` (`:582`, `:618`, `:940`), `RPC_PROBE_CAP` (`:670`),
  `WRITE_PROBE_CAP` (`:722`), and the realtime `[:20]` (`:867`) all bound their
  loops via list slicing. These caps *are* enforced.
- **`net_guard` SSRF policy itself is correct.** `scan_target_block_reason`
  (`net_guard.py:31`) resolves the host and checks *every* resolved address,
  always blocks link-local/metadata/multicast/unspecified regardless of the
  opt-in (`:52`), and only relaxes loopback/private behind an explicit env var
  (`:55`). Good DNS-rebind-resistant design — the problem is *where it is not
  called* (W1), not the function.
- **`offline_guard` is a genuine hard stop.** It monkey-patches
  `socket.socket.connect` (`offline_guard.py:73`) so non-loopback egress raises
  `OfflineViolation`. Default-deny, strict literal-loopback matching (`:48`),
  refuses to treat `host.docker.internal`-style names as loopback.
- **Two-user access-control comparison is GET-only and double-gated.**
  `compare_access_control_urls` requires *two* explicit auth contexts
  (`access_control.py:30`), uses `requests.get`, `allow_redirects=False`
  (`:42`,`:48`), caps URLs (`max_urls=10`), and only fires on object-shaped URLs
  (`_OBJECT_ID_RE`, `:16`). Read-only and reasonably scoped.
- **Redaction at the BaaS finding boundary.** `request_url` uses
  `redact_url(...)` (e.g. `:535`, `:608`) and `_finding` redacts the api_key via
  `redact_value` (`:1073`). The raw api_key is sent in headers but never embedded
  in a finding snippet.

---

## Weaknesses

| id | sev | file:line | evidence | fix |
|----|-----|-----------|----------|-----|
| **W1** 🔴 | **S0** | `browser_scanner.py:468` → `baas_validator.py:328,574,903,983,1023` (probe targets); `app.py:1428,1440` | **SSRF guard bypass via attacker-controlled BaaS URL.** The web `/scan` path enables `baas_validate` from untrusted request JSON (`app.py:1428`) and passes `target_guard=_scan_target_is_blocked` to `scan_site` (`app.py:1440`). But `target_guard` is **never threaded into `run_browser_scan` / `_run_baas_validation` / `validate_baas_config`**. The BaaS probe target is `config.project_url`, extracted verbatim from the *scanned page's own JavaScript* (`browser_scanner.py:327` `setEndpoint("…/v1")`, `:337` `new PocketBase("…")`, `:309/315` firebase URL). The Appwrite/PocketBase regexes accept **any host** (`baas_validator.py:151` `https?://[a-zA-Z0-9.-]+/v1`, `:152` `https?://[a-zA-Z0-9.-]+`). An attacker who controls a page KeyLeak scans can set `new PocketBase("http://169.254.169.254")` or `setEndpoint("http://10.0.0.5/v1")` and KeyLeak's server will issue GET requests to internal/cloud-metadata hosts via the default prober (`baas_validator.py:117`, plain `requests.request`, no host check). The carefully-built SSRF guard is silently bypassed for exactly the requests that read live data back. | Re-validate every BaaS `project_url` (and the firebase storage host at `:942`) through `scan_target_block_reason` *inside* `validate_baas_config` before any probe fires; thread `target_guard`/`allow_private` from `scan_site` → `run_browser_scan` → `_run_baas_validation`. Refuse out-of-scope probe hosts (not same registrable domain as the scanned origin) by default. |
| **W2** | **S1** | `bundles.py:50` decl; absent in `site_scanner.py` / `browser_scanner.py` / `baas_validator.py` | **Rate limiting is declared but never enforced.** `ProbePolicy.rate_per_sec` exists and `validate_bundles` checks it is positive (`bundles.py:180`), but there is **no `time.sleep`, token bucket, or limiter anywhere on the probe path** (`grep` for `rate_per_sec`/`time.sleep` in the scan path returns nothing). The BaaS validator, subdomain-takeover pool (`subdomain_takeover.py:128`, 16 concurrent workers), and access-control comparison all fire as fast as the network allows. The tool promises rate-limited probing it does not deliver — both a courtesy/abuse risk against third-party infra and a legal-risk amplifier. | Pass the active `ProbePolicy` into the scan engine and enforce `rate_per_sec` with a shared limiter across all probe call sites (BaaS, takeover, access-control). Bound `subdomain_takeover` concurrency by the policy, not a hardcoded `DEFAULT_WORKERS=16`. |
| **W3** | **S1** | `browser_scanner.py:468`; `bundles.py:48,182` | **`allow_write_probe` policy flag is dead-wired.** The bundle policy field and its `validate_bundles` invariant (`bundles.py:182`) suggest a bundle can opt into the write probe — but `_run_baas_validation` never reads `policy.allow_write_probe` and never forwards it to `validate_baas_config`. Today this fails *safe* (write probe is unreachable), but it is a latent foot-gun: a future edit that "wires the policy through" would silently turn on a DB-mutating POST with no second gate. The safety of the mutating probe currently rests on an *accidental* omission, not an enforced control. | Make the gate explicit and intentional: thread `allow_write_probe` end-to-end, and add a runtime assertion that it can only be true when an explicit operator flag (not page-derived data) is set. Keep "no built-in bundle enables it" as a tested invariant. |
| **W4** | **S1** | `privacy_filter.py:61` invoked only at `local_scanner.py:296` | **PII scrubber never runs on the browser/BaaS path.** `scrub_snippet` is wired only into the *local file* scanner. Browser- and site-scan findings — which include live response-derived data such as open-table column names (`baas_validator.py:532` `col_summary`) and Firebase top-level DB keys read from the victim DB (`:925` `top_keys`) — are emitted to the report/SSE/JSON **without any PII scrubbing**. The module docstring claims it "runs after detector match when Evidence.snippet is built", but that is false for the network path. The exact leakage the module exists to prevent (adjacent PII riding along in a snippet) is unmitigated where it is most likely: live data pulled from a misconfigured database. | Invoke `scrub_snippet` on every `Evidence.snippet` at a single emission chokepoint (e.g. in `_to_finding` and in BaaS `Finding` construction), not only in `local_scanner`. Treat column names / DB keys as untrusted content. |
| **W5** | **S2** | `subdomain_takeover.py:65-71`; `baas_validator.py` probers | **Probe requests follow redirects into unguarded hosts.** `_probe_host` issues `requests.get(..., allow_redirects=True)` (`subdomain_takeover.py:70`) against pre-filtered subdomains, but a 30x redirect can bounce the request to an internal/metadata host that was never run through `scan_target_block_reason` (Python `requests` re-resolves and follows by default). Same class as W1 but via redirect rather than page-supplied URL. The access-control comparison correctly uses `allow_redirects=False`; the takeover and BaaS probers do not. | Set `allow_redirects=False` on probe requests, or install a per-request redirect hook that re-validates each hop's host through the SSRF guard. |
| **W6** | **S2** | `subdomain_takeover.py:81` (`sig in body`) | **Substring fingerprint match is attacker-spoofable / FP-prone.** Takeover is asserted on a raw `if sig in body` substring test against the full response body. Several fingerprints are short generic phrases (`"Repository not found"`, `"project not found"`, `"404 Web Site not found"`, Unbounce's `"The requested URL was not found on this server"` which is the stock Apache 404). Any page that merely *contains* the string — including an attacker who wants to inject a false "high" finding into a victim's report, or a normal 404 page — yields a high-severity `subdomain_takeover` finding. | Require the fingerprint *and* a corroborating signal (matching CNAME/Server header, status code, or provider-specific response shape). Drop or tighten the generic-404 fingerprints. Lower confidence until corroborated. |
| **W7** | **S2** | `baas_validator.py:557-564` | **`_table_severity` defaults every unknown table to `high`.** Any anon-readable relation not matching a sensitive keyword is rated `high` confidence-0.95 (`:527`). Combined with the OpenAPI enumeration (`:389`) that probes tables never referenced in client JS, a Supabase project that *intentionally* exposes public reference tables (e.g. `countries`, `feature_flags`) generates a wall of high-severity "no effective RLS" findings. Erodes signal and pushes users toward alert fatigue / ignoring real critical findings. | Default unknown tables to `medium`; reserve `high`/`critical` for the sensitive-keyword set; treat enumerated-only relations (`is_lead`) as `low`/`medium` leads (the downgrade at `:495` helps but still lands at `high`). |
| **W8** | **S3** | `baas_validator.py:910` | **Firebase `body != "null"` dead/confusing compare.** The default prober parses JSON (`:120`), so a Firebase `null` body arrives as Python `None` (already handled by `body is not None`). The `body != "null"` string compare only matters in the text-fallback path and is otherwise inert; a Firebase DB whose root literally serializes to the JSON value `null` vs an error is conflated. Minor correctness smell, not a safety issue. | Branch on the parsed type explicitly; drop the string compare or document the text-fallback case. |
| **W9** | **S3** | `blast_radius.py:140-143` | **JWT scope keyword match is naive.** `dangerous = [s for s in ("admin","write","delete","manage") if s in scope_str.lower()]` substring-matches, so a benign scope like `read:writeups` or `admin_readonly` flags as dangerous. Low impact (advisory flag only), but contributes to FP noise in the blast-radius advisory. | Tokenize scope on whitespace/`:`/`,` and match whole tokens. |

---

## Detailed traces (per the brief)

### 1. Read-only invariant — every place that sends a request

| call site | method | mutating? | gating |
|-----------|--------|-----------|--------|
| `baas_validator.py:328` key-valid root | GET | no | — |
| `:468` table read | GET | no | `TABLE_PROBE_CAP` |
| `:574,623` storage list | GET | no | `BUCKET_PROBE_CAP` |
| `:658` RPC | **no request** (lead only) | no | `RPC_PROBE_CAP` |
| `:724` **write probe POST** | **POST insert** | **YES** | `if allow_write_probe` (`:381`), default `False` (`:285`), never enabled by any live caller |
| `:828` auth settings | GET | no | — |
| `:903,942` firebase | GET | no | `BUCKET_PROBE_CAP` |
| `:983,994` appwrite | GET | no | `[:5]`/`TABLE_PROBE_CAP` |
| `:1023,1036` pocketbase | GET | no | `TABLE_PROBE_CAP` |
| `blast_radius.py:70,74,90,103,171` | GET | no | one finding at a time |
| `subdomain_takeover.py:65` | GET | no | `max_workers` |
| `access_control.py:36,43` | GET, `allow_redirects=False` | no | `max_urls` |

**Conclusion:** the *only* mutating call path is `_probe_write_access`, and it is
genuinely unreachable from production code today (the default is `False` and the
live caller `browser_scanner.py:468` never passes the flag). The read-only-by-
default invariant **holds in practice**, but on an accidental omission rather
than an enforced control (W3). No other destructive/mutating path exists.

### 2. Scope & SSRF

- Crawl scope = same registrable domain, enforced in `_filter_links`
  (`site_scanner.py:338`) and re-checked on every crawled URL (`:638`). Correct.
- Subdomain enumeration + crawled links are guarded by `target_guard`
  (`site_scanner.py:584-599`, `:638`). Correct.
- **Probe targets are NOT scope-checked.** BaaS `project_url` comes from page JS
  and is probed with no `target_guard` and no same-domain check (W1). This both
  defeats SSRF containment *and* breaks scope: KeyLeak will probe a third-party
  `*.supabase.co` / arbitrary Appwrite/PocketBase host that is not the scanned
  registrable domain at all.
- `net_guard.scan_target_block_reason` is solid but only wired into `scan_site`'s
  host filtering, not the probe layer.
- Redirect-following probes (W5) can leave scope/guard mid-request.

### 3. Rate limiting & caps

- Per-category **caps are enforced** (slices). Good.
- **Rate limits are not enforced at all** (W2): `rate_per_sec` is declared,
  validated for positivity, and then ignored by every probe.
- **`max_requests` network budget is not enforced for probing**: only
  `max_pages`/`max_subdomains` bound the crawl; the BaaS validator's total probe
  count is bounded only by the sum of its hardcoded caps, not by `ProbePolicy`.
- `ProbePolicy` is effectively **inert at runtime** — `grep` shows it is
  consulted nowhere outside `bundles.py`.

### 4. Privacy

- `privacy_filter.scrub_snippet` works correctly and preserves the redacted
  token (`privacy_filter.py:77`).
- It is **only invoked on the local-file path** (`local_scanner.py:296`).
  Browser/site/BaaS findings bypass it entirely (W4), so live response-derived
  data (table columns, Firebase keys) reaches the report/JSON un-scrubbed. This
  is the highest-impact privacy gap because that path reads *other people's*
  data out of misconfigured databases.
- Secret redaction (api_key, request URLs) on the BaaS path is fine.

### 5. Correctness bugs

- W6 substring takeover FP / spoofing.
- W7 `_table_severity` over-rates unknown tables to `high`.
- W8 Firebase `body != "null"` inert compare.
- W9 JWT scope substring match.
- Prober injection model is clean: every network call is injectable
  (`baas_validator.py:23`, `blast_radius.py:27`), tests never hit the network.
  No injection-of-untrusted-prober risk found.
- JWT decode (`baas_validator.py:762`, `blast_radius.py:113`) correctly adds
  padding and never *verifies* signatures (claims-only, intended). No crash on
  malformed input (try/except). Fine.

---

## Ranked Improvements (usefulness, without weakening safety)

1. **Probe-target SSRF + scope re-validation (fixes W1/W5).** Highest leverage:
   it is simultaneously the worst safety bug *and* a usefulness win — once probe
   hosts are validated and scoped, the operator can trust that "BaaS validation"
   never reaches infra they did not authorize. Add an `--allow-offsite-baas`
   opt-in for the legitimate `*.supabase.co` case.
2. **Wire `ProbePolicy` into the engine and enforce `rate_per_sec` +
   `max_requests` (fixes W2).** Turns the bundle abstraction from documentation
   into a real control. Lets users say "scan gently" and have it mean something —
   essential for "test before you ship" against shared staging infra.
3. **Single PII-scrub chokepoint for all findings (fixes W4).** One call in the
   finding-construction path closes the leak across every scan mode and makes the
   privacy promise true everywhere, not just for local files.
4. **Write-probe as a first-class, explicitly-operator-gated capability (fixes
   W3).** Make it reachable *only* via an explicit CLI/operator flag (never from
   page-derived data), default off, with the rollback-vs-invalid-body behavior
   surfaced to the user before it runs. This is the single most useful "test
   before ship" probe (does anon actually get to *write*?) — worth doing
   *correctly* rather than leaving it dead-wired.
5. **Corroborated takeover + recalibrated table severity (fixes W6/W7).** Reduces
   false positives so the high/critical findings users actually act on stay
   trustworthy. Add CNAME/Server-header corroboration to takeover; demote
   unknown-table reads to medium.

---

## Subsystem health score: **58 / 100**

**Justification.** The core read-only-by-default invariant for the single
mutating probe holds, the injectable-prober test architecture is clean, the
per-category caps are real, and `net_guard`/`offline_guard` are individually
well-designed (these earn the score its floor). But the subsystem **fails to
actually enforce three of its five headline safety promises on the active-
probing path**: probe targets escape the SSRF/scope guard entirely (W1, an
exploitable S0 via attacker-controlled page content on the web `/scan` route),
rate limiting is vaporware (W2), and PII redaction never runs on the network
path (W4). `ProbePolicy` is inert at runtime, so the bundle safety model is
largely aspirational. The write-probe being safe by *accidental* omission (W3)
rather than enforced control is a latent landmine. These are not theoretical —
W1 lets an authorized defensive scanner be turned into an SSRF proxy against
cloud metadata, which is precisely the failure mode this subsystem exists to
prevent. Score reflects "good primitives, unenforced at the boundary that
matters."
