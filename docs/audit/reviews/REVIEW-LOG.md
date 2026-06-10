# Audit Remediation — Adversarial Review Log

Every shipped item passes an adversarial gate (reviewers attack it, demand proof,
score 0–100; bar 85). This log records rounds, scores, and what changed.

## R1 — Tier 0 safety (A1 SSRF, A2 extension SSRF, A3 PII chokepoint)

Two reviewers (Opus, general-purpose, read real source) attacked the Tier-0 fixes.
**Both scored well below 85 and found real, verified bypasses** — the gate worked.

### Reviewer 1 — BaaS SSRF fix: **38/100**
Confirmed must-fixes (all reproduced against real code):
- **MF-1 🔴 Redirect bypass** — the prober used `requests.request` with default
  `allow_redirects=True`; a guard-approved public host could `302 → 169.254.169.254`.
  The headline S0 was only first-hop-safe.
- **MF-2 🔴** — `subdomain_takeover._probe_host` was completely unguarded **and**
  followed redirects; reachable from the web `/scan` full-site path with
  crt.sh-seeded (attacker-influenceable) subdomain names.
- **MF-3 DNS rebinding / TOCTOU** — no connection-time IP pinning; the guard's
  `getaddrinfo` and `requests`' connect resolve independently. Rated medium-high.
- Confirmed **closed** (credit): decimal/hex/octal/IPv4-mapped encodings on the
  Python side (`getaddrinfo` normalizes before `ipaddress` check); proxy path is
  guarded; `blast_radius` (fixed vendor hosts) safe.

### Reviewer 2 — PII chokepoint: **38/100**; extension SSRF guard: **22/100**
Confirmed must-fixes:
- **FIX1-MF1 🔴** — the browser **extension** serializes findings client-side and
  did NO PII scrubbing; the "every scan mode" claim was false.
- **FIX1-MF2 🔴** — the phone regex started mid-token and masked digits inside a
  secret (`sk_live_4242…` → `sk_live_424242[phone]`), corrupting evidence.
- **FIX1-MF3** — only `evidence.snippet` was scrubbed; `source`/`request_url`
  could carry PII (residual — see resolution).
- **FIX2-MF1 🔴** — `isBlockedScanHost` missed IPv4-mapped IPv6
  (`[::ffff:169.254.169.254]`) → cloud metadata reachable.
- **FIX2-MF2 🔴** — `redirect:'follow'` re-fetched a 3xx Location without re-validation.
- **FIX2-MF3 🔴** — same-origin allowance was port-blind (`127.0.0.1:8080` page
  could unlock fetches to `127.0.0.1:6379`).

### Resolution (all committed, tests added)
| Finding | Fix | Test |
|---|---|---|
| MF-1 | New `net_guard.guarded_request` — disables auto-redirects, **re-validates every redirect hop**; BaaS prober routes through it | `test_net_guard.GuardedRequestTests` (redirect→internal blocked, no 2nd request) |
| MF-2 | `subdomain_takeover._probe_host` routes through `guarded_request`; `SSRFBlocked → no signal` | `test_subdomain_takeover` (4 cases incl. SSRF-blocked) |
| MF-3 (rebinding) | **Documented residual** in `guarded_request` docstring — mitigated by read-only probes, caps, redirect-revalidation, host pre-check; full connect-time IP pinning tracked as follow-up | n/a (honest residual) |
| FIX1-MF1 | Ported `scrubText`/`scrubSnippet` into `extension/lib/reporting.js`, applied in `normalizeFinding` | `extension/tests/pii-scrub.test.js` |
| FIX1-MF2 | Phone regex `(?<![\w])` leading guard | `test_privacy_filter` + `pii-scrub.test.js` |
| FIX1-MF3 | Docstring scoped honestly: snippet is the only scanned-content field; source/request_url are URL-redacted upstream; risk_reason/remediation are tool-authored | corrected claim |
| FIX2-MF1 | `isBlockedScanHost` handles `::ffff:` mapped IPv6 (hex + dotted) | `url-guard.test.js` (metadata + loopback) |
| FIX2-MF2 | `redirect:'manual'` + refuse to follow + final-URL re-check | syntax-verified; manual review |
| FIX2-MF3 | Same-origin allowance now compares full **origin** (proto+host+port) | `url-guard.test.js` (port-bound) |
| (extra) `access_control` | Real-fetch path now guarded via `url_block_reason` | existing tests green |

### Correction to the audit matrix (honesty)
- **W5 was partly wrong:** `tldextract` **is** declared in `requirements.txt`; the 4
  suite errors were the dev *environment* lacking installed deps + no CI to catch
  it. Genuinely missing from `requirements.txt`: `PyYAML`, `PySocks` (now added).
- **W8 confirmed true:** `[project]` had no `dependencies` key → fixed (E2).

**R1 status:** all trivially-exploitable must-fixes resolved + test-guarded; full
suite 220 Python + 20 extension green. One documented residual (DNS rebinding,
medium, mitigations in place). **R2 re-review pending** to confirm the redirect and
mapped-IPv6 closures hold.

## R2 — re-review of R1 fixes: **88/100 (PASS, bar 85)**

Re-reviewer reproduced every closure against HEAD and CONFIRMED all six must-fixes
closed (redirect re-validation incl. protocol-relative/capital-Location; mapped-IPv6
incl. fully-expanded/mixed-case; redirect:'manual'; full-origin compare; phone-regex;
extension scrub). No working exploit remains; no overclaims; rebinding residual
honestly documented. Two non-blocking hardening notes — both applied:
- **http(s)-scheme check** added to `net_guard.url_block_reason` (blocks a redirect to
  `gopher://`/`ftp://`/`file:` slipping the host-only guard). Test added.
- **mapped-IPv6 regex broadened** to cover `::ffff:0:x.x.x.x` (translated) and
  `64:ff9b::x.x.x.x` (NAT64) trailing IPv4. Test added.

**Tier 0 LOCKED.** 221 Python + 20 extension tests green.

## R3 — Tier 1 (B1/B2/B3) + D4 + E1: **82/100 → fixed**

Reviewer ran the suite (234 green) and confirmed B1 (92), B2 (95), E1 (95) solid.
Two must-fixes found and resolved:
- **B3-MF1 (62→fixed):** verdict counted the static detector default `validated`
  as "actively confirmed" (33/37 high-crit detectors). Now only `confirmed`
  (live probe) counts; static matches say "static detections — verify". Tests updated.
- **D4-FN (70→fixed):** unpinned reusable workflows + `docker://` tag actions
  slipped. Regex broadened + new `gh_actions_unpinned_docker_action`. Tests added.
No false positives found in D4. E1 SHA pins API-verified. 237 Python + 20 extension green.

## R4 — D2 lifecycle scanner + holistic branch pass: **86/100 (PASS)**

Final holistic reviewer ran the full suite (243 green, no flakiness), confirmed
Tier-0 safety intact, no regressions, and docs honest. Verdict: "sound to hand to
a human reviewer." Flagged D2 as an honest-but-narrow first cut with confirmed FNs
— all closed in R4 hardening:
- nested-monorepo node_modules; sh -c "$(curl)" / ;-chained / PowerShell forms;
  bare user/repo shorthand + remote tarball deps; per-file size cap; bun FP fix;
  truncation info-finding. 11 D2 tests.
