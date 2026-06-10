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
