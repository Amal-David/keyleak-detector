# Security Model

KeyLeak Detector is designed to be local-first. The safest way to use it is on your own machine, against systems you own or have permission to test.

## What Stays Local

- Target URLs
- Captured browser traffic
- Auth cookies and bearer tokens
- Findings and reports
- Local file scan results

The project does not require a hosted service for scanning.

## Authenticated Scans

Authenticated scans can reveal issues that unauthenticated scans cannot, but they also carry more risk.

Use this operating model:

- Use throwaway test accounts.
- Use short-lived cookies or tokens.
- Avoid production administrator credentials.
- Revoke test credentials after scanning sensitive environments.
- Do not paste real customer data into bug reports or screenshots.

Two-user access-control comparison is opt-in. Provide a second throwaway user with `--bearer-b` or `--cookie-b`; KeyLeak will only compare object-looking URLs with those explicit credentials and will not reuse browser cookies automatically.

## Private Scans Through a Proxy

The global `--proxy` flag (off by default) routes a scan's outbound traffic
through an HTTP/HTTPS/SOCKS5 proxy so the operator's source IP stays private. It
governs only target and validation traffic — crt.sh subdomain lookups, the
Playwright crawl, and BaaS validation probes. The local KeyLeak web bridge
(loopback) is never proxied.

- Aliases: `--proxy warp` (Cloudflare WARP proxy mode, `socks5://127.0.0.1:40000`)
  and `--proxy tor` (`socks5://127.0.0.1:9050`).
- **Trust the proxy, not the protocol.** Whoever runs the proxy can see and log
  every request routed through it, including secrets a scan discovers. Prefer a
  trusted local proxy (Cloudflare WARP, Tor) over random free public proxies,
  which are an active man-in-the-middle risk and the wrong tool for a
  secret-scanner.
- WARP and Tor are loopback endpoints, so `--proxy warp` coexists with
  `--offline`. A non-loopback proxy is refused under `--offline`, preserving the
  "only loopback sockets" guarantee.

## Detector Packs

The default CLI and web profile runs the `leak` pack. The Chrome extension runs `leak`, `appsec`, and `access-control` as a launch-gate front door. `correctness` and `housekeeping` are repo/CI-oriented packs and are advisory unless the caller opts into blocking on their severities.

Appsec and correctness checks are intentionally labeled as leads unless KeyLeak has direct proof, such as a two-user access-control comparison. Treat lead findings as review prompts, not exploit claims.

## Redaction

Normalized reports redact detected values by default. The web scanner API returns normalized findings by default; set `KEYLEAK_INCLUDE_LEGACY_FINDINGS=1` only for local debugging when raw legacy findings are needed. Treat local logs, screenshots, and any deliberate reveal action as sensitive.

## Chrome Extension

The extension uses powerful browser permissions because it passively observes web traffic in the active browser.

Use it when:

- testing your own app
- testing an approved bug bounty target
- reviewing a local/staging environment

Avoid it when:

- browsing unrelated personal accounts
- handling highly sensitive third-party data
- using a shared browser profile

The extension stores per-tab reports in `chrome.storage.local` and renders redacted evidence by default. The popup has a deliberate reveal control for local debugging, but copied JSON/Markdown reports use redacted values.

## Hosted Scanning

Hosted scanning is intentionally deferred. The V1 agentic audit layer is local
and self-hosted: `keyleak audit` runs deterministic scanners on the operator's
machine, writes redacted local artifacts, and only performs active probing inside
an explicit `--authorized-scope`.

The future cloud shape is a control plane over isolated local or self-hosted
workers, not hosted scanning by default. Tenancy, retention policy, abuse
controls, credential custody, and legal review remain deferred until the local
artifact and safety model are proven.

## Limits

KeyLeak is not a full DAST or exploit framework. It does not prove exploitability
for every finding. Treat `lead` findings as high-signal prompts, `validated`
findings as deterministic evidence, and `confirmed` findings as active
probe/exploit-validation evidence.

## GDPR Article 30 Record

Honest record of every field KeyLeak captures, where it lives, how long, and why. Operators of authenticated scans become data controllers for any third-party data the capture touches; this table is the basis for a DPA conversation.

| Surface | Field | Source | Stored where | Retention | Purpose |
|---|---|---|---|---|---|
| `keyleak local` | File content (≤5 MiB / file) | Local FS | RAM only; stdout if `--json/--sarif/--markdown` | Scan lifetime | Secret + leak detection |
| `keyleak scan` | Request headers + URLs | mitmproxy capture (localhost) | RAM | Scan lifetime | Header / URL leak detection |
| `keyleak scan` | Response bodies (≤5 MiB) | mitmproxy capture | RAM | Scan lifetime | Bundle / source-map detection |
| `keyleak scan` | Session cookies / bearer tokens | User-supplied via `--bearer/--cookie` flags | RAM | Scan lifetime | Authenticated scan |
| `keyleak self-audit` | Workflow YAML, lockfile metadata, CODEOWNERS, package.json | Local FS | RAM | Scan lifetime | Supply-chain hygiene |
| `keyleak allowlist-diff` | Per-PR allowlist + changed-file list | Git refs / repo working tree | RAM | Scan lifetime | Allowlist provenance gate |
| Chrome extension (legacy / sunsetting) | DOM, localStorage, sessionStorage | content script | `chrome.storage.local` | Until tab close + redact | Live in-browser detection |

### Redaction guarantees

- Detected secrets are emitted as `[redacted:<8-hex>]` where the 8-hex is HMAC-SHA256(`per_scan_salt`, secret). Two reports of the same content scanned with different salts produce different HMACs — diffing them does not recover the secret. Within one scan (same salt), the same secret produces the same HMAC, so deduplication still works.
- The per-scan salt is 32 bytes of `os.urandom`, held in memory only, discarded at process exit.
- Snippet emission additionally masks adjacent emails (→ `[email]`), phone numbers (→ `[phone]`), SSN-like strings (→ `[ssn]`), card-like numbers (→ `[card-or-num]`), and US-style street addresses (→ `[addr]`). The matched (already-redacted) secret survives the PII pass.

### What is NOT collected

- No telemetry. No analytics. No phone-home.
- No crash reports.
- No findings are persisted to disk by KeyLeak. The user must explicitly redirect stdout to a file (`> report.json`) or upload it as a CI artifact.
- No outbound network call is made under `--offline` mode (Wave 1.5).

### Right to erasure

Because KeyLeak does not persist data, deleting a captured scan is the operator's responsibility: remove the redirected report file. The Chrome extension's `chrome.storage.local` data is cleared by uninstalling the extension or via the popup's "clear" control.

### Responsible disclosure

When KeyLeak detects a leaked third-party credential during a pentest (e.g., a customer's Stripe key in their public bundle), the operator becomes a *knowing possessor* of an active credential. The `keyleak disclose` CLI (Wave 1.7) produces a signed, timestamped disclosure packet that routes to the vendor's published security contact and creates a chain-of-custody record.
