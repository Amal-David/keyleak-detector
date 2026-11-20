# Changelog

All notable changes to KeyLeak Detector are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project aims to follow [Semantic Versioning](https://semver.org/).

## Unreleased

## [0.8.1] — 2026-11-20

A small release that labels keys meant for browsers instead of reporting them
as leaked secrets, and shows the probe behind each active BaaS finding. The
Chrome extension release is v1.3.2 and is distributed separately.

### Added
- Findings produced by an active BaaS probe show the probe next to them: the
  request method and URL, the HTTP status, and a summary of what came back
  (row count, column names and types; never row values). Text, Markdown and
  HTML reports print a `Probe:` line, and JSON evidence gains `request_method`.

### Changed
- Keys meant to ship to browsers are labeled `public_by_design` and reported as
  `low` instead of looking like leaked secrets: a Google key in a Firebase web
  config or a Maps JavaScript URL, a Supabase anon key (JWT with role `anon`), and
  Supabase publishable keys. Text, Markdown and HTML reports show the label. The
  CLI, the extension and the browser app apply the same rule.
- `firebase_client_config` only fires when the object holding `apiKey: AIza...`
  also has Firebase config fields, so a Gemini SDK key is not reported as a
  Firebase web key, even beside a real Firebase config.

### Chrome extension 1.3.2 — 2026-11-20
- Labels keys meant for browsers as public by design and reports them as low,
  using the same rule as the CLI.

## [0.8.0] — 2026-11-19

A feature release adding PHP and incident checks, a Python serialization
review, and a browser app, with a safer default for discovery-tool installation.
The Chrome extension release is v1.3.1 and is distributed separately.

### Added
- `keyleak php-check URL --authorized` assesses ordinary response headers for the
  October 2026 PHP advisories. Hidden versions remain unknown.
- `keyleak incident-check PATH` checks selected manifests for compromised
  dependencies and outdated trust packages, with optional `--ca-bundle` and
  `--railway` inputs.
- `keyleak local . --include serialization` reviews Python dataclasses, attrs
  classes, Pydantic models and NamedTuples for credential fields exposed through
  repr or serializers. It is opt-in and does not import or execute scanned code.
- `keyleak capabilities --json` lists installed checks, skills, coverage limits
  and report contracts without scanning; `--include agent-assets` checks skill
  instructions, agent rules and MCP configuration for credential patterns.

### Changed
- `keyleak site-scan` and `scan_site()` no longer install `subfinder` by
  default. Pass `--auto-install` to opt in; `KEYLEAK_NO_AUTO_INSTALL=1` or
  `KEYLEAK_MANAGED_INSTALL=1` vetoes installation. `amass` is never installed
  by KeyLeak; it is used only when already present.
- The README is a short entry point; scan options, agent usage and extension
  setup moved to `docs/`.

### Fixed
- Local, archive and binary scans keep findings collected before a limit or a
  decompression error and report the remaining scope as incomplete coverage.
- Prefixed ZIP archives are scanned within the existing bounds, and nested
  archive discovery stays inside the selected directories.
- Partial TAR members are removed after extraction errors.

### Security
- Dependency pins updated for reviewed advisories, including `requests` 2.34.2,
  `soupsieve` 4.1, `certifi` 2026.10.23, `python-dotenv` 1.2.4 and `PyYAML` 6.0.3.
- Scan exception details stay out of public error responses, scan progress
  streams end with their public error, and a TLS minimum is enforced.
- URL redaction covers encoded secret query names and bounds its work on long
  or international URLs.

### Chrome extension 1.3.1 — 2026-11-19
- The popup's key test no longer sends detected credentials to their provider;
  it inspects JWT claims locally only. The Supabase access checks are unchanged:
  a Supabase key seen in page traffic is still sent to that project's own
  endpoints to test table and storage access.

### Browser app and delivery

- Add a static browser scanner for local text, files/folders, ordinary ZIP text
  entries and embedded source-map content, with a dedicated worker, redacted
  local history, report exports and offline application caching.
- Support explicit CORS-limited HTTPS resource scanning and bounded DNS-over-HTTPS
  candidate discovery. Browser reports state unsupported and incomplete scope;
  native CLI/runtime scanning remains a separate capability.
- Add GitHub Pages publication from tested `main` builds, with project-path and
  custom-domain-root support and the existing PHP utility preserved.
- Automate allowlisted extension ZIP packaging and checksummed GitHub Release
  assets alongside the existing PyPI Trusted Publishing workflow. Chrome Web
  Store submission remains a separate publisher operation.

## [0.7.0] — 2026-10-11

A feature release for deeper local audits and browser privacy controls. The
Chrome extension release is v1.3.0 and is distributed separately.

### Added
- `keyleak audit` coordinates local, archive, and authorized browser/site scan
  phases, records coverage and artifacts, and requires explicit authorization
  and network attestation for active network phases.
- Opt-in `--scan-binaries` inspects bounded printable strings in recognized
  native artifacts and in supported ZIP/tar archives without executing files.
- Opt-in dependency-source and build-output scanning reports skipped or capped
  work as incomplete coverage.

### Security and privacy
- Browser and site scans guard redirects, subresources, and WebSocket targets;
  incomplete collection is visible in reports.
- The extension stores redacted findings, keeps raw values in service-worker
  memory, and can pause collection for the current origin.
- HTML and SARIF reports include structured remediation with a legacy fallback.

### Chrome extension 1.3.0 — 2026-10-11
- Per-origin pause/resume applies to page content, network headers, and frames.
- Raw findings are removed from persisted extension storage and stay in
  service-worker memory; copied reports remain redacted.
- Local full scans use the native helper with an exact extension-origin
  allowlist and a challenge before sending the selected target to loopback.

## [0.6.1] — 2026-07-08

A patch release for finding identity, report reliability, and Python dependency
hardening after the 0.6.0 launch.

### Security
- Updated the Python dependency graph, including the JWT/request stack, and moved
  `mitmproxy` out of the core package dependency path so normal installs are not
  blocked by optional proxy-capture dependencies.
- Proxy capture now preserves and logs concrete `mitmproxy` import-time failures
  before falling back to the existing disabled-proxy runtime path.

### Fixed
- Finding fingerprints are stable across harmless line shifts and can be keyed
  with configured HMAC material for reproducible, non-secret report identity.
- Legacy baseline and suppression files remain compatible with the newer
  fingerprint/report identity shape.
- Scan errors and suppression loading now fail louder instead of silently
  producing misleadingly clean reports.

## [0.6.0] — 2026-06-10

A security-and-usefulness release. Highlights: an attack-chain correlation engine,
scan bundles, a dependency lifecycle-hook scanner, and a full hardening pass that
fixed an SSRF in the active prober. The Chrome extension ships separately as
**v1.2.0** (see below).

### Security
- **Fixed an SSRF in BaaS active probing.** The probe target was taken from the
  scanned page's own JavaScript, so a hostile page could make the scanner issue
  requests to internal/`169.254.169.254`/loopback hosts. Egress is now validated
  through a guard that also **re-validates every redirect hop** (no 302-into-internal),
  with IPv4-mapped-IPv6/NAT64/encoding bypasses covered.
- **Cross-host credential safety on redirects:** `Authorization`/`Cookie`/api-key
  headers are stripped when a redirect changes host, and the verb is normalized
  (303 / non-idempotent 301-302 → bodyless GET). Default request timeouts added.
- **PII scrubbing now applies to every scan surface** (CLI, browser, and the
  extension), not just local-file scans — adjacent emails/phones/cards are masked
  before any report or serializer sees them.
- **Extension remote-fetch SSRF guard:** blocks internal/non-routable targets
  (incl. IPv4-mapped IPv6) unless same-origin, and refuses to follow redirects.
- BaaS write-probe stays **read-only by default**; the one mutating probe is
  opt-in and enabled by no built-in bundle.

### Added
- **Attack-chain correlation engine** — correlates individual findings into
  chained attack vectors (e.g. a published anon key **+** an RLS-less table =
  unauthenticated data exfiltration) and renders them in the JSON/Markdown/HTML
  reports.
- **Scan bundles** — `keyleak bundles` and `--bundle <id>` select named groups of
  detector packs + scan phases (secrets, quick, baas, authz, recon, deep, …).
- **Dependency lifecycle-hook scanner** — walks `node_modules` (incl. nested
  monorepo trees) and flags malicious `preinstall`/`postinstall`/`prepare`
  scripts (download-and-exec, base64 stagers, PowerShell IEX, Bun stagers, known
  payload filenames) and non-registry git-ref/tarball dependencies — the
  Shai-Hulud / Miasma / Bitwarden-CLI supply-chain class.
- **GitHub Actions hardening detectors** — unpinned actions / reusable workflows /
  `docker://` tags, `permissions: write-all`, and secrets echoed in `run:`.
- **OpenAPI-root table enumeration** for Supabase, catching tables reachable via
  the REST root even when not referenced in client code.
- **`--proxy` support** (HTTP/HTTPS/SOCKS5, with `warp`/`tor` aliases) covering
  every outbound path of a scan.
- **CI** (`.github/workflows/ci.yml`, `pull_request`-triggered, SHA-pinned
  actions) running the Python + extension test suites and the launch-gate.
- A ranked runtime-vulnerability catalog and full code-audit report under `docs/`.

### Changed
- **Ship verdict is confidence-aware:** it distinguishes findings confirmed by a
  live probe from static detections, and no longer claims a confidence gate it
  doesn't enforce.
- **Bundles fail loud:** a bundle with no runnable detectors hard-fails instead of
  running an empty "passing" scan; passive-only runs warn rather than implying
  active coverage.
- `pip install .` now ships runtime dependencies (added `[project].dependencies`).

### Fixed
- False-positive/negative hardening across the Supabase table enumeration
  (`200 []` is treated as protected, views handled correctly, token-boundary
  table-severity matching with plural support).
- Detection-surface consistency between the CLI and the browser/extension paths.

## [0.5.x] — earlier

- 0.5.4 / 0.5.1 / 0.5.0 — Full Site Scan (subdomain enumeration + crawl), GitHub
  Action, BaaS vulnerability scanner with active validation, Chrome extension,
  HTML reports, and the `baas` detector pack. See the GitHub Releases page for
  details.

---

## Chrome extension

The browser extension is versioned independently of the Python package
(it ships to the Chrome Web Store).

### Extension 1.2.0 — 2026-06-10
- PII scrubbing of evidence snippets in the live browser scan (parity with the CLI).
- Vulnerable-JS-library (CVE) detection on loaded libraries.
- SSRF-guarded remote-resource fetches (internal-host + redirect protections).
- Shared detection logic kept in sync with the CLI detector bundle.

[0.6.1]: https://github.com/Amal-David/keyleak-detector/releases/tag/v0.6.1
[0.6.0]: https://github.com/Amal-David/keyleak-detector/releases/tag/v0.6.0
[0.7.0]: https://github.com/Amal-David/keyleak-detector/releases/tag/v0.7.0
[0.8.0]: https://github.com/Amal-David/keyleak-detector/releases/tag/v0.8.0
[0.8.1]: https://github.com/Amal-David/keyleak-detector/releases/tag/v0.8.1
