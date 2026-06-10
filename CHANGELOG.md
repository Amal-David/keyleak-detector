# Changelog

All notable changes to KeyLeak Detector are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project aims to follow [Semantic Versioning](https://semver.org/).

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

[0.6.0]: https://github.com/Amal-David/keyleak-detector/releases/tag/v0.6.0
