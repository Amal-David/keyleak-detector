# KeyLeak Detector

[![PyPI](https://img.shields.io/pypi/v/keyleak-detector?color=34d399&logo=python&logoColor=white)](https://pypi.org/project/keyleak-detector/)
[![GitHub](https://img.shields.io/github/stars/Amal-David/keyleak-detector?style=flat&logo=github)](https://github.com/Amal-David/keyleak-detector)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![GitHub Action](https://img.shields.io/badge/GitHub_Action-available-2088FF?logo=githubactions&logoColor=white)](docs/github-action.md)
[![Chrome Extension](https://img.shields.io/badge/Chrome-Extension-4285F4?logo=googlechrome&logoColor=white)](extension/)
[![Python](https://img.shields.io/badge/Python-3.12%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)

KeyLeak finds exposed credentials in browser traffic, local projects, build
artifacts, and supported deployment archives. It checks selected backend-as-a-
service configurations and returns redacted evidence with remediation guidance.

## Install

KeyLeak requires Python 3.12 or newer.

```bash
python -m pip install keyleak-detector
```

Or run without a permanent install:

```bash
uvx keyleak-detector --help
```

## Quick start

Scan the current project before shipping:

```bash
keyleak local . --launch-profile launch-gate --fail-on high
```

Scan a web app you own or are authorized to test:

```bash
keyleak browser-scan https://your-owned-app.example --html > report.html
```

Scan an authorized site and its pages:

```bash
keyleak site-scan your-owned-domain.example \
  --depth 3 --max-pages 100 --max-subdomains 25 --baas-validate --html \
  > site-report.html
```

Use `--json`, `--sarif`, `--markdown`, or `--html` for machine-readable or shareable reports. See the [agent scan runbook](docs/AGENT_SCAN_HOWTO.md) for setup and triage examples.

## Choose a scan

- **PHP patch assessment:** `keyleak php-check URL --authorized` checks ordinary response headers for the October 2026 PHP advisories. The local web bridge includes a URL form at `/php-check`. Hidden versions remain unknown; a patched banner does not prove a site is safe.
  The [public PHP checker](https://keyleakdetector.com/php-check/) offers URL assessment and a browser-side version comparison.
- **Incident inputs:** `keyleak incident-check .` checks selected manifests for compromised dependencies and outdated trust packages. Add `--ca-bundle FILE` for fingerprint checks or `--railway` for operator-requested recovery guidance. See [incident checks and limits](docs/OCTOBER_2026_INCIDENTS.md).
- **Local project:** `keyleak local .` scans supported configuration, CI, Docker, MCP, source-map, and log files. Source files in `node_modules` and root `dist/` are opt-in.
- **Binary release:** add `--scan-binaries` to scan printable strings in recognized native files. Use `keyleak archive release.zip --scan-binaries` for ZIP/tar archives, including APK/IPA ZIP containers.
- **Web app:** `keyleak browser-scan URL` scans one authorized target; `keyleak site-scan DOMAIN` discovers and crawls an authorized site.
- **Coordinated audit:** `keyleak audit --help` describes the local, archive, and authorized network phases. Active network scans require explicit scope and attestation.

Audit writes redacted artifacts under `.keyleak/audits/`; `artifact_dir` is reported as an absolute path.

Advanced coverage limits, source scanning options, archive behavior, and examples are in [scanner workflows](docs/SCANNER_WORKFLOWS.md) and the [binary artifact guide](docs/BINARY_ARTIFACT_SCANNING.md).

### Local coverage options

Local scans cover configuration and infrastructure files such as `.env`, MCP,
CI, Docker, source maps, and logs. Add source trees or release artifacts
explicitly:

```bash
keyleak local . --scan-node-modules --json
keyleak local . --scan-dist --json
keyleak local . --scan-binaries --sarif
keyleak archive release.zip --scan-binaries --out release-report.json
```

`--scan-node-modules` checks JavaScript and TypeScript source; `--scan-dist`
includes root `dist/` build output. `--scan-binaries` checks printable strings
in supported executables and binary members of ZIP/tar archives, with bounded
common decoding and nested archive traversal. APK and IPA files are ZIP containers;
DEX and mobile resource semantics remain unsupported. The scanner does not execute
artifacts; encrypted and runtime-assembled secrets can be missed. Limits and unsupported scope are reported
as incomplete coverage, never as a clean result. See the [binary guide](docs/BINARY_ARTIFACT_SCANNING.md)
for supported formats, caps, and output examples.

Full site scans can use crt.sh, DNS, and pinned `subfinder` for subdomain
discovery. If you do not want automatic tool installation, pass
`--no-auto-install` or set `KEYLEAK_NO_AUTO_INSTALL=1`. `keyleak doctor`
reports which discovery tools are available.

## Findings and safe use

Reports include a verdict, severity, confidence, source, evidence, remediation, and a re-test command. Normalized reports redact credential values by default. Binary findings include a zero-based byte offset and omit surrounding string snippets so nearby credentials cannot leak through context.

Scans are bounded. If a file, archive, or scan limit is reached, earlier findings remain in the report and coverage is marked incomplete. Exit code `0` means the selected threshold passed with complete coverage; `1` means the command failed; `2` means the threshold was reached or coverage was incomplete.

Use KeyLeak only on systems you own or have permission to test. Authenticated
scans should use throwaway credentials, for example:

```bash
keyleak scan https://your-staging-app.example \
  --profile authenticated --bearer "$THROWAWAY_TOKEN"
```

KeyLeak does not upload reports to a hosted service. Values are redacted in
normalized reports by default. A proxy can see the scan traffic routed through
it, so use a trusted local proxy rather than an unknown public service. Read the
[security model](docs/SECURITY_MODEL.md) before scanning sensitive targets.

### Read the result

KeyLeak retains the machine statuses `SAFE_TO_SHIP`, `REVIEW`, and `BLOCK_SHIP`.
Local zero-finding reports say **No findings in selected checks** and include
coverage, inventory, extraction limits, and a retest command preserving scan options.
Archive envelopes bind the report and input digests; HMAC authentication requires
`KEYLEAK_COC_KEY`. Use the evidence,
confidence, remediation, and re-test command to decide what to fix. The default
launch gate blocks on high and critical findings:

- Exit `0`: the selected threshold passed and coverage is complete.
- Exit `1`: the command failed.
- Exit `2`: findings met `--fail-on`, or coverage was incomplete or malformed.

If you believe a result is a false positive, report its detector, source, and
why it is benign. Do not include unredacted credential values in an issue.

## Chrome extension

The extension observes request and response metadata, page content, and
fetch/XHR responses locally. It redacts stored and copied findings, keeps raw
finding values in service-worker memory, and lets you pause collection for an
origin. `nativeMessaging` is used for explicit full scans through the installed
local helper; it sends fixed lifecycle actions, a startup challenge, and local
proof, not page URLs or scan data.

- [Install the published Chrome Web Store extension](https://chromewebstore.google.com/detail/keyleak-detector/ildodbfchnbmndkcijllpmihcbfchgdl) (listing version **1.2.0**).
- [Download extension v1.3.0](https://github.com/Amal-David/keyleak-detector/releases/download/v0.7.0/keyleak-detector-extension-v1.3.0.zip) from the GitHub release. This ZIP is available for unpacked testing; it has not been submitted to the store listing.
- For local development, load the `extension/` directory in
  `chrome://extensions`, then run `poetry run keyleak install-extension-host`
  from a source checkout. The helper restricts access to the exact extension
  origin.

## What it detects

- API credentials, private keys, JWT risks, and secrets in browser responses or local files.
- Supabase, Firebase, Appwrite, PocketBase, and Convex configuration or access-control issues.
- Risky npm lifecycle hooks, CI workflow settings, exposed local configuration, and selected build artifacts.
- Opt-in application-security and correctness leads, labeled for review when they are not validated exploits.

KeyLeak complements dedicated source-secret scanners and DAST tools. It is not a general exploit framework. See [Convex support and safety boundaries](docs/CONVEX_SUPPORT.md) for provider-specific limits.

## GitHub Action

Use the [GitHub Action guide](docs/github-action.md) to scan a deployment or repository in CI. The action supports browser and local modes, SARIF upload, and configurable failure thresholds.

## Development

```bash
git clone https://github.com/Amal-David/keyleak-detector.git
cd keyleak-detector
poetry install
poetry run playwright install chromium
poetry run keyleak local . --launch-profile launch-gate --fail-on high
```

To run the Flask web UI, use `poetry run python app.py` and open `http://127.0.0.1:5002`. For detector contributions, see [CONTRIBUTING.md](CONTRIBUTING.md) and the [detector authoring guide](docs/DETECTOR_AUTHORING.md).

## Releases and documentation

The current Python package release is **0.7.0**. The extension Web Store
listing and downloadable ZIP can have different versions because store updates
require a separate submission.

- [Changelog](CHANGELOG.md)
- [Scanner workflows](docs/SCANNER_WORKFLOWS.md)
- [Binary artifact scanning](docs/BINARY_ARTIFACT_SCANNING.md)
- [Security model](docs/SECURITY_MODEL.md)
- [Agent scan runbook](docs/AGENT_SCAN_HOWTO.md)

## License

MIT. See [LICENSE](LICENSE).
