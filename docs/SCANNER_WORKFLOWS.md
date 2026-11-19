# Scanner workflows: local builds, browser pages, and sites

Use this guide to pick a scan, try the local build checks on a fictional `ABCapp`, and understand what a clean or incomplete result means. The example key below is a synthetic detector test string, not a credential; the sample never calls a provider or contacts a real site.

The commands in this guide are available in KeyLeak 0.7.0 and current source checkouts. Older installed releases may not include every flag shown here.

## Choose a scan

| Goal | Command | What it does |
| --- | --- | --- |
| Check a repository before shipping | `poetry run keyleak local <repo>` | Reads local files; makes no network requests. |
| Include installed JavaScript dependencies | Add `--scan-node-modules` | Checks bounded dependency source files for known fingerprints and a suspicious credential-read/network/persistence pattern. It does not run install scripts. |
| Include the built frontend | Add `--scan-dist` | Scans the repository’s root `dist/` output and local source maps. This is opt-in. |
| Check one owned running page | `poetry run keyleak browser-scan <authorized-url>` | Opens one page with Playwright and inspects browser-visible content and requests. |
| Crawl an owned domain | `poetry run keyleak site-scan <authorized-domain>` | Discovers subdomains and crawls pages within the configured depth/page/subdomain limits. |

Start with local scanning. It is the fastest way to check a release without contacting a server. Site discovery and crawling make network requests; only use a domain you own or are explicitly authorized to test. `--baas-validate` sends active probes and should be enabled only when you are authorized to test those endpoints.

## Try the local build and dependency scan

From a source checkout, install the project once:

```bash
poetry install
```

Create a disposable `ABCapp` example outside your repository. The key-like value is intentionally fake and only exercises the local detector. The dependency sample is comments only: the detector recognizes the three suspicious source patterns, but no script is run.

```bash
DEMO_ROOT="$(mktemp -d)"
export DEMO_ROOT
python3 - <<'PY'
import os
from pathlib import Path

root = Path(os.environ["DEMO_ROOT"]) / "abc-app"
fake_key = "AKIA" + "1234567890" + "ABCDEF"
(root / "dist").mkdir(parents=True)
(root / "node_modules" / "abc-demo" / "dist").mkdir(parents=True)
(root / "dist" / "main.js").write_text(
    f'window.ABC_CONFIG = {{ accessKey: "{fake_key}" }};\n'
    "//# sourceMappingURL=main.js.map\n",
    encoding="utf-8",
)
(root / "node_modules" / "abc-demo" / "dist" / "index.js").write_text(
    "// Scan-only text. These are comments, not executable code.\n"
    "// const token = process.env.NPM_TOKEN;\n"
    "// fetch('https://example.invalid');\n"
    "// fs.writeFileSync('~/.ssh/authorized_keys', token);\n",
    encoding="utf-8",
)
PY
```

Run the opt-in scopes and save JSON for review:

```bash
poetry run keyleak local "$DEMO_ROOT/abc-app" \
  --scan-node-modules --scan-dist --json --fail-on high \
  > "$DEMO_ROOT/report.json"
scan_exit=$?
```

Exit `2` is expected for this deliberately flagged example. `--fail-on high` makes the gate fail on high or critical findings; incomplete coverage also returns `2`. Exit `1` means the command itself errored. This command’s output is JSON; findings stay redacted.

Read only the summary and coverage first:

```bash
python3 - "$DEMO_ROOT/report.json" <<'PY'
import json
import sys

report = json.load(open(sys.argv[1], encoding="utf-8"))
print("verdict:", report["verdict"]["status"])
print("findings:", report["summary"]["total_findings"])
print("coverage:", report["coverage"]["status"])
print("coverage counts:", {
    key: report["coverage"][key]
    for key in ("attempted", "completed", "skipped", "failed")
})
print("coverage reasons:", report["coverage"]["reasons"])
PY
```

On the example above, the result was `BLOCK_SHIP` with three findings: one critical dependency source-pattern finding, one high AWS-key-pattern finding, and one low source-map reference. Coverage was `incomplete` (3 attempted, 2 completed, 1 skipped) because `main.js` declares a source map that is missing. The example returned exit `2`. The critical triad finding is a syntactic match on the intentionally comment-only fixture, not a malware verdict; the scan did not install the dependency or execute its file.

For a clean follow-up, replace the fake key, remove the scan-only comment fixture, and either provide the declared map or remove its stale `sourceMappingURL` comment. Rerunning the same command returned `SAFE_TO_SHIP`, zero findings, complete 2/2 coverage, and exit `0`. That result only describes the synthetic files; it does not verify a real release.

Dependency source files in `node_modules` and root `dist/` build files are excluded unless their opt-in flags are set. When the `leak` pack is active, the separate lifecycle-hook audit may still read package manifests and install scripts under `node_modules`; it does not execute them. Both opt-in source scopes have file, directory, and byte budgets. File symlinks that leave the scan root are skipped and make coverage incomplete. Local source-map declarations are followed: if a declared map is absent and no usable sibling map exists, KeyLeak preserves any findings and marks coverage incomplete instead of reporting an unqualified clean result.

## Check one local browser page

For a page that is still running locally, install Chromium once:

```bash
poetry run playwright install chromium
```

Create a local HTML page in the disposable directory and serve only on loopback:

```bash
mkdir -p "$DEMO_ROOT/site"
python3 - <<'PY'
import os
from pathlib import Path

fake_key = "AKIA" + "1234567890" + "ABCDEF"
Path(os.environ["DEMO_ROOT"], "site", "index.html").write_text(
    "<!doctype html><title>ABCapp local demo</title>"
    f'<script>window.ABC_DEMO_KEY = "{fake_key}";</script>',
    encoding="utf-8",
)
PY
python3 -m http.server --bind 127.0.0.1 8765 --directory "$DEMO_ROOT/site"
```

In a second terminal, scan that local fixture with outbound networking disabled. The private-target override is needed only because the example deliberately targets loopback:

```bash
KEYLEAK_ALLOW_PRIVATE_TARGETS=1 poetry run keyleak --offline \
  browser-scan http://127.0.0.1:8765/ --json --fail-on high \
  > "$DEMO_ROOT/browser-report.json"
```

The local run found two high-severity synthetic patterns, had complete one-page coverage, and exited `2`. Stop the test server when finished. For a real browser scan, substitute a URL you are authorized to inspect and omit `KEYLEAK_ALLOW_PRIVATE_TARGETS` unless the target is your local development server.

For a multi-page site, replace the placeholder below with a domain you control. This command performs real subdomain discovery and crawling; it is not an offline or mock example:

```bash
poetry run keyleak site-scan YOUR_AUTHORIZED_DOMAIN \
  --no-auto-install --depth 1 --max-pages 10 --max-subdomains 5 \
  --json > site-report.json
```

Unsafe subresources, redirects, WebSocket targets, and failed page navigation are reflected in coverage; findings from pages that did scan remain in the report. The egress guard is not a transport-level DNS pinning guarantee, so keep the target authorized and the scan bounds small. Add `--baas-validate` only when active probing is approved.

## Use the extension and reports safely

On a page you control, click the KeyLeak extension and choose **PAUSE SITE** to stop collection for that origin. The origin includes the scheme, host, and port; a subdomain is a separate origin. **RESUME SITE** restores collection. While paused, the extension does not inspect page bodies or analyze/store that page’s web-request headers, including framed-page activity.

Stored findings and copied/exported reports remain redacted. A **REVEAL** control temporarily shows an available raw sample in the popup from service-worker memory; raw samples are not saved to Chrome storage, reports, logs, or analytics. Reveal only when needed and do not paste the value into an issue or chat. The value disappears on navigation, clearing, tab close, or worker restart.

To export findings for code review, use `--sarif`; HTML, Markdown, and JSON are also supported. For a detector’s structured fix steps, run `poetry run keyleak explain leak.aws_access_key --json`. Rotate any real exposed credential, remove it from the client bundle, rebuild, and rescan. Moving a value into a `VITE_`/`NEXT_PUBLIC_` variable still puts it in client code; privileged calls belong on a backend. A clean local example cannot prove a real provider credential was revoked.

## Install options

The KeyLeak CLI requires Python 3.12 or newer. The [static browser app](BROWSER_APP.md) runs without a Python installation on the visitor's device.

```bash
python -m pip install keyleak-detector
```

Or run without a permanent install:

```bash
uvx keyleak-detector --help
```

## Command summary

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

Use `--json`, `--sarif`, `--markdown`, or `--html` for machine-readable or shareable reports. See the [agent scan runbook](AGENT_SCAN_HOWTO.md) for setup and triage examples.

- **Local project:** `keyleak local .` scans supported configuration, CI, Docker, MCP, source-map, and log files. Source files in `node_modules` and root `dist/` are opt-in.
- **Binary release:** add `--scan-binaries` to scan printable strings in recognized native files. Use `keyleak archive release.zip --scan-binaries` for ZIP/tar archives, including APK/IPA ZIP containers.
- **Web app:** `keyleak browser-scan URL` scans one authorized target; `keyleak site-scan DOMAIN` discovers and crawls an authorized site.
- **Coordinated audit:** `keyleak audit --help` describes the local, archive, and authorized network phases. Active network scans require explicit scope and attestation.

Audit writes redacted artifacts under `.keyleak/audits/`; `artifact_dir` is reported as an absolute path.

Advanced coverage limits, source scanning options, archive behavior, and examples are in [scanner workflows](#choose-a-scan) and the [binary artifact guide](BINARY_ARTIFACT_SCANNING.md).

## Local coverage options

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
as incomplete coverage, never as a clean result. See the [binary guide](BINARY_ARTIFACT_SCANNING.md)
for supported formats, caps, and output examples.

Full site scans can use crt.sh, DNS, and installed `subfinder` / `amass` for
subdomain discovery. They do **not** install missing tools by default. Operators
can explicitly opt in with `--auto-install`; `--no-auto-install` remains
supported. `KEYLEAK_NO_AUTO_INSTALL=1` or `KEYLEAK_MANAGED_INSTALL=1` vetoes
installation even with explicit consent. `keyleak doctor` reports available
discovery tools. See [distribution readiness](DISTRIBUTION.md) for the
migration note and package-manager contract.

## Findings, verdicts, and exit codes

Reports include a verdict, severity, confidence, source, evidence, remediation, and a re-test command. Normalized reports redact credential values by default. Binary findings include a zero-based byte offset and omit surrounding string snippets so nearby credentials cannot leak through context.

Scans are bounded. If a file, archive, or scan limit is reached, earlier findings remain in the report and coverage is marked incomplete. Exit code `0` means the selected threshold passed with complete coverage; `1` means the command failed; `2` means the threshold was reached or coverage was incomplete.

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

## Authenticated scans and proxies

Use KeyLeak only on systems you own or have permission to test. Authenticated
scans should use throwaway credentials. `keyleak scan` posts to the local KeyLeak web
scanner at `http://127.0.0.1:5002` and exits `1` if it is not running; start it first from
a source checkout with `poetry run python app.py` (see [CONTRIBUTING.md](../CONTRIBUTING.md#development)).
Then run the scan in a second terminal. If KeyLeak is installed only in the checkout's Poetry
environment, prefix the command with `poetry run`:

```bash
keyleak scan https://your-staging-app.example \
  --profile authenticated --bearer "$THROWAWAY_TOKEN"
```

KeyLeak does not upload reports to a hosted service. Values are redacted in
normalized reports by default. A proxy can see the scan traffic routed through
it, so use a trusted local proxy rather than an unknown public service. Read the
[security model](SECURITY_MODEL.md) before scanning sensitive targets.
