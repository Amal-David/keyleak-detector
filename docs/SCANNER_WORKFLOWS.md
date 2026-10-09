# Scanner workflows: local builds, browser pages, and sites

Use this guide to pick a scan, try the local build checks on a fictional `ABCapp`, and understand what a clean or incomplete result means. The example key below is a synthetic detector test string, not a credential; the sample never calls a provider or contacts a real site.

The flags here describe the PR source checkout; an installed release may not include them yet.

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

`node_modules` and root `dist/` are excluded unless their opt-in flags are set. Both opt-in scopes have file, directory, and byte budgets. File symlinks that leave the scan root are skipped and make coverage incomplete. Local source-map declarations are followed: if a declared map is absent and no usable sibling map exists, KeyLeak preserves any findings and marks coverage incomplete instead of reporting an unqualified clean result.

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
