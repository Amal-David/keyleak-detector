# KeyLeak GitHub Action

Scan your codebase and preview deployments for exposed API keys, BaaS misconfigurations, and secrets — directly in your CI/CD pipeline.

## Quick Start

### Scan local files on every PR

```yaml
name: KeyLeak Security Scan
on: [pull_request]

jobs:
  keyleak:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Amal-David/keyleak-detector@v0.5.0
        with:
          mode: local
          fail-on: high
```

### Scan Vercel preview deployments

```yaml
name: KeyLeak Preview Scan
on:
  deployment_status:

jobs:
  keyleak:
    if: github.event.deployment_status.state == 'success'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Amal-David/keyleak-detector@v0.5.0
        with:
          mode: browser
          url: ${{ github.event.deployment_status.target_url }}
          baas-validate: true
          fail-on: high
```

### Scan Netlify deploy previews

```yaml
name: KeyLeak Netlify Scan
on:
  deployment_status:

jobs:
  keyleak:
    if: github.event.deployment_status.state == 'success'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Amal-David/keyleak-detector@v0.5.0
        with:
          mode: browser
          url: ${{ github.event.deployment_status.environment_url }}
          baas-validate: true
          fail-on: high
```

### Full scan (local + browser)

```yaml
- uses: Amal-David/keyleak-detector@v0.5.0
  with:
    mode: both
    url: https://preview.example.com
    baas-validate: true
    fail-on: high
    output-format: sarif
```

## Inputs

| Input | Default | Description |
|---|---|---|
| `mode` | `local` | `local` (files), `browser` (live URL), or `both` |
| `url` | | URL to scan in browser mode |
| `baas-validate` | `false` | Enable active BaaS validation (Supabase RLS, Firebase rules) |
| `fail-on` | `high` | Severity threshold: `low`, `medium`, `high`, `critical` |
| `launch-profile` | `ci` | Profile: `launch-gate`, `local-dev`, `bug-bounty`, `ci`, `full` |
| `allowlist` | `keyleak-allowlist.yaml` | Path to allowlist file |
| `output-format` | `json` | Output: `json`, `sarif`, `markdown`, `html` |

## Outputs

| Output | Description |
|---|---|
| `verdict` | `SAFE_TO_SHIP`, `REVIEW`, or `BLOCK_SHIP` |
| `findings-count` | Total findings across the requested scans, including the self-audit in local mode; available for every output format when report processing succeeds |
| `report-path` | Absolute path to the local or browser report; in `both` mode this is the browser report. Use this output instead of assuming a file in the checkout |

## Failure behavior and reports

The action fails if a scanner returns an error or finds an issue at or above
`fail-on`. A failure in the self-audit, local scan, or browser scan remains a
failure even if a later scan succeeds. The requested scans still run so their
reports can help diagnose the problem. Empty reports and invalid JSON report
metadata also fail the action.

Invalid inputs fail before any scan runs. The `browser` and `both` modes require
an HTTP(S) `url`; an absent URL is a configuration error.

Generated reports are retained in the `keyleak-report` artifact even when a scan
fails. They are stored in a private, temporary directory outside the checkout.
Local mode includes the self-audit report and `keyleak-report.<format>`; browser
mode includes `keyleak-browser-report.<format>`; `both` includes all three.
Each scan runs once and produces JSON; other formats are rendered from that
same report, and the original JSON is retained alongside them. If rendering
fails, `report-path` points to the original JSON for diagnosis. No report
artifact is uploaded for a configuration error that prevents scanning.

For every output format, `verdict` reflects the most severe report verdict, and
a scanner or report-processing error sets it to `BLOCK_SHIP`. The action's exit
status honors `fail-on`, so choosing `critical` can permit a successful check
whose report still identifies high-severity findings as `BLOCK_SHIP`.

## SARIF Integration

Upload findings to GitHub Security tab:

```yaml
- uses: Amal-David/keyleak-detector@v0.5.0
  id: keyleak
  with:
    mode: local
    output-format: sarif
    fail-on: high

- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: ${{ steps.keyleak.outputs.report-path }}
```
