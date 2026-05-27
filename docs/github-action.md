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
| `findings-count` | Total number of findings |
| `report-path` | Path to the generated report file |

## SARIF Integration

Upload findings to GitHub Security tab:

```yaml
- uses: Amal-David/keyleak-detector@v0.5.0
  with:
    mode: local
    output-format: sarif
    fail-on: high

- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: keyleak-report.sarif
```
