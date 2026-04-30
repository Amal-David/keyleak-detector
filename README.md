# KeyLeak Detector

[![GitHub](https://img.shields.io/badge/GitHub-Amal--David%2Fkeyleak--detector-blue?logo=github)](https://github.com/Amal-David/keyleak-detector)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.9%2B-blue)](https://www.python.org/)

KeyLeak Detector is a local-first runtime leak detector for modern web apps.

It catches secrets and risky exposures that only show up after your app runs: JavaScript bundles, API responses, request/response headers, DOM data attributes, authenticated pages, exposed files, subdomains, source maps, MCP/agent configs, and AI provider keys.

The default trust model is simple: run it locally, scan systems you own, and keep test credentials on your machine.

## Why This Exists

Static scanners are essential, but they miss leaks that appear at runtime:

- A frontend bundle contains an AI provider key after build-time injection.
- An API response includes a token only after login.
- A preview deploy exposes `.env`, `.git`, backups, source maps, or debug bundles.
- A generated app ships object IDs and weak authorization paths.
- Agent/MCP config files collect powerful tool tokens in local project folders.

KeyLeak is meant to answer one launch question quickly:

```text
Can I ship this preview without leaking something obvious and expensive?
```

## What Changed

The current `main` branch includes the relaunch work that moved KeyLeak beyond a single website scanner:

- A local-first product story for runtime leaks in AI-built and fast-shipped web apps.
- A normalized finding/report model with verdict, proof, fix guidance, confidence, and re-test commands.
- A CLI with `keyleak scan` for running web apps and `keyleak local` for local files/configs.
- JSON, Markdown, and SARIF output for local use, CI gates, and security review workflows.
- Baseline and allowlist support so teams can suppress known findings and fail only on new risk.
- A deliberately vulnerable fixture in `fixtures/vulnerable-demo` for safe demos and tests.
- A Chrome extension in `extension/` for passive local browser monitoring.
- New local detectors for AI provider keys, MCP/agent configs, GraphQL hints, hidden prompt-injection text, source maps, CI files, Docker files, logs, and classic secrets.
- Contributor docs, detector authoring docs, issue templates, PR template, and security model docs.
- UI layout cleanup for the web scanner results, filters, findings, and attack vector sections.

## The Delta Four Result

Every serious scan should lead to four things:

- `Verdict`: `SAFE TO SHIP`, `REVIEW`, or `BLOCK SHIP`.
- `Proof`: redacted evidence, source, detector, and confidence.
- `Fix`: exact remediation and rotation guidance.
- `Re-test`: the command or profile to run after fixing.

Example CLI result:

```bash
keyleak scan https://preview.example.com
BLOCK SHIP: 1 critical, 0 high, 2 medium, 3 low
Critical or high-confidence exposures need fixing before release.
Re-test: keyleak scan https://preview.example.com
```

## What It Checks

| Area | Status | Notes |
|---|---:|---|
| Runtime JS/API response secrets | Strong | Browser + proxy capture scans scripts, headers, URLs, and responses. |
| AI/LLM provider keys | Strong | OpenAI, Anthropic, Gemini, OpenRouter, Groq, Hugging Face, and more. |
| Cloud/SaaS/PAT/webhooks | Strong | AWS, GitHub, Stripe, Slack, SendGrid, PyPI, database URLs, private keys. |
| Auth-only leaks | Partial | Authenticated bearer/cookie scan support exists; two-user diff is planned. |
| IDOR/BOLA hints | Early | Flags obvious direct object references and auth mismatch signals. |
| Attack surface | Partial | Security headers, TLS, exposed files, admin paths, subdomain enumeration. |
| Local config leaks | New | `keyleak local` scans `.env`, MCP, CI, Docker, source maps, and logs. |
| Source maps/debug bundles | New | Local scanner detects source map content and provider keys. |
| GraphQL/LLM/agent hints | Early | Local detectors catch GraphQL introspection and prompt-injection-style text. |

KeyLeak is not a full DAST, not exploit automation, and not a replacement for GitLeaks, TruffleHog, GitHub secret scanning, or GitGuardian. It is the runtime/browser/local-config layer that complements them.

## How To Use It Now

Use the surface that matches your workflow.

### 1. Run The Web UI With Docker

This is the fastest way to try the browser scanner without installing Python dependencies locally.

```bash
git clone https://github.com/Amal-David/keyleak-detector.git
cd keyleak-detector
docker compose up -d
```

Open `http://localhost:5002`.

Use the page input for a basic runtime scan. Use the authenticated scan modal only with throwaway test credentials.

### 2. Run The Web UI Locally

Use this path when you want to develop the Flask app, scanner, templates, CSS, or JavaScript.

```bash
poetry install
poetry run playwright install chromium
poetry run python app.py
```

Open `http://localhost:5002`.

If you do not use Poetry, create a virtual environment and install the package locally:

```bash
python3.11 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
python -m playwright install chromium
python app.py
```

### 3. Scan Local Files And Configs

Use `keyleak local` before pushing or shipping. It scans local files without starting the web app.

```bash
poetry install
poetry run keyleak local fixtures/vulnerable-demo
poetry run keyleak local . --json
poetry run keyleak local . --sarif --fail-on high
```

By default, local mode includes `env,mcp,ci,docker,sourcemaps,logs`.

Limit the scan to specific file families:

```bash
poetry run keyleak local . --include env,mcp,sourcemaps
```

Exit codes are designed for automation: `0` means the selected threshold passed, `1` means the command failed, and `2` means findings met `--fail-on`.

### 4. Scan A Running Web App From The CLI

Use `keyleak scan` when you have a preview URL, staging URL, or local app URL.

The CLI talks to the local KeyLeak web scanner API, so start the web app first:

```bash
poetry run python app.py
poetry run keyleak scan https://preview.example.com --json
poetry run keyleak scan https://preview.example.com --bearer "$TOKEN" --fail-on medium
```

You can also point the CLI at the Docker web scanner:

```bash
docker compose up -d
poetry run keyleak scan http://host.docker.internal:3000 --server http://127.0.0.1:5002
```

### 5. Run Authenticated Scans

Use authenticated mode only against systems you own or have permission to test.

```bash
poetry run keyleak scan https://preview.example.com \
  --profile authenticated \
  --bearer "$THROWAWAY_TOKEN"
```

Use a cookie instead of a bearer token:

```bash
poetry run keyleak scan https://preview.example.com \
  --profile authenticated \
  --cookie "session=throwaway-session"
```

Use both when the app requires both:

```bash
poetry run keyleak scan https://preview.example.com \
  --profile authenticated \
  --bearer "$THROWAWAY_TOKEN" \
  --cookie "session=throwaway-session"
```

### 6. Generate Reports For CI Or Review

Use JSON for baselines, SARIF for code scanning systems, and Markdown for human review.

```bash
poetry run keyleak local . --json > keyleak-report.json
poetry run keyleak local . --sarif > keyleak.sarif
poetry run keyleak local . --markdown > keyleak-report.md
```

Fail on high or critical findings:

```bash
poetry run keyleak local . --fail-on high
poetry run keyleak scan https://preview.example.com --fail-on critical
```

Suppress known findings with a previous JSON report or allowlist:

```bash
poetry run keyleak local . --baseline keyleak-report.json
poetry run keyleak local . --allowlist keyleak-allowlist.txt
```

## Safe Demo

The repo includes an intentionally vulnerable local fixture:

```bash
poetry run keyleak local fixtures/vulnerable-demo --markdown
```

This gives contributors and Hacker News readers a safe way to see a `BLOCK SHIP` result without scanning random systems.

## Web Scanner

Basic scan:

1. Loads the target in headless Chromium through mitmproxy.
2. Captures URLs, headers, responses, inline scripts, and DOM config data.
3. Applies custom and GitLeaks-derived secret patterns.
4. Runs attack-surface checks for exposed files, security headers, admin paths, TLS, and subdomains.
5. Returns a verdict, summary, findings, proof, fix guidance, and re-test command.

Authenticated scan:

1. Adds a throwaway bearer token and/or cookie to the browser context.
2. Scans authenticated pages and traffic.
3. Applies best-effort access-control heuristics for direct object references.

Use throwaway credentials only.

## Chrome Extension

The `extension/` folder contains an experimental local Chrome extension that passively monitors pages as you browse.

It scans:

- request and response headers
- URLs and query parameters
- fetch/XHR response bodies
- inline scripts
- data attributes and page config

### Load It In Chrome

The extension is not published to the Chrome Web Store yet. Load it from this repo:

1. Clone or pull the latest `main` branch.
2. Open `chrome://extensions` in Chrome.
3. Enable `Developer mode`.
4. Click `Load unpacked`.
5. Select the `extension/` folder, not the repository root.
6. Pin `KeyLeak Detector` from the Chrome toolbar extensions menu.
7. Browse an app you own or have permission to test.
8. Click the KeyLeak toolbar icon to see findings for the current tab.

The exact folder to select is:

```text
keyleak-detector/extension
```

### Use The Popup

The popup shows:

- a badge count for findings on the current tab
- severity filters for `HIGH`, `MED`, and `LOW`
- scan activity stats for requests, response bodies, scripts, data attributes, and meta tags
- redacted finding values and sources
- a `CLEAR` button to reset findings for the current tab

### Use The DevTools Panel

Open Chrome DevTools on a page, then select the `Secrets` panel. It shows a wider table with severity, type, value, source, and context for the inspected tab.

### Extension Permissions

The extension requests `webRequest`, `storage`, `activeTab`, `tabs`, and `<all_urls>` because it observes requests, headers, page content, and fetch/XHR responses locally.

Use it for development, staging, bug bounty scopes, or owned systems. Disable it when browsing unrelated sensitive sites. See [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md) before using it on sensitive browsing sessions.

## Reports

CLI output formats:

```bash
poetry run keyleak local . --json
poetry run keyleak local . --markdown
poetry run keyleak local . --sarif
poetry run keyleak scan https://preview.example.com --baseline keyleak-baseline.json --fail-on high
```

Each normalized finding includes:

- `id`
- `type`
- `severity`
- `confidence`
- `detector_id`
- `source`
- `evidence`
- `redacted_value`
- `risk_reason`
- `remediation`
- `references`
- `validation_status`

Baselines and allowlists are intentionally simple. A baseline can be a previous KeyLeak JSON report; those finding IDs/signatures are suppressed so CI fails only on new findings. An allowlist can be JSON (`ids`, `detector_ids`, `types`, `source_contains`) or a line file using entries like `id:finding_...`, `detector:local:openai_api_key`, `type:source_map_reference`, or `source:fixtures/vulnerable-demo`.

## Security Model

- Local-first: scans run on your machine or self-hosted Docker container.
- No hosted credential upload is required.
- Values are redacted in normalized reports by default.
- Authenticated scans should use throwaway test credentials.
- Only scan systems you own or have explicit permission to test.

Read [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md) for details and limits.

## Contributing

Useful PRs are very welcome. The best contribution lanes are:

- add provider patterns with fixtures
- add safe vulnerable fixtures
- improve false-positive handling
- add remediation playbooks
- improve Chrome extension UX or tests
- add report exporters
- improve CLI profiles and CI behavior
- add MCP/agent/LLM leak detectors

Start with [CONTRIBUTING.md](CONTRIBUTING.md) and [docs/DETECTOR_AUTHORING.md](docs/DETECTOR_AUTHORING.md).

## Roadmap

- Shared scanner core for web UI, CLI, and extension.
- More detector fixtures and report tests.
- GitHub Action and CI mode.
- Two-user authenticated comparison for IDOR/BOLA.
- GraphQL, OAuth/OIDC, CORS, source-map, and agent-web safety detectors.
- Generated extension pattern bundle from the shared registry.

## Responsible Use

Only scan systems you own or have written permission to test. Unauthorized scanning may be illegal. Handle findings securely, rotate exposed credentials immediately, and report vulnerabilities through responsible disclosure.

## Acknowledgments

- [GitLeaks](https://github.com/gitleaks/gitleaks) for the industry-standard secret scanning rules that KeyLeak imports.
- [Keyleaksecret](https://github.com/0xSojalSec/Keyleaksecret) for additional pattern inspiration.

## License

MIT. See [LICENSE](LICENSE).
