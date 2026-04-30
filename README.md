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

## Quick Start

### Docker Web UI

```bash
git clone https://github.com/Amal-David/keyleak-detector.git
cd keyleak-detector
docker compose up -d
```

Open `http://localhost:5002`.

### Local Web UI

```bash
poetry install
poetry run playwright install chromium
poetry run python app.py
```

Open `http://localhost:5002`.

### CLI

```bash
poetry install
poetry run keyleak local fixtures/vulnerable-demo
poetry run keyleak local . --json
poetry run keyleak local . --sarif --fail-on high
```

The URL scanner uses the local web scanner API:

```bash
poetry run python app.py
poetry run keyleak scan https://preview.example.com --json
poetry run keyleak scan https://preview.example.com --bearer "$TOKEN" --fail-on medium
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

It requests powerful browser permissions because it needs to observe web traffic locally. See [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md) before using it on sensitive browsing sessions.

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
