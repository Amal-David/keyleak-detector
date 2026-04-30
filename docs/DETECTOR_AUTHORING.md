# Detector Authoring

KeyLeak detectors should be small, explainable, and fixture-backed.

## Detector Metadata

Each detector needs:

- `id`: stable snake_case identifier
- `pattern`: regular expression
- `severity`: `low`, `medium`, `high`, or `critical`
- `description`: what was found
- `remediation`: what the user should do next
- `categories`: where the detector applies, such as `env`, `mcp`, `ci`, `docker`, `sourcemaps`, or `logs`

Local file detectors live in `keyleak/detectors.py`.

## Quality Bar

Good detectors:

- match a real leak shape
- avoid placeholders and docs examples
- explain blast radius
- include one vulnerable fixture
- include false-positive coverage when broad

Avoid detectors that only match variable names like `apiKey`, `token`, or `secret` without a high-entropy value.

## Fixture Workflow

1. Add a fixture under `fixtures/`.
2. Add or update a `unittest` case under `tests/`.
3. Run:

```bash
python -m unittest
poetry run keyleak local fixtures/vulnerable-demo
```

## Severity Guidance

- `critical`: likely usable credential, private key, database URL, production payment key.
- `high`: credential-like value with meaningful blast radius or auth-sensitive config.
- `medium`: suspicious exposure, prompt-injection content, introspection, weak auth signal.
- `low`: hardening issue or metadata that needs review but is not a direct secret.
