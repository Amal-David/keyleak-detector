# Contributing To KeyLeak Detector

KeyLeak is trying to become the local runtime leak detector people run before shipping modern web apps. The best PRs make the tool more trustworthy, easier to run, or easier to extend.

## Good First PRs

- Add one provider detector with a fixture.
- Add one known false-positive fixture.
- Improve one remediation message.
- Add one vulnerable demo file under `fixtures/`.
- Improve Chrome extension copy or layout.
- Add a small docs section for a real workflow you tested.

## Development

```bash
poetry install
poetry run playwright install chromium
poetry run python app.py
python -m unittest
```

CLI smoke tests:

```bash
poetry run keyleak local fixtures/vulnerable-demo
poetry run keyleak local fixtures/vulnerable-demo --json
poetry run keyleak local fixtures/vulnerable-demo --sarif
```

The vulnerable demo fixtures intentionally contain fake, detector-shaped values so KeyLeak can prove its findings without scanning random systems. They are excluded from GitHub secret scanning via `.github/secret_scanning.yml`; never replace them with real credentials.

## Detector Contributions

Every detector PR should include:

- a detector ID with a clear name
- severity and remediation text
- one vulnerable fixture that should match
- one false-positive fixture if the pattern is broad
- a test or updated expected behavior

Prefer confidence and evidence quality over broad matching. A noisy detector makes the whole tool less trusted.

## Security Boundaries

- Do not add live credential validation by default.
- Do not send findings or credentials to third-party services.
- Redact secret values in reports and screenshots.
- Use throwaway credentials in demos and tests.
- Keep active probes safe, rate-limited, and documented.

## Pull Request Checklist

- I tested the changed path.
- I added or updated fixtures where relevant.
- I redacted any secrets in docs, screenshots, and logs.
- I kept the change local-first and self-host friendly.
- I explained user-visible behavior in the PR description.
