# Security Model

KeyLeak Detector is designed to be local-first. The safest way to use it is on your own machine, against systems you own or have permission to test.

## What Stays Local

- Target URLs
- Captured browser traffic
- Auth cookies and bearer tokens
- Findings and reports
- Local file scan results

The project does not require a hosted service for scanning.

## Authenticated Scans

Authenticated scans can reveal issues that unauthenticated scans cannot, but they also carry more risk.

Use this operating model:

- Use throwaway test accounts.
- Use short-lived cookies or tokens.
- Avoid production administrator credentials.
- Revoke test credentials after scanning sensitive environments.
- Do not paste real customer data into bug reports or screenshots.

## Redaction

Normalized reports redact detected values by default. Raw findings from older scanner paths may still include original values for local display, so treat local logs and screenshots as sensitive until the scanner core refactor is complete.

## Chrome Extension

The extension uses powerful browser permissions because it passively observes web traffic in the active browser.

Use it when:

- testing your own app
- testing an approved bug bounty target
- reviewing a local/staging environment

Avoid it when:

- browsing unrelated personal accounts
- handling highly sensitive third-party data
- using a shared browser profile

## Hosted Scanning

Hosted scanning is intentionally deferred. A hosted version would require abuse controls, tenancy, credential-handling policy, retention policy, and legal review. The default project direction is local-first.

## Limits

KeyLeak is not a full DAST or exploit framework. It does not prove exploitability for every finding. Treat results as high-signal evidence that needs remediation or human review.
