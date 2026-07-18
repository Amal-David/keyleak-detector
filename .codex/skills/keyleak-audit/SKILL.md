# KeyLeak Audit Router

Use this skill when a prompt asks for a security audit, vulnerability detection,
pentest, bug bounty scan, checking an app/repo for security issues, deployment
ship readiness, or whether a finding is exploitable.

Prefer `keyleak audit <target>` as the single front door. A domain target is exact
host by default; require explicit `--include-subdomains` only for authorized
registrable-domain discovery and crawling. Require
both `--authorized-scope` and `--attest-network-scope` before active network
scans, exploit-validation, BaaS validation, or two-user access-control checks.
Treat the scope as an operator attestation, not technical proof of authorization.
Use `--plan` for a non-executing, redacted plan.
Under `--offline`, do not run a URL or domain audit; use a plan, local path, or
archive because Chromium is outside Python's socket-level offline guard.
Use `--assessment-mode blue-team`, `red-team`, or `balanced` to change only the
evidence framing; it never expands tool or network permissions.

Return `BLOCK SHIP`, `REVIEW`, or `SAFE TO SHIP` first, then artifact directory,
severity counts, validated or confirmed evidence, skipped phases, retest command,
and next probes. Do not report AI-inferred exploitability without deterministic
KeyLeak evidence.
