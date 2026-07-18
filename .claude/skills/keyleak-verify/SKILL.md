# KeyLeak Audit Router

Use this skill when a prompt asks for a security audit, vulnerability detection,
pentest, bug bounty scan, checking an app/repo for security issues, deployment
ship readiness, or whether a finding is exploitable.

## Route

Prefer the single front door:

```bash
keyleak audit <target> --intent security-audit
```

Choose intent from the user wording:

- `ship`: release, deploy, launch gate, preview readiness.
- `security-audit`: security audit, vulnerability detection, check this repo/app.
- `bug-bounty`: bug bounty, pentest, is this exploitable, authorized target testing.

Choose `--assessment-mode blue-team` for defensive remediation, `red-team` for
bounded attacker-perspective questions, or leave the default `balanced`. The mode
changes reporting focus only; it never expands tool or network permissions.

Choose target from the prompt:

- local path or repo: pass the path directly.
- archive: pass the zip/tar path directly.
- one preview/live URL: pass the full URL.
- whole site/domain: pass the domain.

## Authorization Gate

Never run active network scans, exploit-validation, BaaS probes, or two-user
access-control checks without explicit authorized scope. If scope is missing,
ask only for the missing scope statement and stop.
If the operator requested `--offline`, do not run URL or domain audits: use
`--plan`, a local path, or an archive instead because Chromium is a separate
process outside Python's socket-level offline guard.

Good scope examples:

- `owned repo`
- `owned preview deployment`
- `owned domain + staging accounts`
- `authorized bug bounty scope: app.example.com`

For an authenticated single-user browser scan, accept only a short-lived,
operator-managed Playwright storage-state file with restrictive permissions.
The audit command intentionally does not accept bearer tokens or cookies on the
command line, and its two-user comparison remains unavailable until a
non-argv credential handoff is implemented. Do not request admin credentials.

## Commands

Local repo audit:

```bash
keyleak audit . --intent security-audit --depth exploit-validation --authorized-scope "owned repo"
```

Preview ship audit:

```bash
keyleak audit https://preview.example.com --intent ship --depth active --authorized-scope "owned preview deployment" --attest-network-scope --json
```

Bug bounty/domain audit (exact host by default; add `--include-subdomains` only for
an authorized registrable-domain assessment):

```bash
keyleak audit example.com --intent bug-bounty --depth exploit-validation --authorized-scope "owned domain + staging accounts" --attest-network-scope --include-subdomains --json
```

Authenticated single-user validation:

```bash
keyleak audit https://app.example.com --intent bug-bounty --depth active \
  --authorized-scope "owned staging app" \
  --attest-network-scope \
  --auth-state /secure/path/storage-state.json --json
```

## Report Back

Report the verdict first, using exactly one of:

- `BLOCK SHIP`
- `REVIEW`
- `SAFE TO SHIP`

Then include:

- artifact directory
- findings count by severity
- confirmed or validated exploit evidence, if any
- skipped phases and why
- retest command
- next probes to run

Do not claim exploitability from an AI guess. Use this vocabulary:

- `lead`: plausible static/passive signal.
- `validated`: deterministic evidence supports the finding.
- `confirmed`: active probe or exploit-validation evidence confirmed impact.

All artifacts must stay redacted. Never paste raw auth headers, cookies, bearer
tokens, browser payloads, or raw secrets into the final answer.
