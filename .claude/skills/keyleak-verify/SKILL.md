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

Choose target from the prompt:

- local path or repo: pass the path directly.
- archive: pass the zip/tar path directly.
- one preview/live URL: pass the full URL.
- whole site/domain: pass the domain.

## Authorization Gate

Never run active network scans, exploit-validation, BaaS probes, or two-user
access-control checks without explicit authorized scope. If scope is missing,
ask only for the missing scope statement and stop.

Good scope examples:

- `owned repo`
- `owned preview deployment`
- `owned domain + staging accounts`
- `authorized bug bounty scope: app.example.com`

For exploit-validation access-control checks, ask for throwaway user credentials
only when needed:

- user A: `--bearer` or `--cookie`
- user B: `--bearer-b` or `--cookie-b`

Do not request admin credentials. Prefer short-lived staging credentials.

## Commands

Local repo audit:

```bash
keyleak audit . --intent security-audit --depth exploit-validation --authorized-scope "owned repo"
```

Preview ship audit:

```bash
keyleak audit https://preview.example.com --intent ship --depth active --authorized-scope "owned preview deployment" --json
```

Bug bounty/domain audit:

```bash
keyleak audit example.com --intent bug-bounty --depth exploit-validation --authorized-scope "owned domain + staging accounts" --json
```

Two-user validation:

```bash
keyleak audit https://app.example.com --intent bug-bounty --depth exploit-validation \
  --authorized-scope "owned staging app" \
  --bearer "<user-a-token>" --bearer-b "<user-b-token>" --json
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
