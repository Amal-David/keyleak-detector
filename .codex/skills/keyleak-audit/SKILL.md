# KeyLeak Audit Router

Use this skill when a prompt asks for a security audit, vulnerability detection,
pentest, bug bounty scan, checking an app/repo for security issues, deployment
ship readiness, or whether a finding is exploitable.

Prefer `keyleak audit <target>` as the single front door. Require
`--authorized-scope` before active network scans, exploit-validation, BaaS
validation, or two-user access-control checks. Ask only for missing scope or
throwaway user credentials when those are necessary.

Return `BLOCK SHIP`, `REVIEW`, or `SAFE TO SHIP` first, then artifact directory,
severity counts, validated or confirmed evidence, skipped phases, retest command,
and next probes. Do not report AI-inferred exploitability without deterministic
KeyLeak evidence.
