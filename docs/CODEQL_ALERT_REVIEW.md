# Remaining CodeQL alerts: 23 October 2026

Reviewed the seven open alerts on main revision `38a4d6dbb01116f42a087bc4eb4f0c6381daee68`, including the Python analysis's source-to-sink traces.

| Alert | Assessment | Disposition |
| --- | --- | --- |
| [#1](https://github.com/Amal-David/keyleak-detector/security/code-scanning/1) | Certificate inspection relied on runtime TLS defaults. Modern Python already defaults to TLS 1.2; the application did not state its own floor. | Require at least TLS 1.2 before the handshake, preserving a stricter default, hostname verification and certificate verification. |
| [#5](https://github.com/Amal-David/keyleak-detector/security/code-scanning/5) | An attack-scan exception reached JSON, nested reports and SSE. Credential scrubbing did not remove internal details. | Keep the scrubbed diagnostic in server logs and return a fixed public error with `status: error`. |
| [#8](https://github.com/Amal-David/keyleak-detector/security/code-scanning/8) | `/stop-proxy` returned `str(exception)` directly. | Return a fixed error; log only the exception type. |
| [#11](https://github.com/Amal-David/keyleak-detector/security/code-scanning/11) | False positive: the trace labels a BaaS API key as a password and treats redaction as password storage. | Retain the redaction contract and document a false-positive dismissal. |
| [#15](https://github.com/Amal-David/keyleak-detector/security/code-scanning/15) | False positive: the trace labels `CUSTOM_SECRET_PATTERNS` and imported detector metadata as secret values. | Retain the pattern-compilation diagnostic and document a false-positive dismissal. |
| [#17](https://github.com/Amal-David/keyleak-detector/security/code-scanning/17) | The generic scan-error fallback included the scrubbed exception text in its response. | Return fixed actionable messages. |
| [#18](https://github.com/Amal-David/keyleak-detector/security/code-scanning/18) | A page-interaction exception was interpolated into a public response. | Return a fixed page-load error and keep the scrubbed diagnostic in logs. |

For #11, `keyleak.baas_validator._finding` calls `redact_value(config.api_key)` without `run_salt`, so that specific call cannot reach the flagged HMAC branch. Other callers use HMAC-SHA256 with a random per-scan key to redact and correlate findings within a scan. The result is not a password verifier or login credential. Existing reporting tests verify that different scan keys change the redacted value. Replacing it with a password KDF would change the report contract without fixing an authentication defect.

For #15, the trace starts at the static detector dictionary or `get_enhanced_patterns`, then follows the detector name to a regex-compilation warning. The importer loads regex definitions from GitLeaks or its local pattern cache; no captured finding or supplied authentication value reaches this log through that trace. The alert confuses detection rules with detected credentials.

No CodeQL rule, workflow, security check or branch protection is disabled. False-positive dismissals apply to those individual alerts.

## Verification

- New regression checks failed before the repairs, then passed: four exception paths and the explicit TLS floor. The TLS check also proves a TLS 1.3 policy is preserved.
- Related web, TLS, reporting, BaaS and PHP suites: 135 tests and 51 subtests passed.
- Full local suite: 480 passed, 27 failed, 1 skipped, 99 subtests passed. The 27 failure identities exactly match the previously reproduced baseline: macOS Bash action tests and an unavailable Playwright browser binary. No new failure identity appeared; the local full suite is not green.
- Local launch gate: no findings. Self-audit passed the high-severity threshold with the existing medium missing-CODEOWNERS warning.
- Reuse, quality, efficiency and maintainability reviews ran sequentially. Existing `_safe_scan_error`, browser mocks, report and SSE paths were reused; no new error abstraction was added. There is no configured project-wide lint or typecheck command.
- Hosted CI, CodeQL and review outcomes must be checked on the final PR head before merging.

References: [Python TLS context policy](https://docs.python.org/3/library/ssl.html#ssl.create_default_context), [CodeQL password-hashing query](https://codeql.github.com/codeql-query-help/python/py-weak-sensitive-data-hashing/).
