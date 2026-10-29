# Agent integration and detection-flow audit

Reviewed 2026-10-29 against the secret-serialization branch, starting at 9d6daa1.

## Outcome and scope

Position KeyLeak as a local evidence tool that security agents can discover and call
for credential exposure, artifact inspection, supply-chain hygiene and remediation
verification. The implementation adds capability discovery, installable skills and
agent-asset secret coverage. It does not add autonomous exploitation.

This is a source-contract and regression-test audit of the end-to-end flow, plus a
representative GitHub ecosystem survey. It is not an exhaustive inventory of GitHub,
a line-by-line audit of every detector, a precision/recall benchmark, a certification
of isolation, or a live assessment of external systems. External skills were read as
reference material; their code and offensive procedures were not executed or imported.

## Findings and actions

Frequency and impact are engineering estimates on 1–10 scales, not measured rates.

| Finding | Frequency evidence and score | Impact evidence and score | Action |
|---|---|---|---|
| Parent audit loses local/archive coverage gaps | 6: every local/archive phase used unconditional completion except local symlinks; size/read/parse limits are routine | 7: a phase could look complete despite skipped input; regression verifies partial phase and review verdict | Fixed using existing child coverage helper; retained findings |
| Audit skill lacks discovery metadata | 9: the checked-in router had no YAML frontmatter | 4: compatible skill loaders cannot reliably select it by name/description | Added metadata and specific task triggers |
| Capability discovery requires source inspection | 8: only a human-readable bundles command existed | 5: registered rules and declared phases can be mistaken for executed coverage | Added versioned JSON catalog derived from registries, with execution caveats |
| Skill/rule documents are missed by ordinary secret file selection | 7: SKILL.md, AGENTS.md and shell scripts under skill packages were not ordinarily selected | 7: credentials shared with agents can be copied into prompts or published | Added opt-in agent-assets category; positive/negative selection and redaction tests |

Cursor rule files already had MCP-category coverage; the new category preserves it.
Rule counts count registered patterns, not independently validated vulnerability classes.
No new precision or recall claim is made.

## Flow coverage matrix

| Stage | Evidence inspected | Assessment / limits |
|---|---|---|
| Discovery and selection | CLI parser, bundles.py, detectors.py, existing audit skill | Catalog exposes registered vs unpopulated packs and actual workflow entry points; bundle phases remain declarations |
| Planning and authority | audit.py target classification, normalization, authorization guards and plan output; test_audit.py | Planning is non-executing. Text attestation is not proof of authority. Default security-audit depth is broader than passive; skills explicitly select planning/local paths |
| Local collection | local_scanner.py selection, symlink handling, byte limits; serialization_audit.py; local/binary/serialization tests | New agent assets reuse existing detectors, limits and redaction. Python serialization is bounded and opt-in; no cross-file/JS claim |
| Archives and binaries | archive_scanner.py extraction paths, budgets and report envelope; binary/archive contract tests | Preserve provenance and incomplete coverage. Parent audit now propagates child gaps |
| Browser and site | browser_scanner.py request guards; site_scanner.py reporting; browser egress/redaction and site SSRF tests | Chromium is a separate process; Python socket blocking is not browser isolation. Live browser proof remains limited by the missing installed executable |
| Network and optional validation | net_guard.py, offline_guard.py, proxy.py, BaaS validation policy | Default write probe is off. net_guard.py itself documents residual DNS resolution/connect timing risk. No external probes performed; runtime guard completeness is not certified |
| Access-control evidence | audit authorization phase and two-user handoff contract; access-control/reporting tests | Audit command does not provide a safe two-user credential handoff; do not advertise it as an implemented end-to-end agent workflow |
| Evidence and triage | models.py, reporting.py, suppressions.py, audit artifact writer and scrubber | Preserve validation status, coverage, suppression decisions and redaction. Correlation and patterns are not proof of exploitability |
| Extension and web bridge | extension manifest, worker/reporting boundaries, Flask/extension security tests | Separate execution and serialization paths; extension requests broad host access. No installed-browser consent or live bridge deployment certification performed |
| Packaging and CI | CLI entry point, dependency metadata, distribution tests, Action tests | Source checks verified locally; installed skill-host discovery and publication are separate release checks. Existing Action failures reproduce on base |

The four simplification reviews run inline under repository instructions: reuse,
quality, efficiency and maintainability. The catalog reuses DETECTORS, PROFILE_PACKS,
BUNDLES, runnable_packs and unpopulated_packs. Agent asset selection reuses the MCP
pattern category; coverage propagation reuses _child_coverage_reason. No new scan
executor, package installer, model provider, or RPC transport is introduced.

## Representative GitHub survey

These are repository-advertised capabilities, not independently measured effectiveness.
The useful comparison is the interface and evidence contract, not skill counts.

| Primary source | Advertised emphasis | Implication for KeyLeak |
|---|---|---|
| [Trail of Bits skills](https://github.com/trailofbits/skills) | Code auditing, static analysis, false-positive checking, variant analysis and testing skills | Supply redacted machine-readable evidence that reviewers can challenge; complement existing analysis tools |
| [Sentry skills](https://github.com/getsentry/skills) | Development and security review guidance, including secret serialization | Turn bounded, testable source patterns into explicit scanner checks; retain manual-review limits |
| [0x0pointer skills](https://github.com/0x0pointer/skills) | Offensive-security methodology organized around vulnerability classes | Offer precise finding IDs, evidence and coverage rather than another broad methodology prompt |
| [timsonner agent-skills](https://github.com/timsonner/agent-skills) | Skill catalog including a penetration-testing suite | Keep task-specific skill names and descriptions easy for a host to discover |
| [deep-pentest-skill](https://github.com/like041123/deep-pentest-skill) | Reconnaissance, discovery, chaining and reporting orchestration | Provide local evidence/report handoffs; do not treat orchestration breadth as verified coverage |
| [Claude-Red](https://github.com/SnailSploit/claude-red) | Offensive methodology across multiple attack domains | Keep KeyLeak's scope explicit; no payload, evasion or attack-chain automation imported |
| [Claude-BugHunter](https://github.com/elementalsouls/Claude-BugHunter) | Bug-hunting and external red-team skill workflows | Support repeatable local collection and remediation review without promising autonomous exploitability decisions |

The user's reference was to the broad offensive/red-team skill ecosystem, not one
specific DeepSeek project. [DeepSeek Harness safety guidance](https://github.com/deepseek-ai/deepseek-harness/blob/master/SAFETY.md)
separately highlights that agent access to files, credentials, plugins and processes
requires trust boundaries. That is relevant context for agent-asset scanning, not
evidence that static secret scanning establishes sandbox security.

## Discovery and adoption

`keyleak capabilities --json` reports schema version, scanner version, workflows,
network requirements, skill names, registered rules, profiles, bundle declarations
and report semantics. It returns before proxy setup or scanning. It does not expose
regex payloads or execute tools. Treat discovery as descriptive data.

Four [Agent Skills-format](https://agentskills.io/specification) entry points are in
`.codex/skills/`: keyleak-audit, keyleak-local-review, keyleak-agent-assets, and
keyleak-report-triage. Each contains required name/description frontmatter and a
bounded workflow. To use them in another project, review and copy the selected skill
directory into that host's supported skill directory (for example `.agents/skills/`
or `.claude/skills/`). Skills require an approved KeyLeak installation on PATH.
They are repository-distributed; pip installation alone does not install these skills.
No automatic host configuration or unreviewed third-party skill installation is performed.

## Next work, not claimed as shipped

1. Publish the skills/index after review; verify actual discovery in each supported host.
2. Build a held-out labeled corpus and report false positives and missed classes per check.
3. Close the documented network isolation gaps before expanding live-agent integrations.
4. Add bounded language-specific serialization coverage only with parser-backed evidence and fixtures.
5. Consider an MCP wrapper only when real consumers need it; the CLI JSON contract already serves local agents.

Do not label these items as implemented coverage or inflate the detector list with
unimplemented vulnerability names. Local evidence quality and honest failure reporting
are the differentiators to measure.

## Verification receipt

- Focused discovery/audit/reporting/serialization: 129 passed, 35 subtests passed.
- Full Python suite: 577 passed, 27 failed, 1 skipped, 222 subtests passed. Failures
  match the unchanged-base browser executable and GitHub Action shell-array issues
  reproduced during serialization work. This is not a green local full-suite result.
- Extension: 49 passed, zero failures or skips.
- Four skill files passed the skill-creator validator.
- Launch gate: exit 0, 198/198 attempted files completed, one medium finding,
  zero high/critical findings. Self-audit: exit 0, one low finding.
- Compilation and whitespace checks passed. No project lint/typecheck is configured.
- No live external validation, offensive skill execution, installed-host skill
  discovery, hosted publication, or held-out detector benchmark was performed.

## PR 39 review follow-up

Frequency/impact estimates below use 1–10 scales; examples are covered by regression
checks. All products exceed the implementation threshold of 5.

| Finding | Frequency and evidence | Impact and evidence | Resolution |
|---|---|---|---|
| Attribute writes erase holder bindings | 7: assigning config fields before logging is ordinary application code | 7: hides an exposing serializer use | Invalidate only names in Store context |
| Explicit repr formatting suppressed by string overrides | 5: diagnostic f-strings use repr conversions | 7: a custom safe str does not protect repr | Preserve !r/!a semantics |
| Absolute ancestor exclusion | 5: checkouts commonly sit beneath build/examples directories | 8: excludes the entire requested Python scope | Classify exclusions relative to the scan root |
| attr namespace aliases missing | 5: supported attrs API spellings | 6: missed holders or wrong protection state | Add modern attr decorators and field alias |
| Optional secret annotations misclassified | 7: optional configuration credentials are common | 4: false generated-output leads | Unwrap optional forms while retaining mixed plain-string unions |
| Numeric metadata treated as credentials | 6: TTL/length/security flags are ordinary config fields | 3: noisy findings | Exclude three exact typed metadata names; retain numeric tokens/passwords |
| Ordinary class methods skipped | 8: service methods routinely receive typed config | 7: missed serializer use | Traverse non-holder classes with isolated bindings |
| Missing structural fingerprints | 6: baselines and allowlists are supported workflows | 5: findings cannot be suppressed by fingerprint | Reuse keyed fingerprint helper; verify suppression across line shifts |
| Empty optional arrays under Bash 3 nounset | 9: default Action settings leave both arrays empty on macOS | 6: scan step fails before output | Preserve optional argument quoting with conditional expansion |

The CodeQL clear-text-storage alert references a deliberately synthetic detector test
value, not a credential. The fixture variable is now explicitly named synthetic_value;
the plaintext fixture and redaction assertion remain, so the test still checks the
required behavior. The docstring-coverage suggestion is stylistic; blanket narration
was not added to satisfy a percentage. Existing scope/constraint documentation remains.
