# October 2026 incident checks

Advisory snapshot: **22 October 2026**. These checks are read-only. They neither
execute exploit payloads nor rotate credentials or modify trust stores.

## PHP URL assessment

```bash
keyleak php-check https://your-owned-site.example/ --authorized --json
```

For a URL form, run the repository's Flask bridge locally:

```bash
python -m flask --app app run --host 127.0.0.1 --port 5002
```

Open `http://127.0.0.1:5002/php-check`, or follow the PHP link on the home page.
The form is loopback-only, including behind a proxy: it does not trust forwarded
client-address headers. It is not a public hosted scanner. Container ingress
that appears as a non-loopback peer is refused; use the CLI there.

The checker sends one ordinary streaming GET to the supplied URL and examines
only `Server` and `X-Powered-By`. It reads no response body, sends no ambient
cookies or netrc credentials, and follows no redirects. It accepts public
HTTP(S) targets on ports 80/443 without URL credentials, queries or fragments.
PHP checks refuse `--proxy` before network work because an independently
resolving proxy cannot preserve the validated numeric destination. Other scan
modes retain their existing proxy support. `--offline` refuses URL assessment.

Results:

| Result | Meaning |
| --- | --- |
| `potentially_affected` | Banner predates upstream fixes; vendor backports may apply. |
| `patched_version_reported` | Banner advertises a fixed version; origin/worker state remains unverified. |
| `unknown` | Missing, conflicting, vendor-suffixed, prerelease, unsupported-branch, redirect/error, or failed response. |

No result means “safe.” Unknown coverage exits 2; a potentially affected version
also exits 2 at the default high threshold. A patched banner exits 0 with a
REVIEW verdict. Exit 0 means the selected failure threshold was not met.

[PHP's advisory](https://www.php.net/archive/2026.php#2026-10-21-5) identifies
CVE-2026-109618 and CVE-2026-109619 and fixes in 8.2.35, 8.3.36, 8.4.27 and
8.5.12. Older branches may have vendor backports. Check the runtime actually
serving requests, deploy a supported fixed package, and restart every worker.
Hiding the PHP banner or updating application code does not patch the runtime.

Direct PHP checks now resolve and validate all returned addresses, then connect
to a validated numeric address with the original TLS hostname. They refuse
private/reserved targets, send no ambient credentials, follow no redirects and
close the socket after ten seconds. Only native global IPv6 destinations are
accepted; translation/transition addresses are refused. Neither the public PHP
service nor its CLI assessment accepts a proxy or exposes the legacy scanner.

## Local incident inputs

```bash
keyleak --offline incident-check . --json
keyleak --offline incident-check . --ca-bundle /path/to/roots.pem --railway --html > incident-report.html
```

The directory mode checks only root `requirements.txt`, `poetry.lock`, `uv.lock`,
`package.json` and `package-lock.json`. A supported manifest can also be supplied
directly. Inputs are bounded to 4 MiB each. Unsupported requirements directives,
malformed/oversized/unreadable inputs and symlinks produce incomplete coverage.
Nested projects, installed packages, yarn/pnpm lockfiles and container layers
are outside this check. An unresolved relevant Python dependency produces a
verification finding. The snapshot is bundled: this command does not download
or claim to refresh an advisory feed.

### LiteLLM and malicious AI setup packages

- Exact `litellm==1.107.0` references are flagged. A manifest reference does not
  prove execution. The [maintainer report](https://docs.litellm.ai/blog/security-incident-oct-21-2026)
  distinguishes compromised published artifacts from the clean source tag.
  If affected artifacts ran, rebuild from verified artifacts and rotate reachable
  credentials from a clean environment. Do not start Python in an affected
  environment merely to inspect it: startup hooks may execute again.
- npm `claude-desktop-setup` and `@decoopus/claude-setup` match their malware
  advisories, including nested npm lockfile entries. The latter also illustrates
  the risk of malicious configuration redirecting credentials to an attacker
  gateway. General gateway policy auditing is not implemented here.

Sources: [GitHub malware advisory](https://github.com/advisories/GHSA-f4mf-vhm8-xxqc),
[OpenSSF/OSV advisory](https://osv.dev/vulnerability/MAL-2026-18054).

### eMudhra / emSign

Eight intermediate CA keys were compromised. TLS clients can remain exposed
when independent trust stores retain affected chains and do not enforce the
relevant revocations. Browser protection does not establish protection for
Python, Node, containers, pip or other independent clients.

Checks flag pinned versions older than the [Python packaging guidance](https://discuss.python.org/t/information-for-python-users-regarding-emudhra-emsign-ca-certificate-security-incident/109576):
certifi 2026.10.19, pip 26.2.2, uv 0.13.4, sigstore 4.5.1, conda 26.9.4
and pixi 0.82.1.
This is version evidence, not a live TLS acceptance test; vendor backports need
separate confirmation.

An explicitly supplied PEM bundle is checked by DER SHA-256 fingerprint against
the four anchors in the incident's [root inventory](https://emudhra.we-have-a-problem.com/roots.json).
These anchors are not themselves described as compromised private keys. Their
presence is a lead for trust-policy review, not proof that the client accepts
a compromised chain. Their absence does not establish a safe trust store.
Intermediate-key/SPKI matching and active chain validation are outside this check.
The scanner does not remove roots or change system trust. Apply vendor updates,
rebuild environments/images, and verify rejection in each actual client.

Source: [Chrome/Android security response](https://blog.google/security/protecting-chrome-and-android-users-from-compromised-emudhra-intermediate-ca-certificates/).

### Railway

Railway's [21 October disclosure](https://blog.railway.com/p/security-disclosure-wednesday-october-21st)
reports possible access to encrypted environment variables and some decrypted
contents. The provider recommends rotating environment secrets and private
registry credentials and reviewing logs. The initial account scope remains
under investigation in that disclosure.

`--railway` is an operator assertion that includes this recovery guidance; it
does not query Railway, collect environment values, identify affected accounts,
or confirm theft. Rotate secrets at their issuers, update all consuming services,
revoke old credentials, verify service recovery, and review access logs.
Replacing a local `.env` file alone does not revoke an exposed credential.

## Verified coverage and implementation boundary

Baseline inspected: origin/main `d97d8c82f28fc924fafb63fb833d7ab5b3ec9025`.
The PR was rebased onto `ae62056`, preserving the subsequent mainline security updates.
The dirty primary checkout was also searched for the incident identifiers and
preserved. Existing mechanisms were reused rather than replaced:

| Existing mechanism | Verified scope | Remaining limit |
| --- | --- | --- |
| `detectors.py`, `local_scanner.py` | Secret/configuration patterns and redaction | Does not infer provider-side credential theft. |
| `lifecycle_audit.py` | Parses npm manifests for dangerous lifecycle commands | Does not establish the safety of published Python artifacts. |
| `feeds.py`, `detectors_dynamic.py` | IOC manifest generation/loading code exists | Not a general, verified resolved-dependency advisory matcher. |
| `js_library_cves.py` | Small browser-library version table | Does not establish origin PHP patch status. |
| `models.py`, `reporting.py` | Shared findings, evidence, coverage and output formats | Reused by both new CLI commands. |
| `net_guard.py`, `proxy.py` | Existing address guard and proxy mapping for other scan modes | PHP transport pins the validated address and refuses independently resolving proxies. |

No dedicated PHP, Railway, eMudhra or named new malware checks were found in
those baseline paths. This update adds bounded incident-specific checks, not
general SCA, EDR or certificate-chain validation.

The new check found KeyLeak's own Poetry lockfile still pinned certifi
2026.6.17. This update pins certifi 2026.10.19 across Poetry, PEP 621 and
requirements.txt, and regenerates the Poetry lockfile. Existing installations
and container images still require an update/rebuild; changing the source
manifest does not update a running installation or pip's vendored trust store.

Deferred work: maintained advisory/database integration, image digest inventory,
general AI endpoint policy, NGINX version/configuration checks, and automated
rotation. None is claimed as implemented by this update.

## Validation

- Focused incident, PHP, web-boundary, shared-reporting and dependency tests:
  **110 passed, 68 subtests passed** after final alert and Unicode-path repairs.
- Broad Python run: **476 passed, 27 failed, 1 skipped, 97 subtests passed**.
  All 27 failure identities reproduced against untouched baseline code: the
  GitHub Action tests encounter macOS Bash empty-array behavior and the browser
  egress test lacks its expected Playwright browser binary. This is not a green
  full-suite result. The reused environment has Playwright 1.55.0, while the
  project pins 1.63.0; dependencies were not installed into that shared environment.
- Desktop and 390px mobile Chrome form submission passed with an offline mocked
  assessment result; no third-party target was scanned. The browser check caught
  and corrected a referrer-policy interaction that rejected legitimate form POSTs.
- Local launch gate: exit 0, no findings. Self-audit: exit 0 at the high threshold,
  with the existing medium `CODEOWNERS` warning. Fingerprint generation was
  disabled because `KEYLEAK_FINDING_FINGERPRINT_KEY` was unset.
- The new incident check initially flagged certifi 2026.6.17 in this repository;
  after the lock update, only the assessment-scope notice remains.
- The locked certifi wheel's SHA-256 matched the lockfile. Its 120 public CA
  certificates contain none of the four incident anchors. No wheel was executed
  or installed for this inspection.
- Poetry lock consistency, Python compilation and diff whitespace checks passed.
  No standalone lint/type-check configuration was added. The four required code
  review perspectives were applied sequentially; duplicate lockfile findings and
  repeated SSL-context construction were removed. URL validation remains stricter
  than the existing loose JavaScript version parser by design.

These results do not establish live PHP exploitability, acceptance/rejection of
compromised TLS chains by every runtime, or account-specific Railway exposure.
No package publication, credential rotation, personal exposure audit or system
trust change is part of this work.

## Public launch architecture

The user's goal is a checker for other people's PHP projects, not an audit of
their own infrastructure. Keep the existing GitHub Pages domain,
`keyleakdetector.com`, and serve the frontend at `/php-check/`. GitHub Pages
cannot run Python or fetch arbitrary origin headers on behalf of browsers.
The frontend therefore calls a dedicated Render API; a version-only comparison
runs in the browser, with parity tests against the Python advisory policy.

`render.yaml` defines one `1c-2g` service (1 CPU / 2 GB RAM), currently listed
at **$25/month compute**. Workspace subscriptions and bandwidth usage are
separate charges: this is not a guaranteed $25 total bill. Autoscaling and
automatic deployments are disabled. No database, browser runtime or proxy
scanner is installed. Build dependencies are in `deploy/php-check/requirements.txt`.

The public application is `keyleak.php_service:app`, served by one Gunicorn
worker with eight threads. It exposes only the checker, JavaScript, `/healthz`
and `/api/check`. It caps request bodies at 4 KiB, concurrent assessments at
four, total admitted assessments at 120/minute, and repeated target hostnames
at one per 30 seconds. Target identifiers in the bounded in-memory limiter are
salted hashes. The endpoint takes a permission acknowledgement and does not
log submitted URLs, headers or bodies. Provider access metadata may still exist.
CORS permits the existing KeyLeak domain; it is not treated as authentication.

A URL result is banner evidence, never a remote proof of vulnerability or
safety. Redirects, hidden versions, vendor suffixes, conflicting banners and
request failures remain unknown. The tool does not bypass CDNs, probe phpinfo
paths or send malformed/OOM payloads. Rate limits favor bounded cost and target
load over throughput during a Hacker News spike.

Primary hosting references: [Render pricing](https://render.com/pricing),
[Blueprint specification](https://render.com/docs/blueprint-spec),
[GitHub Pages](https://docs.github.com/en/pages/getting-started-with-github-pages/what-is-github-pages).

### Delivery status

Ready-for-review PR: https://github.com/Amal-David/keyleak-detector/pull/32.
The user explicitly approved the paid Render service on 22 October 2026. The
checker is live at https://keyleakdetector.com/php-check/ with its backend at
https://keyleak-php-check.onrender.com. The domain remains on the existing
`gh-pages` publishing source with HTTPS enforced; no DNS migration was needed.

Deployment receipt:

- Render service: `srv-dbd42b7avr4c73ca78tg`; one `1c-2g` instance in Oregon,
  automatic deployments off, no autoscaling configured. Compute is USD 25/month;
  the approved applicable bandwidth/workspace fees remain separate.
- Verified backend code: `f3395dcc80d432002cd0ff05f8477bdbd90c0822`, deployment
  `dep-dbd44m3rjlhs73d341cg`, status `live`. The initial service deployment was
  replaced by this revision after the final review fixes.
- Published Pages commit: `cbfdc9fb7796e2d19fce67c886a8ee8082d7e31b`. It adds
  `/php-check/`, a homepage navigation link and a sitemap entry while preserving
  the existing `CNAME`. The build API reported `built` for that commit.
- Live HTML and JavaScript bytes exactly matched `site/php-check/` in the reviewed
  source. HTML SHA-256: `e2de9bf99a64ab92fa7e7498bc079a84f2f7297609482d5d0150f4d906864bbf`;
  JavaScript SHA-256: `1f59c5c9303022a4999725f97c758843d90cbbdacdc3823a7afb4123a8c52d08`.
- Live checks passed: health 200, no legacy `/scan` route (404), Pages CORS
  preflight 204, missing permission 400, invalid scheme 400 without consuming the
  target quota, private target 400, foreign origin 403, ordinary owned-target
  HTTPS assessment 200, and repeated-target limit 429 with Retry-After.
- Real Chrome passed the custom-domain URL flow with its live API, desktop and
  390px mobile layouts, and browser-side version comparisons for 8.3.35,
  8.4.27 and a vendor-suffixed version. No page JavaScript errors occurred.
  Only the user's own public site was used as a live scan target. It correctly
  returned unknown; no vulnerable third-party site or exploit was tested.

Final review repairs also cover HTTPS Host authority formatting, URL validation
before target-quota reservation, peer dependencies, unsupported npm lockfile
structures, missing root manifests when a CA bundle is supplied, and offline
CLI rejection before process-wide socket changes. All have regression coverage.

Rollback: suspend this new service in its Render dashboard and revert Pages
commit `cbfdc9f` with a normal revert. Do not change unrelated services or force
push the publishing branch. The source PR remains unmerged; the backend is
deliberately pinned to the tested PR revision with automatic deploys disabled.

Automated CodeQL review flagged the intentional user-URL fetch sinks and the
synthetic credential fixture. The former use validated numeric-address pinning
and the test fixture contains no real secret. The independently resolving CLI
proxy path has since been removed rather than exempted from the IP-pinning rule.
These alerts were not dismissed. An explicit TLS 1.2 minimum was added and tested
alongside certificate verification and original-hostname SNI preservation.
Further GitHub checks/reviews may remain queued; local proof is not a CI pass.

## Controlled QA and remaining-alert review — 23 October 2026

The purpose of this round was to verify detection, rather than to find or probe
unconsenting vulnerable websites. No exploit payload was used, and no claim of
personal-system compromise was made.

### Research boundaries

- [PHP's advisory](https://www.php.net/archive/2026.php#2026-10-21-5) covers web-serving
  PHP runtimes and defines the upstream fixed versions. A domain alone does not
  reveal whether its serving runtime has the fixes.
- [AWS's bulletin](https://aws.amazon.com/security/security-bulletins/2026-143-aws/)
  documents affected PHP workloads and update actions for Elastic Beanstalk,
  Amazon Linux and Lightsail. It is not permission to test customer domains.
- [Six Apart](https://www.sixapart.jp/movabletype/news/amp/2026/10/22-0020.html)
  reports upgrading Movable Type Cloud to PHP 8.3.36 on 22 October. Its managed
  environments were reported patched; they were not treated as vulnerable test sites.
- [Ubuntu's notice](https://ubuntu.com/security/notices/USN-8948-1) lists the fixed
  backport `8.3.6-0ubuntu0.24.04.13`. This is why vendor-suffixed or hidden versions
  remain unknown rather than being labelled definitely vulnerable or safe.

### Reproducible actual-runtime QA

Run `python -m scripts.qa_php_runtime_banners` from an installed checkout with
Docker available. It builds only a tiny version-response page on official PHP
images, executes ordinary loopback HTTP requests, classifies their real headers,
and removes its containers and temporary image tags. It does not expose a port,
mount host directories, forward credentials or give the runtimes network access.
Each container is non-root, read-only, capability-free, and resource-limited.

The official base image digests tested were:

- PHP 8.3.35: `sha256:b62d1f1ff98037e7ec8ee5e5ed382bfe2d88d054b05e0d09bcc851e3342072c2`.
- PHP 8.3.36: `sha256:74caa458ad8d6c5e401eb9f8841a62faeab9b7be42b54cd37986d7685f857618`.

| Controlled response | Expected and observed result |
| --- | --- |
| Actual PHP 8.3.35, version exposed | `potentially_affected` |
| Actual PHP 8.3.36, version exposed | `patched_version_reported` |
| Actual PHP 8.3.35, version hidden | `unknown` |

### Deployed browser/backend QA

A temporary owned Python server replayed frozen response headers from the above
runtimes. Only that header-only server was exposed through a temporary tunnel;
the old PHP runtime was never public. Real Chrome submitted these owned URLs
through `keyleakdetector.com/php-check/` and its production Render API, respecting
the target rate limit. All six cases passed:

| Header-only fixture | Observed result |
| --- | --- |
| Old upstream version | `potentially_affected` |
| Patched upstream version | `patched_version_reported` |
| Hidden version | `unknown` |
| Vendor backport suffix | `unknown` |
| Redirect response | `unknown` |
| HTTP error response | `unknown` |

The mobile layout also passed without overflow or page JavaScript errors.
Redirect/error results now explain the cause; redirect users are asked for the
final canonical URL. Temporary fixtures are shut down after final verification.

### Security review disposition

- The insecure-TLS alert's instance was already marked fixed; TLS 1.2 remains
  the explicit minimum and original-hostname certificate verification is retained.
- The independently resolving CLI proxy path was a real pinning gap. It was
  removed; PHP proxy requests fail before preflight, and the dedicated service
  no longer depends on Requests. Other scanner modes retain their proxy policy.
- Native public IPv6 is required, additionally rejecting NAT64 and transition
  forms that could otherwise translate an apparently global address to a private
  destination. Mixed public/private DNS replies remain refused.
- The direct HTTP-sink alert is reviewed against validated numeric socket
  connections, no second hostname resolution, no redirects and no proxy path.
  Controlled HTTPS QA and private/translated-address regressions verify that
  policy. The tainted hostname is used for Host/SNI, not a second connection.
- The clear-text-storage alert refers to a literal fake credential in a temporary
  unit-test input whose purpose is to verify report redaction. It is not a stored
  production credential; the test is retained.
- The canonical Pages-path comment is satisfied by the published `gh-pages/php-check/`
  route and its live browser tests. Previously repaired comment cases remain covered.

False-positive dispositions require the above evidence; no CodeQL rule or check
is disabled and no branch-protection bypass is used for merge.

Fresh analysis then identified a real polynomial-time regex in the shared URL
redactor (alert 12). It was replaced with a forward-only parser preserving raw
URL spelling and existing redaction semantics. The replacement matched the
previous behavior on 22,000 bounded differential cases; formatting and long-input
regressions cover the change. This alert was repaired rather than dismissed.
The subsequent Unicode-path review comment was also valid: paths are now
percent-encoded while preserving existing escapes and URI delimiters, with an
exact outgoing-request regression test.

Final alert dispositions: 12 (URL-redaction work), 19 (old fetch fingerprint),
20 (proxy fetch), and 21 (TLS minimum) were fixed through code/analysis. Alerts
22 (literal synthetic test credential) and 23/24 (the same IP-pinned fetch sink
before/after URI encoding) were individually marked false positive with the
specific QA evidence. The test credential and all CodeQL rules remain in place.
GitHub default-setup analysis does not permit an explicit workflow retry here;
the normal analysis of this evidence commit refreshes its alert-summary check.
