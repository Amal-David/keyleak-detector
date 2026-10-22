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
The CLI respects an explicit `--proxy`; `--offline` refuses URL assessment.

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
close the socket after ten seconds. An explicitly requested CLI proxy delegates
connection/DNS handling to that trusted proxy and retains the hostname guard.
The public service does not accept a proxy setting or expose the legacy scanner.

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
certifi 2026.10.19, pip 26.2.2, uv 0.13.4, sigstore 4.5.1 and pixi 0.82.1.
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
| `net_guard.py`, `proxy.py` | Address guard and explicit proxy mapping | Direct PHP transport now pins the validated address; explicit proxies are trusted operator inputs. |

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
  **105 passed, 53 subtests passed** after the public API and transport review.
- Broad Python run: **471 passed, 27 failed, 1 skipped, 82 subtests passed**.
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
The Pages configuration was verified through GitHub: the custom domain is
`keyleakdetector.com`, HTTPS is enforced, and the publishing source is the
`gh-pages` branch. Frontend files are prepared in `site/php-check/`; the separate
Pages checkout has not been changed or published.

Render CLI authentication and blueprint validation succeeded. Automatic approval
review rejected paid service creation because the architecture discussion was
not explicit authorization to provision an ongoing paid resource. No Render
checker service was created. Provisioning and publication await explicit approval
of one $25/month compute instance plus applicable bandwidth/workspace charges.
After approval: create the service from the reviewed branch with auto-deploy off,
verify its `/healthz` and public-IP refusal behavior, confirm its actual Render
URL, then copy the reviewed frontend to `gh-pages/php-check/` and verify the
custom-domain form against the live API. Do not publish an unconnected URL form.

Automated CodeQL review flagged the intentional user-URL fetch sinks and the
synthetic credential fixture. The former use validated numeric-address pinning
(or an explicitly requested CLI proxy), and the fixture contains no real secret.
These alerts were not dismissed. An explicit TLS 1.2 minimum was added and tested
alongside certificate verification and original-hostname SNI preservation.
Further GitHub checks/reviews may remain queued; local proof is not a CI pass.
