# Running a KeyLeak Scan — Agent How-To

A self-contained runbook for an AI agent (or a human) dropped into this repo with the
task "scan something for leaked secrets." It covers environment setup, choosing the
right command, running it, and interpreting the result — including the false-positive
patterns that trip up a naive read of the output.

> **Authorization first.** Only scan assets you own or are explicitly authorized to
> test. `site-scan` enumerates subdomains and crawls live pages; `--baas-validate`
> sends *active* probes to detected Supabase/Firebase endpoints. Treat it like any
> other active security tool.

---

## TL;DR — the comprehensive live scan

```bash
# From the repo root, after setup (see Step 1):
poetry run keyleak site-scan example.com \
  --launch-profile full \
  --depth 3 --max-pages 100 --max-subdomains 25 \
  --baas-validate \
  --fail-on low \
  --json > report.json
```

This enumerates subdomains (crt.sh + DNS), crawls every reachable page per host, runs
**all** detector packs, and actively validates any BaaS config it finds. `--json`
writes the full structured report; render other formats from it (Step 6) instead of
re-crawling.

---

## Step 1 — Set up the environment (pick ONE)

The CLI entry point is `keyleak` (defined in `pyproject.toml` → `keyleak.cli:main`).
You get that command after any install path below. All scanning modes that touch a
live site need a Playwright browser binary, so install Chromium too.

```bash
# Poetry (canonical)
poetry install
poetry run playwright install chromium

# uv
uv sync
uv run playwright install chromium

# pip + venv
python -m venv venv && source venv/bin/activate
pip install -e .
python -m playwright install chromium
```

### No-install fallback (run straight from a checkout)

If you can't or don't want to install the package but the dependencies are importable
(e.g. an existing `venv/` is present), invoke the CLI module directly from the repo
root — there is no `python -m keyleak` entry, so call `main()`:

```bash
./venv/bin/python -c "import sys; from keyleak.cli import main; sys.exit(main())" \
  site-scan example.com --launch-profile full --json > report.json
```

Everywhere below, `keyleak <args>` is shorthand for `poetry run keyleak <args>` or the
fallback launcher above.

---

## Step 2 — Preflight with `doctor`

```bash
keyleak doctor
```

`doctor` checks Python, Playwright, mitmproxy, Node, loopback network, and the
allowlist file, and prints a `fix:` line for each failure. A common one on a partial
checkout:

```text
[✗] keyleak-imports: Missing modules: yaml
    fix: Run `pip install -e .` (or `poetry install`) from the repo root.
```

That means dependencies aren't fully installed. A scan mode may still run if its code
path doesn't import the missing module — but don't trust a green result from a red
`doctor`. Fix the environment first.

---

## Step 3 — Pick the right command

| Goal | Command | Notes |
|---|---|---|
| Scan a **local repo / build artifacts** for secrets, MCP/CI configs, source maps | `keyleak local <path>` | No network. Fastest. Good for CI / pre-merge gates. |
| Scan **one live page or SPA** | `keyleak browser-scan <url>` | Headless Playwright injects the analyzer into a single URL. |
| Scan a **whole domain** (subdomains + crawl) | `keyleak site-scan <domain>` | The comprehensive live option. Bounded by `--depth` / `--max-pages` / `--max-subdomains`. |
| Scan a deployment **archive** (tar/zip/dir) | `keyleak archive <path>` | Emits a chain-of-custody envelope. |
| Scan via the **Flask web bridge** (mitmproxy capture) | `keyleak scan <url> --server http://127.0.0.1:5002` | Start `python app.py` first. |
| Audit **this repo's own** supply-chain hygiene | `keyleak self-audit .` | Tag pins, dangerous workflow triggers, lockfile, CODEOWNERS. |

For "run a full comprehensive scan of a website," the answer is **`site-scan`**.

---

## Step 4 — Run the comprehensive scan

```bash
keyleak site-scan example.com \
  --launch-profile full \
  --depth 3 --max-pages 100 --max-subdomains 25 \
  --baas-validate \
  --scan-budget 30 \
  --fail-on low \
  --json > report.json
```

- It can take several minutes (per-page budget × pages × hosts). Run it in the
  background / with a generous timeout and watch the `[keyleak] Scanning [n/N] ...`
  progress on stderr.
- `--json` is written to **stdout**; progress goes to **stderr**. Redirect stdout to a
  file (`> report.json`) and let progress print, or capture both separately.
- `--baas-validate` sends active probes. Drop it if you only want passive detection.

---

## Step 5 — Launch profiles & detector packs

`--launch-profile` selects which packs run (source of truth: `keyleak/detectors.py`).

| Profile | Packs enabled |
|---|---|
| `launch-gate` (default) | `leak` |
| `local-dev` | `leak` |
| `bug-bounty` | `leak`, `appsec`, `access-control`, `baas` |
| `ci` | `leak`, `appsec`, `access-control`, `baas` |
| `full` | **all**: `leak`, `appsec`, `access-control`, `correctness`, `housekeeping`, `baas` |

| Pack | Finds |
|---|---|
| `leak` | Secrets, exposed config, source maps, browser-visible leak signals |
| `appsec` | SQL injection, XSS, auth-bypass leads |
| `access-control` | IDOR, missing tenant checks, ownership-check leads |
| `correctness` | N+1, regressions, off-by-one, timezone/date, semantic config leads |
| `housekeeping` | Missing tests, dead code, stale comments/docs |
| `baas` | BaaS misconfig: open tables, exposed admin logic, storage, RPC abuse |

Use `--launch-profile full` for "comprehensive." Override precisely with
`--packs leak,baas` if you only want specific packs.

---

## Step 6 — Output formats (and how to get several from one crawl)

`--json`, `--sarif`, `--markdown`, and `--html` are **mutually exclusive** and each
prints to stdout. Don't re-crawl a live site just to change format — emit `--json`
once, then render the rest from the saved report:

```python
import json
from keyleak.models import ScanReport
from keyleak.reporting import format_html, format_markdown, report_to_text

report = ScanReport.from_dict(json.load(open("report.json")))
open("report.html", "w").write(format_html(report))
open("report.md", "w").write(format_markdown(report))
print(report_to_text(report))   # terminal summary
```

---

## Step 7 — Interpret the result

The report carries a top-level `verdict` (`SAFE_TO_SHIP`, `REVIEW`, or `BLOCK_SHIP`), a `summary` with
per-severity counts, a `pack_summary`, the `subdomains` and `scanned_urls` covered, and
`provenance` (which URLs each finding appeared on).

**Exit codes** are driven by `--fail-on` (`low`/`medium`/`high`/`critical`):

| Exit | Meaning |
|---|---|
| `0` | No finding at or above the `--fail-on` threshold |
| `2` | At least one finding met the threshold (gate should fail) |
| `1` | The scan itself errored (bad target, Playwright missing, etc.) |

For a CI gate use `--fail-on high`; to *see everything* during analysis use
`--fail-on low` (so the exit code reflects "found something") and read the report.

> If you append another shell command after the scan (e.g. `; echo done`), that
> command's exit code — not the scanner's — is what the shell reports. Check
> `report.json`'s `summary`/`verdict`, not just `$?`, when chaining.

---

## Step 8 — Triage: known false-positive / over-escalation patterns

A `BLOCK_SHIP` verdict is a prompt to investigate, not a confirmed breach. Always read
the **evidence snippet and the live context** before reporting a finding as real.

- **Google `AIza…` keys in a `firebaseConfig`.** The `AIza…` prefix is shared by
  Firebase **Web** API keys and Gemini/Google API keys, so the same token can fire as
  both `baas.firebase_client_config` (medium, accurate) *and* `leak.gemini_api_key`
  (critical). A key sitting inside a `firebaseConfig` (`apiKey`, `authDomain`,
  `projectId`, `appId`) is a Firebase **Web** key, which Google designs to ship
  publicly in every client — it identifies the project, it is not a credential. The
  "critical Gemini leak" is usually an over-escalation of that same key. The *real*
  hardening action is to confirm the key has **API key restrictions** (HTTP-referrer
  allowlist + restrict to the APIs you actually use) and that **Firestore/Storage
  Security Rules** are locked down — the public key is only dangerous if it's
  unrestricted or the rules are open.
- **Fixture / example / test paths.** `.env.example`, `/fixtures/`, `/tests/`,
  `docker-compose.yml` and similar are suppressed by default. Use
  `--no-default-suppressions` to see them; don't report them as live leaks.
- **Same secret on many pages.** Check `provenance` — one bundled key reused across N
  routes is one finding, not N.

When in doubt, fetch the live URL and look at the surrounding code before escalating.

---

## Step 9 — Suppress known/expected findings

- `--allowlist <file>` — suppress known-OK findings (JSON or line-based;
  `keyleak-allowlist.yaml` is the repo default).
- `--baseline <prev-report.json>` — suppress everything already present in a previous
  report, so you only see *new* exposures (pairs well with `keyleak diff`).
- `--no-default-suppressions` — turn OFF the built-in fixture-path suppressions.

---

## Command quick reference

```bash
keyleak doctor                                   # environment preflight
keyleak local . --launch-profile launch-gate --fail-on high   # local pre-merge gate
keyleak self-audit . --fail-on high              # this repo's supply-chain hygiene
keyleak browser-scan https://app.example.com --html > report.html   # one live SPA
keyleak site-scan example.com --launch-profile full --baas-validate --json > report.json
keyleak explain leak.gemini_api_key              # remediation card for a detector
keyleak diff baseline.json current.json          # only findings new since baseline
```

See `CONTRIBUTING.md` for contribution conventions and `docs/DETECTOR_AUTHORING.md`
for adding detectors.
