# Meta-analysis: attack-vector correlation engine + rule book (D7)

The missing capability: an ethical hacker rarely exploits one finding in isolation
— they **chain** signals (leaked anon key + a table with no RLS; an IDOR + PII in
the response; SSRF + cloud metadata). KeyLeak today emits independent findings.
This adds a **correlation engine** that derives composite **attack vectors** from
combinations of findings, escalating severity and narrating the path.

## Mechanism decision (the goal delegated this)

**Deterministic rule engine first; optional local-LLM assist second.** Rationale:
KeyLeak is offline/privacy-first (`offline_guard`, `net_guard`, `privacy_filter`);
a transparent, dependency-free, reproducible rule engine fits CI and audit, and
never ships finding data to a model. We add a **pluggable `CorrelationAssist`
interface** so a locally-run model (e.g. Qwen via Ollama) can *propose* additional
chains the rules didn't encode — but it is **opt-in, offline-local, and never
required**; the default path is pure rules. Rules are the product; the LLM is a
power-user amplifier that only ever *adds* candidate chains for human review.

> **Status:** the engine core (`keyleak/attack_chains.py`, `correlate()`) is built
> and tested (M6a). The wiring described below — the new `build_report` param, the
> report section, and the `browser_scanner`/`site_scanner` call sites — is **M6b,
> not yet implemented**, so `correlate()` produces no user-visible output yet. The
> single-URL host-alignment requirement (pass the scan `target`) is locked by a test
> so M6b cannot regress it.

## Where it hooks (grounded — corrected after review R1)

`reporting.build_report(target, findings, scan_mode, attack_vectors=..., profile,
packs)` already exists, but its `attack_vectors` param is **not** a general
channel: `_attack_vector_findings()` only understands the shape
`{"subdomains": [{"host", "findings": [...]}]}` and flattens it into plain
`category="access-control"` findings — it would lose the AttackVector model and
severity-escalation. So correlation gets a **new** `attack_chains` parameter
(not a reuse of `attack_vectors`): `build_report(..., attack_chains: list[AttackVector] = None)`
plus a dedicated `_attack_vector_section()` serializer. `correlate(findings,
context)` runs after normalize and its result is passed in via that new param.

**Provenance (corrected):** `report.extra["provenance"]` (finding.id → [urls]) is
populated by `site_scanner._merge_findings`, **not** by `build_report`, and only
for multi-page site scans. Single-URL `browser_scan` and BaaS-validation findings
have **no** provenance entry — so `correlate` must derive a host key with a
fallback: `provenance.get(finding.id)` else the host parsed from
`finding.evidence.request_url` or `finding.source`. Without this fallback the
flagship single-URL RLS chain would silently never fire.

## Data model

Legs match on the **real fields that exist today** — `finding.type` and
`finding.detector_id` — NOT on a `canonical_class` taxonomy (which does not exist
in the codebase; introducing one would be a separate prerequisite milestone). Each
leg is a set of accepted `finding.type` values (and/or `detector_id` globs):

```python
@dataclass(frozen=True)
class ChainLeg:
    types: tuple = ()     # accepted finding.type values, e.g. ("baas_open_table",)
    detector_globs: tuple = ()  # OR globs over detector_id, e.g. ("access-control.*",)
    where: str = "any"    # "same_host" | "any" — provenance constraint (with fallback host)
    min_count: int = 1

@dataclass(frozen=True)
class ChainRule:
    id: str
    name: str
    legs: tuple[ChainLeg, ...]      # ALL must be satisfied (AND); a leg may OR via classes
    severity: str                   # severity of the composite vector (usually escalated)
    confidence: str                 # "confirmed" if active-probe legs, else "lead"
    narrative: str                  # templated: how the chain is exploited
    remediation: str
    references: tuple = ()
    requires_same_host: bool = True # most chains only make sense on one target

@dataclass
class AttackVector:
    id: str; rule_id: str; name: str; severity: str; confidence: str
    member_finding_ids: list[str]; hosts: list[str]
    narrative: str; remediation: str
```

`correlate(findings, context) -> list[AttackVector]`:
1. Index findings by `finding.type` and `finding.detector_id`, and by host —
   host from `provenance[finding.id]` else parsed from `evidence.request_url` /
   `source` (the single-URL fallback).
2. For each `ChainRule`, find finding sets satisfying every leg (respecting
   `where`/`requires_same_host`). Leg matching is on the concrete `types` /
   `detector_globs` sets above; detector renames are handled by keeping those
   sets in one place next to the rules, not by an absent class layer.
3. Emit one `AttackVector` per satisfied combination (dedupe by member-id set).
4. Escalation: vector severity = `max(rule.severity, max(member severity))`;
   confidence = `confirmed` only if at least one leg came from an active probe.
5. Cap vectors (e.g. 100) and rank by severity then member count.

Reporting: a new **"Attack vectors"** section above per-finding details — each card
shows the chain name, the legs (with links to member findings), the narrative, and
the combined severity. Verdict escalates to BLOCK SHIP on any `critical` vector.

## Seed rule book (v1 — ~24 chains)

The class-name labels in the table below are **shorthand for sets of real
`finding.type` values that the code emits today** (so the engine matches on
fields that exist). The mapping for the highest-value chains, using the actual
strings from `baas_validator.py`, `detectors.py`, and `access_control.py`:

| shorthand | real finding.type / detector_id |
|-----------|----------------------------------|
| anon-key present | `supabase_publishable_key`, `supabase_url`, `firebase_client_config` |
| baas-rls open-table | `baas_open_table` (active-probe, confirmed) |
| baas-rls open-write | `baas_writable_table` |
| baas open-storage | `baas_open_storage` |
| service_role leak | `baas_service_role_exposed` |
| idor/bola | `idor` (detector_id `access-control.*two_user*`) |
| source-map exposed | `source_map_reference` |
| cors wildcard | `baas_cors_wildcard` (BaaS) / a `cors_*` client finding (M2) |

New finding types added in M2–M5 (e.g. `actuator_exposed`, `exposed_env_file`,
`jwt_alg_none`, `ssrf_*`) extend these leg sets. Severity shown is the *composite*.

| id | chain (legs) | composite | why it matters |
|----|--------------|-----------|----------------|
| `rls-anon-fulldb` | supabase/anon-key **+** baas-rls open-table (same host) | critical | Leaked-by-design anon key becomes full DB read because RLS is off. The CBSE case. |
| `rls-write-takeover` | anon-key **+** baas-rls open-write | critical | Anon can mutate rows → data integrity / takeover. |
| `service-role-leak` | secrets-exposure(service_role JWT) | critical | RLS-bypassing key in the bundle = total BaaS compromise (single-leg, but escalated + narrated). |
| `idor-pii-exfil` | access-control idor/bola **+** excessive-data(PII in response) | critical | Enumerable IDs + PII bodies = scripted bulk customer-data theft. |
| `idor-massassign-priv` | idor/bola **+** mass-assignment | critical | Read others' objects + set `role/isAdmin` → privilege escalation. |
| `ssrf-metadata-creds` | ssrf **+** ssrf-cloud-metadata reachable | critical | SSRF to 169.254.169.254 → cloud creds → account takeover. |
| `sourcemap-secret` | source-map exposed **+** secrets-exposure | high | Source maps reveal pre-min code + build-time secrets. |
| `sourcemap-apimap` | source-map exposed **+** api endpoint inventory | high | Accelerated reverse-engineering of auth + authz edges. |
| `cors-cred-theft` | cors wildcard+credentials **+** sensitive authed endpoint | high | Any origin reads authed responses → cross-origin data theft. |
| `jwt-forge-privesc` | jwt alg-none/weak **+** role/admin claim present | critical | Forge/alter JWT → privilege escalation. |
| `actuator-env-db` | debug-endpoint(actuator/env) **+** db creds in env | critical | `/actuator/env` (or `/debug`) exposes DB creds → DB takeover. |
| `subdomain-cookie-theft` | subdomain-takeover **+** cookie scoped to parent domain | high | Takeover a dangling subdomain → steal parent-domain session cookies. |
| `hosthdr-reset-ato` | host-header injection **+** password-reset flow | critical | Poison reset link host → account takeover. |
| `resettoken-enum-ato` | password-reset token leakage **+** user enumeration | critical | Enumerate users + predict/leak reset tokens → ATO. |
| `xss-cookie-session` | stored/dom XSS **+** cookie missing HttpOnly | high | XSS reads session cookie → session theft. |
| `xss-no-csp` | xss **+** missing CSP | high | No CSP makes the XSS trivially weaponizable. |
| `openredirect-oauth` | open-redirect **+** oauth/oidc flow | high | redirect_uri abuse → OAuth token/code theft. |
| `graphql-introspect-bola` | graphql introspection **+** bola/bopla | high | Introspected schema + object-level gaps → mass object access. |
| `ratelimit-cred-stuffing` | rate-limit missing **+** login/auth endpoint | high | No throttle on login → credential stuffing / brute force. |
| `defaultcreds-admin` | default-creds **+** admin endpoint reachable | critical | Default creds on an exposed admin panel → full compromise. |
| `git-env-disclosure` | exposed .git/.env/backup **+** secrets-exposure | critical | Source + secret disclosure from misconfigured static files. |
| `verbose-version-exploit` | verbose error/stack trace **+** outdated framework/lib version | high | Stack trace fingerprints stack + version → targeted known-CVE exploit. |
| `storage-pii-exfil` | baas open-storage-bucket **+** PII-shaped object names | high | Public bucket + customer files → PII exfiltration. |
| `smuggling-cache` | request smuggling **+** shared cache / web cache deception | high | Desync + cache → mass session/data leak (active, lead unless confirmed). |

Each row becomes a `ChainRule`. `requires_same_host=True` for all except
single-leg escalations (`service-role-leak`). Confidence is `confirmed` when an
active-probe leg fired (e.g. the RLS open-table probe), else `lead`.

## Why rules (not an LLM) by default

- Reproducible + explainable: every vector cites exactly which findings triggered
  it and why — essential for a security tool's credibility and for CI gating.
- Offline + private: no finding data leaves the host.
- Cheap + fast: runs in-process over the finding list.
- The LLM hook (`CorrelationAssist`) stays available for fuzzy, novel chains, but
  its output is labeled `assist:lead` and never gates a build on its own.

## Implementation plan (P7)

1. `keyleak/attack_chains.py`: dataclasses + `SEED_CHAINS` (the table above) +
   `correlate(findings, context)`. Pure, unit-tested with synthetic finding sets
   (each rule has a positive + a negative fixture — tests verify intent: the chain
   fires only when all legs + host constraint hold).
2. Wire `correlate()` into `build_report`; add the "Attack vectors" report section
   (json/markdown/html/sarif) + verdict escalation.
3. Optional `CorrelationAssist` protocol + a no-op default; a local-Qwen adapter
   documented but off by default and behind `offline_guard` allowances.
