"""Detector registry for local files and generated browser bundles."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, List, Optional, Pattern, Sequence, Tuple

from .models import Remediation, derive_remediation


DETECTOR_SCHEMA_VERSION = 1
MIN_KEYLEAK_VERSION = "0.1.0"


@dataclass(frozen=True)
class Detector:
    id: str
    pattern: str
    severity: str
    description: str
    remediation: str
    categories: List[str]
    min_match_length: int = 8
    capture_group: int = 0
    pack: str = "leak"
    finding_type: str = ""
    validation_status: str = "validated"
    references: Tuple[str, ...] = ()
    extension: bool = True
    attack_scenario: Optional[str] = None
    # Wave 1.3 — Detector ABI extension.
    # All new fields are defaulted so existing entries don't need editing.
    schema_version: int = DETECTOR_SCHEMA_VERSION
    min_keyleak_version: str = MIN_KEYLEAK_VERSION
    # Old IDs to keep honoring after a rename. Suppressions referencing any
    # entry in ``id_aliases`` still match this detector.
    id_aliases: Tuple[str, ...] = ()
    # Wave 1.6 — Structured Remediation override. If None, the reporter
    # derives a Remediation from ``description`` / ``attack_scenario`` /
    # ``remediation``. Detectors can opt-in to richer cards by setting an
    # explicit ``RemediationOverride`` (a dict with the four fields, kept
    # as a dict to preserve ``frozen=True`` semantics).
    remediation_v2: Optional[dict] = None
    # Q.1 — minimum Shannon entropy (bits/char) for the captured value.
    # Detectors whose pattern can legitimately match dictionary-shaped
    # strings (``sk-*``, ``hf_*``, etc.) set this to ~4.0 to reject
    # ``sk-indigo-twilight-color-1`` while keeping real high-entropy keys.
    # ``None`` skips the check.
    min_entropy: Optional[float] = None

    def compile(self) -> Pattern[str]:
        return re.compile(self.pattern, re.IGNORECASE | re.MULTILINE)

    @property
    def canonical_id(self) -> str:
        return f"{self.pack}.{self.id}"

    @property
    def result_type(self) -> str:
        return self.finding_type or self.id

    @property
    def canonical_id_aliases(self) -> Tuple[str, ...]:
        return tuple(f"{self.pack}.{alias}" for alias in self.id_aliases)

    def get_remediation(self) -> Remediation:
        """Return the structured Remediation card for this detector.

        Uses ``remediation_v2`` if explicitly set, else derives one from the
        existing ``description`` / ``attack_scenario`` / ``remediation`` fields.
        Wave-1.6 contract: every detector returns a populated card.
        """

        if self.remediation_v2:
            return Remediation.from_dict(self.remediation_v2)
        return derive_remediation(
            self.description,
            self.attack_scenario,
            self.remediation,
        )


def find_detector(canonical_id: str):
    """Look up a detector by ``canonical_id`` (e.g. ``leak.openai_api_key``)."""

    for detector in DETECTORS:
        if detector.canonical_id == canonical_id:
            return detector
        if canonical_id in detector.canonical_id_aliases:
            return detector
    return None


DETECTOR_PACKS = {
    "leak": "Secrets, exposed config, source maps, and browser-visible leak signals.",
    "appsec": "SQL injection, XSS, and auth-bypass leads.",
    "access-control": "IDOR, missing tenant checks, and ownership-check leads.",
    "correctness": "N+1, regression, off-by-one, timezone/date, and semantic config leads.",
    "housekeeping": "Missing tests, dead code, and stale comments or docs.",
    "baas": "BaaS misconfiguration: open tables, exposed admin logic, storage, and RPC abuse vectors.",
    # Runtime-vulnerability program packs (populated incrementally in M2-M7).
    # Registered up front so scan bundles resolve through normalize_packs; a pack
    # with no detectors yet simply contributes nothing until its milestone lands.
    "injection": "Injection + input-validation leads found at runtime: SQLi/NoSQLi/SSTI/command/SSRF/open-redirect/traversal.",
    "authn": "Authentication/session leads: JWT flaws, OAuth/OIDC, session + cookie, password reset, OTP-in-response, 2FA bypass.",
    "client": "Client-side/browser leads: DOM XSS, prototype pollution, postMessage, tokens in web storage, clickjacking.",
    "api": "API-layer leads: excessive data exposure, broken object/property-level authz, enumeration, GraphQL introspection/abuse.",
    "recon": "Attack-surface/recon leads: subdomain takeover, debug/admin endpoints, exposed files, default credentials.",
    "headers": "Security-header and cookie-flag hygiene (passive).",
}

HEATMAP_ROWS = {
    "sql_injection": "appsec",
    "xss": "appsec",
    "auth_bypass": "appsec",
    "idor": "access-control",
    "missing_tenant_check": "access-control",
    "secret_in_logs": "leak",
    "n_plus_one_query": "correctness",
    "regression": "correctness",
    "off_by_one": "correctness",
    "timezone_date_bug": "correctness",
    "env_config_bug": "correctness",
    "test_missing": "housekeeping",
    "dead_code": "housekeeping",
    "stale_doc": "housekeeping",
}

PROFILE_PACKS = {
    "launch-gate": ("leak",),
    "local-dev": ("leak",),
    "bug-bounty": ("leak", "appsec", "access-control", "baas"),
    "ci": ("leak", "appsec", "access-control", "baas"),
    "full": tuple(DETECTOR_PACKS.keys()),
}

EXTENSION_PROFILE_PACKS = {
    "launch-gate": ("leak", "appsec", "access-control", "baas"),
    "local-dev": ("leak", "appsec", "access-control", "baas"),
    "bug-bounty": ("leak", "appsec", "access-control", "baas"),
    "ci": ("leak", "appsec", "access-control", "baas"),
    "full": ("leak", "appsec", "access-control", "baas"),
}

WEB_PROFILE_PACKS = {
    "launch-gate": ("leak",),
    "local-dev": ("leak",),
    "bug-bounty": ("leak", "appsec", "access-control", "baas"),
    "ci": ("leak", "appsec", "access-control", "baas"),
    "full": ("leak", "appsec", "access-control", "baas"),
}


DETECTORS = [
    Detector(
        "openai_api_key",
        r"\bsk-(?!(?:ant|or)-)(?:proj-)?[A-Za-z0-9_-]{20,}\b",
        "critical",
        "OpenAI API key exposed.",
        "Rotate the OpenAI key, remove it from client/config files, and load it server-side from a secret manager.",
        ["env", "ci", "docker", "mcp", "sourcemaps", "logs"],
        attack_scenario="Anyone who scrapes the bundle, response, or repo runs inference on your bill. Costs can spike to thousands of dollars within hours, and the key fingerprints your account for follow-up abuse.",
        # Q.1 — reject dictionary-word matches like `sk-indigo-twilight-color-1`
        # (Skeleton UI class names) or `madatnlp/sk-kogptv2-kormath-causal`
        # (HuggingFace model names). Real OpenAI keys are ~5.0 bits/char.
        min_entropy=4.0,
    ),
    Detector(
        "anthropic_api_key",
        r"\bsk-ant-[A-Za-z0-9_-]{80,}\b",
        "critical",
        "Anthropic API key exposed.",
        "Rotate the Anthropic key and move model calls behind a trusted server boundary.",
        ["env", "ci", "docker", "mcp", "sourcemaps", "logs"],
        attack_scenario="A leaked Anthropic key lets attackers spin up large Claude jobs on your bill, harvest any prompts or context they replay through it, and probe whatever tools your agent has bound to the same key.",
    ),
    Detector(
        "openrouter_api_key",
        r"\bsk-or-v1-[A-Za-z0-9]{48,}\b",
        "critical",
        "OpenRouter API key exposed.",
        "Rotate the OpenRouter key and audit usage because this can proxy access to multiple model providers.",
        ["env", "ci", "docker", "mcp", "sourcemaps", "logs"],
    ),
    Detector(
        "gemini_api_key",
        r"\bAIza[0-9A-Za-z\-_]{35}\b",
        "critical",
        "Google Gemini/API key exposed.",
        "Rotate or restrict the Google API key, audit API usage, and keep model/provider credentials server-side.",
        ["env", "ci", "docker", "mcp", "sourcemaps", "logs"],
    ),
    Detector(
        "huggingface_token",
        r"\bhf_[A-Za-z0-9]{32,}\b",
        "high",
        "Hugging Face token exposed.",
        "Rotate the token, review model/dataset access, and avoid shipping provider tokens in browser bundles.",
        ["env", "ci", "docker", "mcp", "sourcemaps", "logs"],
    ),
    Detector(
        "replicate_api_key",
        r"\br8_[A-Za-z0-9]{40,}\b",
        "critical",
        "Replicate API key exposed.",
        "Rotate the Replicate key and move inference calls behind a trusted server boundary.",
        ["env", "ci", "docker", "mcp", "sourcemaps", "logs"],
    ),
    Detector(
        "perplexity_api_key",
        r"\bpplx-[A-Za-z0-9]{40,}\b",
        "critical",
        "Perplexity API key exposed.",
        "Rotate the Perplexity key and keep model-provider credentials out of client-side code.",
        ["env", "ci", "docker", "mcp", "sourcemaps", "logs"],
    ),
    Detector(
        "anyscale_api_key",
        r"\besecret_[A-Za-z0-9]{40,}\b",
        "critical",
        "Anyscale API key exposed.",
        "Rotate the Anyscale key and audit inference endpoint usage.",
        ["env", "ci", "docker", "mcp", "sourcemaps", "logs"],
    ),
    Detector(
        "groq_api_key",
        r"\bgsk_[A-Za-z0-9]{40,}\b",
        "critical",
        "Groq API key exposed.",
        "Rotate the Groq key and keep inference credentials out of browser and agent config files.",
        ["env", "ci", "docker", "mcp", "sourcemaps", "logs"],
    ),
    Detector(
        "github_pat",
        r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{70,}\b",
        "critical",
        "GitHub token exposed.",
        "Revoke the token, review repository access, and regenerate with the smallest necessary scope.",
        ["env", "ci", "docker", "mcp", "sourcemaps", "logs"],
        attack_scenario="Attackers clone every private repo the token can read, push malicious commits or workflow files, and harvest CI secrets from workflow logs. Tokens with `repo` scope often own enough of the supply chain to backdoor downstream consumers.",
    ),
    Detector(
        "aws_access_key",
        r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
        "high",
        "AWS access key ID exposed.",
        "Rotate the access key and prefer IAM roles or workload identity over static credentials.",
        ["env", "ci", "docker", "mcp", "sourcemaps", "logs"],
        attack_scenario="With even a guessable secret nearby, attackers enumerate S3 buckets, mint short-lived credentials via `sts:GetSessionToken`, and pivot into anything the IAM principal can reach. AKIA prefixes appear in honeypots within minutes of being public.",
    ),
    Detector(
        "aws_secret_key",
        r"\baws.{0,30}(?:secret|access).{0,20}[\"'\s:=]+([A-Za-z0-9/+=]{40})",
        "critical",
        "AWS secret access key-like value exposed.",
        "Rotate the AWS secret, review CloudTrail activity, and use IAM roles or a secret manager instead.",
        ["env", "ci", "docker", "mcp", "sourcemaps", "logs"],
        8,
        1,
        attack_scenario="Paired with the access key ID this is full AWS API access in the principal's scope: dump RDS snapshots, spin up crypto miners on every region's compute quota, or wipe everything and demand ransom for restore.",
    ),
    Detector(
        "google_service_account",
        r"\"type\":\s*\"service_account\"[\s\S]*?\"private_key\":\s*\"-----BEGIN PRIVATE KEY-----",
        "critical",
        "Google service account key material exposed.",
        "Revoke the service account key, audit IAM permissions, and move service credentials to secret storage.",
        ["env", "ci", "docker", "mcp", "sourcemaps", "logs"],
    ),
    Detector(
        "firebase_server_key",
        r"\bAAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{120,}\b",
        "high",
        "Firebase/FCM server key exposed.",
        "Rotate the Firebase key and confirm Firebase security rules prevent unauthorized access.",
        ["env", "ci", "docker", "mcp", "sourcemaps", "logs"],
    ),
    Detector(
        "stripe_secret_key",
        r"\bsk_(?:live|test)_[0-9A-Za-z]{24,}\b",
        "critical",
        "Stripe secret key exposed.",
        "Rotate the Stripe key and move payment operations behind server-side endpoints.",
        ["env", "ci", "docker", "sourcemaps", "logs"],
        attack_scenario="A `sk_live_` key is direct Stripe API access: attackers refund or void any charge, create payouts to attacker-controlled bank accounts, dump customer payment metadata, and rack up fraudulent transactions before anyone notices.",
    ),
    Detector(
        "stripe_restricted_key",
        r"\brk_(?:live|test)_[0-9A-Za-z]{24,}\b",
        "critical",
        "Stripe restricted key exposed.",
        "Rotate the Stripe restricted key and move payment operations to server-side endpoints.",
        ["env", "ci", "docker", "sourcemaps", "logs"],
    ),
    Detector(
        "slack_token",
        r"\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,32}\b",
        "critical",
        "Slack token exposed.",
        "Revoke the Slack token, review workspace app scopes, and regenerate with least privilege.",
        ["env", "ci", "docker", "mcp", "sourcemaps", "logs"],
    ),
    Detector(
        "slack_webhook",
        r"https://hooks\.slack\.com/services/[A-Za-z0-9_/-]{20,}",
        "high",
        "Slack webhook URL exposed.",
        "Regenerate the webhook and keep it out of browser bundles and public config.",
        ["env", "ci", "docker", "mcp", "sourcemaps", "logs"],
    ),
    Detector(
        "gitlab_token",
        r"\bglpat-[A-Za-z0-9\-]{20,}\b",
        "critical",
        "GitLab token exposed.",
        "Revoke the GitLab token, review project/group access, and regenerate with the smallest scope possible.",
        ["env", "ci", "docker", "mcp", "sourcemaps", "logs"],
    ),
    Detector(
        "npm_token",
        r"\bnpm_[A-Za-z0-9\-_]{36}\b",
        "critical",
        "npm token exposed.",
        "Revoke the npm token and audit package publish activity.",
        ["env", "ci", "docker", "mcp", "sourcemaps", "logs"],
    ),
    Detector(
        "sendgrid_api_key",
        r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b",
        "critical",
        "SendGrid API key exposed.",
        "Rotate the SendGrid key and audit mail-sending activity for abuse.",
        ["env", "ci", "docker", "mcp", "sourcemaps", "logs"],
    ),
    Detector(
        "pypi_upload_token",
        r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,}\b",
        "critical",
        "PyPI upload token exposed.",
        "Revoke the PyPI token and audit package release history.",
        ["env", "ci", "docker", "mcp", "sourcemaps", "logs"],
    ),
    Detector(
        "database_url",
        r"\b(?:postgres(?:ql)?|mysql(?:2)?|mongodb(?:\+srv)?|redis)://[^\s'\"<>]+:[^\s'\"<>]+@[^\s'\"<>]+",
        "critical",
        "Database connection string with credentials exposed.",
        "Rotate database credentials, restrict network access, and move connection strings to server-only configuration.",
        ["env", "ci", "docker", "mcp", "sourcemaps", "logs"],
        attack_scenario="The embedded credentials grant whatever role the DB user has — typically full read of every row. Attackers pull customer PII, payment records, and password hashes for credential stuffing elsewhere; if the DB is internet-reachable it's game over.",
    ),
    Detector(
        "dotnet_sql_connection_string",
        r"(?:(?:Server|Data Source)\s*=\s*[^;'\"]+;[\s\S]{0,200}?(?:Password|Pwd)\s*=\s*[^;'\"\s]{3,}|jdbc:(?:sqlserver|postgresql|mysql|oracle:thin)://[^\s'\"]+[?;&](?:password|pwd)\s*=\s*[^\s'\"&;]{3,})",
        "critical",
        "ADO.NET / ODBC / JDBC database connection string with an embedded password.",
        "Rotate the database password, move connection strings to a server-side secret store, and never ship them in client bundles, config files, or logs.",
        ["env", "ci", "docker", "config", "code", "sourcemaps", "logs"],
        validation_status="validated",
        references=(
            "https://cwe.mitre.org/data/definitions/798.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
        ),
        attack_scenario="A connection string with a high-privilege account (e.g. the SQL Server `sa` login) hands an attacker direct read/write to every database on that instance. On shared/multi-tenant hosting, one exposed string compromises every co-located tenant's data at once.",
    ),
    Detector(
        "private_key",
        r"-----BEGIN (?:(?:RSA|DSA|EC|OPENSSH) )?PRIVATE KEY-----[\s\S]+?-----END (?:(?:RSA|DSA|EC|OPENSSH) )?PRIVATE KEY-----",
        "critical",
        "Private key exposed.",
        "Revoke and rotate the key immediately, then audit every system where it was trusted.",
        ["env", "ci", "docker", "mcp", "logs"],
        attack_scenario="Whoever holds the key can impersonate the server or user it was issued to: sign fake TLS certs, mint JWTs your services already trust, or SSH into every host that trusts this key. Rotation is mandatory; you cannot un-leak a private key.",
    ),
    Detector(
        "jwt_token",
        r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
        "medium",
        "JWT found in browser-visible content.",
        "Confirm the token is short-lived, not logged or embedded, and does not expose sensitive claims.",
        ["env", "ci", "docker", "mcp", "sourcemaps", "logs"],
        attack_scenario="A leaked JWT impersonates its subject until expiry. Even without the signing key, the base64 payload usually reveals role, tenant, and internal IDs that accelerate attacks against the rest of the system.",
    ),
    Detector(
        "bearer_token",
        r"\bbearer[\s:=]+([A-Za-z0-9_\-.]{20,})\b",
        "high",
        "Bearer token found in browser-visible content.",
        "Move bearer tokens out of static content and use short-lived session-bound tokens.",
        ["env", "ci", "docker", "mcp", "sourcemaps", "logs"],
        8,
        1,
    ),
    Detector(
        "http_basic_auth",
        r"\bhttps?://([A-Za-z0-9_-]+):([^@\s]+)@",
        "high",
        "HTTP Basic Auth credentials embedded in a URL.",
        "Rotate the credentials and replace URL-embedded credentials with a safer authentication mechanism.",
        ["env", "ci", "docker", "mcp", "sourcemaps", "logs"],
        attack_scenario="Credentials in URLs land in browser history, web-server logs, HTTP `Referer` headers, and CI logs. Anyone with read access to those logs escalates straight to whatever the credential authenticates against.",
    ),
    Detector(
        "mcp_config_secret",
        r"(?:mcp|modelcontextprotocol|tool|server).{0,80}(?:api[_-]?key|token|secret|password)[\"'\s:=]+[\"']?([A-Za-z0-9_\-./+=]{20,})",
        "high",
        "MCP or agent tool credential exposed.",
        "Move agent/tool credentials to local secret storage and review connected tool permissions.",
        ["mcp", "env", "docker", "logs"],
        8,
        1,
        extension=False,
    ),
    Detector(
        "hidden_prompt_injection",
        r"(?:ignore (?:all )?previous instructions|system prompt|developer message|exfiltrate|send (?:the )?(?:token|secret|api key)|hidden instruction)",
        "medium",
        "Prompt-injection style instruction found in content.",
        "Treat untrusted content as data, isolate agent tools, and avoid giving browsing agents access to secrets.",
        ["sourcemaps", "logs"],
    ),
    Detector(
        "graphql_introspection_hint",
        r"\b(?:__schema|__type|IntrospectionQuery)\b",
        "medium",
        "GraphQL introspection or schema content exposed.",
        "Confirm introspection is intentionally exposed and protected on production APIs.",
        ["sourcemaps", "logs"],
        1,
    ),
    Detector(
        "source_map_reference",
        r"sourceMappingURL=[^\s'\"<>]+\.map\b",
        "low",
        "Browser bundle references a source map.",
        "Review generated source maps for embedded secrets and avoid publishing private source in production.",
        ["sourcemaps"],
        attack_scenario="Source maps reveal pre-minified code, in-line API URLs, internal field names, and sometimes secrets injected at build time. Attackers reverse-engineer your auth flow, business rules, and authorization edges much faster than they could from the minified bundle.",
    ),
    Detector(
        "npm_optional_dep_git_ref",
        r"\"optionalDependencies\"\s*:\s*\{[^}]*\"[^\"]+\"\s*:\s*\"(?:github:[^\"]+|git\+(?:https?|ssh)://[^\"]+)#[a-f0-9]{7,40}",
        "high",
        "package.json optionalDependencies points to a git commit SHA. This is the Mini Shai-Hulud (TanStack 2026) attack vector.",
        "Remove the git-ref optionalDependency. Replace with a pinned semver from the registry or vendor the code in-tree.",
        ["env", "ci", "docker", "mcp", "sourcemaps", "logs", "code", "config"],
        20,
        0,
        "leak",
        "npm_optional_dep_git_ref",
        "validated",
        ("https://tanstack.com/blog/npm-supply-chain-compromise-postmortem", "https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem"),
        True,
        "An attacker that lands a PR adding `optionalDependencies: { '@x/setup': 'github:org/repo#<sha>' }` runs arbitrary code on every install via the orphan commit's `prepare` hook. This is exactly how Mini Shai-Hulud compromised 42 @tanstack/* packages on 2026-05-11 and stole AWS/GCP/Vault/GitHub/npm credentials from anyone who installed.",
    ),
    Detector(
        "gh_actions_pull_request_target",
        r"(?:^|\n)\s*on\s*:[\s\S]{0,400}\bpull_request_target\b",
        # L.2 — downgraded from medium to info after the dogfood showed ~150
        # mediums against repos that all use ``pull_request_target`` for
        # legitimate labeler / CLA / dependabot bots. The trigger ALONE is
        # not a leak; the actual Pwn Request requires also checking out
        # ``github.event.pull_request.head.ref``. That pattern is now a
        # separate ``gh_actions_pwn_request_head_ref`` detector (high).
        "info",
        "GitHub Actions workflow uses pull_request_target. Informational only — the leak shape is `pull_request_target` + checkout of `head.ref`. See `gh_actions_pwn_request_head_ref`.",
        "If this workflow runs untrusted PR code: switch to `pull_request`. If it only reads PR metadata (labeler, CLA bot), this trigger is fine and you can suppress this notice.",
        ["ci"],
        12,
        0,
        "leak",
        "gh_actions_pull_request_target",
        "lead",
        ("https://securitylab.github.com/research/github-actions-preventing-pwn-requests/",),
        True,
        "`pull_request_target` alone is informational — the worm hit @tanstack via the combination of this trigger AND a checkout of `head.ref` in the same job. Workflows that only read PR metadata (assign reviewers, label PRs, validate CLA) are safe.",
    ),
    Detector(
        # L.2 — the real Pwn Request pattern: pull_request_target + checkout
        # of head.ref (or head.sha) in the same workflow. This is the high-
        # severity finding that the original detector was conflating with
        # legitimate labeler bots.
        "gh_actions_pwn_request_head_ref",
        r"\bpull_request_target\b[\s\S]{0,4000}?actions/checkout[\s\S]{0,400}?ref\s*:\s*\$\{\{\s*github\.event\.pull_request\.head\.(?:ref|sha)\s*\}\}",
        "high",
        "GitHub Actions workflow combines pull_request_target with checkout of head.ref/head.sha — this is the Pwn Request pattern that compromised TanStack/Mini-Shai-Hulud.",
        "Move untrusted-code work into a separate `pull_request`-triggered workflow that has no secrets, and use `workflow_run` to pass artifacts only.",
        ["ci"],
        24,
        0,
        "leak",
        "gh_actions_pwn_request_head_ref",
        "validated",
        (
            "https://securitylab.github.com/research/github-actions-preventing-pwn-requests/",
            "https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem",
        ),
        True,
        "A `pull_request_target` workflow that also checks out the head branch runs attacker-controlled code with the base repo's secrets. Mini Shai-Hulud rode this exact combo into TanStack — a forked PR added a malicious script, the workflow checked it out, and the OIDC + npm tokens left.",
    ),
    Detector(
        "gh_actions_secrets_tojson",
        r"toJSON\(\s*secrets\s*\)",
        "high",
        "GitHub Actions workflow serializes all secrets via toJSON(secrets). Mini Shai-Hulud (2026) used this exact pattern to bulk-exfiltrate CI secrets.",
        "Reference only the specific secrets the job needs (`${{ secrets.NPM_TOKEN }}`). Never pass the entire `secrets` object as JSON to a step.",
        ["ci"],
        12,
        0,
        "leak",
        "gh_actions_secrets_tojson",
        "validated",
        ("https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem",),
        True,
        "`toJSON(secrets)` dumps every CI secret the job has into a single blob — typically logged or passed to a tool. Any later step that writes that blob to disk, logs it, or sends it over the network exfiltrates the entire vault. It's a load-bearing IOC for the Mini Shai-Hulud worm.",
    ),
    Detector(
        "shai_hulud_c2_domain",
        r"\b(?:filev2\.getsession\.org|seed[1-3]\.getsession\.org|api\.masscan\.cloud|git-tanstack\.com)\b",
        "critical",
        "Mini Shai-Hulud command-and-control or exfiltration domain found.",
        "Treat the host as compromised. Rotate every credential reachable from the affected machine or CI runner: AWS, GCP, Kubernetes, Vault, GitHub, npm, SSH. Then audit egress logs to confirm what left.",
        ["env", "ci", "docker", "mcp", "sourcemaps", "logs", "code"],
        8,
        0,
        "leak",
        "shai_hulud_c2_domain",
        "validated",
        ("https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem", "https://tanstack.com/blog/npm-supply-chain-compromise-postmortem"),
        True,
        "The Mini Shai-Hulud worm sends stolen credentials to known Session/Oxen messenger, mass-scan, and fake TanStack infrastructure endpoints. If code, logs, or build artifacts mention the IOC domains matched by this detector, treat the installed dependency or host as already exfiltrating data.",
    ),
    Detector(
        "npm_prepare_bun_payload",
        r"\"(?:prepare|preinstall|postinstall)\"\s*:\s*\"[^\"]*\b(?:bun\s+run|node\s+(?:\./)?(?:tanstack_runner|router_init|router_runtime))[^\"]*\"",
        "high",
        "package.json prepare/preinstall/postinstall script runs Bun or a TanStack-style payload file. Mini Shai-Hulud (2026) executed `bun run tanstack_runner.js && exit 1`.",
        "Inspect the script and the referenced JS file. If the file is bundled, opaque, or not in version control, treat the package as compromised. Add `--ignore-scripts` to your install command and switch to pnpm v10+ for default-off lifecycle execution.",
        ["env", "ci", "docker", "mcp", "code", "config"],
        18,
        0,
        "leak",
        "npm_prepare_bun_payload",
        "lead",
        ("https://tanstack.com/blog/npm-supply-chain-compromise-postmortem",),
        True,
        "The TanStack worm executed its payload through `prepare: \"bun run tanstack_runner.js && exit 1\"` in the malicious tarball's package.json. Any install (developer machine or CI runner) immediately ran the harvester. `--ignore-scripts` blocks this vector entirely; pnpm v10 does it by default in CI.",
    ),
    Detector(
        "webhook_url",
        r"\bhttps?://[^\s'\"<>]+webhook[^\s'\"<>]*",
        "medium",
        "Webhook URL exposed.",
        "Review whether the webhook is secret-bearing, rotate it if sensitive, and add authentication where possible.",
        ["env", "ci", "docker", "mcp", "sourcemaps", "logs"],
    ),
    Detector(
        "private_ip",
        r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b",
        "low",
        "Private network address exposed.",
        "Review whether internal topology details should be visible in client-side content.",
        ["sourcemaps", "logs"],
    ),
    Detector(
        "secret_in_logs_lead",
        r"(?:console\.log|logger\.(?:debug|info|warn|error)|print\s*\()[\s\S]{0,120}?(?<![a-z0-9_])(?:api[_-]?key|secret|token|password|authorization|cookie)(?![a-z0-9_])",
        "medium",
        "Secret-in-logs lead found.",
        "Remove secrets from logs, redact sensitive fields at the logger boundary, and rotate any value that may already have been written.",
        ["code", "sourcemaps", "logs"],
        12,
        0,
        "leak",
        "secret_in_logs",
        "lead",
    ),
    Detector(
        "sql_injection_lead",
        r"(?:\b(?:SELECT|UPDATE|DELETE|INSERT)\b[\s\S]{0,160}(?:\+\s*(?:req|request|params|query|body|input|user)|\$\{[^}]+\})|(?:sql|query)\s*[:=]\s*[`'\"][\s\S]{0,120}\$\{[^}]+\}|(?:SQL syntax|mysql_fetch|PostgreSQL query failed|SQLiteException|ODBC SQL Server Driver))",
        "medium",
        "SQL injection lead found in query construction or database error output.",
        "Parameterize the query, validate the input at the boundary, and re-test the endpoint with the launch gate after the fix.",
        ["code", "sourcemaps", "logs"],
        12,
        0,
        "appsec",
        "sql_injection",
        "lead",
        ("https://owasp.org/www-community/attacks/SQL_Injection",),
        False,
    ),
    Detector(
        "xss_sink_lead",
        r"(?:\b(?:innerHTML|outerHTML)\s*=\s*(?:location|window\.location|document\.URL|[\s\S]{0,80}(?:searchParams|location\.hash|message\.data|postMessage))|document\.write\s*\([\s\S]{0,120}(?:location|document\.URL|message\.data)|insertAdjacentHTML\s*\([\s\S]{0,160}(?:location|message\.data|query|hash)|dangerouslySetInnerHTML\s*=\s*\{\{)",
        "medium",
        "XSS lead found where untrusted input can reach an HTML sink.",
        "Render untrusted values as text, sanitize unavoidable HTML with an allowlist sanitizer, and add a regression test for the sink.",
        ["code", "sourcemaps", "logs"],
        12,
        0,
        "appsec",
        "xss",
        "lead",
        ("https://owasp.org/www-community/attacks/xss/",),
    ),
    Detector(
        "auth_bypass_lead",
        r"\b(?:disable[_-]?auth|skip[_-]?auth|bypass[_-]?auth|auth[_-]?disabled|ALLOW_ALL_USERS|requireAuth\s*[:=]\s*false|isAdmin\s*[:=]\s*true|TODO:?[\s\S]{0,60}(?:auth|authorization|permission))\b",
        "medium",
        "Auth-bypass lead found in shipped code or config.",
        "Remove bypass flags from production paths, enforce server-side authorization, and add an auth regression test.",
        ["code", "env", "ci", "docker", "sourcemaps", "logs", "config"],
        8,
        0,
        "appsec",
        "auth_bypass",
        "lead",
        ("https://owasp.org/Top10/A01_2021-Broken_Access_Control/",),
    ),
    Detector(
        "idor_direct_object_lead",
        r"(?:/(?:users?|accounts?|customers?|tenants?|organizations?|orgs?|projects?|orders?)/[0-9a-fA-F-]{6,}|(?:user|account|customer|tenant|organization|project|order)[_-]?id\s*[:=]\s*[`'\"]?\$\{?[^`'\"\s}]+)",
        "medium",
        "Direct object reference lead found in a sensitive resource path or parameter.",
        "Verify object ownership on the server with tenant/user scoped queries and re-test with two throwaway users.",
        ["code", "sourcemaps", "logs"],
        6,
        0,
        "access-control",
        "idor",
        "lead",
        ("https://owasp.org/Top10/A01_2021-Broken_Access_Control/",),
        attack_scenario="If the server doesn't check ownership, swapping `/users/123` for `/users/124` returns another tenant's data. Attackers script through every ID to enumerate the full customer base. Validate with a two-user scan: `keyleak scan ... --bearer $A --bearer-b $B`.",
    ),
    Detector(
        "missing_tenant_check_lead",
        r"(?:TODO:?[\s\S]{0,80}(?:tenant|ownership|authorization|permission)|(?:tenant|org|organization|workspace|account)[_-]?id[\s\S]{0,80}(?:optional|nullable|skip|TODO|FIXME))",
        "medium",
        "Missing tenant or ownership-check lead found.",
        "Make the tenant boundary mandatory in server-side queries and add a cross-tenant negative test.",
        ["code", "sourcemaps", "logs", "config"],
        8,
        0,
        "access-control",
        "missing_tenant_check",
        "lead",
        ("https://owasp.org/Top10/A01_2021-Broken_Access_Control/",),
    ),
    Detector(
        "n_plus_one_query_lead",
        r"(?:for\s+.+:\s*(?:\n[^\n]*){0,6}\.(?:query|get|filter|find|select)\(|for\s*\([^)]*\)\s*\{[\s\S]{0,400}(?:SELECT\s+|\.query\(|\.find\(|\.filter\())",
        "low",
        "N+1 query lead found near a loop and database access.",
        "Batch or eager-load the related data, then add a query-count or performance regression test.",
        ["code", "tests", "logs"],
        12,
        0,
        "correctness",
        "n_plus_one_query",
        "lead",
        (),
        False,
    ),
    Detector(
        "regression_signal",
        r"(?:AssertionError|Expected [^\n]{1,120} but got|regression(?: test)? failed|breaks existing|failing tests?|FAILED [^\n]{0,80}tests?)",
        "low",
        "Regression signal found in code comments, tests, or logs.",
        "Reproduce the failing path, add or fix the regression test, and keep this advisory non-blocking unless the profile opts in.",
        ["code", "tests", "logs"],
        12,
        0,
        "correctness",
        "regression",
        "lead",
        (),
        False,
    ),
    Detector(
        "off_by_one_lead",
        r"(?:off[-_ ]by[-_ ]one|range\s*\(\s*len\s*\([^)]+\)\s*\+\s*1|for\s*\([^;]+;[^;]+<=\s*[^;]+\.length|index\s*[<>]=\s*(?:len|length))",
        "low",
        "Off-by-one lead found in index or loop boundary logic.",
        "Check the boundary condition, add tests for empty/one/many cases, and re-run the correctness profile.",
        ["code", "tests"],
        8,
        0,
        "correctness",
        "off_by_one",
        "lead",
        (),
        False,
    ),
    Detector(
        "timezone_date_lead",
        r"(?:datetime\.now\s*\(\s*\)|datetime\.utcnow\s*\(\s*\)|new Date\s*\(\s*[^)]*\)\s*[\.;]|Date\.parse\s*\(|tzinfo\s*=\s*None|timezone\s*TODO|TODO:?[\s\S]{0,80}(?:timezone|date boundary|DST))",
        "low",
        "Timezone or date-boundary lead found.",
        "Use timezone-aware dates, store UTC at boundaries, and add tests across DST/month/year transitions.",
        ["code", "tests", "config"],
        8,
        0,
        "correctness",
        "timezone_date_bug",
        "lead",
        (),
        False,
    ),
    Detector(
        "config_risk_lead",
        r"(?:\bDEBUG\s*=\s*True\b|\bNODE_ENV\s*=\s*development\b|\b(?:VERIFY_SSL|TLS_VERIFY|SSL_VERIFY)\s*=\s*(?:false|0|no)\b|\b(?:ALLOW_ORIGINS|CORS_ORIGIN|CORS_ALLOW_ALL_ORIGINS)\s*[:=]\s*(?:\*|true)\b)",
        "low",
        "Semantic config-risk lead found.",
        "Move risky development config out of launch profiles and assert production-safe defaults in CI.",
        ["env", "ci", "docker", "config", "code"],
        8,
        0,
        "correctness",
        "env_config_bug",
        "lead",
        (),
        False,
    ),
    Detector(
        "missing_test_lead",
        r"(?:TODO:?[\s\S]{0,80}(?:add|write|restore|missing)[\s\S]{0,40}(?:test|spec|coverage)|(?:describe|it|test)\.skip\s*\(|pytest\.mark\.skip|xit\s*\()",
        "info",
        "Missing or skipped test lead found.",
        "Add the missing test or document why the skip is temporary and tracked.",
        ["code", "tests", "docs"],
        8,
        0,
        "housekeeping",
        "test_missing",
        "lead",
        (),
        False,
    ),
    Detector(
        "dead_code_lead",
        r"(?:dead code|unused code|TODO:?[\s\S]{0,80}(?:remove|delete|cleanup)|\bdebugger\s*;|console\.log\s*\()",
        "info",
        "Dead-code or debug-code lead found.",
        "Remove dead/debug code or move intentional diagnostics behind an explicit development guard.",
        ["code", "tests", "docs"],
        8,
        0,
        "housekeeping",
        "dead_code",
        "lead",
        (),
        False,
    ),
    Detector(
        "stale_doc_lead",
        r"(?:stale (?:comment|doc|documentation)|outdated (?:comment|doc|documentation)|wrong doc|TODO:?[\s\S]{0,80}(?:update|fix|sync)[\s\S]{0,40}(?:doc|readme|comment))",
        "info",
        "Stale comment or documentation lead found.",
        "Update the comment or documentation so it matches current behavior, or delete it if it no longer helps.",
        ["code", "docs", "tests"],
        8,
        0,
        "housekeeping",
        "stale_doc",
        "lead",
        (),
        False,
    ),
    # ------------------------------------------------------------------
    # BaaS pack — Backend-as-a-Service misconfiguration detectors
    # ------------------------------------------------------------------
    Detector(
        "supabase_url",
        r"\bhttps://[a-z0-9]{20,}\.supabase\.co\b",
        "medium",
        "Supabase project URL exposed in client bundle.",
        "Verify RLS policies are enforced on all tables. Run `keyleak browser-scan` with BaaS validation to confirm.",
        ["sourcemaps", "code", "env"],
        pack="baas",
        finding_type="supabase_url",
        validation_status="lead",
        references=("https://supabase.com/docs/guides/auth/row-level-security",),
        attack_scenario="Combined with the anon key, the project URL enables direct REST API queries against every table. Missing or misconfigured RLS makes all data readable by anyone.",
    ),
    # Note: Supabase JWT-format anon keys are detected by the BaaS validator's
    # extract_baas_config() via proximity to a Supabase URL, not by a standalone
    # regex detector.  A standalone JWT regex would overlap with the generic
    # jwt_token detector and produce false positives on non-Supabase JWTs.
    Detector(
        "supabase_publishable_key",
        r"\bsb_publishable_[A-Za-z0-9_-]{20,}\b",
        "medium",
        "Supabase publishable key (non-standard format) exposed in client bundle.",
        "Confirm RLS policies protect every table. Run BaaS validation to test.",
        ["sourcemaps", "code", "env"],
        pack="baas",
        finding_type="supabase_publishable_key",
        validation_status="lead",
    ),
    Detector(
        "firebase_client_config",
        r"apiKey['\"\s:=]+AIza[0-9A-Za-z_-]{35}",
        "medium",
        "Firebase client configuration with API key exposed in client bundle.",
        "Firebase client config is designed for client use, but verify Firestore Security Rules and Storage Rules deny unauthorized access.",
        ["sourcemaps", "code", "env"],
        pack="baas",
        finding_type="firebase_client_config",
        validation_status="lead",
        references=("https://firebase.google.com/docs/rules",),
        attack_scenario="Firebase config grants access to Firestore, Realtime Database, and Storage. Without security rules, an attacker can read all documents, write arbitrary data, and access every file in Cloud Storage.",
    ),
    Detector(
        "client_side_admin_check",
        r"(?:is_admin|isAdmin|is_superuser|isSuperuser)\s*(?:===?\s*(?:true|!0)|!==?\s*(?:false|!1))",
        "high",
        "Client-side admin/role check found. Authorization decisions in browser JS are trivially bypassable.",
        "Move all authorization checks to the server. Use Supabase RLS policies or Firebase Security Rules to enforce admin-only access.",
        ["sourcemaps", "code"],
        pack="baas",
        finding_type="client_side_admin_check",
        validation_status="lead",
        references=("https://owasp.org/Top10/A01_2021-Broken_Access_Control/",),
        attack_scenario="An attacker sets is_admin=true in the browser console or modifies the JS bundle. Every admin-gated mutation (payouts, user management, moderation) becomes accessible.",
    ),
    Detector(
        "baas_select_star",
        r"\.from\(['\"][a-z_][a-z0-9_]*['\"]\)[\s\S]{0,60}\.select\(['\"]?\*['\"]?\)",
        "low",
        "BaaS table query uses select('*'), fetching all columns including potentially sensitive ones.",
        "Specify only the columns you need in select(). This reduces data exposure and improves performance.",
        ["sourcemaps", "code"],
        pack="baas",
        finding_type="baas_select_star",
        validation_status="lead",
    ),
    Detector(
        "baas_table_reference",
        r"\.from\(['\"]([a-z_][a-z0-9_]{1,62})['\"]\)",
        "info",
        "BaaS table name referenced in client bundle.",
        "Review whether this table's RLS policies are correctly configured.",
        ["sourcemaps", "code"],
        1,
        1,
        "baas",
        "baas_table_reference",
        "lead",
    ),
    Detector(
        "baas_rpc_call",
        r"\.rpc\(['\"]([a-z_][a-z0-9_]{1,62})['\"]",
        "info",
        "BaaS RPC function called from client bundle.",
        "Verify this RPC function validates caller identity and rate-limits requests.",
        ["sourcemaps", "code"],
        1,
        1,
        "baas",
        "baas_rpc_call",
        "lead",
    ),
    Detector(
        "baas_storage_bucket",
        r"\.storage\.from\(['\"]([a-z0-9_-]{1,62})['\"]\)",
        "low",
        "BaaS storage bucket referenced in client bundle.",
        "Verify storage bucket policies restrict who can upload, download, and list objects.",
        ["sourcemaps", "code"],
        1,
        1,
        "baas",
        "baas_storage_bucket",
        "lead",
    ),
    # Wave 4.2 — Firebase active validation detectors
    Detector(
        "firebase_db_url",
        r"\bhttps://[a-z0-9-]+\.firebaseio\.com\b",
        "medium",
        "Firebase Realtime Database URL exposed in client bundle.",
        "Verify Firebase Security Rules deny unauthorized read/write access.",
        ["sourcemaps", "code", "env"],
        pack="baas",
        finding_type="firebase_db_url",
        validation_status="lead",
        references=("https://firebase.google.com/docs/database/security",),
        attack_scenario="The Realtime Database URL allows direct REST API access. Without security rules, all data is readable and writable by anyone.",
    ),
    Detector(
        "firebase_storage_bucket",
        r"\b[a-z0-9-]+\.appspot\.com\b",
        "info",
        "Firebase/GCP storage bucket referenced in client bundle.",
        "Verify Cloud Storage security rules restrict access.",
        ["sourcemaps", "code", "env"],
        pack="baas",
        finding_type="firebase_storage_bucket",
        validation_status="lead",
    ),
    # Wave 4.3 — Appwrite & PocketBase detectors
    Detector(
        "appwrite_endpoint",
        r"\.setEndpoint\(['\"]https?://[^'\"]+/v1['\"]\)",
        "medium",
        "Appwrite API endpoint exposed in client bundle.",
        "Verify Appwrite collection permissions deny unauthorized access.",
        ["sourcemaps", "code"],
        pack="baas",
        finding_type="appwrite_endpoint",
        validation_status="lead",
    ),
    Detector(
        "pocketbase_url",
        r"new PocketBase\(['\"]https?://[^'\"]+['\"]\)",
        "medium",
        "PocketBase instance URL exposed in client bundle.",
        "Verify PocketBase collection API rules restrict access.",
        ["sourcemaps", "code"],
        pack="baas",
        finding_type="pocketbase_url",
        validation_status="lead",
    ),
    # Wave 4.4 — Write operation detection detectors
    Detector(
        "baas_insert_call",
        r"\.(?:insert|upsert)\(",
        "info",
        "BaaS insert/upsert mutation found in client code.",
        "Verify RLS policies restrict who can write to this table.",
        ["sourcemaps", "code"],
        pack="baas",
        finding_type="baas_insert_call",
        validation_status="lead",
    ),
    Detector(
        "baas_delete_call",
        r"\.delete\(\)",
        "info",
        "BaaS delete mutation found in client code.",
        "Verify RLS policies restrict who can delete from this table.",
        ["sourcemaps", "code"],
        pack="baas",
        finding_type="baas_delete_call",
        validation_status="lead",
    ),
    # Wave 4.5 — Auth flow analysis detector
    Detector(
        "baas_password_auth",
        r"signInWithPassword",
        "info",
        "Password-based authentication flow detected in client code.",
        "Ensure password policies, rate limiting, and email confirmation are configured.",
        ["sourcemaps", "code"],
        pack="baas",
        finding_type="baas_password_auth",
        validation_status="lead",
    ),
    # Wave 4.6 — Realtime channel security detectors
    Detector(
        "baas_realtime_channel",
        r"\.channel\(['\"]([^'\"]+)['\"]\)",
        "info",
        "Supabase Realtime channel subscription in client code.",
        "Verify channel policies restrict who can subscribe.",
        ["sourcemaps", "code"],
        1,
        1,
        "baas",
        "baas_realtime_channel",
        "lead",
    ),
    Detector(
        "baas_realtime_subscribe",
        r"\.on\(['\"]postgres_changes['\"]",
        "info",
        "Supabase Realtime postgres_changes subscription in client code.",
        "Verify RLS policies apply to realtime subscriptions.",
        ["sourcemaps", "code"],
        pack="baas",
        finding_type="baas_realtime_subscribe",
        validation_status="lead",
    ),
    # ------------------------------------------------------------------
    # Runtime-only detectors — patterns only visible in live HTTP traffic
    # ------------------------------------------------------------------
    Detector(
        "otp_in_response",
        r"""(?:"otp"|"OTP"|"verification_code"|"verificationCode"|"2fa_code"|"twoFactorCode"|"sms_code"|"smsCode"|"pin_code"|"pinCode"|"one_time_password"|"mfa_code")\s*:\s*["']?(\d{4,8}|(?=[A-Za-z0-9]{4,8}\b)(?=[A-Za-z0-9]*\d)[A-Za-z0-9]{4,8})["']?""",
        "critical",
        "OTP or verification code found in API response body. Server sends the code to the client instead of validating server-side.",
        "Move OTP validation server-side. The server should verify the code, never send it to the client. This enables client-side OTP bypass.",
        ["sourcemaps", "code", "logs"],
        4,
        1,
        "appsec",
        "otp_in_response",
        "validated",
        ("https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",),
        True,
        attack_scenario="The server sends the OTP value in the API response. An attacker reads it from the network tab and enters it — bypassing two-factor authentication entirely. This is a recurring cause of real-world authentication breaches.",
    ),
    Detector(
        "hardcoded_credential_in_bundle",
        r"(?:(?:master[_-]?)?(?:password|passwd|pwd)|secret[_-]?key|admin[_-]?(?:password|secret|token)|default[_-]?(?:password|secret))\s*[:=]\s*[\"']([A-Za-z0-9!@#$%^&*_\-+=.]{8,64})[\"']",
        "high",
        "Hardcoded password or secret found in code.",
        "Remove the hardcoded credential, use environment variables or a secret manager, and rotate the exposed value.",
        ["code", "sourcemaps", "logs"],
        8,
        1,
        "appsec",
        "hardcoded_credential",
        "lead",
        (),
        False,
        attack_scenario="A hardcoded password in a JS bundle is accessible to any user who downloads the file. If it's a master password or admin secret, it grants full access bypass.",
        min_entropy=3.5,
    ),
]


def normalize_packs(packs: Optional[Iterable[str]] = None, profile: str = "launch-gate", surface: str = "local") -> Tuple[str, ...]:
    if packs:
        requested = tuple(dict.fromkeys(pack.strip().lower() for pack in packs if pack and pack.strip()))
    else:
        profile_map = EXTENSION_PROFILE_PACKS if surface == "extension" else WEB_PROFILE_PACKS if surface == "web" else PROFILE_PACKS
        requested = tuple(profile_map.get((profile or "launch-gate").strip().lower(), PROFILE_PACKS["launch-gate"]))

    invalid = [pack for pack in requested if pack not in DETECTOR_PACKS]
    if invalid:
        raise ValueError(f"Unknown detector pack(s): {', '.join(invalid)}")
    if surface in {"extension", "web"}:
        repo_only = [pack for pack in requested if pack in {"correctness", "housekeeping"}]
        if repo_only:
            raise ValueError(f"Repo-only detector pack(s): {', '.join(repo_only)}")
    return requested


def categories_for_packs(packs: Sequence[str]) -> Tuple[str, ...]:
    categories = set()
    for detector in DETECTORS:
        if detector.pack in packs:
            categories.update(detector.categories)
    return tuple(sorted(categories))


def detectors_for_categories(categories: Iterable[str], packs: Optional[Iterable[str]] = None, extension_only: bool = False) -> List[Detector]:
    requested = {category.strip().lower() for category in categories if category.strip()}
    requested_packs = set(normalize_packs(packs, profile="full")) if packs else set(DETECTOR_PACKS)
    detectors = [
        detector for detector in DETECTORS
        if detector.pack in requested_packs and (not extension_only or detector.extension)
    ]
    if not requested:
        return detectors
    return [detector for detector in detectors if requested.intersection(detector.categories)]


def detectors_for_packs(packs: Iterable[str], extension_only: bool = False) -> List[Detector]:
    requested_packs = set(normalize_packs(packs, profile="full"))
    return [
        detector for detector in DETECTORS
        if detector.pack in requested_packs and (not extension_only or detector.extension)
    ]
