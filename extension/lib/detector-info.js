/**
 * Generated detector knowledge base for KeyLeak Detector UI.
 * Source of truth: keyleak.detectors.DETECTORS.
 * Regenerate with: python3 scripts/generate_extension_patterns.py
 */

export const DETECTOR_INFO = {
  "anthropic_api_key": {
    "attack_scenario": "A leaked Anthropic key lets attackers spin up large Claude jobs on your bill, harvest any prompts or context they replay through it, and probe whatever tools your agent has bound to the same key.",
    "categories": [
      "env",
      "ci",
      "docker",
      "mcp",
      "sourcemaps",
      "logs"
    ],
    "description": "Anthropic API key exposed.",
    "detector_id": "leak.anthropic_api_key",
    "finding_type": "anthropic_api_key",
    "id": "anthropic_api_key",
    "pack": "leak",
    "references": [],
    "remediation": "Rotate the Anthropic key and move model calls behind a trusted server boundary.",
    "severity": "critical",
    "validation_status": "validated"
  },
  "anyscale_api_key": {
    "attack_scenario": null,
    "categories": [
      "env",
      "ci",
      "docker",
      "mcp",
      "sourcemaps",
      "logs"
    ],
    "description": "Anyscale API key exposed.",
    "detector_id": "leak.anyscale_api_key",
    "finding_type": "anyscale_api_key",
    "id": "anyscale_api_key",
    "pack": "leak",
    "references": [],
    "remediation": "Rotate the Anyscale key and audit inference endpoint usage.",
    "severity": "critical",
    "validation_status": "validated"
  },
  "appwrite_endpoint": {
    "attack_scenario": null,
    "categories": [
      "sourcemaps",
      "code"
    ],
    "description": "Appwrite API endpoint exposed in client bundle.",
    "detector_id": "baas.appwrite_endpoint",
    "finding_type": "appwrite_endpoint",
    "id": "appwrite_endpoint",
    "pack": "baas",
    "references": [],
    "remediation": "Verify Appwrite collection permissions deny unauthorized access.",
    "severity": "medium",
    "validation_status": "lead"
  },
  "auth_bypass_lead": {
    "attack_scenario": null,
    "categories": [
      "code",
      "env",
      "ci",
      "docker",
      "sourcemaps",
      "logs",
      "config"
    ],
    "description": "Auth-bypass lead found in shipped code or config.",
    "detector_id": "appsec.auth_bypass_lead",
    "finding_type": "auth_bypass",
    "id": "auth_bypass_lead",
    "pack": "appsec",
    "references": [
      "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"
    ],
    "remediation": "Remove bypass flags from production paths, enforce server-side authorization, and add an auth regression test.",
    "severity": "medium",
    "validation_status": "lead"
  },
  "aws_access_key": {
    "attack_scenario": "With even a guessable secret nearby, attackers enumerate S3 buckets, mint short-lived credentials via `sts:GetSessionToken`, and pivot into anything the IAM principal can reach. AKIA prefixes appear in honeypots within minutes of being public.",
    "categories": [
      "env",
      "ci",
      "docker",
      "mcp",
      "sourcemaps",
      "logs"
    ],
    "description": "AWS access key ID exposed.",
    "detector_id": "leak.aws_access_key",
    "finding_type": "aws_access_key",
    "id": "aws_access_key",
    "pack": "leak",
    "references": [],
    "remediation": "Rotate the access key and prefer IAM roles or workload identity over static credentials.",
    "severity": "high",
    "validation_status": "validated"
  },
  "aws_secret_key": {
    "attack_scenario": "Paired with the access key ID this is full AWS API access in the principal's scope: dump RDS snapshots, spin up crypto miners on every region's compute quota, or wipe everything and demand ransom for restore.",
    "categories": [
      "env",
      "ci",
      "docker",
      "mcp",
      "sourcemaps",
      "logs"
    ],
    "description": "AWS secret access key-like value exposed.",
    "detector_id": "leak.aws_secret_key",
    "finding_type": "aws_secret_key",
    "id": "aws_secret_key",
    "pack": "leak",
    "references": [],
    "remediation": "Rotate the AWS secret, review CloudTrail activity, and use IAM roles or a secret manager instead.",
    "severity": "critical",
    "validation_status": "validated"
  },
  "baas_delete_call": {
    "attack_scenario": null,
    "categories": [
      "sourcemaps",
      "code"
    ],
    "description": "BaaS delete mutation found in client code.",
    "detector_id": "baas.baas_delete_call",
    "finding_type": "baas_delete_call",
    "id": "baas_delete_call",
    "pack": "baas",
    "references": [],
    "remediation": "Verify RLS policies restrict who can delete from this table.",
    "severity": "info",
    "validation_status": "lead"
  },
  "baas_insert_call": {
    "attack_scenario": null,
    "categories": [
      "sourcemaps",
      "code"
    ],
    "description": "BaaS insert/upsert mutation found in client code.",
    "detector_id": "baas.baas_insert_call",
    "finding_type": "baas_insert_call",
    "id": "baas_insert_call",
    "pack": "baas",
    "references": [],
    "remediation": "Verify RLS policies restrict who can write to this table.",
    "severity": "info",
    "validation_status": "lead"
  },
  "baas_password_auth": {
    "attack_scenario": null,
    "categories": [
      "sourcemaps",
      "code"
    ],
    "description": "Password-based authentication flow detected in client code.",
    "detector_id": "baas.baas_password_auth",
    "finding_type": "baas_password_auth",
    "id": "baas_password_auth",
    "pack": "baas",
    "references": [],
    "remediation": "Ensure password policies, rate limiting, and email confirmation are configured.",
    "severity": "info",
    "validation_status": "lead"
  },
  "baas_realtime_channel": {
    "attack_scenario": null,
    "categories": [
      "sourcemaps",
      "code"
    ],
    "description": "Supabase Realtime channel subscription in client code.",
    "detector_id": "baas.baas_realtime_channel",
    "finding_type": "baas_realtime_channel",
    "id": "baas_realtime_channel",
    "pack": "baas",
    "references": [],
    "remediation": "Verify channel policies restrict who can subscribe.",
    "severity": "info",
    "validation_status": "lead"
  },
  "baas_realtime_subscribe": {
    "attack_scenario": null,
    "categories": [
      "sourcemaps",
      "code"
    ],
    "description": "Supabase Realtime postgres_changes subscription in client code.",
    "detector_id": "baas.baas_realtime_subscribe",
    "finding_type": "baas_realtime_subscribe",
    "id": "baas_realtime_subscribe",
    "pack": "baas",
    "references": [],
    "remediation": "Verify RLS policies apply to realtime subscriptions.",
    "severity": "info",
    "validation_status": "lead"
  },
  "baas_rpc_call": {
    "attack_scenario": null,
    "categories": [
      "sourcemaps",
      "code"
    ],
    "description": "BaaS RPC function called from client bundle.",
    "detector_id": "baas.baas_rpc_call",
    "finding_type": "baas_rpc_call",
    "id": "baas_rpc_call",
    "pack": "baas",
    "references": [],
    "remediation": "Verify this RPC function validates caller identity and rate-limits requests.",
    "severity": "info",
    "validation_status": "lead"
  },
  "baas_select_star": {
    "attack_scenario": null,
    "categories": [
      "sourcemaps",
      "code"
    ],
    "description": "BaaS table query uses select('*'), fetching all columns including potentially sensitive ones.",
    "detector_id": "baas.baas_select_star",
    "finding_type": "baas_select_star",
    "id": "baas_select_star",
    "pack": "baas",
    "references": [],
    "remediation": "Specify only the columns you need in select(). This reduces data exposure and improves performance.",
    "severity": "low",
    "validation_status": "lead"
  },
  "baas_storage_bucket": {
    "attack_scenario": null,
    "categories": [
      "sourcemaps",
      "code"
    ],
    "description": "BaaS storage bucket referenced in client bundle.",
    "detector_id": "baas.baas_storage_bucket",
    "finding_type": "baas_storage_bucket",
    "id": "baas_storage_bucket",
    "pack": "baas",
    "references": [],
    "remediation": "Verify storage bucket policies restrict who can upload, download, and list objects.",
    "severity": "low",
    "validation_status": "lead"
  },
  "baas_table_reference": {
    "attack_scenario": null,
    "categories": [
      "sourcemaps",
      "code"
    ],
    "description": "BaaS table name referenced in client bundle.",
    "detector_id": "baas.baas_table_reference",
    "finding_type": "baas_table_reference",
    "id": "baas_table_reference",
    "pack": "baas",
    "references": [],
    "remediation": "Review whether this table's RLS policies are correctly configured.",
    "severity": "info",
    "validation_status": "lead"
  },
  "bearer_token": {
    "attack_scenario": null,
    "categories": [
      "env",
      "ci",
      "docker",
      "mcp",
      "sourcemaps",
      "logs"
    ],
    "description": "Bearer token found in browser-visible content.",
    "detector_id": "leak.bearer_token",
    "finding_type": "bearer_token",
    "id": "bearer_token",
    "pack": "leak",
    "references": [],
    "remediation": "Move bearer tokens out of static content and use short-lived session-bound tokens.",
    "severity": "high",
    "validation_status": "validated"
  },
  "client_side_admin_check": {
    "attack_scenario": "An attacker sets is_admin=true in the browser console or modifies the JS bundle. Every admin-gated mutation (payouts, user management, moderation) becomes accessible.",
    "categories": [
      "sourcemaps",
      "code"
    ],
    "description": "Client-side admin/role check found. Authorization decisions in browser JS are trivially bypassable.",
    "detector_id": "baas.client_side_admin_check",
    "finding_type": "client_side_admin_check",
    "id": "client_side_admin_check",
    "pack": "baas",
    "references": [
      "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"
    ],
    "remediation": "Move all authorization checks to the server. Use Supabase RLS policies or Firebase Security Rules to enforce admin-only access.",
    "severity": "high",
    "validation_status": "lead"
  },
  "database_url": {
    "attack_scenario": "The embedded credentials grant whatever role the DB user has \u2014 typically full read of every row. Attackers pull customer PII, payment records, and password hashes for credential stuffing elsewhere; if the DB is internet-reachable it's game over.",
    "categories": [
      "env",
      "ci",
      "docker",
      "mcp",
      "sourcemaps",
      "logs"
    ],
    "description": "Database connection string with credentials exposed.",
    "detector_id": "leak.database_url",
    "finding_type": "database_url",
    "id": "database_url",
    "pack": "leak",
    "references": [],
    "remediation": "Rotate database credentials, restrict network access, and move connection strings to server-only configuration.",
    "severity": "critical",
    "validation_status": "validated"
  },
  "firebase_client_config": {
    "attack_scenario": "Firebase config grants access to Firestore, Realtime Database, and Storage. Without security rules, an attacker can read all documents, write arbitrary data, and access every file in Cloud Storage.",
    "categories": [
      "sourcemaps",
      "code",
      "env"
    ],
    "description": "Firebase client configuration with API key exposed in client bundle.",
    "detector_id": "baas.firebase_client_config",
    "finding_type": "firebase_client_config",
    "id": "firebase_client_config",
    "pack": "baas",
    "references": [
      "https://firebase.google.com/docs/rules"
    ],
    "remediation": "Firebase client config is designed for client use, but verify Firestore Security Rules and Storage Rules deny unauthorized access.",
    "severity": "medium",
    "validation_status": "lead"
  },
  "firebase_db_url": {
    "attack_scenario": "The Realtime Database URL allows direct REST API access. Without security rules, all data is readable and writable by anyone.",
    "categories": [
      "sourcemaps",
      "code",
      "env"
    ],
    "description": "Firebase Realtime Database URL exposed in client bundle.",
    "detector_id": "baas.firebase_db_url",
    "finding_type": "firebase_db_url",
    "id": "firebase_db_url",
    "pack": "baas",
    "references": [
      "https://firebase.google.com/docs/database/security"
    ],
    "remediation": "Verify Firebase Security Rules deny unauthorized read/write access.",
    "severity": "medium",
    "validation_status": "lead"
  },
  "firebase_server_key": {
    "attack_scenario": null,
    "categories": [
      "env",
      "ci",
      "docker",
      "mcp",
      "sourcemaps",
      "logs"
    ],
    "description": "Firebase/FCM server key exposed.",
    "detector_id": "leak.firebase_server_key",
    "finding_type": "firebase_server_key",
    "id": "firebase_server_key",
    "pack": "leak",
    "references": [],
    "remediation": "Rotate the Firebase key and confirm Firebase security rules prevent unauthorized access.",
    "severity": "high",
    "validation_status": "validated"
  },
  "firebase_storage_bucket": {
    "attack_scenario": null,
    "categories": [
      "sourcemaps",
      "code",
      "env"
    ],
    "description": "Firebase/GCP storage bucket referenced in client bundle.",
    "detector_id": "baas.firebase_storage_bucket",
    "finding_type": "firebase_storage_bucket",
    "id": "firebase_storage_bucket",
    "pack": "baas",
    "references": [],
    "remediation": "Verify Cloud Storage security rules restrict access.",
    "severity": "info",
    "validation_status": "lead"
  },
  "gemini_api_key": {
    "attack_scenario": null,
    "categories": [
      "env",
      "ci",
      "docker",
      "mcp",
      "sourcemaps",
      "logs"
    ],
    "description": "Google Gemini/API key exposed.",
    "detector_id": "leak.gemini_api_key",
    "finding_type": "gemini_api_key",
    "id": "gemini_api_key",
    "pack": "leak",
    "references": [],
    "remediation": "Rotate or restrict the Google API key, audit API usage, and keep model/provider credentials server-side.",
    "severity": "critical",
    "validation_status": "validated"
  },
  "gh_actions_pull_request_target": {
    "attack_scenario": "`pull_request_target` alone is informational \u2014 the worm hit @tanstack via the combination of this trigger AND a checkout of `head.ref` in the same job. Workflows that only read PR metadata (assign reviewers, label PRs, validate CLA) are safe.",
    "categories": [
      "ci"
    ],
    "description": "GitHub Actions workflow uses pull_request_target. Informational only \u2014 the leak shape is `pull_request_target` + checkout of `head.ref`. See `gh_actions_pwn_request_head_ref`.",
    "detector_id": "leak.gh_actions_pull_request_target",
    "finding_type": "gh_actions_pull_request_target",
    "id": "gh_actions_pull_request_target",
    "pack": "leak",
    "references": [
      "https://securitylab.github.com/research/github-actions-preventing-pwn-requests/"
    ],
    "remediation": "If this workflow runs untrusted PR code: switch to `pull_request`. If it only reads PR metadata (labeler, CLA bot), this trigger is fine and you can suppress this notice.",
    "severity": "info",
    "validation_status": "lead"
  },
  "gh_actions_pwn_request_head_ref": {
    "attack_scenario": "A `pull_request_target` workflow that also checks out the head branch runs attacker-controlled code with the base repo's secrets. Mini Shai-Hulud rode this exact combo into TanStack \u2014 a forked PR added a malicious script, the workflow checked it out, and the OIDC + npm tokens left.",
    "categories": [
      "ci"
    ],
    "description": "GitHub Actions workflow combines pull_request_target with checkout of head.ref/head.sha \u2014 this is the Pwn Request pattern that compromised TanStack/Mini-Shai-Hulud.",
    "detector_id": "leak.gh_actions_pwn_request_head_ref",
    "finding_type": "gh_actions_pwn_request_head_ref",
    "id": "gh_actions_pwn_request_head_ref",
    "pack": "leak",
    "references": [
      "https://securitylab.github.com/research/github-actions-preventing-pwn-requests/",
      "https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem"
    ],
    "remediation": "Move untrusted-code work into a separate `pull_request`-triggered workflow that has no secrets, and use `workflow_run` to pass artifacts only.",
    "severity": "high",
    "validation_status": "validated"
  },
  "gh_actions_secrets_tojson": {
    "attack_scenario": "`toJSON(secrets)` dumps every CI secret the job has into a single blob \u2014 typically logged or passed to a tool. Any later step that writes that blob to disk, logs it, or sends it over the network exfiltrates the entire vault. It's a load-bearing IOC for the Mini Shai-Hulud worm.",
    "categories": [
      "ci"
    ],
    "description": "GitHub Actions workflow serializes all secrets via toJSON(secrets). Mini Shai-Hulud (2026) used this exact pattern to bulk-exfiltrate CI secrets.",
    "detector_id": "leak.gh_actions_secrets_tojson",
    "finding_type": "gh_actions_secrets_tojson",
    "id": "gh_actions_secrets_tojson",
    "pack": "leak",
    "references": [
      "https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem"
    ],
    "remediation": "Reference only the specific secrets the job needs (`${{ secrets.NPM_TOKEN }}`). Never pass the entire `secrets` object as JSON to a step.",
    "severity": "high",
    "validation_status": "validated"
  },
  "github_pat": {
    "attack_scenario": "Attackers clone every private repo the token can read, push malicious commits or workflow files, and harvest CI secrets from workflow logs. Tokens with `repo` scope often own enough of the supply chain to backdoor downstream consumers.",
    "categories": [
      "env",
      "ci",
      "docker",
      "mcp",
      "sourcemaps",
      "logs"
    ],
    "description": "GitHub token exposed.",
    "detector_id": "leak.github_pat",
    "finding_type": "github_pat",
    "id": "github_pat",
    "pack": "leak",
    "references": [],
    "remediation": "Revoke the token, review repository access, and regenerate with the smallest necessary scope.",
    "severity": "critical",
    "validation_status": "validated"
  },
  "gitlab_token": {
    "attack_scenario": null,
    "categories": [
      "env",
      "ci",
      "docker",
      "mcp",
      "sourcemaps",
      "logs"
    ],
    "description": "GitLab token exposed.",
    "detector_id": "leak.gitlab_token",
    "finding_type": "gitlab_token",
    "id": "gitlab_token",
    "pack": "leak",
    "references": [],
    "remediation": "Revoke the GitLab token, review project/group access, and regenerate with the smallest scope possible.",
    "severity": "critical",
    "validation_status": "validated"
  },
  "google_service_account": {
    "attack_scenario": null,
    "categories": [
      "env",
      "ci",
      "docker",
      "mcp",
      "sourcemaps",
      "logs"
    ],
    "description": "Google service account key material exposed.",
    "detector_id": "leak.google_service_account",
    "finding_type": "google_service_account",
    "id": "google_service_account",
    "pack": "leak",
    "references": [],
    "remediation": "Revoke the service account key, audit IAM permissions, and move service credentials to secret storage.",
    "severity": "critical",
    "validation_status": "validated"
  },
  "graphql_introspection_hint": {
    "attack_scenario": null,
    "categories": [
      "sourcemaps",
      "logs"
    ],
    "description": "GraphQL introspection or schema content exposed.",
    "detector_id": "leak.graphql_introspection_hint",
    "finding_type": "graphql_introspection_hint",
    "id": "graphql_introspection_hint",
    "pack": "leak",
    "references": [],
    "remediation": "Confirm introspection is intentionally exposed and protected on production APIs.",
    "severity": "medium",
    "validation_status": "validated"
  },
  "groq_api_key": {
    "attack_scenario": null,
    "categories": [
      "env",
      "ci",
      "docker",
      "mcp",
      "sourcemaps",
      "logs"
    ],
    "description": "Groq API key exposed.",
    "detector_id": "leak.groq_api_key",
    "finding_type": "groq_api_key",
    "id": "groq_api_key",
    "pack": "leak",
    "references": [],
    "remediation": "Rotate the Groq key and keep inference credentials out of browser and agent config files.",
    "severity": "critical",
    "validation_status": "validated"
  },
  "hidden_prompt_injection": {
    "attack_scenario": null,
    "categories": [
      "sourcemaps",
      "logs"
    ],
    "description": "Prompt-injection style instruction found in content.",
    "detector_id": "leak.hidden_prompt_injection",
    "finding_type": "hidden_prompt_injection",
    "id": "hidden_prompt_injection",
    "pack": "leak",
    "references": [],
    "remediation": "Treat untrusted content as data, isolate agent tools, and avoid giving browsing agents access to secrets.",
    "severity": "medium",
    "validation_status": "validated"
  },
  "http_basic_auth": {
    "attack_scenario": "Credentials in URLs land in browser history, web-server logs, HTTP `Referer` headers, and CI logs. Anyone with read access to those logs escalates straight to whatever the credential authenticates against.",
    "categories": [
      "env",
      "ci",
      "docker",
      "mcp",
      "sourcemaps",
      "logs"
    ],
    "description": "HTTP Basic Auth credentials embedded in a URL.",
    "detector_id": "leak.http_basic_auth",
    "finding_type": "http_basic_auth",
    "id": "http_basic_auth",
    "pack": "leak",
    "references": [],
    "remediation": "Rotate the credentials and replace URL-embedded credentials with a safer authentication mechanism.",
    "severity": "high",
    "validation_status": "validated"
  },
  "huggingface_token": {
    "attack_scenario": null,
    "categories": [
      "env",
      "ci",
      "docker",
      "mcp",
      "sourcemaps",
      "logs"
    ],
    "description": "Hugging Face token exposed.",
    "detector_id": "leak.huggingface_token",
    "finding_type": "huggingface_token",
    "id": "huggingface_token",
    "pack": "leak",
    "references": [],
    "remediation": "Rotate the token, review model/dataset access, and avoid shipping provider tokens in browser bundles.",
    "severity": "high",
    "validation_status": "validated"
  },
  "idor_direct_object_lead": {
    "attack_scenario": "If the server doesn't check ownership, swapping `/users/123` for `/users/124` returns another tenant's data. Attackers script through every ID to enumerate the full customer base. Validate with a two-user scan: `keyleak scan ... --bearer $A --bearer-b $B`.",
    "categories": [
      "code",
      "sourcemaps",
      "logs"
    ],
    "description": "Direct object reference lead found in a sensitive resource path or parameter.",
    "detector_id": "access-control.idor_direct_object_lead",
    "finding_type": "idor",
    "id": "idor_direct_object_lead",
    "pack": "access-control",
    "references": [
      "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"
    ],
    "remediation": "Verify object ownership on the server with tenant/user scoped queries and re-test with two throwaway users.",
    "severity": "medium",
    "validation_status": "lead"
  },
  "jwt_token": {
    "attack_scenario": "A leaked JWT impersonates its subject until expiry. Even without the signing key, the base64 payload usually reveals role, tenant, and internal IDs that accelerate attacks against the rest of the system.",
    "categories": [
      "env",
      "ci",
      "docker",
      "mcp",
      "sourcemaps",
      "logs"
    ],
    "description": "JWT found in browser-visible content.",
    "detector_id": "leak.jwt_token",
    "finding_type": "jwt_token",
    "id": "jwt_token",
    "pack": "leak",
    "references": [],
    "remediation": "Confirm the token is short-lived, not logged or embedded, and does not expose sensitive claims.",
    "severity": "medium",
    "validation_status": "validated"
  },
  "mcp_config_secret": {
    "attack_scenario": null,
    "categories": [
      "mcp",
      "env",
      "docker",
      "logs"
    ],
    "description": "MCP or agent tool credential exposed.",
    "detector_id": "leak.mcp_config_secret",
    "finding_type": "mcp_config_secret",
    "id": "mcp_config_secret",
    "pack": "leak",
    "references": [],
    "remediation": "Move agent/tool credentials to local secret storage and review connected tool permissions.",
    "severity": "high",
    "validation_status": "validated"
  },
  "missing_tenant_check_lead": {
    "attack_scenario": null,
    "categories": [
      "code",
      "sourcemaps",
      "logs",
      "config"
    ],
    "description": "Missing tenant or ownership-check lead found.",
    "detector_id": "access-control.missing_tenant_check_lead",
    "finding_type": "missing_tenant_check",
    "id": "missing_tenant_check_lead",
    "pack": "access-control",
    "references": [
      "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"
    ],
    "remediation": "Make the tenant boundary mandatory in server-side queries and add a cross-tenant negative test.",
    "severity": "medium",
    "validation_status": "lead"
  },
  "npm_optional_dep_git_ref": {
    "attack_scenario": "An attacker that lands a PR adding `optionalDependencies: { '@x/setup': 'github:org/repo#<sha>' }` runs arbitrary code on every install via the orphan commit's `prepare` hook. This is exactly how Mini Shai-Hulud compromised 42 @tanstack/* packages on 2026-05-11 and stole AWS/GCP/Vault/GitHub/npm credentials from anyone who installed.",
    "categories": [
      "env",
      "ci",
      "docker",
      "mcp",
      "sourcemaps",
      "logs",
      "code",
      "config"
    ],
    "description": "package.json optionalDependencies points to a git commit SHA. This is the Mini Shai-Hulud (TanStack 2026) attack vector.",
    "detector_id": "leak.npm_optional_dep_git_ref",
    "finding_type": "npm_optional_dep_git_ref",
    "id": "npm_optional_dep_git_ref",
    "pack": "leak",
    "references": [
      "https://tanstack.com/blog/npm-supply-chain-compromise-postmortem",
      "https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem"
    ],
    "remediation": "Remove the git-ref optionalDependency. Replace with a pinned semver from the registry or vendor the code in-tree.",
    "severity": "high",
    "validation_status": "validated"
  },
  "npm_prepare_bun_payload": {
    "attack_scenario": "The TanStack worm executed its payload through `prepare: \"bun run tanstack_runner.js && exit 1\"` in the malicious tarball's package.json. Any install (developer machine or CI runner) immediately ran the harvester. `--ignore-scripts` blocks this vector entirely; pnpm v10 does it by default in CI.",
    "categories": [
      "env",
      "ci",
      "docker",
      "mcp",
      "code",
      "config"
    ],
    "description": "package.json prepare/preinstall/postinstall script runs Bun or a TanStack-style payload file. Mini Shai-Hulud (2026) executed `bun run tanstack_runner.js && exit 1`.",
    "detector_id": "leak.npm_prepare_bun_payload",
    "finding_type": "npm_prepare_bun_payload",
    "id": "npm_prepare_bun_payload",
    "pack": "leak",
    "references": [
      "https://tanstack.com/blog/npm-supply-chain-compromise-postmortem"
    ],
    "remediation": "Inspect the script and the referenced JS file. If the file is bundled, opaque, or not in version control, treat the package as compromised. Add `--ignore-scripts` to your install command and switch to pnpm v10+ for default-off lifecycle execution.",
    "severity": "high",
    "validation_status": "lead"
  },
  "npm_token": {
    "attack_scenario": null,
    "categories": [
      "env",
      "ci",
      "docker",
      "mcp",
      "sourcemaps",
      "logs"
    ],
    "description": "npm token exposed.",
    "detector_id": "leak.npm_token",
    "finding_type": "npm_token",
    "id": "npm_token",
    "pack": "leak",
    "references": [],
    "remediation": "Revoke the npm token and audit package publish activity.",
    "severity": "critical",
    "validation_status": "validated"
  },
  "openai_api_key": {
    "attack_scenario": "Anyone who scrapes the bundle, response, or repo runs inference on your bill. Costs can spike to thousands of dollars within hours, and the key fingerprints your account for follow-up abuse.",
    "categories": [
      "env",
      "ci",
      "docker",
      "mcp",
      "sourcemaps",
      "logs"
    ],
    "description": "OpenAI API key exposed.",
    "detector_id": "leak.openai_api_key",
    "finding_type": "openai_api_key",
    "id": "openai_api_key",
    "pack": "leak",
    "references": [],
    "remediation": "Rotate the OpenAI key, remove it from client/config files, and load it server-side from a secret manager.",
    "severity": "critical",
    "validation_status": "validated"
  },
  "openrouter_api_key": {
    "attack_scenario": null,
    "categories": [
      "env",
      "ci",
      "docker",
      "mcp",
      "sourcemaps",
      "logs"
    ],
    "description": "OpenRouter API key exposed.",
    "detector_id": "leak.openrouter_api_key",
    "finding_type": "openrouter_api_key",
    "id": "openrouter_api_key",
    "pack": "leak",
    "references": [],
    "remediation": "Rotate the OpenRouter key and audit usage because this can proxy access to multiple model providers.",
    "severity": "critical",
    "validation_status": "validated"
  },
  "perplexity_api_key": {
    "attack_scenario": null,
    "categories": [
      "env",
      "ci",
      "docker",
      "mcp",
      "sourcemaps",
      "logs"
    ],
    "description": "Perplexity API key exposed.",
    "detector_id": "leak.perplexity_api_key",
    "finding_type": "perplexity_api_key",
    "id": "perplexity_api_key",
    "pack": "leak",
    "references": [],
    "remediation": "Rotate the Perplexity key and keep model-provider credentials out of client-side code.",
    "severity": "critical",
    "validation_status": "validated"
  },
  "pocketbase_url": {
    "attack_scenario": null,
    "categories": [
      "sourcemaps",
      "code"
    ],
    "description": "PocketBase instance URL exposed in client bundle.",
    "detector_id": "baas.pocketbase_url",
    "finding_type": "pocketbase_url",
    "id": "pocketbase_url",
    "pack": "baas",
    "references": [],
    "remediation": "Verify PocketBase collection API rules restrict access.",
    "severity": "medium",
    "validation_status": "lead"
  },
  "private_ip": {
    "attack_scenario": null,
    "categories": [
      "sourcemaps",
      "logs"
    ],
    "description": "Private network address exposed.",
    "detector_id": "leak.private_ip",
    "finding_type": "private_ip",
    "id": "private_ip",
    "pack": "leak",
    "references": [],
    "remediation": "Review whether internal topology details should be visible in client-side content.",
    "severity": "low",
    "validation_status": "validated"
  },
  "private_key": {
    "attack_scenario": "Whoever holds the key can impersonate the server or user it was issued to: sign fake TLS certs, mint JWTs your services already trust, or SSH into every host that trusts this key. Rotation is mandatory; you cannot un-leak a private key.",
    "categories": [
      "env",
      "ci",
      "docker",
      "mcp",
      "logs"
    ],
    "description": "Private key exposed.",
    "detector_id": "leak.private_key",
    "finding_type": "private_key",
    "id": "private_key",
    "pack": "leak",
    "references": [],
    "remediation": "Revoke and rotate the key immediately, then audit every system where it was trusted.",
    "severity": "critical",
    "validation_status": "validated"
  },
  "pypi_upload_token": {
    "attack_scenario": null,
    "categories": [
      "env",
      "ci",
      "docker",
      "mcp",
      "sourcemaps",
      "logs"
    ],
    "description": "PyPI upload token exposed.",
    "detector_id": "leak.pypi_upload_token",
    "finding_type": "pypi_upload_token",
    "id": "pypi_upload_token",
    "pack": "leak",
    "references": [],
    "remediation": "Revoke the PyPI token and audit package release history.",
    "severity": "critical",
    "validation_status": "validated"
  },
  "replicate_api_key": {
    "attack_scenario": null,
    "categories": [
      "env",
      "ci",
      "docker",
      "mcp",
      "sourcemaps",
      "logs"
    ],
    "description": "Replicate API key exposed.",
    "detector_id": "leak.replicate_api_key",
    "finding_type": "replicate_api_key",
    "id": "replicate_api_key",
    "pack": "leak",
    "references": [],
    "remediation": "Rotate the Replicate key and move inference calls behind a trusted server boundary.",
    "severity": "critical",
    "validation_status": "validated"
  },
  "secret_in_logs_lead": {
    "attack_scenario": null,
    "categories": [
      "code",
      "sourcemaps",
      "logs"
    ],
    "description": "Secret-in-logs lead found.",
    "detector_id": "leak.secret_in_logs_lead",
    "finding_type": "secret_in_logs",
    "id": "secret_in_logs_lead",
    "pack": "leak",
    "references": [],
    "remediation": "Remove secrets from logs, redact sensitive fields at the logger boundary, and rotate any value that may already have been written.",
    "severity": "medium",
    "validation_status": "lead"
  },
  "sendgrid_api_key": {
    "attack_scenario": null,
    "categories": [
      "env",
      "ci",
      "docker",
      "mcp",
      "sourcemaps",
      "logs"
    ],
    "description": "SendGrid API key exposed.",
    "detector_id": "leak.sendgrid_api_key",
    "finding_type": "sendgrid_api_key",
    "id": "sendgrid_api_key",
    "pack": "leak",
    "references": [],
    "remediation": "Rotate the SendGrid key and audit mail-sending activity for abuse.",
    "severity": "critical",
    "validation_status": "validated"
  },
  "shai_hulud_c2_domain": {
    "attack_scenario": "The Mini Shai-Hulud worm sends stolen credentials to the Session/Oxen messenger network (`filev2.getsession.org`, `seed{1,2,3}.getsession.org`) and uses `api.masscan.cloud` and `git-tanstack.com` for C2. If your code, logs, or build artifacts mention any of these, an installed dependency is already exfiltrating data.",
    "categories": [
      "env",
      "ci",
      "docker",
      "mcp",
      "sourcemaps",
      "logs",
      "code"
    ],
    "description": "Mini Shai-Hulud command-and-control or exfiltration domain found.",
    "detector_id": "leak.shai_hulud_c2_domain",
    "finding_type": "shai_hulud_c2_domain",
    "id": "shai_hulud_c2_domain",
    "pack": "leak",
    "references": [
      "https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem",
      "https://tanstack.com/blog/npm-supply-chain-compromise-postmortem"
    ],
    "remediation": "Treat the host as compromised. Rotate every credential reachable from the affected machine or CI runner: AWS, GCP, Kubernetes, Vault, GitHub, npm, SSH. Then audit egress logs to confirm what left.",
    "severity": "critical",
    "validation_status": "validated"
  },
  "slack_token": {
    "attack_scenario": null,
    "categories": [
      "env",
      "ci",
      "docker",
      "mcp",
      "sourcemaps",
      "logs"
    ],
    "description": "Slack token exposed.",
    "detector_id": "leak.slack_token",
    "finding_type": "slack_token",
    "id": "slack_token",
    "pack": "leak",
    "references": [],
    "remediation": "Revoke the Slack token, review workspace app scopes, and regenerate with least privilege.",
    "severity": "critical",
    "validation_status": "validated"
  },
  "slack_webhook": {
    "attack_scenario": null,
    "categories": [
      "env",
      "ci",
      "docker",
      "mcp",
      "sourcemaps",
      "logs"
    ],
    "description": "Slack webhook URL exposed.",
    "detector_id": "leak.slack_webhook",
    "finding_type": "slack_webhook",
    "id": "slack_webhook",
    "pack": "leak",
    "references": [],
    "remediation": "Regenerate the webhook and keep it out of browser bundles and public config.",
    "severity": "high",
    "validation_status": "validated"
  },
  "source_map_reference": {
    "attack_scenario": "Source maps reveal pre-minified code, in-line API URLs, internal field names, and sometimes secrets injected at build time. Attackers reverse-engineer your auth flow, business rules, and authorization edges much faster than they could from the minified bundle.",
    "categories": [
      "sourcemaps"
    ],
    "description": "Browser bundle references a source map.",
    "detector_id": "leak.source_map_reference",
    "finding_type": "source_map_reference",
    "id": "source_map_reference",
    "pack": "leak",
    "references": [],
    "remediation": "Review generated source maps for embedded secrets and avoid publishing private source in production.",
    "severity": "low",
    "validation_status": "validated"
  },
  "sql_injection_lead": {
    "attack_scenario": null,
    "categories": [
      "code",
      "sourcemaps",
      "logs"
    ],
    "description": "SQL injection lead found in query construction or database error output.",
    "detector_id": "appsec.sql_injection_lead",
    "finding_type": "sql_injection",
    "id": "sql_injection_lead",
    "pack": "appsec",
    "references": [
      "https://owasp.org/www-community/attacks/SQL_Injection"
    ],
    "remediation": "Parameterize the query, validate the input at the boundary, and re-test the endpoint with the launch gate after the fix.",
    "severity": "medium",
    "validation_status": "lead"
  },
  "stripe_restricted_key": {
    "attack_scenario": null,
    "categories": [
      "env",
      "ci",
      "docker",
      "sourcemaps",
      "logs"
    ],
    "description": "Stripe restricted key exposed.",
    "detector_id": "leak.stripe_restricted_key",
    "finding_type": "stripe_restricted_key",
    "id": "stripe_restricted_key",
    "pack": "leak",
    "references": [],
    "remediation": "Rotate the Stripe restricted key and move payment operations to server-side endpoints.",
    "severity": "critical",
    "validation_status": "validated"
  },
  "stripe_secret_key": {
    "attack_scenario": "A `sk_live_` key is direct Stripe API access: attackers refund or void any charge, create payouts to attacker-controlled bank accounts, dump customer payment metadata, and rack up fraudulent transactions before anyone notices.",
    "categories": [
      "env",
      "ci",
      "docker",
      "sourcemaps",
      "logs"
    ],
    "description": "Stripe secret key exposed.",
    "detector_id": "leak.stripe_secret_key",
    "finding_type": "stripe_secret_key",
    "id": "stripe_secret_key",
    "pack": "leak",
    "references": [],
    "remediation": "Rotate the Stripe key and move payment operations behind server-side endpoints.",
    "severity": "critical",
    "validation_status": "validated"
  },
  "supabase_publishable_key": {
    "attack_scenario": null,
    "categories": [
      "sourcemaps",
      "code",
      "env"
    ],
    "description": "Supabase publishable key (non-standard format) exposed in client bundle.",
    "detector_id": "baas.supabase_publishable_key",
    "finding_type": "supabase_publishable_key",
    "id": "supabase_publishable_key",
    "pack": "baas",
    "references": [],
    "remediation": "Confirm RLS policies protect every table. Run BaaS validation to test.",
    "severity": "medium",
    "validation_status": "lead"
  },
  "supabase_url": {
    "attack_scenario": "Combined with the anon key, the project URL enables direct REST API queries against every table. Missing or misconfigured RLS makes all data readable by anyone.",
    "categories": [
      "sourcemaps",
      "code",
      "env"
    ],
    "description": "Supabase project URL exposed in client bundle.",
    "detector_id": "baas.supabase_url",
    "finding_type": "supabase_url",
    "id": "supabase_url",
    "pack": "baas",
    "references": [
      "https://supabase.com/docs/guides/auth/row-level-security"
    ],
    "remediation": "Verify RLS policies are enforced on all tables. Run `keyleak browser-scan` with BaaS validation to confirm.",
    "severity": "medium",
    "validation_status": "lead"
  },
  "webhook_url": {
    "attack_scenario": null,
    "categories": [
      "env",
      "ci",
      "docker",
      "mcp",
      "sourcemaps",
      "logs"
    ],
    "description": "Webhook URL exposed.",
    "detector_id": "leak.webhook_url",
    "finding_type": "webhook_url",
    "id": "webhook_url",
    "pack": "leak",
    "references": [],
    "remediation": "Review whether the webhook is secret-bearing, rotate it if sensitive, and add authentication where possible.",
    "severity": "medium",
    "validation_status": "validated"
  },
  "xss_sink_lead": {
    "attack_scenario": null,
    "categories": [
      "code",
      "sourcemaps",
      "logs"
    ],
    "description": "XSS lead found where untrusted input can reach an HTML sink.",
    "detector_id": "appsec.xss_sink_lead",
    "finding_type": "xss",
    "id": "xss_sink_lead",
    "pack": "appsec",
    "references": [
      "https://owasp.org/www-community/attacks/xss/"
    ],
    "remediation": "Render untrusted values as text, sanitize unavoidable HTML with an allowlist sanitizer, and add a regression test for the sink.",
    "severity": "medium",
    "validation_status": "lead"
  }
};

export function getDetectorInfo(detectorId) {
  if (!detectorId) return null;
  if (DETECTOR_INFO[detectorId]) return DETECTOR_INFO[detectorId];
  // Detector IDs surface as either bare ids (`openai_api_key`)
  // or canonical ids (`leak.openai_api_key`). Fall back to the trailing segment.
  const tail = String(detectorId).split('.').pop();
  return DETECTOR_INFO[tail] || null;
}
