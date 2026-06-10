/**
 * Generated detector bundle for KeyLeak Detector.
 * Source of truth: keyleak.detectors.DETECTORS.
 * Regenerate with: python3 scripts/generate_extension_patterns.py
 */

const PATTERN_DEFINITIONS = [
  {
    "capture_group": 0,
    "categories": [
      "env",
      "ci",
      "docker",
      "mcp",
      "sourcemaps",
      "logs"
    ],
    "category": "leak",
    "description": "OpenAI API key exposed.",
    "detector_id": "leak.openai_api_key",
    "finding_type": "openai_api_key",
    "flags": "gim",
    "id": "openai_api_key",
    "min_match_length": 8,
    "pack": "leak",
    "pattern": "\\bsk-(?!(?:ant|or)-)(?:proj-)?[A-Za-z0-9_-]{20,}\\b",
    "references": [],
    "remediation": "Rotate the OpenAI key, remove it from client/config files, and load it server-side from a secret manager.",
    "severity": "critical",
    "validation_status": "validated"
  },
  {
    "capture_group": 0,
    "categories": [
      "env",
      "ci",
      "docker",
      "mcp",
      "sourcemaps",
      "logs"
    ],
    "category": "leak",
    "description": "Anthropic API key exposed.",
    "detector_id": "leak.anthropic_api_key",
    "finding_type": "anthropic_api_key",
    "flags": "gim",
    "id": "anthropic_api_key",
    "min_match_length": 8,
    "pack": "leak",
    "pattern": "\\bsk-ant-[A-Za-z0-9_-]{80,}\\b",
    "references": [],
    "remediation": "Rotate the Anthropic key and move model calls behind a trusted server boundary.",
    "severity": "critical",
    "validation_status": "validated"
  },
  {
    "capture_group": 0,
    "categories": [
      "env",
      "ci",
      "docker",
      "mcp",
      "sourcemaps",
      "logs"
    ],
    "category": "leak",
    "description": "OpenRouter API key exposed.",
    "detector_id": "leak.openrouter_api_key",
    "finding_type": "openrouter_api_key",
    "flags": "gim",
    "id": "openrouter_api_key",
    "min_match_length": 8,
    "pack": "leak",
    "pattern": "\\bsk-or-v1-[A-Za-z0-9]{48,}\\b",
    "references": [],
    "remediation": "Rotate the OpenRouter key and audit usage because this can proxy access to multiple model providers.",
    "severity": "critical",
    "validation_status": "validated"
  },
  {
    "capture_group": 0,
    "categories": [
      "env",
      "ci",
      "docker",
      "mcp",
      "sourcemaps",
      "logs"
    ],
    "category": "leak",
    "description": "Google Gemini/API key exposed.",
    "detector_id": "leak.gemini_api_key",
    "finding_type": "gemini_api_key",
    "flags": "gim",
    "id": "gemini_api_key",
    "min_match_length": 8,
    "pack": "leak",
    "pattern": "\\bAIza[0-9A-Za-z\\-_]{35}\\b",
    "references": [],
    "remediation": "Rotate or restrict the Google API key, audit API usage, and keep model/provider credentials server-side.",
    "severity": "critical",
    "validation_status": "validated"
  },
  {
    "capture_group": 0,
    "categories": [
      "env",
      "ci",
      "docker",
      "mcp",
      "sourcemaps",
      "logs"
    ],
    "category": "leak",
    "description": "Hugging Face token exposed.",
    "detector_id": "leak.huggingface_token",
    "finding_type": "huggingface_token",
    "flags": "gim",
    "id": "huggingface_token",
    "min_match_length": 8,
    "pack": "leak",
    "pattern": "\\bhf_[A-Za-z0-9]{32,}\\b",
    "references": [],
    "remediation": "Rotate the token, review model/dataset access, and avoid shipping provider tokens in browser bundles.",
    "severity": "high",
    "validation_status": "validated"
  },
  {
    "capture_group": 0,
    "categories": [
      "env",
      "ci",
      "docker",
      "mcp",
      "sourcemaps",
      "logs"
    ],
    "category": "leak",
    "description": "Replicate API key exposed.",
    "detector_id": "leak.replicate_api_key",
    "finding_type": "replicate_api_key",
    "flags": "gim",
    "id": "replicate_api_key",
    "min_match_length": 8,
    "pack": "leak",
    "pattern": "\\br8_[A-Za-z0-9]{40,}\\b",
    "references": [],
    "remediation": "Rotate the Replicate key and move inference calls behind a trusted server boundary.",
    "severity": "critical",
    "validation_status": "validated"
  },
  {
    "capture_group": 0,
    "categories": [
      "env",
      "ci",
      "docker",
      "mcp",
      "sourcemaps",
      "logs"
    ],
    "category": "leak",
    "description": "Perplexity API key exposed.",
    "detector_id": "leak.perplexity_api_key",
    "finding_type": "perplexity_api_key",
    "flags": "gim",
    "id": "perplexity_api_key",
    "min_match_length": 8,
    "pack": "leak",
    "pattern": "\\bpplx-[A-Za-z0-9]{40,}\\b",
    "references": [],
    "remediation": "Rotate the Perplexity key and keep model-provider credentials out of client-side code.",
    "severity": "critical",
    "validation_status": "validated"
  },
  {
    "capture_group": 0,
    "categories": [
      "env",
      "ci",
      "docker",
      "mcp",
      "sourcemaps",
      "logs"
    ],
    "category": "leak",
    "description": "Anyscale API key exposed.",
    "detector_id": "leak.anyscale_api_key",
    "finding_type": "anyscale_api_key",
    "flags": "gim",
    "id": "anyscale_api_key",
    "min_match_length": 8,
    "pack": "leak",
    "pattern": "\\besecret_[A-Za-z0-9]{40,}\\b",
    "references": [],
    "remediation": "Rotate the Anyscale key and audit inference endpoint usage.",
    "severity": "critical",
    "validation_status": "validated"
  },
  {
    "capture_group": 0,
    "categories": [
      "env",
      "ci",
      "docker",
      "mcp",
      "sourcemaps",
      "logs"
    ],
    "category": "leak",
    "description": "Groq API key exposed.",
    "detector_id": "leak.groq_api_key",
    "finding_type": "groq_api_key",
    "flags": "gim",
    "id": "groq_api_key",
    "min_match_length": 8,
    "pack": "leak",
    "pattern": "\\bgsk_[A-Za-z0-9]{40,}\\b",
    "references": [],
    "remediation": "Rotate the Groq key and keep inference credentials out of browser and agent config files.",
    "severity": "critical",
    "validation_status": "validated"
  },
  {
    "capture_group": 0,
    "categories": [
      "env",
      "ci",
      "docker",
      "mcp",
      "sourcemaps",
      "logs"
    ],
    "category": "leak",
    "description": "GitHub token exposed.",
    "detector_id": "leak.github_pat",
    "finding_type": "github_pat",
    "flags": "gim",
    "id": "github_pat",
    "min_match_length": 8,
    "pack": "leak",
    "pattern": "\\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\\b|\\bgithub_pat_[A-Za-z0-9_]{70,}\\b",
    "references": [],
    "remediation": "Revoke the token, review repository access, and regenerate with the smallest necessary scope.",
    "severity": "critical",
    "validation_status": "validated"
  },
  {
    "capture_group": 0,
    "categories": [
      "env",
      "ci",
      "docker",
      "mcp",
      "sourcemaps",
      "logs"
    ],
    "category": "leak",
    "description": "AWS access key ID exposed.",
    "detector_id": "leak.aws_access_key",
    "finding_type": "aws_access_key",
    "flags": "gim",
    "id": "aws_access_key",
    "min_match_length": 8,
    "pack": "leak",
    "pattern": "\\b(?:AKIA|ASIA)[0-9A-Z]{16}\\b",
    "references": [],
    "remediation": "Rotate the access key and prefer IAM roles or workload identity over static credentials.",
    "severity": "high",
    "validation_status": "validated"
  },
  {
    "capture_group": 1,
    "categories": [
      "env",
      "ci",
      "docker",
      "mcp",
      "sourcemaps",
      "logs"
    ],
    "category": "leak",
    "description": "AWS secret access key-like value exposed.",
    "detector_id": "leak.aws_secret_key",
    "finding_type": "aws_secret_key",
    "flags": "gim",
    "id": "aws_secret_key",
    "min_match_length": 8,
    "pack": "leak",
    "pattern": "\\baws.{0,30}(?:secret|access).{0,20}[\\\"'\\s:=]+([A-Za-z0-9/+=]{40})",
    "references": [],
    "remediation": "Rotate the AWS secret, review CloudTrail activity, and use IAM roles or a secret manager instead.",
    "severity": "critical",
    "validation_status": "validated"
  },
  {
    "capture_group": 0,
    "categories": [
      "env",
      "ci",
      "docker",
      "mcp",
      "sourcemaps",
      "logs"
    ],
    "category": "leak",
    "description": "Google service account key material exposed.",
    "detector_id": "leak.google_service_account",
    "finding_type": "google_service_account",
    "flags": "gim",
    "id": "google_service_account",
    "min_match_length": 8,
    "pack": "leak",
    "pattern": "\\\"type\\\":\\s*\\\"service_account\\\"[\\s\\S]*?\\\"private_key\\\":\\s*\\\"-----BEGIN PRIVATE KEY-----",
    "references": [],
    "remediation": "Revoke the service account key, audit IAM permissions, and move service credentials to secret storage.",
    "severity": "critical",
    "validation_status": "validated"
  },
  {
    "capture_group": 0,
    "categories": [
      "env",
      "ci",
      "docker",
      "mcp",
      "sourcemaps",
      "logs"
    ],
    "category": "leak",
    "description": "Firebase/FCM server key exposed.",
    "detector_id": "leak.firebase_server_key",
    "finding_type": "firebase_server_key",
    "flags": "gim",
    "id": "firebase_server_key",
    "min_match_length": 8,
    "pack": "leak",
    "pattern": "\\bAAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{120,}\\b",
    "references": [],
    "remediation": "Rotate the Firebase key and confirm Firebase security rules prevent unauthorized access.",
    "severity": "high",
    "validation_status": "validated"
  },
  {
    "capture_group": 0,
    "categories": [
      "env",
      "ci",
      "docker",
      "sourcemaps",
      "logs"
    ],
    "category": "leak",
    "description": "Stripe secret key exposed.",
    "detector_id": "leak.stripe_secret_key",
    "finding_type": "stripe_secret_key",
    "flags": "gim",
    "id": "stripe_secret_key",
    "min_match_length": 8,
    "pack": "leak",
    "pattern": "\\bsk_(?:live|test)_[0-9A-Za-z]{24,}\\b",
    "references": [],
    "remediation": "Rotate the Stripe key and move payment operations behind server-side endpoints.",
    "severity": "critical",
    "validation_status": "validated"
  },
  {
    "capture_group": 0,
    "categories": [
      "env",
      "ci",
      "docker",
      "sourcemaps",
      "logs"
    ],
    "category": "leak",
    "description": "Stripe restricted key exposed.",
    "detector_id": "leak.stripe_restricted_key",
    "finding_type": "stripe_restricted_key",
    "flags": "gim",
    "id": "stripe_restricted_key",
    "min_match_length": 8,
    "pack": "leak",
    "pattern": "\\brk_(?:live|test)_[0-9A-Za-z]{24,}\\b",
    "references": [],
    "remediation": "Rotate the Stripe restricted key and move payment operations to server-side endpoints.",
    "severity": "critical",
    "validation_status": "validated"
  },
  {
    "capture_group": 0,
    "categories": [
      "env",
      "ci",
      "docker",
      "mcp",
      "sourcemaps",
      "logs"
    ],
    "category": "leak",
    "description": "Slack token exposed.",
    "detector_id": "leak.slack_token",
    "finding_type": "slack_token",
    "flags": "gim",
    "id": "slack_token",
    "min_match_length": 8,
    "pack": "leak",
    "pattern": "\\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,32}\\b",
    "references": [],
    "remediation": "Revoke the Slack token, review workspace app scopes, and regenerate with least privilege.",
    "severity": "critical",
    "validation_status": "validated"
  },
  {
    "capture_group": 0,
    "categories": [
      "env",
      "ci",
      "docker",
      "mcp",
      "sourcemaps",
      "logs"
    ],
    "category": "leak",
    "description": "Slack webhook URL exposed.",
    "detector_id": "leak.slack_webhook",
    "finding_type": "slack_webhook",
    "flags": "gim",
    "id": "slack_webhook",
    "min_match_length": 8,
    "pack": "leak",
    "pattern": "https://hooks\\.slack\\.com/services/[A-Za-z0-9_/-]{20,}",
    "references": [],
    "remediation": "Regenerate the webhook and keep it out of browser bundles and public config.",
    "severity": "high",
    "validation_status": "validated"
  },
  {
    "capture_group": 0,
    "categories": [
      "env",
      "ci",
      "docker",
      "mcp",
      "sourcemaps",
      "logs"
    ],
    "category": "leak",
    "description": "GitLab token exposed.",
    "detector_id": "leak.gitlab_token",
    "finding_type": "gitlab_token",
    "flags": "gim",
    "id": "gitlab_token",
    "min_match_length": 8,
    "pack": "leak",
    "pattern": "\\bglpat-[A-Za-z0-9\\-]{20,}\\b",
    "references": [],
    "remediation": "Revoke the GitLab token, review project/group access, and regenerate with the smallest scope possible.",
    "severity": "critical",
    "validation_status": "validated"
  },
  {
    "capture_group": 0,
    "categories": [
      "env",
      "ci",
      "docker",
      "mcp",
      "sourcemaps",
      "logs"
    ],
    "category": "leak",
    "description": "npm token exposed.",
    "detector_id": "leak.npm_token",
    "finding_type": "npm_token",
    "flags": "gim",
    "id": "npm_token",
    "min_match_length": 8,
    "pack": "leak",
    "pattern": "\\bnpm_[A-Za-z0-9\\-_]{36}\\b",
    "references": [],
    "remediation": "Revoke the npm token and audit package publish activity.",
    "severity": "critical",
    "validation_status": "validated"
  },
  {
    "capture_group": 0,
    "categories": [
      "env",
      "ci",
      "docker",
      "mcp",
      "sourcemaps",
      "logs"
    ],
    "category": "leak",
    "description": "SendGrid API key exposed.",
    "detector_id": "leak.sendgrid_api_key",
    "finding_type": "sendgrid_api_key",
    "flags": "gim",
    "id": "sendgrid_api_key",
    "min_match_length": 8,
    "pack": "leak",
    "pattern": "\\bSG\\.[A-Za-z0-9_-]{22}\\.[A-Za-z0-9_-]{43}\\b",
    "references": [],
    "remediation": "Rotate the SendGrid key and audit mail-sending activity for abuse.",
    "severity": "critical",
    "validation_status": "validated"
  },
  {
    "capture_group": 0,
    "categories": [
      "env",
      "ci",
      "docker",
      "mcp",
      "sourcemaps",
      "logs"
    ],
    "category": "leak",
    "description": "PyPI upload token exposed.",
    "detector_id": "leak.pypi_upload_token",
    "finding_type": "pypi_upload_token",
    "flags": "gim",
    "id": "pypi_upload_token",
    "min_match_length": 8,
    "pack": "leak",
    "pattern": "\\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9\\-_]{50,}\\b",
    "references": [],
    "remediation": "Revoke the PyPI token and audit package release history.",
    "severity": "critical",
    "validation_status": "validated"
  },
  {
    "capture_group": 0,
    "categories": [
      "env",
      "ci",
      "docker",
      "mcp",
      "sourcemaps",
      "logs"
    ],
    "category": "leak",
    "description": "Database connection string with credentials exposed.",
    "detector_id": "leak.database_url",
    "finding_type": "database_url",
    "flags": "gim",
    "id": "database_url",
    "min_match_length": 8,
    "pack": "leak",
    "pattern": "\\b(?:postgres(?:ql)?|mysql(?:2)?|mongodb(?:\\+srv)?|redis)://[^\\s'\\\"<>]+:[^\\s'\\\"<>]+@[^\\s'\\\"<>]+",
    "references": [],
    "remediation": "Rotate database credentials, restrict network access, and move connection strings to server-only configuration.",
    "severity": "critical",
    "validation_status": "validated"
  },
  {
    "capture_group": 0,
    "categories": [
      "env",
      "ci",
      "docker",
      "config",
      "code",
      "sourcemaps",
      "logs"
    ],
    "category": "leak",
    "description": "ADO.NET / ODBC / JDBC database connection string with an embedded password.",
    "detector_id": "leak.dotnet_sql_connection_string",
    "finding_type": "dotnet_sql_connection_string",
    "flags": "gim",
    "id": "dotnet_sql_connection_string",
    "min_match_length": 8,
    "pack": "leak",
    "pattern": "(?:(?:Server|Data Source)\\s*=\\s*[^;'\\\"]+;[\\s\\S]{0,200}?(?:Password|Pwd)\\s*=\\s*[^;'\\\"\\s]{3,}|jdbc:(?:sqlserver|postgresql|mysql|oracle:thin)://[^\\s'\\\"]+[?;&](?:password|pwd)\\s*=\\s*[^\\s'\\\"&;]{3,})",
    "references": [
      "https://cwe.mitre.org/data/definitions/798.html",
      "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"
    ],
    "remediation": "Rotate the database password, move connection strings to a server-side secret store, and never ship them in client bundles, config files, or logs.",
    "severity": "critical",
    "validation_status": "validated"
  },
  {
    "capture_group": 0,
    "categories": [
      "env",
      "ci",
      "docker",
      "mcp",
      "logs"
    ],
    "category": "leak",
    "description": "Private key exposed.",
    "detector_id": "leak.private_key",
    "finding_type": "private_key",
    "flags": "gim",
    "id": "private_key",
    "min_match_length": 8,
    "pack": "leak",
    "pattern": "-----BEGIN (?:(?:RSA|DSA|EC|OPENSSH) )?PRIVATE KEY-----[\\s\\S]+?-----END (?:(?:RSA|DSA|EC|OPENSSH) )?PRIVATE KEY-----",
    "references": [],
    "remediation": "Revoke and rotate the key immediately, then audit every system where it was trusted.",
    "severity": "critical",
    "validation_status": "validated"
  },
  {
    "capture_group": 0,
    "categories": [
      "env",
      "ci",
      "docker",
      "mcp",
      "sourcemaps",
      "logs"
    ],
    "category": "leak",
    "description": "JWT found in browser-visible content.",
    "detector_id": "leak.jwt_token",
    "finding_type": "jwt_token",
    "flags": "gim",
    "id": "jwt_token",
    "min_match_length": 8,
    "pack": "leak",
    "pattern": "\\beyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\b",
    "references": [],
    "remediation": "Confirm the token is short-lived, not logged or embedded, and does not expose sensitive claims.",
    "severity": "medium",
    "validation_status": "validated"
  },
  {
    "capture_group": 1,
    "categories": [
      "env",
      "ci",
      "docker",
      "mcp",
      "sourcemaps",
      "logs"
    ],
    "category": "leak",
    "description": "Bearer token found in browser-visible content.",
    "detector_id": "leak.bearer_token",
    "finding_type": "bearer_token",
    "flags": "gim",
    "id": "bearer_token",
    "min_match_length": 8,
    "pack": "leak",
    "pattern": "\\bbearer[\\s:=]+([A-Za-z0-9_\\-.]{20,})\\b",
    "references": [],
    "remediation": "Move bearer tokens out of static content and use short-lived session-bound tokens.",
    "severity": "high",
    "validation_status": "validated"
  },
  {
    "capture_group": 0,
    "categories": [
      "env",
      "ci",
      "docker",
      "mcp",
      "sourcemaps",
      "logs"
    ],
    "category": "leak",
    "description": "HTTP Basic Auth credentials embedded in a URL.",
    "detector_id": "leak.http_basic_auth",
    "finding_type": "http_basic_auth",
    "flags": "gim",
    "id": "http_basic_auth",
    "min_match_length": 8,
    "pack": "leak",
    "pattern": "\\bhttps?://([A-Za-z0-9_-]+):([^@\\s]+)@",
    "references": [],
    "remediation": "Rotate the credentials and replace URL-embedded credentials with a safer authentication mechanism.",
    "severity": "high",
    "validation_status": "validated"
  },
  {
    "capture_group": 0,
    "categories": [
      "sourcemaps",
      "logs"
    ],
    "category": "leak",
    "description": "Prompt-injection style instruction found in content.",
    "detector_id": "leak.hidden_prompt_injection",
    "finding_type": "hidden_prompt_injection",
    "flags": "gim",
    "id": "hidden_prompt_injection",
    "min_match_length": 8,
    "pack": "leak",
    "pattern": "(?:ignore (?:all )?previous instructions|system prompt|developer message|exfiltrate|send (?:the )?(?:token|secret|api key)|hidden instruction)",
    "references": [],
    "remediation": "Treat untrusted content as data, isolate agent tools, and avoid giving browsing agents access to secrets.",
    "severity": "medium",
    "validation_status": "validated"
  },
  {
    "capture_group": 0,
    "categories": [
      "sourcemaps",
      "logs"
    ],
    "category": "leak",
    "description": "GraphQL introspection or schema content exposed.",
    "detector_id": "leak.graphql_introspection_hint",
    "finding_type": "graphql_introspection_hint",
    "flags": "gim",
    "id": "graphql_introspection_hint",
    "min_match_length": 1,
    "pack": "leak",
    "pattern": "\\b(?:__schema|__type|IntrospectionQuery)\\b",
    "references": [],
    "remediation": "Confirm introspection is intentionally exposed and protected on production APIs.",
    "severity": "medium",
    "validation_status": "validated"
  },
  {
    "capture_group": 0,
    "categories": [
      "sourcemaps"
    ],
    "category": "leak",
    "description": "Browser bundle references a source map.",
    "detector_id": "leak.source_map_reference",
    "finding_type": "source_map_reference",
    "flags": "gim",
    "id": "source_map_reference",
    "min_match_length": 8,
    "pack": "leak",
    "pattern": "sourceMappingURL=[^\\s'\\\"<>]+\\.map\\b",
    "references": [],
    "remediation": "Review generated source maps for embedded secrets and avoid publishing private source in production.",
    "severity": "low",
    "validation_status": "validated"
  },
  {
    "capture_group": 0,
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
    "category": "leak",
    "description": "package.json optionalDependencies points to a git commit SHA. This is the Mini Shai-Hulud (TanStack 2026) attack vector.",
    "detector_id": "leak.npm_optional_dep_git_ref",
    "finding_type": "npm_optional_dep_git_ref",
    "flags": "gim",
    "id": "npm_optional_dep_git_ref",
    "min_match_length": 20,
    "pack": "leak",
    "pattern": "\\\"optionalDependencies\\\"\\s*:\\s*\\{[^}]*\\\"[^\\\"]+\\\"\\s*:\\s*\\\"(?:github:[^\\\"]+|git\\+(?:https?|ssh)://[^\\\"]+)#[a-f0-9]{7,40}",
    "references": [
      "https://tanstack.com/blog/npm-supply-chain-compromise-postmortem",
      "https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem"
    ],
    "remediation": "Remove the git-ref optionalDependency. Replace with a pinned semver from the registry or vendor the code in-tree.",
    "severity": "high",
    "validation_status": "validated"
  },
  {
    "capture_group": 0,
    "categories": [
      "ci"
    ],
    "category": "leak",
    "description": "GitHub Actions workflow uses pull_request_target. Informational only \u2014 the leak shape is `pull_request_target` + checkout of `head.ref`. See `gh_actions_pwn_request_head_ref`.",
    "detector_id": "leak.gh_actions_pull_request_target",
    "finding_type": "gh_actions_pull_request_target",
    "flags": "gim",
    "id": "gh_actions_pull_request_target",
    "min_match_length": 12,
    "pack": "leak",
    "pattern": "(?:^|\\n)\\s*on\\s*:[\\s\\S]{0,400}\\bpull_request_target\\b",
    "references": [
      "https://securitylab.github.com/research/github-actions-preventing-pwn-requests/"
    ],
    "remediation": "If this workflow runs untrusted PR code: switch to `pull_request`. If it only reads PR metadata (labeler, CLA bot), this trigger is fine and you can suppress this notice.",
    "severity": "info",
    "validation_status": "lead"
  },
  {
    "capture_group": 0,
    "categories": [
      "ci"
    ],
    "category": "leak",
    "description": "GitHub Actions workflow combines pull_request_target with checkout of head.ref/head.sha \u2014 this is the Pwn Request pattern that compromised TanStack/Mini-Shai-Hulud.",
    "detector_id": "leak.gh_actions_pwn_request_head_ref",
    "finding_type": "gh_actions_pwn_request_head_ref",
    "flags": "gim",
    "id": "gh_actions_pwn_request_head_ref",
    "min_match_length": 24,
    "pack": "leak",
    "pattern": "\\bpull_request_target\\b[\\s\\S]{0,4000}?actions/checkout[\\s\\S]{0,400}?ref\\s*:\\s*\\$\\{\\{\\s*github\\.event\\.pull_request\\.head\\.(?:ref|sha)\\s*\\}\\}",
    "references": [
      "https://securitylab.github.com/research/github-actions-preventing-pwn-requests/",
      "https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem"
    ],
    "remediation": "Move untrusted-code work into a separate `pull_request`-triggered workflow that has no secrets, and use `workflow_run` to pass artifacts only.",
    "severity": "high",
    "validation_status": "validated"
  },
  {
    "capture_group": 0,
    "categories": [
      "ci"
    ],
    "category": "leak",
    "description": "GitHub Actions workflow serializes all secrets via toJSON(secrets). Mini Shai-Hulud (2026) used this exact pattern to bulk-exfiltrate CI secrets.",
    "detector_id": "leak.gh_actions_secrets_tojson",
    "finding_type": "gh_actions_secrets_tojson",
    "flags": "gim",
    "id": "gh_actions_secrets_tojson",
    "min_match_length": 12,
    "pack": "leak",
    "pattern": "toJSON\\(\\s*secrets\\s*\\)",
    "references": [
      "https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem"
    ],
    "remediation": "Reference only the specific secrets the job needs (`${{ secrets.NPM_TOKEN }}`). Never pass the entire `secrets` object as JSON to a step.",
    "severity": "high",
    "validation_status": "validated"
  },
  {
    "capture_group": 0,
    "categories": [
      "env",
      "ci",
      "docker",
      "mcp",
      "sourcemaps",
      "logs",
      "code"
    ],
    "category": "leak",
    "description": "Mini Shai-Hulud command-and-control or exfiltration domain found.",
    "detector_id": "leak.shai_hulud_c2_domain",
    "finding_type": "shai_hulud_c2_domain",
    "flags": "gim",
    "id": "shai_hulud_c2_domain",
    "min_match_length": 8,
    "pack": "leak",
    "pattern": "\\b(?:filev2\\.getsession\\.org|seed[1-3]\\.getsession\\.org|api\\.masscan\\.cloud|git-tanstack\\.com)\\b",
    "references": [
      "https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem",
      "https://tanstack.com/blog/npm-supply-chain-compromise-postmortem"
    ],
    "remediation": "Treat the host as compromised. Rotate every credential reachable from the affected machine or CI runner: AWS, GCP, Kubernetes, Vault, GitHub, npm, SSH. Then audit egress logs to confirm what left.",
    "severity": "critical",
    "validation_status": "validated"
  },
  {
    "capture_group": 0,
    "categories": [
      "env",
      "ci",
      "docker",
      "mcp",
      "code",
      "config"
    ],
    "category": "leak",
    "description": "package.json prepare/preinstall/postinstall script runs Bun or a TanStack-style payload file. Mini Shai-Hulud (2026) executed `bun run tanstack_runner.js && exit 1`.",
    "detector_id": "leak.npm_prepare_bun_payload",
    "finding_type": "npm_prepare_bun_payload",
    "flags": "gim",
    "id": "npm_prepare_bun_payload",
    "min_match_length": 18,
    "pack": "leak",
    "pattern": "\\\"(?:prepare|preinstall|postinstall)\\\"\\s*:\\s*\\\"[^\\\"]*\\b(?:bun\\s+run|node\\s+(?:\\./)?(?:tanstack_runner|router_init|router_runtime))[^\\\"]*\\\"",
    "references": [
      "https://tanstack.com/blog/npm-supply-chain-compromise-postmortem"
    ],
    "remediation": "Inspect the script and the referenced JS file. If the file is bundled, opaque, or not in version control, treat the package as compromised. Add `--ignore-scripts` to your install command and switch to pnpm v10+ for default-off lifecycle execution.",
    "severity": "high",
    "validation_status": "lead"
  },
  {
    "capture_group": 0,
    "categories": [
      "env",
      "ci",
      "docker",
      "mcp",
      "sourcemaps",
      "logs"
    ],
    "category": "leak",
    "description": "Webhook URL exposed.",
    "detector_id": "leak.webhook_url",
    "finding_type": "webhook_url",
    "flags": "gim",
    "id": "webhook_url",
    "min_match_length": 8,
    "pack": "leak",
    "pattern": "\\bhttps?://[^\\s'\\\"<>]+webhook[^\\s'\\\"<>]*",
    "references": [],
    "remediation": "Review whether the webhook is secret-bearing, rotate it if sensitive, and add authentication where possible.",
    "severity": "medium",
    "validation_status": "validated"
  },
  {
    "capture_group": 0,
    "categories": [
      "sourcemaps",
      "logs"
    ],
    "category": "leak",
    "description": "Private network address exposed.",
    "detector_id": "leak.private_ip",
    "finding_type": "private_ip",
    "flags": "gim",
    "id": "private_ip",
    "min_match_length": 8,
    "pack": "leak",
    "pattern": "\\b(?:10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}|172\\.(?:1[6-9]|2[0-9]|3[0-1])\\.\\d{1,3}\\.\\d{1,3}|192\\.168\\.\\d{1,3}\\.\\d{1,3})\\b",
    "references": [],
    "remediation": "Review whether internal topology details should be visible in client-side content.",
    "severity": "low",
    "validation_status": "validated"
  },
  {
    "capture_group": 0,
    "categories": [
      "code",
      "sourcemaps",
      "logs"
    ],
    "category": "leak",
    "description": "Secret-in-logs lead found.",
    "detector_id": "leak.secret_in_logs_lead",
    "finding_type": "secret_in_logs",
    "flags": "gim",
    "id": "secret_in_logs_lead",
    "min_match_length": 12,
    "pack": "leak",
    "pattern": "(?:console\\.log|logger\\.(?:debug|info|warn|error)|print\\s*\\()[\\s\\S]{0,120}?(?<![a-z0-9_])(?:api[_-]?key|secret|token|password|authorization|cookie)(?![a-z0-9_])",
    "references": [],
    "remediation": "Remove secrets from logs, redact sensitive fields at the logger boundary, and rotate any value that may already have been written.",
    "severity": "medium",
    "validation_status": "lead"
  },
  {
    "capture_group": 0,
    "categories": [
      "code",
      "sourcemaps",
      "logs"
    ],
    "category": "appsec",
    "description": "XSS lead found where untrusted input can reach an HTML sink.",
    "detector_id": "appsec.xss_sink_lead",
    "finding_type": "xss",
    "flags": "gim",
    "id": "xss_sink_lead",
    "min_match_length": 12,
    "pack": "appsec",
    "pattern": "(?:\\b(?:innerHTML|outerHTML)\\s*=\\s*(?:location|window\\.location|document\\.URL|[\\s\\S]{0,80}(?:searchParams|location\\.hash|message\\.data|postMessage))|document\\.write\\s*\\([\\s\\S]{0,120}(?:location|document\\.URL|message\\.data)|insertAdjacentHTML\\s*\\([\\s\\S]{0,160}(?:location|message\\.data|query|hash)|dangerouslySetInnerHTML\\s*=\\s*\\{\\{)",
    "references": [
      "https://owasp.org/www-community/attacks/xss/"
    ],
    "remediation": "Render untrusted values as text, sanitize unavoidable HTML with an allowlist sanitizer, and add a regression test for the sink.",
    "severity": "medium",
    "validation_status": "lead"
  },
  {
    "capture_group": 0,
    "categories": [
      "code",
      "env",
      "ci",
      "docker",
      "sourcemaps",
      "logs",
      "config"
    ],
    "category": "appsec",
    "description": "Auth-bypass lead found in shipped code or config.",
    "detector_id": "appsec.auth_bypass_lead",
    "finding_type": "auth_bypass",
    "flags": "gim",
    "id": "auth_bypass_lead",
    "min_match_length": 8,
    "pack": "appsec",
    "pattern": "\\b(?:disable[_-]?auth|skip[_-]?auth|bypass[_-]?auth|auth[_-]?disabled|ALLOW_ALL_USERS|requireAuth\\s*[:=]\\s*false|isAdmin\\s*[:=]\\s*true|TODO:?[\\s\\S]{0,60}(?:auth|authorization|permission))\\b",
    "references": [
      "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"
    ],
    "remediation": "Remove bypass flags from production paths, enforce server-side authorization, and add an auth regression test.",
    "severity": "medium",
    "validation_status": "lead"
  },
  {
    "capture_group": 0,
    "categories": [
      "code",
      "sourcemaps",
      "logs"
    ],
    "category": "access-control",
    "description": "Direct object reference lead found in a sensitive resource path or parameter.",
    "detector_id": "access-control.idor_direct_object_lead",
    "finding_type": "idor",
    "flags": "gim",
    "id": "idor_direct_object_lead",
    "min_match_length": 6,
    "pack": "access-control",
    "pattern": "(?:/(?:users?|accounts?|customers?|tenants?|organizations?|orgs?|projects?|orders?)/[0-9a-fA-F-]{6,}|(?:user|account|customer|tenant|organization|project|order)[_-]?id\\s*[:=]\\s*[`'\\\"]?\\$\\{?[^`'\\\"\\s}]+)",
    "references": [
      "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"
    ],
    "remediation": "Verify object ownership on the server with tenant/user scoped queries and re-test with two throwaway users.",
    "severity": "medium",
    "validation_status": "lead"
  },
  {
    "capture_group": 0,
    "categories": [
      "code",
      "sourcemaps",
      "logs",
      "config"
    ],
    "category": "access-control",
    "description": "Missing tenant or ownership-check lead found.",
    "detector_id": "access-control.missing_tenant_check_lead",
    "finding_type": "missing_tenant_check",
    "flags": "gim",
    "id": "missing_tenant_check_lead",
    "min_match_length": 8,
    "pack": "access-control",
    "pattern": "(?:TODO:?[\\s\\S]{0,80}(?:tenant|ownership|authorization|permission)|(?:tenant|org|organization|workspace|account)[_-]?id[\\s\\S]{0,80}(?:optional|nullable|skip|TODO|FIXME))",
    "references": [
      "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"
    ],
    "remediation": "Make the tenant boundary mandatory in server-side queries and add a cross-tenant negative test.",
    "severity": "medium",
    "validation_status": "lead"
  },
  {
    "capture_group": 0,
    "categories": [
      "sourcemaps",
      "code",
      "env"
    ],
    "category": "baas",
    "description": "Supabase project URL exposed in client bundle.",
    "detector_id": "baas.supabase_url",
    "finding_type": "supabase_url",
    "flags": "gim",
    "id": "supabase_url",
    "min_match_length": 8,
    "pack": "baas",
    "pattern": "\\bhttps://[a-z0-9]{20,}\\.supabase\\.co\\b",
    "references": [
      "https://supabase.com/docs/guides/auth/row-level-security"
    ],
    "remediation": "Verify RLS policies are enforced on all tables. Run `keyleak browser-scan` with BaaS validation to confirm.",
    "severity": "medium",
    "validation_status": "lead"
  },
  {
    "capture_group": 0,
    "categories": [
      "sourcemaps",
      "code",
      "env"
    ],
    "category": "baas",
    "description": "Supabase publishable key (non-standard format) exposed in client bundle.",
    "detector_id": "baas.supabase_publishable_key",
    "finding_type": "supabase_publishable_key",
    "flags": "gim",
    "id": "supabase_publishable_key",
    "min_match_length": 8,
    "pack": "baas",
    "pattern": "\\bsb_publishable_[A-Za-z0-9_-]{20,}\\b",
    "references": [],
    "remediation": "Confirm RLS policies protect every table. Run BaaS validation to test.",
    "severity": "medium",
    "validation_status": "lead"
  },
  {
    "capture_group": 0,
    "categories": [
      "sourcemaps",
      "code",
      "env"
    ],
    "category": "baas",
    "description": "Firebase client configuration with API key exposed in client bundle.",
    "detector_id": "baas.firebase_client_config",
    "finding_type": "firebase_client_config",
    "flags": "gim",
    "id": "firebase_client_config",
    "min_match_length": 8,
    "pack": "baas",
    "pattern": "apiKey['\\\"\\s:=]+AIza[0-9A-Za-z_-]{35}",
    "references": [
      "https://firebase.google.com/docs/rules"
    ],
    "remediation": "Firebase client config is designed for client use, but verify Firestore Security Rules and Storage Rules deny unauthorized access.",
    "severity": "medium",
    "validation_status": "lead"
  },
  {
    "capture_group": 0,
    "categories": [
      "sourcemaps",
      "code"
    ],
    "category": "baas",
    "description": "Client-side admin/role check found. Authorization decisions in browser JS are trivially bypassable.",
    "detector_id": "baas.client_side_admin_check",
    "finding_type": "client_side_admin_check",
    "flags": "gim",
    "id": "client_side_admin_check",
    "min_match_length": 8,
    "pack": "baas",
    "pattern": "(?:is_admin|isAdmin|is_superuser|isSuperuser)\\s*(?:===?\\s*(?:true|!0)|!==?\\s*(?:false|!1))",
    "references": [
      "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"
    ],
    "remediation": "Move all authorization checks to the server. Use Supabase RLS policies or Firebase Security Rules to enforce admin-only access.",
    "severity": "high",
    "validation_status": "lead"
  },
  {
    "capture_group": 0,
    "categories": [
      "sourcemaps",
      "code"
    ],
    "category": "baas",
    "description": "BaaS table query uses select('*'), fetching all columns including potentially sensitive ones.",
    "detector_id": "baas.baas_select_star",
    "finding_type": "baas_select_star",
    "flags": "gim",
    "id": "baas_select_star",
    "min_match_length": 8,
    "pack": "baas",
    "pattern": "\\.from\\(['\\\"][a-z_][a-z0-9_]*['\\\"]\\)[\\s\\S]{0,60}\\.select\\(['\\\"]?\\*['\\\"]?\\)",
    "references": [],
    "remediation": "Specify only the columns you need in select(). This reduces data exposure and improves performance.",
    "severity": "low",
    "validation_status": "lead"
  },
  {
    "capture_group": 1,
    "categories": [
      "sourcemaps",
      "code"
    ],
    "category": "baas",
    "description": "BaaS table name referenced in client bundle.",
    "detector_id": "baas.baas_table_reference",
    "finding_type": "baas_table_reference",
    "flags": "gim",
    "id": "baas_table_reference",
    "min_match_length": 1,
    "pack": "baas",
    "pattern": "\\.from\\(['\\\"]([a-z_][a-z0-9_]{1,62})['\\\"]\\)",
    "references": [],
    "remediation": "Review whether this table's RLS policies are correctly configured.",
    "severity": "info",
    "validation_status": "lead"
  },
  {
    "capture_group": 1,
    "categories": [
      "sourcemaps",
      "code"
    ],
    "category": "baas",
    "description": "BaaS RPC function called from client bundle.",
    "detector_id": "baas.baas_rpc_call",
    "finding_type": "baas_rpc_call",
    "flags": "gim",
    "id": "baas_rpc_call",
    "min_match_length": 1,
    "pack": "baas",
    "pattern": "\\.rpc\\(['\\\"]([a-z_][a-z0-9_]{1,62})['\\\"]",
    "references": [],
    "remediation": "Verify this RPC function validates caller identity and rate-limits requests.",
    "severity": "info",
    "validation_status": "lead"
  },
  {
    "capture_group": 1,
    "categories": [
      "sourcemaps",
      "code"
    ],
    "category": "baas",
    "description": "BaaS storage bucket referenced in client bundle.",
    "detector_id": "baas.baas_storage_bucket",
    "finding_type": "baas_storage_bucket",
    "flags": "gim",
    "id": "baas_storage_bucket",
    "min_match_length": 1,
    "pack": "baas",
    "pattern": "\\.storage\\.from\\(['\\\"]([a-z0-9_-]{1,62})['\\\"]\\)",
    "references": [],
    "remediation": "Verify storage bucket policies restrict who can upload, download, and list objects.",
    "severity": "low",
    "validation_status": "lead"
  },
  {
    "capture_group": 0,
    "categories": [
      "sourcemaps",
      "code",
      "env"
    ],
    "category": "baas",
    "description": "Firebase Realtime Database URL exposed in client bundle.",
    "detector_id": "baas.firebase_db_url",
    "finding_type": "firebase_db_url",
    "flags": "gim",
    "id": "firebase_db_url",
    "min_match_length": 8,
    "pack": "baas",
    "pattern": "\\bhttps://[a-z0-9-]+\\.firebaseio\\.com\\b",
    "references": [
      "https://firebase.google.com/docs/database/security"
    ],
    "remediation": "Verify Firebase Security Rules deny unauthorized read/write access.",
    "severity": "medium",
    "validation_status": "lead"
  },
  {
    "capture_group": 0,
    "categories": [
      "sourcemaps",
      "code",
      "env"
    ],
    "category": "baas",
    "description": "Firebase/GCP storage bucket referenced in client bundle.",
    "detector_id": "baas.firebase_storage_bucket",
    "finding_type": "firebase_storage_bucket",
    "flags": "gim",
    "id": "firebase_storage_bucket",
    "min_match_length": 8,
    "pack": "baas",
    "pattern": "\\b[a-z0-9-]+\\.appspot\\.com\\b",
    "references": [],
    "remediation": "Verify Cloud Storage security rules restrict access.",
    "severity": "info",
    "validation_status": "lead"
  },
  {
    "capture_group": 0,
    "categories": [
      "sourcemaps",
      "code"
    ],
    "category": "baas",
    "description": "Appwrite API endpoint exposed in client bundle.",
    "detector_id": "baas.appwrite_endpoint",
    "finding_type": "appwrite_endpoint",
    "flags": "gim",
    "id": "appwrite_endpoint",
    "min_match_length": 8,
    "pack": "baas",
    "pattern": "\\.setEndpoint\\(['\\\"]https?://[^'\\\"]+/v1['\\\"]\\)",
    "references": [],
    "remediation": "Verify Appwrite collection permissions deny unauthorized access.",
    "severity": "medium",
    "validation_status": "lead"
  },
  {
    "capture_group": 0,
    "categories": [
      "sourcemaps",
      "code"
    ],
    "category": "baas",
    "description": "PocketBase instance URL exposed in client bundle.",
    "detector_id": "baas.pocketbase_url",
    "finding_type": "pocketbase_url",
    "flags": "gim",
    "id": "pocketbase_url",
    "min_match_length": 8,
    "pack": "baas",
    "pattern": "new PocketBase\\(['\\\"]https?://[^'\\\"]+['\\\"]\\)",
    "references": [],
    "remediation": "Verify PocketBase collection API rules restrict access.",
    "severity": "medium",
    "validation_status": "lead"
  },
  {
    "capture_group": 0,
    "categories": [
      "sourcemaps",
      "code"
    ],
    "category": "baas",
    "description": "BaaS insert/upsert mutation found in client code.",
    "detector_id": "baas.baas_insert_call",
    "finding_type": "baas_insert_call",
    "flags": "gim",
    "id": "baas_insert_call",
    "min_match_length": 8,
    "pack": "baas",
    "pattern": "\\.(?:insert|upsert)\\(",
    "references": [],
    "remediation": "Verify RLS policies restrict who can write to this table.",
    "severity": "info",
    "validation_status": "lead"
  },
  {
    "capture_group": 0,
    "categories": [
      "sourcemaps",
      "code"
    ],
    "category": "baas",
    "description": "BaaS delete mutation found in client code.",
    "detector_id": "baas.baas_delete_call",
    "finding_type": "baas_delete_call",
    "flags": "gim",
    "id": "baas_delete_call",
    "min_match_length": 8,
    "pack": "baas",
    "pattern": "\\.delete\\(\\)",
    "references": [],
    "remediation": "Verify RLS policies restrict who can delete from this table.",
    "severity": "info",
    "validation_status": "lead"
  },
  {
    "capture_group": 0,
    "categories": [
      "sourcemaps",
      "code"
    ],
    "category": "baas",
    "description": "Password-based authentication flow detected in client code.",
    "detector_id": "baas.baas_password_auth",
    "finding_type": "baas_password_auth",
    "flags": "gim",
    "id": "baas_password_auth",
    "min_match_length": 8,
    "pack": "baas",
    "pattern": "signInWithPassword",
    "references": [],
    "remediation": "Ensure password policies, rate limiting, and email confirmation are configured.",
    "severity": "info",
    "validation_status": "lead"
  },
  {
    "capture_group": 1,
    "categories": [
      "sourcemaps",
      "code"
    ],
    "category": "baas",
    "description": "Supabase Realtime channel subscription in client code.",
    "detector_id": "baas.baas_realtime_channel",
    "finding_type": "baas_realtime_channel",
    "flags": "gim",
    "id": "baas_realtime_channel",
    "min_match_length": 1,
    "pack": "baas",
    "pattern": "\\.channel\\(['\\\"]([^'\\\"]+)['\\\"]\\)",
    "references": [],
    "remediation": "Verify channel policies restrict who can subscribe.",
    "severity": "info",
    "validation_status": "lead"
  },
  {
    "capture_group": 0,
    "categories": [
      "sourcemaps",
      "code"
    ],
    "category": "baas",
    "description": "Supabase Realtime postgres_changes subscription in client code.",
    "detector_id": "baas.baas_realtime_subscribe",
    "finding_type": "baas_realtime_subscribe",
    "flags": "gim",
    "id": "baas_realtime_subscribe",
    "min_match_length": 8,
    "pack": "baas",
    "pattern": "\\.on\\(['\\\"]postgres_changes['\\\"]",
    "references": [],
    "remediation": "Verify RLS policies apply to realtime subscriptions.",
    "severity": "info",
    "validation_status": "lead"
  },
  {
    "capture_group": 1,
    "categories": [
      "sourcemaps",
      "code",
      "logs"
    ],
    "category": "appsec",
    "description": "OTP or verification code found in API response body. Server sends the code to the client instead of validating server-side.",
    "detector_id": "appsec.otp_in_response",
    "finding_type": "otp_in_response",
    "flags": "gim",
    "id": "otp_in_response",
    "min_match_length": 4,
    "pack": "appsec",
    "pattern": "(?:\"otp\"|\"OTP\"|\"verification_code\"|\"verificationCode\"|\"2fa_code\"|\"twoFactorCode\"|\"sms_code\"|\"smsCode\"|\"pin_code\"|\"pinCode\"|\"one_time_password\"|\"mfa_code\")\\s*:\\s*[\"']?(\\d{4,8}|(?=[A-Za-z0-9]{4,8}\\b)(?=[A-Za-z0-9]*\\d)[A-Za-z0-9]{4,8})[\"']?",
    "references": [
      "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"
    ],
    "remediation": "Move OTP validation server-side. The server should verify the code, never send it to the client. This enables client-side OTP bypass.",
    "severity": "critical",
    "validation_status": "validated"
  }
];

const PATTERNS = {};
const COMPILED_PATTERNS = {};

for (const definition of PATTERN_DEFINITIONS) {
  try {
    const entry = {
      id: definition.id,
      detector_id: definition.detector_id,
      finding_type: definition.finding_type || definition.id,
      pattern: new RegExp(definition.pattern, definition.flags),
      severity: definition.severity,
      description: definition.description,
      remediation: definition.remediation,
      pack: definition.pack || definition.category || 'leak',
      category: definition.category || definition.pack || 'leak',
      categories: definition.categories || [],
      min_match_length: definition.min_match_length || 8,
      capture_group: definition.capture_group || 0,
      validation_status: definition.validation_status || 'lead',
      references: definition.references || [],
    };
    PATTERNS[definition.id] = entry;
    COMPILED_PATTERNS[definition.id] = entry;
  } catch (error) {
    console.warn(`[KeyLeak] Skipping invalid detector pattern: ${definition.id}`, error);
  }
}

export { PATTERN_DEFINITIONS, PATTERNS, COMPILED_PATTERNS };
