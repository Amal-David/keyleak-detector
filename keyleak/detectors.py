"""Detector registry for local files and generated browser bundles."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, List, Pattern


@dataclass(frozen=True)
class Detector:
    id: str
    pattern: str
    severity: str
    description: str
    remediation: str
    categories: List[str]
    min_match_length: int = 8

    def compile(self) -> Pattern[str]:
        return re.compile(self.pattern, re.IGNORECASE | re.MULTILINE | re.DOTALL)


DETECTORS = [
    Detector(
        "openai_api_key",
        r"\bsk-(?!(?:ant|or)-)(?:proj-)?[A-Za-z0-9_-]{20,}\b",
        "critical",
        "OpenAI API key exposed.",
        "Rotate the OpenAI key, remove it from client/config files, and load it server-side from a secret manager.",
        ["env", "ci", "docker", "mcp", "sourcemaps", "logs"],
    ),
    Detector(
        "anthropic_api_key",
        r"\bsk-ant-[A-Za-z0-9_-]{80,}\b",
        "critical",
        "Anthropic API key exposed.",
        "Rotate the Anthropic key and move model calls behind a trusted server boundary.",
        ["env", "ci", "docker", "mcp", "sourcemaps", "logs"],
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
    ),
    Detector(
        "aws_access_key",
        r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
        "high",
        "AWS access key ID exposed.",
        "Rotate the access key and prefer IAM roles or workload identity over static credentials.",
        ["env", "ci", "docker", "mcp", "sourcemaps", "logs"],
    ),
    Detector(
        "stripe_secret_key",
        r"\bsk_(?:live|test)_[0-9A-Za-z]{24,}\b",
        "critical",
        "Stripe secret key exposed.",
        "Rotate the Stripe key and move payment operations behind server-side endpoints.",
        ["env", "ci", "docker", "sourcemaps", "logs"],
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
        "database_url",
        r"\b(?:postgres(?:ql)?|mysql(?:2)?|mongodb(?:\+srv)?|redis)://[^\s'\"<>]+:[^\s'\"<>]+@[^\s'\"<>]+",
        "critical",
        "Database connection string with credentials exposed.",
        "Rotate database credentials, restrict network access, and move connection strings to server-only configuration.",
        ["env", "ci", "docker", "mcp", "sourcemaps", "logs"],
    ),
    Detector(
        "private_key",
        r"-----BEGIN (?:(?:RSA|DSA|EC|OPENSSH) )?PRIVATE KEY-----[\s\S]+?-----END (?:(?:RSA|DSA|EC|OPENSSH) )?PRIVATE KEY-----",
        "critical",
        "Private key exposed.",
        "Revoke and rotate the key immediately, then audit every system where it was trusted.",
        ["env", "ci", "docker", "mcp", "logs"],
    ),
    Detector(
        "mcp_config_secret",
        r"(?:mcp|modelcontextprotocol|tool|server).{0,80}(?:api[_-]?key|token|secret|password)[\"'\s:=]+[\"']?([A-Za-z0-9_\-./+=]{20,})",
        "high",
        "MCP or agent tool credential exposed.",
        "Move agent/tool credentials to local secret storage and review connected tool permissions.",
        ["mcp", "env", "docker", "logs"],
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
    ),
]


def detectors_for_categories(categories: Iterable[str]) -> List[Detector]:
    requested = {category.strip().lower() for category in categories if category.strip()}
    if not requested:
        return list(DETECTORS)
    return [detector for detector in DETECTORS if requested.intersection(detector.categories)]
