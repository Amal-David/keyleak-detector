"""Local file/config scanner for secrets and agent-era exposures."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable, List, Sequence

from .detectors import Detector, detectors_for_categories
from .models import Evidence, Finding, confidence_for_severity
from .redaction import redact_snippet, redact_value
from .reporting import build_report


DEFAULT_INCLUDES = ("env", "mcp", "ci", "docker", "sourcemaps", "logs")
MAX_FILE_BYTES = 5 * 1024 * 1024
SKIP_DIRS = {
    ".git",
    ".hg",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "__pycache__",
    "dist",
    "node_modules",
    "venv",
}


def scan_path(path: str, includes: Sequence[str] = DEFAULT_INCLUDES):
    target = Path(path).expanduser().resolve()
    findings: List[Finding] = []

    for file_path, categories in _iter_candidate_files(target, includes):
        findings.extend(scan_file(file_path, detectors_for_categories(categories)))

    return build_report(str(target), findings, scan_mode="local")


def scan_file(file_path: Path, detectors: Iterable[Detector]) -> List[Finding]:
    try:
        if file_path.stat().st_size > MAX_FILE_BYTES:
            return []
        content = file_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []

    findings: List[Finding] = []
    seen = set()
    for detector in detectors:
        regex = detector.compile()
        for match in regex.finditer(content):
            raw_value = match.group(1) if match.groups() else match.group(0)
            if _is_placeholder(raw_value):
                continue
            line = content.count("\n", 0, match.start()) + 1
            snippet = _snippet_for(content, match.start(), match.end())
            key = (detector.id, str(file_path), redact_value(raw_value), line)
            if key in seen:
                continue
            seen.add(key)
            evidence = Evidence(
                source=str(file_path),
                snippet=redact_snippet(snippet, raw_value),
                line=line,
                redacted_value=redact_value(raw_value),
            )
            findings.append(
                Finding(
                    type=detector.id,
                    severity=detector.severity,
                    confidence=confidence_for_severity(detector.severity, str(file_path)),
                    detector_id=f"local:{detector.id}",
                    source=str(file_path),
                    evidence=evidence,
                    risk_reason=detector.description,
                    remediation=detector.remediation,
                )
            )
    return findings


def _iter_candidate_files(target: Path, includes: Sequence[str]):
    if target.is_file():
        categories = _categories_for_file(target, includes)
        if categories:
            yield target, categories
        return

    for root, dirs, files in os.walk(target):
        dirs[:] = [directory for directory in dirs if directory not in SKIP_DIRS]
        root_path = Path(root)
        for filename in files:
            file_path = root_path / filename
            categories = _categories_for_file(file_path, includes)
            if categories:
                yield file_path, categories


def _matches_include(path: Path, includes: Sequence[str]) -> bool:
    return bool(_categories_for_file(path, includes))


def _categories_for_file(path: Path, includes: Sequence[str]) -> List[str]:
    requested = {include.lower() for include in includes}
    name = path.name.lower()
    full = str(path).lower()

    checks = {
        "env": name.startswith(".env") or name.endswith(".env") or name in {"config.json", "secrets.json"},
        "mcp": "mcp" in name or name in {"claude_desktop_config.json", "codex.json"} or ".cursor" in full,
        "ci": ".github/workflows" in full or name in {".gitlab-ci.yml", "circle.yml", "buildkite.yml"},
        "docker": name in {"dockerfile", "compose.yml", "docker-compose.yml"} or name.endswith(".dockerfile"),
        "sourcemaps": name.endswith((".map", ".js", ".html", ".htm")),
        "logs": name.endswith(".log") or name.endswith(".txt"),
    }

    return [include for include in requested if checks.get(include, False)]


def _snippet_for(content: str, start: int, end: int, radius: int = 80) -> str:
    snippet_start = max(0, start - radius)
    snippet_end = min(len(content), end + radius)
    snippet = content[snippet_start:snippet_end].replace("\n", " ")
    if snippet_start > 0:
        snippet = "..." + snippet
    if snippet_end < len(content):
        snippet = snippet + "..."
    return snippet


def _is_placeholder(value: object) -> bool:
    text = str(value or "").strip().lower()
    if len(text) < 8:
        return True
    placeholders = ("example", "placeholder", "your_", "your-", "changeme", "dummy", "fake", "test")
    return any(marker in text for marker in placeholders)
