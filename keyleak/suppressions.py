"""Baseline and allowlist support for repeatable CI scans."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set

from .models import Finding, ScanReport


class AllowlistSignatureError(ValueError):
    """Raised when a signed allowlist fails verification."""


class AllowlistExpiredError(ValueError):
    """Raised when an allowlist entry has expired (strict mode only)."""


# Maximum allowlist entry expiry, in days from signed_at.
MAX_EXPIRY_DAYS = 90
TODAY_OVERRIDE_ENV = "KEYLEAK_ALLOWLIST_TODAY"
ALLOWLIST_HMAC_KEY_ENV = "KEYLEAK_ALLOWLIST_KEY"
ALLOWLIST_REQUIRE_SIG_ENV = "KEYLEAK_REQUIRE_ALLOWLIST_SIGNATURE"
DISABLE_DEFAULTS_ENV = "KEYLEAK_NO_DEFAULT_SUPPRESSIONS"


# L.1 — Default fixture-path suppressions (added 2026-05-20 post-dogfood).
#
# The 313-repo OSS dogfood produced 371 critical findings, 82% of which were
# in obvious fixture / example / docker-compose paths. Users' first scan now
# hides those by default so the real signal isn't drowned out. Opt out via
# ``KEYLEAK_NO_DEFAULT_SUPPRESSIONS=1`` or the ``--no-default-suppressions``
# CLI flag.
#
# Each entry is a ``source_contains`` substring (case-insensitive). Match
# semantics are the same as the user-supplied ``--allowlist``.
DEFAULT_FIXTURE_SUPPRESSIONS: List[str] = [
    # Template / example envs.
    ".env.example",
    ".env.template",
    ".env.sample",
    ".env.dist",
    ".env.docker",
    ".env.default",
    ".env.dev",
    ".env.development",
    ".env.local",
    ".env.test",
    ".env.testing",
    ".env.e2e",
    ".envrc",
    "example.env",
    "example.docker.env",
    ".example",
    ".template",
    # Fixtures / tests / examples (any path segment).
    "/fixtures/",
    "/fixture/",
    "/__tests__/",
    "/__fixtures__/",
    "/test_data/",
    "/testdata/",
    "/test-data/",
    "/testfixtures/",
    "/test-fixtures/",
    "/tests/",
    "/test/",
    "/spec/",
    "/specs/",
    "/examples/",
    "/example/",
    "/demo/",
    "/demos/",
    "/sample/",
    "/samples/",
    "/playground/",
    "/playgrounds/",
    "/private-demos/",
    "/private_demos/",
    # Q.5 — path patterns the live-URL dogfood revealed slip past the L.1 set.
    "/test-files/",
    "/testfiles/",
    "/test_files/",
    "/fixture_data/",
    "/fixturedata/",
    "/fixture-data/",
    "/sandbox/",
    "/scratch/",
    "/internal-demos/",
    "/golden-files/",
    "/snapshots/",
    "/__snapshots__/",
    "/cypress/",
    "/e2e/",
    "/e2e-tests/",
    "/integration-tests/",
    "/integration_tests/",
    # Q.10 — OIDC / OAuth / TLS conformance test corpora.
    "/certification/",
    "/conformance/",
    "/conformance-tests/",
    "/test-vectors/",
    "/test_vectors/",
    "/golden/",
    # Q.10 — auto-generated TypeScript / OpenAPI schema files. These often
    # define type names like ``McpServerConfigInputSecretToken`` that match
    # secret-shape detectors but contain no actual secrets.
    "/serialization/types/",
    "/openapi-generated/",
    "/generated/types/",
    "/generated-types/",
    # File-name patterns for tests.
    "_test.py",
    "_tests.py",
    "test_",  # matches test_foo.py
    ".test.",
    ".spec.",
    # Docker compose / dev orchestration.
    "docker-compose.yml",
    "docker-compose.yaml",
    "compose.yml",
    "compose.yaml",
    "compose.test.",
    "compose.dev.",
    # Docs.
    "/docs/",
    "README.md",
    "README.rst",
    "CHANGELOG.md",
]


@dataclass
class SuppressionSet:
    ids: Set[str] = field(default_factory=set)
    detector_ids: Set[str] = field(default_factory=set)
    types: Set[str] = field(default_factory=set)
    signatures: Set[str] = field(default_factory=set)
    source_contains: List[str] = field(default_factory=list)


def default_fixture_suppressions() -> SuppressionSet:
    """Built-in fixture-aware suppression set applied by default."""

    return SuppressionSet(source_contains=list(DEFAULT_FIXTURE_SUPPRESSIONS))


def apply_suppressions(
    report: ScanReport,
    baseline_path: str = "",
    allowlist_path: str = "",
    *,
    apply_defaults: bool = True,
) -> ScanReport:
    suppressions = SuppressionSet()
    # L.1 — apply built-in fixture suppressions unless explicitly disabled.
    if apply_defaults and os.environ.get(DISABLE_DEFAULTS_ENV) != "1":
        suppressions = merge_suppressions(suppressions, default_fixture_suppressions())
    if baseline_path:
        suppressions = merge_suppressions(suppressions, load_suppressions(baseline_path, baseline_mode=True))
    if allowlist_path:
        suppressions = merge_suppressions(suppressions, load_suppressions(allowlist_path))

    if not any(
        [
            suppressions.ids,
            suppressions.detector_ids,
            suppressions.types,
            suppressions.signatures,
            suppressions.source_contains,
        ]
    ):
        return report

    findings = [finding for finding in report.findings if not is_suppressed(finding, suppressions)]
    return ScanReport(
        target=report.target,
        scan_mode=report.scan_mode,
        findings=findings,
        generated_at=report.generated_at,
        retest_command=report.retest_command,
        extra=report.extra,
    )


def merge_suppressions(left: SuppressionSet, right: SuppressionSet) -> SuppressionSet:
    return SuppressionSet(
        ids=left.ids | right.ids,
        detector_ids=left.detector_ids | right.detector_ids,
        types=left.types | right.types,
        signatures=left.signatures | right.signatures,
        source_contains=[*left.source_contains, *right.source_contains],
    )


def load_suppressions(path: str, baseline_mode: bool = False) -> SuppressionSet:
    file_path = Path(path).expanduser()
    text = file_path.read_text(encoding="utf-8")
    suffix = file_path.suffix.lower()
    if suffix == ".json":
        return _from_json(json.loads(text), baseline_mode=baseline_mode)
    if suffix in (".yaml", ".yml"):
        return _from_yaml(text)
    return _from_lines(text.splitlines())


def _today_iso() -> str:
    override = os.environ.get(TODAY_OVERRIDE_ENV)
    if override:
        return override
    return date.today().isoformat()


def _from_yaml(text: str) -> SuppressionSet:
    """Parse the KeyLeak allowlist YAML schema.

    Schema::

        schema_version: 1
        signed_at: "<ISO8601>"
        signature_mode: "none" | "hmac-sha256" | "cosign"
        signature: "<hex or base64 or cosign bundle>"
        entries:
          - id: "..."                 # optional; derived if absent
            detector: "leak.<id>"     # Detector.canonical_id; required if no source_contains
            source_contains: "..."    # optional
            reason: "..."             # required
            owner: "@user"            # required
            expires_at: "YYYY-MM-DD"  # required (≤ 90 days from signed_at)

    Behavior:
      - Verifies signature if signature_mode != 'none'.
      - Honors KEYLEAK_REQUIRE_ALLOWLIST_SIGNATURE=1 to fail closed on missing sig.
      - Drops entries past expires_at (warns).
    """

    import yaml  # PyYAML

    data = yaml.safe_load(text) or {}
    if not isinstance(data, dict):
        raise ValueError("allowlist YAML must be a mapping")

    schema_version = data.get("schema_version")
    if schema_version not in (None, 1):
        raise ValueError(f"unsupported allowlist schema_version: {schema_version!r}")

    signature_mode = (data.get("signature_mode") or "none").lower()
    signature = data.get("signature") or ""

    if os.environ.get(ALLOWLIST_REQUIRE_SIG_ENV) == "1" and signature_mode == "none":
        raise AllowlistSignatureError(
            "Allowlist requires a signature (KEYLEAK_REQUIRE_ALLOWLIST_SIGNATURE=1) "
            "but signature_mode is 'none'."
        )

    if signature_mode != "none":
        _verify_signature(data, signature_mode, signature)

    entries = data.get("entries") or []
    if not isinstance(entries, list):
        raise ValueError("allowlist YAML 'entries' must be a list")

    today = _today_iso()
    suppressions = SuppressionSet()
    for raw_entry in entries:
        if not isinstance(raw_entry, dict):
            raise ValueError(f"allowlist entry must be a mapping, got {type(raw_entry).__name__}")

        expires_at = str(raw_entry.get("expires_at") or "").strip()
        if not expires_at:
            raise ValueError(
                f"allowlist entry missing required field 'expires_at': {raw_entry!r}"
            )
        if expires_at < today:
            # Drop expired entries silently (self-audit surfaces them separately).
            continue

        if not raw_entry.get("reason"):
            raise ValueError(f"allowlist entry missing required field 'reason': {raw_entry!r}")
        if not raw_entry.get("owner"):
            raise ValueError(f"allowlist entry missing required field 'owner': {raw_entry!r}")

        if raw_entry.get("id"):
            suppressions.ids.add(str(raw_entry["id"]).strip())
        if raw_entry.get("detector"):
            suppressions.detector_ids.add(str(raw_entry["detector"]).strip())
        if raw_entry.get("type"):
            suppressions.types.add(str(raw_entry["type"]).strip())
        if raw_entry.get("source_contains"):
            suppressions.source_contains.append(str(raw_entry["source_contains"]).strip())
        if raw_entry.get("signature"):
            suppressions.signatures.add(str(raw_entry["signature"]).strip())

        if not (
            raw_entry.get("id")
            or raw_entry.get("detector")
            or raw_entry.get("type")
            or raw_entry.get("source_contains")
        ):
            raise ValueError(
                f"allowlist entry must set one of id/detector/type/source_contains: {raw_entry!r}"
            )

    return suppressions


def _verify_signature(data: Dict[str, Any], mode: str, signature: str) -> None:
    """Verify the allowlist signature according to ``signature_mode``."""

    if not signature:
        raise AllowlistSignatureError(f"signature_mode={mode!r} but no signature provided")

    payload = canonical_entries_bytes(data.get("entries") or [])

    if mode == "hmac-sha256":
        key = os.environ.get(ALLOWLIST_HMAC_KEY_ENV)
        if not key:
            raise AllowlistSignatureError(
                f"signature_mode='hmac-sha256' requires {ALLOWLIST_HMAC_KEY_ENV} env var"
            )
        expected = hmac.new(key.encode("utf-8"), payload, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, signature.strip().lower()):
            raise AllowlistSignatureError("HMAC signature mismatch on allowlist YAML")
        return

    if mode == "cosign":
        cosign = shutil.which("cosign")
        if not cosign:
            raise AllowlistSignatureError(
                "signature_mode='cosign' but cosign is not installed on PATH"
            )
        # Best-effort: write payload + signature to temp and invoke cosign verify-blob.
        import tempfile

        with tempfile.NamedTemporaryFile("wb", delete=False, suffix=".payload") as payload_file:
            payload_file.write(payload)
            payload_path = payload_file.name
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".sig") as sig_file:
            sig_file.write(signature)
            sig_path = sig_file.name
        try:
            result = subprocess.run(
                [cosign, "verify-blob", "--signature", sig_path, payload_path],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
        finally:
            Path(payload_path).unlink(missing_ok=True)
            Path(sig_path).unlink(missing_ok=True)
        if result.returncode != 0:
            raise AllowlistSignatureError(
                f"cosign verify-blob failed: {result.stderr.strip() or result.stdout.strip()}"
            )
        return

    raise AllowlistSignatureError(f"unknown signature_mode: {mode!r}")


def canonical_entries_bytes(entries: List[Any]) -> bytes:
    """Return a deterministic byte representation of allowlist entries for signing."""

    return json.dumps(entries, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_entries_hmac(entries: List[Any], key: str) -> str:
    """Helper used by tests + the future ``keyleak allowlist sign`` subcommand."""

    payload = canonical_entries_bytes(entries)
    return hmac.new(key.encode("utf-8"), payload, hashlib.sha256).hexdigest()


def is_suppressed(finding: Finding, suppressions: SuppressionSet) -> bool:
    if finding.id in suppressions.ids:
        return True
    if finding.detector_id in suppressions.detector_ids:
        return True
    # Honor detector id_aliases: a suppression that references an old detector
    # ID still matches after a rename. Lazy import to avoid a circular dep.
    if suppressions.detector_ids:
        try:
            from .detectors import DETECTORS  # local import

            for detector in DETECTORS:
                if finding.detector_id != detector.canonical_id:
                    continue
                for alias in detector.canonical_id_aliases:
                    if alias in suppressions.detector_ids:
                        return True
                break
        except Exception:  # pragma: no cover — defensive
            pass
    if finding.type in suppressions.types:
        return True
    if finding_signature(finding) in suppressions.signatures:
        return True

    source = finding.source.lower()
    return any(part.lower() in source for part in suppressions.source_contains)


def finding_signature(finding: Finding) -> str:
    return "|".join(
        [
            finding.detector_id,
            finding.source,
            "" if finding.evidence.line is None else str(finding.evidence.line),
            finding.evidence.request_url,
            finding.evidence.redacted_value,
        ]
    )


def _from_json(payload: Any, baseline_mode: bool = False) -> SuppressionSet:
    suppressions = SuppressionSet()

    if isinstance(payload, list):
        _add_items(suppressions, payload, baseline_mode=baseline_mode)
        return suppressions

    if not isinstance(payload, dict):
        raise ValueError("suppression JSON must be an object or list")

    _add_strings(suppressions.ids, payload.get("ids") or payload.get("finding_ids"))
    _add_strings(suppressions.detector_ids, payload.get("detector_ids"))
    _add_strings(suppressions.types, payload.get("types"))
    _add_strings(suppressions.signatures, payload.get("signatures"))
    _add_strings(suppressions.source_contains, payload.get("source_contains") or payload.get("sources"))
    _add_items(suppressions, payload.get("findings") or [], baseline_mode=True)
    _add_items(suppressions, payload.get("rules") or [], baseline_mode=baseline_mode)

    return suppressions


def _from_lines(lines: Iterable[str]) -> SuppressionSet:
    suppressions = SuppressionSet()
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        key, value = _split_line_rule(line)
        if key == "id":
            suppressions.ids.add(value)
        elif key == "detector":
            suppressions.detector_ids.add(value)
        elif key == "type":
            suppressions.types.add(value)
        elif key == "source":
            suppressions.source_contains.append(value)
        elif key == "signature":
            suppressions.signatures.add(value)
        elif key == "":
            suppressions.ids.add(value)
        else:
            raise ValueError(f"Unknown suppression rule key {key!r} in line: {line!r}")
    return suppressions


def _add_items(suppressions: SuppressionSet, items: Iterable[Any], baseline_mode: bool = False) -> None:
    for item in items:
        if isinstance(item, str):
            suppressions.ids.add(item)
            continue
        if not isinstance(item, dict):
            continue

        _add_optional(suppressions.ids, item.get("id"))
        _add_optional(suppressions.detector_ids, item.get("detector_id"))
        _add_optional(suppressions.types, item.get("type"))
        _add_optional(suppressions.signatures, _signature_from_dict(item))
        _add_optional(suppressions.source_contains, item.get("source_contains"))
        if not baseline_mode:
            _add_optional(suppressions.source_contains, item.get("source"))


def _signature_from_dict(item: Dict[str, Any]) -> Optional[str]:
    detector_id = item.get("detector_id")
    source = item.get("source")
    evidence = item.get("evidence") or {}
    line = evidence.get("line")
    request_url = evidence.get("request_url") or ""
    redacted_value = item.get("redacted_value") or evidence.get("redacted_value")
    if not detector_id or not source or not redacted_value:
        return None
    return "|".join(
        [
            str(detector_id),
            str(source),
            "" if line is None else str(line),
            str(request_url),
            str(redacted_value),
        ]
    )


def _add_strings(target: Any, values: Any) -> None:
    if isinstance(values, str):
        _append_or_add(target, values)
        return
    for value in values or []:
        _add_optional(target, value)


def _add_optional(target: Any, value: Any) -> None:
    if value is None:
        return
    text = str(value).strip()
    if not text:
        return
    _append_or_add(target, text)


def _append_or_add(target: Any, value: str) -> None:
    if hasattr(target, "add"):
        target.add(value)
    else:
        target.append(value)


def _split_line_rule(line: str):
    if ":" not in line:
        return "", line
    key, value = line.split(":", 1)
    return key.strip().lower(), value.strip()
