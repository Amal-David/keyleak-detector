"""Dynamic IOC detector loader (Wave 3.2).

Loads a signed manifest from disk (typically written by ``keyleak feed sync``)
and converts the per-package IOC entries into :class:`Detector` instances
that the existing scanner pipeline can use without any further plumbing.

Each manifest entry produces one regex that matches the package@version pair
in lockfiles (``package-lock.json``, ``yarn.lock``, ``pnpm-lock.yaml``,
``requirements.txt``, ``poetry.lock``, ``Pipfile.lock``).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Iterable, List, Optional

from .detectors import Detector
from .feeds import verify_manifest


DEFAULT_MANIFEST_PATH = Path(__file__).parent / "data" / "ioc_feed.json"


def load_dynamic_detectors(
    manifest_path: Optional[Path] = None,
    *,
    require_signature: bool = False,
) -> List[Detector]:
    """Return Detector instances built from a signed IOC manifest."""

    path = Path(manifest_path) if manifest_path else DEFAULT_MANIFEST_PATH
    if not path.is_file():
        return []
    document = json.loads(path.read_text(encoding="utf-8"))
    if require_signature and not verify_manifest(document):
        raise ValueError(f"signature verification failed for {path}")

    entries = document.get("entries") or []
    detectors: List[Detector] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        pkg = entry.get("package")
        if not pkg:
            continue
        eco = entry.get("ecosystem") or "npm"
        versions = entry.get("versions") or []
        pattern = _build_pattern(pkg, versions, eco)
        if not pattern:
            continue
        advisory_id = str(entry.get("id") or "MAL-UNKNOWN").lower().replace("-", "_")
        detector = Detector(
            id=f"ioc_{advisory_id}",
            pattern=pattern,
            severity="critical",
            description=f"Malicious package match: {pkg} via {entry.get('id') or 'IOC feed'}.",
            remediation=(
                "Remove the package immediately. Rotate every credential reachable from the "
                "install step. Audit egress logs."
            ),
            categories=["env", "ci", "docker", "code", "config"],
            min_match_length=4,
            pack="leak",
            validation_status="validated",
            references=tuple(entry.get("references") or ()),
            extension=False,  # CLI-only; the bundle stays small
            attack_scenario=str(entry.get("summary") or ""),
        )
        detectors.append(detector)
    return detectors


def _build_pattern(pkg: str, versions: Iterable[str], ecosystem: str) -> str:
    """Build a regex that matches the package@version pair in common lockfiles."""

    quoted_pkg = re.escape(pkg)
    versions = [str(v) for v in versions]
    if not versions:
        # No specific versions provided — match any usage of the package name
        # in a lockfile context. Conservative: only match in JSON-like contexts.
        return rf"\"{quoted_pkg}\"\s*:\s*\""
    version_alt = "|".join(re.escape(v) for v in versions)
    if ecosystem.lower() == "npm":
        # npm lockfile entries: "@x/y": { "version": "1.0.0" } OR "@x/y@1.0.0"
        return rf"\"{quoted_pkg}\"[\s\S]{{0,80}}\"version\"\s*:\s*\"(?:{version_alt})\""
    # Generic fallback for other ecosystems.
    return rf"\b{quoted_pkg}\b[\s,=<>:@]+(?:{version_alt})\b"
