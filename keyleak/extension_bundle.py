"""Generate the Chrome extension detector bundle from the core registry."""

from __future__ import annotations

import json
import re
from typing import Iterable, List, Optional

from .detectors import DETECTORS, Detector, detectors_for_packs, normalize_packs


EXTENSION_PATTERN_FLAGS = "gim"


class IncompatibleExtensionPattern(ValueError):
    """Raised when a detector pattern uses Python-only regex features."""


# Wave 1.3 — Python-side JS-compat guard. The JS shim in
# ``extension/lib/patterns.js`` wraps every ``new RegExp(...)`` in a try/catch
# that ``console.warn``s on failure. Without a validation step here, a pattern
# valid in Python but invalid in JS silently disappears at runtime and the
# extension reports a clean page. The patterns below are known to be
# Python-only and must trip the build.
_JS_INCOMPATIBLE_PATTERNS = [
    (r"\(\?P[<=!]", "named/Python-style group syntax (?P<name>...) is Python-only"),
    (r"\(\?#", "Python inline comment groups (?#...) are not JS"),
    (r"\\A", "Python \\A start-of-string anchor is not JS"),
    (r"\\Z", "Python \\Z end-of-string anchor is not JS"),
    (r"\(\?\(", "Python conditional group (?(...)...) is not JS"),
    (r"\(\?[smix-]+\)", "Python inline flag groups (?s), (?i), (?m) are Python-only — use flags arg in JS instead"),
]


def validate_extension_pattern(pattern: str) -> None:
    """Compile a pattern with Python's ``re`` AND flag known JS-incompat features.

    Raises ``IncompatibleExtensionPattern`` if either check fails. A failure here
    fails the build loudly instead of silently producing a JS shim that drops
    the detector.
    """

    try:
        re.compile(pattern, re.IGNORECASE | re.MULTILINE)
    except re.error as exc:
        raise IncompatibleExtensionPattern(f"Python regex compile failed: {exc}") from exc

    for incompat_pattern, reason in _JS_INCOMPATIBLE_PATTERNS:
        if re.search(incompat_pattern, pattern):
            raise IncompatibleExtensionPattern(f"{reason}: {pattern}")


def extension_pattern_payload(detectors: Optional[Iterable[Detector]] = None, packs: Optional[Iterable[str]] = None) -> List[dict]:
    """Return serializable detector metadata for the extension runtime.

    Validates each detector's regex for JS compatibility before serialization.
    Raises ``IncompatibleExtensionPattern`` if a pattern would silently drop at
    extension runtime.
    """

    if detectors is None:
        detectors = detectors_for_packs(normalize_packs(packs, profile="launch-gate", surface="extension"), extension_only=True)
    payload = []
    for detector in detectors:
        try:
            validate_extension_pattern(detector.pattern)
        except IncompatibleExtensionPattern as exc:
            raise IncompatibleExtensionPattern(
                f"Detector {detector.canonical_id!r} has a JS-incompatible pattern: {exc}"
            ) from exc
        payload.append(
            {
                "id": detector.id,
                "detector_id": detector.canonical_id,
                "finding_type": detector.result_type,
                "pattern": detector.pattern,
                "flags": EXTENSION_PATTERN_FLAGS,
                "severity": detector.severity,
                "description": detector.description,
                "remediation": detector.remediation,
                "pack": detector.pack,
                "category": detector.pack,
                "categories": detector.categories,
                "min_match_length": detector.min_match_length,
                "capture_group": detector.capture_group,
                "validation_status": detector.validation_status,
                "references": list(detector.references),
            }
        )
    return payload


def extension_patterns_js(detectors: Optional[Iterable[Detector]] = None, packs: Optional[Iterable[str]] = None) -> str:
    """Render the checked-in ES module used by the Chrome extension."""
    payload = extension_pattern_payload(detectors, packs=packs)
    encoded = json.dumps(payload, indent=2, sort_keys=True)
    return "\n".join(
        [
            "/**",
            " * Generated detector bundle for KeyLeak Detector.",
            " * Source of truth: keyleak.detectors.DETECTORS.",
            " * Regenerate with: python3 scripts/generate_extension_patterns.py",
            " */",
            "",
            f"const PATTERN_DEFINITIONS = {encoded};",
            "",
            "const PATTERNS = {};",
            "const COMPILED_PATTERNS = {};",
            "",
            "for (const definition of PATTERN_DEFINITIONS) {",
            "  try {",
            "    const entry = {",
            "      id: definition.id,",
            "      detector_id: definition.detector_id,",
            "      finding_type: definition.finding_type || definition.id,",
            "      pattern: new RegExp(definition.pattern, definition.flags),",
            "      severity: definition.severity,",
            "      description: definition.description,",
            "      remediation: definition.remediation,",
            "      pack: definition.pack || definition.category || 'leak',",
            "      category: definition.category || definition.pack || 'leak',",
            "      categories: definition.categories || [],",
            "      min_match_length: definition.min_match_length || 8,",
            "      capture_group: definition.capture_group || 0,",
            "      validation_status: definition.validation_status || 'lead',",
            "      references: definition.references || [],",
            "    };",
            "    PATTERNS[definition.id] = entry;",
            "    COMPILED_PATTERNS[definition.id] = entry;",
            "  } catch (error) {",
            "    console.warn(`[KeyLeak] Skipping invalid detector pattern: ${definition.id}`, error);",
            "  }",
            "}",
            "",
            "export { PATTERN_DEFINITIONS, PATTERNS, COMPILED_PATTERNS };",
            "",
        ]
    )


def extension_info_payload(detectors: Optional[Iterable[Detector]] = None, packs: Optional[Iterable[str]] = None) -> List[dict]:
    """Return rich educational metadata for the extension Learn/Reference UI.

    Kept separate from the runtime pattern bundle so the regex bundle stays small
    and the prose is only loaded when the user opens an educational surface.
    """
    if detectors is None:
        detectors = detectors_for_packs(normalize_packs(packs, profile="full", surface="extension"), extension_only=True)
    payload = []
    for detector in detectors:
        payload.append(
            {
                "id": detector.id,
                "detector_id": detector.canonical_id,
                "finding_type": detector.result_type,
                "severity": detector.severity,
                "pack": detector.pack,
                "categories": list(detector.categories),
                "description": detector.description,
                "remediation": detector.remediation,
                "references": list(detector.references),
                "validation_status": detector.validation_status,
                "attack_scenario": detector.attack_scenario,
            }
        )
    return payload


def extension_info_js(detectors: Optional[Iterable[Detector]] = None, packs: Optional[Iterable[str]] = None) -> str:
    """Render the checked-in ES module that powers the Learn/Reference panels."""
    payload = extension_info_payload(detectors, packs=packs)
    by_id = {entry["id"]: entry for entry in payload}
    encoded = json.dumps(by_id, indent=2, sort_keys=True)
    return "\n".join(
        [
            "/**",
            " * Generated detector knowledge base for KeyLeak Detector UI.",
            " * Source of truth: keyleak.detectors.DETECTORS.",
            " * Regenerate with: python3 scripts/generate_extension_patterns.py",
            " */",
            "",
            f"export const DETECTOR_INFO = {encoded};",
            "",
            "export function getDetectorInfo(detectorId) {",
            "  if (!detectorId) return null;",
            "  if (DETECTOR_INFO[detectorId]) return DETECTOR_INFO[detectorId];",
            "  // Detector IDs surface as either bare ids (`openai_api_key`)",
            "  // or canonical ids (`leak.openai_api_key`). Fall back to the trailing segment.",
            "  const tail = String(detectorId).split('.').pop();",
            "  return DETECTOR_INFO[tail] || null;",
            "}",
            "",
        ]
    )
