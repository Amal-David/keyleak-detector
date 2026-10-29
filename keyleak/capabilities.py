"""Side-effect-free discovery of the installed scanner's defensive capabilities."""

from . import __version__
from .bundles import BUNDLES, runnable_packs, unpopulated_packs
from .detectors import DETECTORS, DETECTOR_PACKS, PROFILE_PACKS


def capability_catalog():
    """Describe registry coverage without equating registered rules with validation."""
    return {
        "schema_version": 1,
        "scanner_version": __version__,
        "discovery_only": True,
        "positioning": "Local evidence collection and remediation verification for security agents.",
        "workflows": [
            {"id": "local-secrets", "command": "local", "network": False,
             "purpose": "Find credential patterns in local config, logs and source maps.",
             "skill": "keyleak-local-review"},
            {"id": "agent-assets", "command": "local", "include": "agent-assets", "network": False,
             "purpose": "Check skill instructions, agent rules and MCP configuration for credential patterns.",
             "skill": "keyleak-agent-assets"},
            {"id": "python-serialization", "command": "local", "include": "serialization", "network": False,
             "purpose": "Review Python generated credential holders and direct same-file serializers; leads only.",
             "skill": "keyleak-local-review"},
            {"id": "supply-chain", "command": "self-audit", "network": False,
             "purpose": "Review repository dependency and workflow hygiene.", "skill": "keyleak-local-review"},
            {"id": "artifact-secrets", "command": "archive", "network": False,
             "purpose": "Inspect bounded archive contents and produce an evidence envelope.",
             "skill": "keyleak-local-review"},
            {"id": "audit-plan", "command": "audit", "required_flags": ["--plan"], "network": False,
             "purpose": "Preview target classification, phases, bounds and skipped work without execution.",
             "skill": "keyleak-audit"},
            {"id": "browser-observation", "command": "browser-scan", "network": True,
             "purpose": "Observe an authorized page and browser-visible content; requires explicit scope review.",
             "skill": None},
            {"id": "site-observation", "command": "site-scan", "network": True,
             "purpose": "Bounded authorized crawling; host scope and egress need separate review.", "skill": None},
            {"id": "report-triage", "command": None, "network": False,
             "purpose": "Review existing redacted JSON/SARIF evidence, coverage and remediation.",
             "skill": "keyleak-report-triage"},
        ],
        "packs": [
            {"id": pack, "description": description,
             "registered_rule_count": sum(rule.pack == pack for rule in DETECTORS),
             "status": "registered" if any(rule.pack == pack for rule in DETECTORS) else "unpopulated"}
            for pack, description in DETECTOR_PACKS.items()
        ],
        "profiles": {key: list(value) for key, value in PROFILE_PACKS.items()},
        "rules": [
            {"id": rule.canonical_id, "pack": rule.pack, "severity": rule.severity,
             "validation_status": rule.validation_status, "categories": list(rule.categories),
             "extension_eligible": rule.extension, "description": rule.description}
            for rule in DETECTORS
        ],
        "bundles": [
            {"id": bundle.id, "runnable_packs": list(runnable_packs(bundle)),
             "unpopulated_packs": list(unpopulated_packs(bundle)),
             "declared_phases": list(bundle.phases),
             "execution_note": "Declared phases are not an execution guarantee; inspect the selected command and resulting coverage."}
            for bundle in BUNDLES.values()
        ],
        "report_contract": {
            "formats": ["json", "sarif", "markdown", "html"],
            "exit_codes": {"0": "Selected threshold passed with complete coverage.",
                           "1": "Command failed.", "2": "Threshold reached or coverage incomplete."},
            "interpretation": "A pattern match or correlated lead is not proof of exploitability. Inspect validation_status and coverage.",
        },
        "limitations": [
            "Registry counts do not include procedural checks and do not measure vulnerability-class coverage.",
            "Skill and agent asset checks detect credential patterns, not prompt-injection resistance or sandbox safety.",
            "Python serialization review does not trace JavaScript or cross-file flows.",
            "No autonomous exploitation or attack execution is provided by these discovery workflows.",
            "Network commands are not made safe or authorized by catalog discovery.",
        ],
    }
