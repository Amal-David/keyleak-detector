"""Bounded static review leads for Convex public function registrations."""

from __future__ import annotations

import re
from itertools import islice
from typing import List

from .models import Evidence, Finding


_LEXEMES = re.compile(r'''//[^\n]*|/\*[\s\S]*?\*/|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`''')
_IMPORT = re.compile(r'''\bimport\s*\{([^}]+)\}\s*from\s*["'](?:\./|\.\./)*_generated/server(?:\.js)?["']''')
_EXPORT = re.compile(r"\bexport\s+(?:const|let|var)\s+([\w$]+)\s*=\s*([\w$]+)\s*\(")
_IDENTITY = re.compile(r"\b(?:\w+\.auth\.getUserIdentity|getAuthUserId|auth\.getUserId)\s*\(")


def audit_convex_source(content: str, source: str) -> List[Finding]:
    # There is no shared JS parser in the scanner. Mask non-code tokens while
    # retaining offsets; findings remain leads because wrappers/flow need review.
    code = _LEXEMES.sub(lambda m: re.sub(r"[^\n]", " ", m.group()), content)
    aliases = {}
    for match in _IMPORT.finditer(content):
        if not code[match.start():match.start() + 6].strip():
            continue
        for binding in match[1].split(","):
            parts = re.split(r"\s+as\s+", binding.strip())
            if parts[0] in {"query", "mutation", "action", "internalQuery", "internalMutation", "internalAction"}:
                aliases[parts[-1]] = parts[0]

    findings = []
    exports = list(islice(_EXPORT.finditer(code), 201))
    line, previous_offset = 1, 0
    for index, match in enumerate(exports):
        if index == 200:
            break
        name, registration = match[1], aliases.get(match[2])
        if registration not in {"query", "mutation", "action"}:
            continue
        line += content.count("\n", previous_offset, match.start())
        previous_offset = match.start()
        # A neighboring function's identity check never authorizes this one.
        end = exports[index + 1].start() if index + 1 < len(exports) else len(code)
        body = code[match.end():end]
        has_identity = bool(_IDENTITY.search(body))
        risk = (
            "No recognized identity lookup appears in this public function's registration. "
            if not has_identity else
            "An identity lookup appears here, but it does not prove that missing identities are rejected or that ownership is checked. "
        )
        risk += (
            "Clients can call public Convex functions directly. Review identity, resource ownership, tenant scope, and protected-field writes. "
            "This static lead does not establish exploitable access; public operations and authorization wrappers can be intentional."
        )
        internal = "internal" + registration.title()
        findings.append(Finding(
            type="convex_public_function_review", severity="medium", confidence=0.6,
            detector_id="baas.convex_public_function_review", source=source,
            evidence=Evidence(source=source, line=line,
                              snippet=f"Public Convex {registration}: {name}",
                              redacted_value=f"convex:{name}:{registration}"),
            risk_reason=risk,
            remediation=(
                f"For a server-only operation, import {internal} from './_generated/server' and replace the {registration} registration with {internal}, preserving its args and handler. "
                "For a client operation, derive identity using await ctx.auth.getUserIdentity(), reject a missing identity, "
                "and authorize ownership or membership before database access. Never trust args.userId or args.role as caller authority. "
                "Add anonymous and different-user denial tests. KeyLeak does not rewrite or invoke this function."
            ),
            validation_status="lead", category="baas",
            references=["https://docs.convex.dev/functions/internal-functions",
                        "https://docs.convex.dev/auth/functions-auth"],
        ))
    return findings
