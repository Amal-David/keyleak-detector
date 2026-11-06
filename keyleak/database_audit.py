"""Read-only analysis of owner-exported Supabase catalog metadata."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import stat
from typing import Any, Dict, List, Tuple

from .models import Evidence, Finding


CATALOG_PATH = ".keyleak/database-audit.json"
MAX_CATALOG_BYTES = 5 * 1024 * 1024
MAX_CATALOG_OBJECTS = 10_000
CLIENT_ROLES = ("anon", "authenticated")
PRIVILEGES = ("select", "insert", "update", "delete", "truncate")


def database_audit_status(findings: List[Finding], supplied: List[Dict[str, Any]] | None = None) -> List[Dict[str, Any]]:
    """Describe audit prerequisites without initiating provider requests."""
    results = list(supplied or [])
    covered = {item["provider"] for item in results}
    for provider in ("supabase", "convex", "firebase", "appwrite", "pocketbase"):
        matches = [f for f in findings if provider in f.type.lower() or provider in f.detector_id.lower()]
        if provider in covered or not matches:
            continue
        if provider == "supabase":
            status = "metadata_required"
            message = f"Supabase permissions were not audited. Export the owner catalog to {CATALOG_PATH} and run a local scan."
        elif provider == "convex":
            status = "source_review" if any(f.type == "convex_public_function_review" for f in matches) else "source_required"
            message = "Convex authorization needs source and owner review; passive query observations do not verify function permissions."
        else:
            status = "not_supported"
            message = f"{provider.title()} schema/permission auditing is not implemented; existing exposure checks do not verify configuration."
        results.append({"provider": provider, "status": status, "message": message})
    return results


def load_catalog(path: Path) -> Dict[str, Any]:
    # Do not follow a conventional metadata path outside the requested project.
    if any(part.is_symlink() for part in (path, *path.parents)):
        raise ValueError("database metadata path contains a symlink")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(descriptor, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("database metadata must be a regular file")
        raw = stream.read(MAX_CATALOG_BYTES + 1)
    if len(raw) > MAX_CATALOG_BYTES:
        raise ValueError("database metadata exceeds the size limit")
    try:
        return json.loads(raw)
    except (UnicodeError, ValueError, RecursionError):
        raise ValueError("database metadata is not valid UTF-8 JSON") from None


def _name(value: Any) -> str:
    if (not isinstance(value, str) or not value or len(value) > 256
            or any(ord(c) < 32 for c in value)):
        raise ValueError("invalid catalog identifier")
    return value


def _quote(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def _names(value: Any) -> List[str]:
    if not isinstance(value, list) or len(value) > MAX_CATALOG_OBJECTS:
        raise ValueError("catalog name list is missing or too large")
    names = [_name(item) for item in value]
    if len(names) != len(set(names)):
        raise ValueError("duplicate catalog identifier")
    return names


def _booleans(value: Any, keys: Tuple[str, ...]) -> Dict[str, bool]:
    if not isinstance(value, dict) or any(type(value.get(key)) is not bool for key in keys):
        raise ValueError("catalog privileges or flags are incomplete")
    return value


def _catalog_finding(code: str, severity: str, source: str, subject: str,
                     risk: str, sql: str) -> Finding:
    return Finding(
        type=f"supabase_{code}", severity=severity, confidence=1.0,
        detector_id=f"baas.supabase_{code}", source=source,
        evidence=Evidence(source=source, snippet=subject, redacted_value=f"catalog:{code}:{subject}"),
        risk_reason=risk + " Confirmed in the supplied catalog snapshot; live state and business intent are not verified.",
        remediation="Review before applying; KeyLeak never executes this SQL.\n" + sql,
        validation_status="validated", category="baas",
        references=["https://supabase.com/docs/guides/api/securing-your-api"],
    )


def audit_supabase_catalog(payload: Any, source: str = "Supabase catalog") -> Tuple[List[Finding], Dict[str, Any]]:
    if (not isinstance(payload, dict) or type(payload.get("version")) is not int
            or payload["version"] != 1 or payload.get("provider") != "supabase"):
        raise ValueError("unsupported database metadata format")
    schemas = payload.get("schemas")
    if not isinstance(schemas, list) or not schemas or len(schemas) > 100:
        raise ValueError("catalog schemas are missing")
    schemas = _names(schemas)
    relations, functions = payload.get("relations"), payload.get("functions")
    if not isinstance(relations, list) or not isinstance(functions, list):
        raise ValueError("catalog relations or functions are missing")
    if len(relations) + len(functions) > MAX_CATALOG_OBJECTS:
        raise ValueError("catalog object limit exceeded")

    findings: List[Finding] = []
    inventory = []
    function_inventory = []
    seen = set()
    for item in relations:
        if not isinstance(item, dict):
            raise ValueError("invalid catalog relation")
        schema, name = _name(item.get("schema")), _name(item.get("name"))
        kind = item.get("kind")
        if schema not in schemas or kind not in {"table", "view", "materialized_view"}:
            raise ValueError("unsupported relation or schema")
        subject = f"{_quote(schema)}.{_quote(name)}"
        if subject in seen:
            raise ValueError("duplicate catalog relation")
        seen.add(subject)
        columns = _names(item.get("columns"))
        write_roles = _names(item.get("write_roles"))
        destructive_roles = _names(item.get("destructive_roles"))
        grants = item.get("grants")
        if not isinstance(grants, dict) or any(role not in grants for role in CLIENT_ROLES):
            raise ValueError("effective client grants are missing")
        for role in CLIENT_ROLES:
            _booleans(grants[role], PRIVILEGES)
        inventory.append({"object": subject, "kind": kind,
                          "rls_enabled": item.get("rls_enabled") if kind == "table" else None,
                          "security_invoker": item.get("security_invoker") if kind == "view" else None,
                          "grants": {role: {p: grants[role][p] for p in PRIVILEGES} for role in CLIENT_ROLES}})
        if kind == "table":
            _booleans(item, ("rls_enabled",))
            if not item["rls_enabled"]:
                reachable = any(grants[role][p] for role in CLIENT_ROLES for p in PRIVILEGES[:4])
                findings.append(_catalog_finding(
                    "rls_disabled", "high" if reachable else "medium", source, subject,
                    "Row-level security is disabled. A client role with matching grants can access all rows for that operation.",
                    f"ALTER TABLE {subject} ENABLE ROW LEVEL SECURITY;\n"
                    "-- Default deny follows until intended per-user or tenant policies are added and tested.",
                ))
        elif kind == "view":
            _booleans(item, ("security_invoker",))
            if not item["security_invoker"]:
                reachable = any(grants[role][p] for role in CLIENT_ROLES for p in PRIVILEGES[:4])
                findings.append(_catalog_finding(
                    "definer_view", "high" if reachable else "medium", source, subject,
                    "This view uses its owner's permissions on underlying tables. A privileged owner may bypass their RLS for client reads or writes.",
                    f"ALTER VIEW {subject} SET (security_invoker = true);\n"
                    "-- PostgreSQL 15+; ensure callers have the intended underlying grants and RLS policies.",
                ))
            writers = [role for role in CLIENT_ROLES if any(grants[role][p] for p in ("insert", "update", "delete"))]
            if writers:
                operations = sorted({p.upper() for role in writers for p in ("insert", "update", "delete") if grants[role][p]})
                grantees = "PUBLIC, anon, authenticated" + "".join(f", {_quote(role)}" for role in write_roles if role not in CLIENT_ROLES)
                column_sql = ""
                if columns:
                    column_list = ", ".join(_quote(column) for column in columns)
                    column_sql = f"\nREVOKE INSERT ({column_list}), UPDATE ({column_list}) ON TABLE {subject} FROM {grantees};"
                findings.append(_catalog_finding(
                    "writable_view", "critical" if not item["security_invoker"] else "high", source, subject,
                    f"Effective grants allow {', '.join(writers)} to attempt {', '.join(operations)} through this view. "
                    "Updatable views or write triggers can modify underlying rows; constraints, RLS, and view rules still determine which writes succeed.",
                    f"REVOKE INSERT, UPDATE, DELETE ON TABLE {subject} FROM {grantees};" + column_sql + "\n"
                    "-- Includes exported inherited grant sources and column grants. Ownership/membership may still require changes; re-export to verify.",
                ))
        else:
            if any(grants[role]["select"] for role in CLIENT_ROLES):
                findings.append(_catalog_finding(
                    "materialized_view_exposed", "high", source, subject,
                    "A client can read this materialized view's stored results. Underlying table RLS does not filter those stored rows for the caller.",
                    f"REVOKE SELECT ON TABLE {subject} FROM PUBLIC, anon, authenticated;\n"
                    "-- Remove inherited access paths too, or publish an explicitly sanitized result.",
                ))
        if kind == "table" and any(grants["anon"][p] for p in ("delete", "truncate")):
            grantees = "PUBLIC, anon" + "".join(f", {_quote(role)}" for role in destructive_roles if role != "anon")
            findings.append(_catalog_finding(
                "anon_destructive_grant", "high", source, subject,
                "The anon role has effective DELETE or TRUNCATE privileges. RLS can restrict DELETE, but does not apply to TRUNCATE. "
                "TRUNCATE is not a REST table operation; reachable privileged SQL functions can make SQL privileges relevant.",
                f"REVOKE DELETE, TRUNCATE ON TABLE {subject} FROM {grantees};\n"
                "-- Ownership/membership may still require changes. Review default privileges for every role creating tables and re-export to verify.",
            ))

    for item in functions:
        if not isinstance(item, dict):
            raise ValueError("invalid catalog function")
        schema, name = _name(item.get("schema")), _name(item.get("name"))
        if schema not in schemas:
            raise ValueError("function schema outside catalog scope")
        _booleans(item, ("security_definer",))
        execute = _booleans(item.get("execute"), CLIENT_ROLES)
        execute_roles = _names(item.get("execute_roles"))
        arguments = item.get("identity_arguments")
        # The collector uses oidvectortypes: argument types only, never defaults
        # or parameter names. Reject unsupported signatures rather than emit SQL.
        if (not isinstance(arguments, str) or len(arguments) > 4096
                or not re.fullmatch(r'[\w .,"\[\]]*', arguments)
                or any(ord(c) < 32 for c in arguments)):
            raise ValueError("unsupported function argument types")
        if "search_path" not in item or (item["search_path"] is not None and not isinstance(item["search_path"], str)):
            raise ValueError("function search_path is missing")
        subject = f"{_quote(schema)}.{_quote(name)}({arguments})"
        function_inventory.append({"object": subject, "security_definer": item["security_definer"],
                                   "execute": {role: execute[role] for role in CLIENT_ROLES},
                                   "search_path_fixed": item["search_path"] is not None})
        if not item["security_definer"]:
            continue
        if any(execute.values()):
            grantees = "PUBLIC, anon, authenticated" + "".join(f", {_quote(role)}" for role in execute_roles if role not in CLIENT_ROLES)
            findings.append(_catalog_finding(
                "definer_executable", "high", source, subject,
                f"Client roles {', '.join(role for role in CLIENT_ROLES if execute[role])} can execute this SECURITY DEFINER function with its owner's privileges. "
                "The function body must verify caller identity and ownership; an execute grant alone does not restrict rows. This audit does not inspect the body.",
                f"REVOKE EXECUTE ON FUNCTION {subject} FROM {grantees};\n"
                "-- Preserve explicitly required policy-helper access. Review owner/inherited grants and regrant only after auditing authorization.",
            ))
        if item["search_path"] is None:
            findings.append(_catalog_finding(
                "function_search_path", "high", source, subject,
                "This SECURITY DEFINER function inherits the session search_path. Unqualified names may resolve to attacker-controlled objects where schema creation is permitted.",
                f"ALTER FUNCTION {subject} SET search_path = '';\n"
                "-- First schema-qualify referenced objects in the function body and test its callers.",
            ))

    return findings, {
        "provider": "supabase", "status": "complete", "scope": "supplied catalog configuration only",
        "schemas": schemas, "relations": len(relations), "functions": len(functions),
        "effective_grants": inventory, "function_privileges": function_inventory, "live_state_verified": False,
        "limitations": ["No policy/body semantics, ownership proof, or live write verification.",
                        "Snapshot freshness and completeness depend on the owner export."],
    }
