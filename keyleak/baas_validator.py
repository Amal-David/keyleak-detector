"""BaaS active validation engine (Wave 4.1).

Detects Supabase, Firebase, and Appwrite configuration extracted from client
bundles, then probes their REST APIs with read-only requests to confirm
whether Row-Level Security (or equivalent) is properly enforced.

Architecture mirrors ``blast_radius.py``: every HTTP call goes through an
injectable ``BaaSProber`` callable so tests never touch the network.
"""

from __future__ import annotations

import base64
import json as _json
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from .models import Evidence, Finding
from .redaction import redact_url, redact_value

BaaSProber = Callable[..., Dict[str, Any]]

# A guard maps a hostname to a block reason (str) or None if the host is safe to
# probe. Defaults to ``net_guard.scan_target_block_reason``.
ProbeTargetGuard = Callable[[str], Optional[str]]

TABLE_PROBE_CAP = 50
BUCKET_PROBE_CAP = 10
RPC_PROBE_CAP = 20
WRITE_PROBE_CAP = 20


@dataclass
class BaaSConfig:
    provider: str
    project_url: str
    api_key: str
    tables: List[str] = field(default_factory=list)
    rpc_functions: List[str] = field(default_factory=list)
    storage_buckets: List[str] = field(default_factory=list)


@dataclass
class BaaSProbeResult:
    probe_type: str
    target: str
    status: str  # "confirmed", "denied", "error", "empty", "lead"
    http_status: Optional[int] = None
    row_count: Optional[int] = None
    columns: Optional[List[str]] = None
    note: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "probe_type": self.probe_type,
            "target": self.target,
            "status": self.status,
        }
        if self.http_status is not None:
            d["http_status"] = self.http_status
        if self.row_count is not None:
            d["row_count"] = self.row_count
        if self.columns:
            d["columns"] = self.columns
        if self.note:
            d["note"] = self.note
        return d


@dataclass
class BaaSValidation:
    provider: str
    project_url_redacted: str
    key_valid: bool = False
    open_tables: List[BaaSProbeResult] = field(default_factory=list)
    protected_tables: List[BaaSProbeResult] = field(default_factory=list)
    accessible_buckets: List[BaaSProbeResult] = field(default_factory=list)
    callable_rpcs: List[BaaSProbeResult] = field(default_factory=list)
    writable_tables: List[BaaSProbeResult] = field(default_factory=list)
    realtime_channels: List[BaaSProbeResult] = field(default_factory=list)
    cors_open: bool = False
    findings: List[Finding] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "provider": self.provider,
            "project_url_redacted": self.project_url_redacted,
            "key_valid": self.key_valid,
            "open_tables": [t.to_dict() for t in self.open_tables],
            "protected_tables": [t.to_dict() for t in self.protected_tables],
            "accessible_buckets": [b.to_dict() for b in self.accessible_buckets],
            "callable_rpcs": [r.to_dict() for r in self.callable_rpcs],
            "writable_tables": [w.to_dict() for w in self.writable_tables],
            "realtime_channels": [c.to_dict() for c in self.realtime_channels],
            "cors_open": self.cors_open,
            "findings_count": len(self.findings),
        }


# ---------------------------------------------------------------------------
# Default HTTP prober — overridden by tests.
# ---------------------------------------------------------------------------

def _probe_target_block_reason(
    url: str,
    *,
    target_guard: Optional[ProbeTargetGuard] = None,
    allow_private: Optional[bool] = None,
) -> Optional[str]:
    """Return a reason if ``url``'s host must not be probed (SSRF guard), else None.

    The probe target comes from the scanned page's own JavaScript, so it is
    attacker-influenced (audit W1/S0). We refuse to send a request to
    non-routable / internal / cloud-metadata hosts. Defaults to
    ``net_guard.scan_target_block_reason`` so egress is SSRF-safe even if a
    caller forgets to supply a guard.
    """
    try:
        host = urlparse(url).hostname
    except Exception:
        return "unparseable probe URL"
    if not host:
        return "probe URL has no host"
    if target_guard is not None:
        return target_guard(host)
    from .net_guard import scan_target_block_reason

    return scan_target_block_reason(host, allow_private=allow_private)


# Response returned in place of a real request when the SSRF guard blocks a
# target. status_code 0 makes every downstream probe treat it as "no result"
# (no finding) rather than crashing the scan.
def _blocked_response(reason: str) -> Dict[str, Any]:
    return {"status_code": 0, "body": None, "headers": {}, "blocked": reason}


def make_default_prober(proxy: Optional[str] = None, *, allow_private: Optional[bool] = None):
    """Build an HTTP prober, optionally routing probes through ``proxy``.

    Every request URL is SSRF-checked against ``net_guard`` before it leaves the
    process: this is the single real-network egress point for BaaS probing, so
    guarding here protects both the default and proxied paths (audit W1/S0).
    Injected probers (tests, custom callers) bypass this by construction — they
    never reach the real network.
    """

    from .proxy import requests_proxies

    proxies = requests_proxies(proxy)

    def _prober(method: str, url: str, headers: Dict[str, str], body: Optional[str] = None) -> Dict[str, Any]:
        # Fast path: refuse obviously-blocked targets without importing requests.
        reason = _probe_target_block_reason(url, allow_private=allow_private)
        if reason:
            return _blocked_response(reason)

        from .net_guard import guarded_request, SSRFBlocked

        kwargs: Dict[str, Any] = {"headers": headers, "timeout": 10}
        if proxies:
            kwargs["proxies"] = proxies
        if body is not None and method.upper() in ("POST", "PUT", "PATCH"):
            kwargs["data"] = body
        try:
            # guarded_request disables auto-redirects and re-validates every
            # redirect hop, so a public host cannot 302 us into an internal one.
            resp = guarded_request(method, url, allow_private=allow_private, **kwargs)
        except SSRFBlocked as exc:
            return _blocked_response(str(exc))
        response_body: Any = None
        try:
            response_body = resp.json()
        except Exception:
            response_body = resp.text[:500] if resp.text else None
        return {
            "status_code": resp.status_code,
            "body": response_body,
            "headers": {k.lower(): v for k, v in resp.headers.items()},
        }

    return _prober


_default_prober = make_default_prober()


# ---------------------------------------------------------------------------
# Config extraction
# ---------------------------------------------------------------------------

_SUPABASE_URL_RE = re.compile(r"https://[a-z0-9]{20,}\.supabase\.co")
_SUPABASE_JWT_RE = re.compile(
    r"eyJ[A-Za-z0-9_-]{30,}\.eyJ[A-Za-z0-9_-]{30,}\.[A-Za-z0-9_-]{20,}"
)
_SUPABASE_PUB_RE = re.compile(r"sb_publishable_[A-Za-z0-9_-]{20,}")

# Firebase
_FIREBASE_DB_RE = re.compile(r"https://[a-z0-9-]+\.firebaseio\.com")
_FIREBASE_KEY_RE = re.compile(r"AIza[0-9A-Za-z_-]{35}")
_FIREBASE_BUCKET_RE = re.compile(r"[a-z0-9-]+\.appspot\.com")

# Appwrite / PocketBase
_APPWRITE_ENDPOINT_RE = re.compile(r"https?://[a-zA-Z0-9.-]+/v1")
_POCKETBASE_URL_RE = re.compile(r"https?://[a-zA-Z0-9.-]+(?::[0-9]+)?")


def extract_baas_config(
    raw_findings: Optional[List[Dict[str, Any]]] = None,
    js_extraction: Optional[Dict[str, Any]] = None,
) -> Optional[BaaSConfig]:
    """Build a BaaSConfig from browser-scan findings and the JS extraction payload."""

    project_url: Optional[str] = None
    api_key: Optional[str] = None
    tables: List[str] = []
    rpcs: List[str] = []
    buckets: List[str] = []

    if js_extraction:
        project_url = js_extraction.get("supabase_url")
        api_key = js_extraction.get("supabase_key")
        tables = list(js_extraction.get("tables") or [])
        rpcs = list(js_extraction.get("rpcs") or [])
        buckets = list(js_extraction.get("buckets") or [])

    for f in raw_findings or []:
        det = f.get("detector_id") or f.get("type") or ""
        val = f.get("value") or ""
        if not project_url and ("supabase_url" in det or _SUPABASE_URL_RE.search(val)):
            m = _SUPABASE_URL_RE.search(val)
            if m:
                project_url = m.group(0)
        if not api_key and ("supabase_anon_key" in det or "supabase_publishable_key" in det):
            api_key = val
        if not api_key and _SUPABASE_JWT_RE.search(val):
            api_key = _SUPABASE_JWT_RE.search(val).group(0)  # type: ignore[union-attr]
        if not api_key and _SUPABASE_PUB_RE.search(val):
            api_key = _SUPABASE_PUB_RE.search(val).group(0)  # type: ignore[union-attr]

    if project_url and api_key:
        tables = list(dict.fromkeys(tables))
        rpcs = list(dict.fromkeys(rpcs))
        buckets = list(dict.fromkeys(buckets))

        return BaaSConfig(
            provider="supabase",
            project_url=project_url.rstrip("/"),
            api_key=api_key,
            tables=tables,
            rpc_functions=rpcs,
            storage_buckets=buckets,
        )

    # Firebase detection
    firebase_url: Optional[str] = None
    firebase_key: Optional[str] = None
    firebase_bucket: Optional[str] = None

    if js_extraction:
        firebase_url = js_extraction.get("firebase_db_url")
        firebase_key = js_extraction.get("firebase_api_key")
        firebase_bucket = js_extraction.get("firebase_storage_bucket")

    for f in raw_findings or []:
        det = f.get("detector_id") or f.get("type") or ""
        val = f.get("value") or ""
        if not firebase_url and ("firebase_db_url" in det or _FIREBASE_DB_RE.search(val)):
            m = _FIREBASE_DB_RE.search(val)
            if m:
                firebase_url = m.group(0)
        if not firebase_key and _FIREBASE_KEY_RE.search(val):
            firebase_key = _FIREBASE_KEY_RE.search(val).group(0)
        if not firebase_bucket and _FIREBASE_BUCKET_RE.search(val):
            firebase_bucket = _FIREBASE_BUCKET_RE.search(val).group(0)

    if firebase_url:
        return BaaSConfig(
            provider="firebase",
            project_url=firebase_url.rstrip("/"),
            api_key=firebase_key or "",
            storage_buckets=[firebase_bucket] if firebase_bucket else [],
        )

    # Appwrite detection
    appwrite_endpoint: Optional[str] = None
    appwrite_project: Optional[str] = None
    if js_extraction:
        appwrite_endpoint = js_extraction.get("appwrite_endpoint")
        appwrite_project = js_extraction.get("appwrite_project")

    for f in raw_findings or []:
        det = f.get("detector_id") or f.get("type") or ""
        val = f.get("value") or ""
        if not appwrite_endpoint and "appwrite_endpoint" in det:
            m = _APPWRITE_ENDPOINT_RE.search(val)
            if m:
                appwrite_endpoint = m.group(0)

    if appwrite_endpoint:
        return BaaSConfig(
            provider="appwrite",
            project_url=appwrite_endpoint.rstrip("/"),
            api_key=appwrite_project or "",
        )

    # PocketBase detection
    pocketbase_url: Optional[str] = None
    if js_extraction:
        pocketbase_url = js_extraction.get("pocketbase_url")
    for f in raw_findings or []:
        det = f.get("detector_id") or f.get("type") or ""
        val = f.get("value") or ""
        if not pocketbase_url and "pocketbase_url" in det:
            m = _POCKETBASE_URL_RE.search(val)
            if m:
                pocketbase_url = m.group(0)

    if pocketbase_url:
        return BaaSConfig(
            provider="pocketbase",
            project_url=pocketbase_url.rstrip("/"),
            api_key="",
        )

    return None


# ---------------------------------------------------------------------------
# Active validation
# ---------------------------------------------------------------------------

def validate_baas_config(
    config: BaaSConfig,
    *,
    prober: Optional[BaaSProber] = None,
    js_extraction: Optional[Dict[str, Any]] = None,
    allow_write_probe: bool = False,
    allow_private: Optional[bool] = None,
) -> BaaSValidation:
    """Run read-only probes against a BaaS configuration.

    Returns a ``BaaSValidation`` with enriched findings. All HTTP calls go
    through ``prober`` (defaults to ``requests`` in production).

    SSRF safety (audit W1/S0): ``config.project_url`` is extracted from the
    scanned page's own JavaScript and is therefore attacker-influenced. When the
    real network prober is used (``prober is None``), the target host is
    validated up front via ``net_guard`` and probing is skipped entirely for
    non-routable / internal / cloud-metadata hosts, rather than emitting
    misleading "key invalid" results. Injected probers (tests, custom callers)
    are trusted and bypass this check; the real egress prober built by
    ``make_default_prober`` is additionally guarded per-request as defense in
    depth.

    By default the scan is strictly read-only. The one mutating probe — a test
    ``POST`` insert used to detect missing write-side RLS — is **skipped unless
    ``allow_write_probe=True``** is passed explicitly, because the ``Prefer:
    tx=rollback`` rollback it relies on is not honored by every PostgREST
    deployment and an un-rolled-back insert would write a row into the target's
    database. No built-in scan bundle enables it.
    """
    if prober is None:
        block_reason = _probe_target_block_reason(config.project_url, allow_private=allow_private)
        if block_reason:
            # Refuse to probe an internal/non-routable target. Return an empty
            # validation (no findings) instead of a stream of HTTP-0 "key
            # invalid" results that would misrepresent a blocked scan.
            return BaaSValidation(
                provider=config.provider,
                project_url_redacted=redact_url(config.project_url),
            )

    if config.provider == "supabase":
        return _validate_supabase(
            config, prober or _default_prober,
            js_extraction=js_extraction, allow_write_probe=allow_write_probe,
        )
    if config.provider == "firebase":
        return _validate_firebase(config, prober or _default_prober)
    if config.provider == "appwrite":
        return _validate_appwrite(config, prober or _default_prober)
    if config.provider == "pocketbase":
        return _validate_pocketbase(config, prober or _default_prober)
    return BaaSValidation(
        provider=config.provider,
        project_url_redacted=redact_url(config.project_url),
    )


def _validate_supabase(config: BaaSConfig, prober: BaaSProber, *, js_extraction: Optional[Dict[str, Any]] = None, allow_write_probe: bool = False) -> BaaSValidation:
    url = config.project_url
    headers = {
        "apikey": config.api_key,
        "Authorization": f"Bearer {config.api_key}",
    }
    validation = BaaSValidation(
        provider="supabase",
        project_url_redacted=redact_url(url),
    )

    try:
        resp = prober("GET", f"{url}/rest/v1/", headers)
    except Exception as exc:
        validation.key_valid = False
        validation.findings.append(_finding(
            "baas_key_validation_error", "medium", config,
            f"Supabase key validation probe failed: {exc}",
            "Check network connectivity and Supabase project status.",
        ))
        return validation

    status = resp.get("status_code", 0)
    validation.key_valid = status == 200
    if not validation.key_valid:
        validation.findings.append(_finding(
            "baas_key_invalid", "info", config,
            f"Supabase anon key returned HTTP {status}. Key may be invalid or project may be paused.",
            "No action needed if the key is intentionally disabled.",
        ))
        return validation

    resp_headers = resp.get("headers") or {}
    cors = resp_headers.get("access-control-allow-origin", "")
    validation.cors_open = cors == "*"
    if validation.cors_open:
        validation.findings.append(_finding(
            "baas_cors_wildcard", "low", config,
            "Supabase REST API returns Access-Control-Allow-Origin: *. Any origin can make authenticated requests.",
            f"Restrict CORS to your application's origin in the Supabase dashboard.",
            validation_status="confirmed",
        ))

    # Enumerate relations exposed via the PostgREST OpenAPI root (GET /rest/v1/),
    # not just the ones named in the page bundle — catches anon-reachable tables
    # never referenced in client JS (the CBSE-class case). Read-only; the global
    # TABLE_PROBE_CAP still bounds total probes; does NOT mutate the caller config.
    root_body = resp.get("body")
    enumerated = _tables_from_openapi(root_body)
    js_named = list(config.tables)
    js_set = set(js_named)
    enumerated_only = frozenset(name for name in enumerated if name not in js_set)
    # Views = relations CONFIRMED read-only by the OpenAPI doc (in paths, no POST).
    # Relations with unknown insertability (definitions-only) default to table.
    view_tables = frozenset(_view_relations(root_body))
    # Probe JS-named + enumerated-only, ordered so sensitive relations come first
    # (stable sort) and the cap cannot starve the dangerous tables.
    union = list(dict.fromkeys(js_named + sorted(enumerated_only)))
    tables_to_probe = sorted(union, key=lambda name: 0 if _table_severity(name) == "critical" else 1)

    _probe_tables(config, headers, prober, validation,
                  tables=tables_to_probe, lead_tables=enumerated_only, view_tables=view_tables)
    _probe_storage(config, headers, prober, validation)
    _probe_rpcs(config, headers, prober, validation)
    # Mutating probe (POST insert) — read-only by default; explicit opt-in only.
    if allow_write_probe:
        _probe_write_access(config, headers, prober, validation)
    _probe_auth_config(config, headers, prober, validation)
    _analyze_realtime(config, validation, js_extraction)

    return validation


def _tables_from_openapi(body: Any) -> List[str]:
    """Extract exposed table names from a PostgREST ``GET /rest/v1/`` OpenAPI doc.

    PostgREST publishes every table it exposes under ``definitions`` (Swagger 2.0)
    and as top-level ``paths`` (``/{table}``). Reading these lets KeyLeak probe
    tables that are reachable by the anon key but never referenced in the page's
    JS — the exact shape of the CBSE-class breach.
    """
    if not isinstance(body, dict):
        return []
    names: set = set()
    definitions = body.get("definitions")
    if isinstance(definitions, dict):
        names.update(key for key in definitions if isinstance(key, str) and key)
    paths = body.get("paths")
    if isinstance(paths, dict):
        for path in paths:
            if not isinstance(path, str):
                continue
            segment = path.strip("/")
            # Exclude root, parameterized paths, and RPC endpoints (/rpc/<fn>, which
            # contain a slash). Do NOT filter on an 'rpc' name prefix — a real table
            # named e.g. rpc_audit_log is legitimate.
            if not segment or "/" in segment or "{" in segment:
                continue
            names.add(segment)
    return sorted(names)


def _view_relations(body: Any) -> set:
    """Relations CONFIRMED read-only by the OpenAPI doc — present in ``paths`` with
    operations but no ``post`` (typically VIEWS, where ``ALTER TABLE ... ENABLE ROW
    LEVEL SECURITY`` is invalid).

    Only positive evidence counts: a relation that is absent from ``paths`` (e.g. a
    definitions-only body) has UNKNOWN insertability and is NOT treated as a view,
    so a base table is never mislabeled and handed bogus view remediation.
    """
    views: set = set()
    if not isinstance(body, dict):
        return views
    paths = body.get("paths")
    if isinstance(paths, dict):
        for path, ops in paths.items():
            if not isinstance(path, str) or not isinstance(ops, dict):
                continue
            segment = path.strip("/")
            if not segment or "/" in segment or "{" in segment:
                continue
            op_names = {str(op).lower() for op in ops}
            if op_names and "post" not in op_names:
                views.add(segment)
    return views


_SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")


def _downgrade_severity(severity: str) -> str:
    try:
        index = _SEVERITY_ORDER.index(severity)
    except ValueError:
        return severity
    return _SEVERITY_ORDER[max(0, index - 1)]


def _probe_tables(
    config: BaaSConfig,
    headers: Dict[str, str],
    prober: BaaSProber,
    validation: BaaSValidation,
    *,
    tables: Optional[List[str]] = None,
    lead_tables: frozenset = frozenset(),
    view_tables: frozenset = frozenset(),
) -> None:
    probe_list = tables if tables is not None else config.tables
    for table in probe_list[:TABLE_PROBE_CAP]:
        try:
            resp = prober("GET", f"{config.project_url}/rest/v1/{table}?select=*&limit=1", headers)
        except Exception:
            validation.protected_tables.append(BaaSProbeResult(
                probe_type="table_read", target=table, status="error", note="probe failed",
            ))
            continue

        status = resp.get("status_code", 0)
        body = resp.get("body")

        if status == 200 and isinstance(body, list):
            if not body:
                # 200 with an empty array: the anon role returned no rows. For a
                # CORRECTLY RLS-protected table this is the expected response (the
                # policy filters every row — you do NOT get a 401/403). So an empty
                # result is evidence of protection (or an empty table), NOT an open
                # table. Reporting it as "no effective RLS" is a false positive.
                validation.protected_tables.append(BaaSProbeResult(
                    probe_type="table_read", target=table, status="empty", http_status=status,
                    note="200 with no rows — anon role read nothing (RLS-protected or empty)",
                ))
                continue

            columns = list(body[0].keys()) if isinstance(body[0], dict) else []
            is_lead = table in lead_tables       # enumerated-only: not in extracted JS names
            is_view = table in view_tables       # not insertable in OpenAPI -> likely a view
            base_severity = _table_severity(table)
            severity = _downgrade_severity(base_severity) if is_lead else base_severity
            relation = "view" if is_view else "table"

            validation.open_tables.append(BaaSProbeResult(
                probe_type="table_read", target=table, status="confirmed",
                http_status=status, row_count=len(body), columns=columns,
            ))

            col_summary = ", ".join(columns[:10])
            if len(columns) > 10:
                col_summary += f" (+{len(columns) - 10} more)"

            reason = f"Supabase {relation} '{table}' returned {len(body)} row(s) to the anon key. "
            if is_lead:
                reason += ("It is exposed by the REST API but is not among the table names "
                           "extracted from the page's JS, so it may be reachable without being "
                           "referenced in client code — verify it isn't loaded dynamically or "
                           "intentionally public.")
            else:
                reason += "It has no effective RLS policy: anyone with the anon key can read these rows."
            if is_view:
                reason += " This is a view; RLS cannot be enabled on a view directly."
                remediation = (f"'{table}' is a view — RLS cannot be enabled on it. Secure the "
                               "underlying table(s) with RLS, or recreate the view with "
                               "security_invoker = on so it respects the caller's RLS.")
            else:
                remediation = (f"Enable RLS: ALTER TABLE {table} ENABLE ROW LEVEL SECURITY; "
                               "then create SELECT/INSERT/UPDATE/DELETE policies.")

            validation.findings.append(Finding(
                type="baas_open_table",
                severity=severity,
                confidence=0.6 if is_lead else 0.95,
                detector_id="baas.open_table",
                source=config.project_url,
                evidence=Evidence(
                    source=config.project_url,
                    snippet=f"{relation.title()} '{table}' readable with anon key. Columns: {col_summary}",
                    redacted_value=f"table:{table}",
                    response_status=status,
                    request_url=f"{redact_url(config.project_url)}/rest/v1/{table}",
                ),
                risk_reason=reason,
                remediation=remediation,
                validation_status="lead" if is_lead else "confirmed",
                category="baas",
                references=["https://supabase.com/docs/guides/auth/row-level-security"],
            ))
        else:
            validation.protected_tables.append(BaaSProbeResult(
                probe_type="table_read", target=table, status="denied", http_status=status,
            ))


_SENSITIVE_TABLE_PREFIXES = (
    "payout", "payment", "billing", "invoice", "subscription",
    "admin", "auth", "credential", "secret", "token",
    "user_block", "report", "dmca", "support_ticket",
    "private", "internal",
)


def _table_severity(table: str) -> str:
    # Match sensitive keywords on token boundaries, including common plural
    # table names, without escalating near-misses like 'authors' or 'reporting'.
    lower = table.lower()
    for keyword in _SENSITIVE_TABLE_PREFIXES:
        if re.search(r"(?:^|[^a-z0-9])" + re.escape(keyword) + r"(?:s|es)?(?:[^a-z0-9]|$)", lower):
            return "critical"
    return "high"


def _probe_storage(
    config: BaaSConfig,
    headers: Dict[str, str],
    prober: BaaSProber,
    validation: BaaSValidation,
) -> None:
    try:
        resp = prober("GET", f"{config.project_url}/storage/v1/bucket", headers)
    except Exception:
        return

    status = resp.get("status_code", 0)
    body = resp.get("body")

    if status == 200 and isinstance(body, list):
        for bucket_info in body[:BUCKET_PROBE_CAP]:
            name = bucket_info.get("name") or bucket_info.get("id") or ""
            if not name:
                continue
            is_public = bucket_info.get("public", False)
            result = BaaSProbeResult(
                probe_type="storage_bucket",
                target=name,
                status="confirmed",
                http_status=status,
                note="public" if is_public else "listed",
            )
            validation.accessible_buckets.append(result)

            if is_public:
                validation.findings.append(Finding(
                    type="baas_open_storage",
                    severity="high",
                    confidence=0.95,
                    detector_id="baas.open_storage",
                    source=config.project_url,
                    evidence=Evidence(
                        source=config.project_url,
                        snippet=f"Storage bucket '{name}' is marked public.",
                        redacted_value=f"bucket:{name}",
                        response_status=status,
                        request_url=f"{redact_url(config.project_url)}/storage/v1/bucket",
                    ),
                    risk_reason=f"Supabase storage bucket '{name}' is publicly accessible. "
                                "Anyone can list and download objects.",
                    remediation=f"Set the '{name}' bucket to private in the Supabase dashboard "
                                "and configure storage policies for authorized access only.",
                    validation_status="confirmed",
                    category="baas",
                ))

    for bucket_name in config.storage_buckets[:BUCKET_PROBE_CAP]:
        already_found = any(b.target == bucket_name for b in validation.accessible_buckets)
        if already_found:
            continue
        try:
            list_resp = prober(
                "GET",
                f"{config.project_url}/storage/v1/object/list/{bucket_name}?limit=1",
                headers,
            )
        except Exception:
            continue
        if list_resp.get("status_code") == 200:
            validation.accessible_buckets.append(BaaSProbeResult(
                probe_type="storage_list",
                target=bucket_name,
                status="confirmed",
                http_status=200,
                note="objects listable",
            ))
            validation.findings.append(Finding(
                type="baas_open_storage",
                severity="medium",
                confidence=0.85,
                detector_id="baas.open_storage",
                source=config.project_url,
                evidence=Evidence(
                    source=config.project_url,
                    snippet=f"Storage bucket '{bucket_name}' objects are listable with anon key.",
                    redacted_value=f"bucket:{bucket_name}",
                    response_status=200,
                    request_url=f"{redact_url(config.project_url)}/storage/v1/object/list/{bucket_name}",
                ),
                risk_reason=f"Storage bucket '{bucket_name}' allows anonymous object listing.",
                remediation=f"Restrict the '{bucket_name}' bucket's storage policy to authenticated users.",
                validation_status="confirmed",
                category="baas",
            ))


def _probe_rpcs(
    config: BaaSConfig,
    headers: Dict[str, str],
    prober: BaaSProber,
    validation: BaaSValidation,
) -> None:
    """Surface RPC functions as leads without executing them.

    POSTing to an RPC endpoint executes the function, which may have
    side effects.  Instead we emit each client-referenced RPC as a
    ``lead`` so operators can review permissions manually.
    """
    for fn in config.rpc_functions[:RPC_PROBE_CAP]:
        validation.callable_rpcs.append(BaaSProbeResult(
            probe_type="rpc_call", target=fn, status="lead",
        ))
        validation.findings.append(Finding(
            type="baas_open_rpc",
            severity="medium",
            confidence=0.6,
            detector_id="baas.open_rpc",
            source=config.project_url,
            evidence=Evidence(
                source=config.project_url,
                snippet=f"RPC function '{fn}' referenced in client code and callable via the REST API.",
                redacted_value=f"rpc:{fn}",
                request_url=f"{redact_url(config.project_url)}/rest/v1/rpc/{fn}",
            ),
            risk_reason=f"Supabase RPC function '{fn}' is exposed to the anon role via the client bundle. "
                        "If it mutates data or returns sensitive information, it may be exploitable.",
            remediation=f"Verify that '{fn}' checks auth.uid() internally. "
                        "Consider revoking EXECUTE from the anon role for sensitive functions.",
            validation_status="lead",
            category="baas",
        ))


# ---------------------------------------------------------------------------
# Wave 4.4 — Write operation detection
# ---------------------------------------------------------------------------

def _probe_write_access(
    config: BaaSConfig,
    headers: Dict[str, str],
    prober: BaaSProber,
    validation: BaaSValidation,
) -> None:
    """Test if open tables accept writes.

    Uses ``Prefer: tx=rollback`` so PostgREST rolls back the transaction
    even if the insert would succeed.  If that header is not honoured
    (requires ``db-tx-end`` on the server), falls back to sending an
    intentionally invalid JSON body whose column name cannot exist in any
    real schema — PostgREST returns 400 (schema error, no row created)
    when inserts are enabled, vs 403 when RLS blocks writes.
    """
    write_headers = {
        **headers,
        "Content-Type": "application/json",
        "Prefer": "tx=rollback, return=minimal",
    }
    probe_body = '{"__keyleak_write_probe__": true}'
    open_table_names = [t.target for t in validation.open_tables]

    for table in open_table_names[:WRITE_PROBE_CAP]:
        try:
            resp = prober("POST", f"{config.project_url}/rest/v1/{table}", write_headers, probe_body)
        except Exception:
            continue

        status = resp.get("status_code", 0)
        # 400 = schema validation error (writes enabled but body invalid — safe)
        # 201 should not happen with empty/invalid body, but flag it
        # 403 = RLS blocks writes (good)
        if status in (400, 201, 409):
            validation.writable_tables.append(BaaSProbeResult(
                probe_type="table_write", target=table, status="confirmed", http_status=status,
            ))
            validation.findings.append(Finding(
                type="baas_writable_table",
                severity="critical",
                confidence=0.9,
                detector_id="baas.writable_table",
                source=config.project_url,
                evidence=Evidence(
                    source=config.project_url,
                    snippet=f"Table '{table}' accepts POST (insert) with anon key (HTTP {status}).",
                    redacted_value=f"writable:{table}",
                    response_status=status,
                    request_url=f"{redact_url(config.project_url)}/rest/v1/{table}",
                ),
                risk_reason=f"Supabase table '{table}' allows unauthenticated inserts. "
                            "Attackers can inject arbitrary rows.",
                remediation=f"Add INSERT policy: CREATE POLICY insert_policy ON {table} "
                            "FOR INSERT WITH CHECK (auth.uid() IS NOT NULL);",
                validation_status="confirmed",
                category="baas",
            ))


# ---------------------------------------------------------------------------
# Wave 4.5 — Auth flow analysis
# ---------------------------------------------------------------------------

def _decode_jwt_claims(token: str) -> Optional[Dict[str, Any]]:
    """Decode JWT payload without verification (we only need the claims)."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        payload = parts[1]
        # Add padding
        payload += "=" * ((4 - len(payload) % 4) % 4)
        decoded = base64.urlsafe_b64decode(payload)
        return _json.loads(decoded)
    except Exception:
        return None


def _probe_auth_config(
    config: BaaSConfig,
    headers: Dict[str, str],
    prober: BaaSProber,
    validation: BaaSValidation,
) -> None:
    # 1. Check JWT claims
    claims = _decode_jwt_claims(config.api_key)
    if claims:
        role = claims.get("role", "")
        if role == "service_role":
            validation.findings.append(Finding(
                type="baas_service_role_exposed",
                severity="critical",
                confidence=1.0,
                detector_id="baas.service_role_exposed",
                source=config.project_url,
                evidence=Evidence(
                    source=config.project_url,
                    snippet="JWT role claim is 'service_role'. This key bypasses all RLS policies.",
                    redacted_value="role:service_role",
                ),
                risk_reason="The exposed key has service_role privileges, bypassing all Row-Level Security. This is equivalent to full database admin access.",
                remediation="Immediately rotate this key. Never expose a service_role key in client code. Use the anon key instead.",
                validation_status="confirmed",
                category="baas",
            ))

        exp = claims.get("exp")
        if exp:
            remaining = exp - time.time()
            if remaining > 365 * 24 * 3600:
                validation.findings.append(Finding(
                    type="baas_long_lived_key",
                    severity="low",
                    confidence=0.8,
                    detector_id="baas.long_lived_key",
                    source=config.project_url,
                    evidence=Evidence(
                        source=config.project_url,
                        snippet=f"JWT expires in {int(remaining / (365 * 24 * 3600))}+ years.",
                        redacted_value="exp:far-future",
                    ),
                    risk_reason="The anon key has a very long expiry. If compromised, it remains valid for years.",
                    remediation="Consider rotating keys periodically or setting shorter expiry in Supabase dashboard.",
                    validation_status="confirmed",
                    category="baas",
                ))

    # 2. Probe auth settings endpoint
    try:
        resp = prober("GET", f"{config.project_url}/auth/v1/settings", headers)
    except Exception:
        return

    if resp.get("status_code") == 200:
        body = resp.get("body") or {}
        if isinstance(body, dict):
            autoconfirm = body.get("mailer_autoconfirm", False)
            if autoconfirm:
                validation.findings.append(Finding(
                    type="baas_no_email_confirmation",
                    severity="medium",
                    confidence=0.85,
                    detector_id="baas.no_email_confirmation",
                    source=config.project_url,
                    evidence=Evidence(
                        source=config.project_url,
                        snippet="mailer_autoconfirm: true — accounts are auto-confirmed without email verification.",
                        redacted_value="autoconfirm:true",
                    ),
                    risk_reason="Email confirmation is disabled. Attackers can create accounts with any email address without verification.",
                    remediation="Enable email confirmation in Supabase Auth settings.",
                    validation_status="confirmed",
                    category="baas",
                ))


# ---------------------------------------------------------------------------
# Wave 4.6 — Realtime channel security
# ---------------------------------------------------------------------------

def _analyze_realtime(
    config: BaaSConfig,
    validation: BaaSValidation,
    js_extraction: Optional[Dict[str, Any]] = None,
) -> None:
    """Pattern-based analysis of realtime channel names. No WebSocket probing."""
    channels = (js_extraction or {}).get("realtime_channels", [])

    for channel in channels[:20]:
        # Check for user-ID-based channel patterns
        if re.search(r"[-_](?:user|uid|id|profile)[-_]?$|^(?:user|notifications|messages|private)[-_]", channel, re.IGNORECASE):
            validation.realtime_channels.append(BaaSProbeResult(
                probe_type="realtime_channel",
                target=channel,
                status="confirmed",
                note="predictable user-based channel name",
            ))
            validation.findings.append(Finding(
                type="baas_predictable_channel",
                severity="medium",
                confidence=0.7,
                detector_id="baas.predictable_channel",
                source=config.project_url,
                evidence=Evidence(
                    source=config.project_url,
                    snippet=f"Realtime channel '{channel}' uses a predictable user-based naming pattern.",
                    redacted_value=f"channel:{channel}",
                ),
                risk_reason=f"Channel '{channel}' appears to include user identifiers. Without channel policies, any client can subscribe to another user's notifications.",
                remediation="Add Realtime channel policies in Supabase or validate subscriptions server-side.",
                validation_status="lead",
                category="baas",
            ))


# ---------------------------------------------------------------------------
# Wave 4.2 — Firebase active validation
# ---------------------------------------------------------------------------

def _validate_firebase(config: BaaSConfig, prober: BaaSProber) -> BaaSValidation:
    validation = BaaSValidation(provider="firebase", project_url_redacted=redact_url(config.project_url))

    # Probe Realtime Database
    try:
        resp = prober("GET", f"{config.project_url}/.json?shallow=true", {})
    except Exception:
        return validation

    status = resp.get("status_code", 0)
    body = resp.get("body")

    if status == 200 and body is not None and body != "null":
        validation.key_valid = True
        top_keys = list(body.keys()) if isinstance(body, dict) else []
        validation.open_tables.append(BaaSProbeResult(
            probe_type="firebase_db_read", target="/", status="confirmed",
            http_status=status, columns=top_keys[:20],
        ))
        validation.findings.append(Finding(
            type="baas_open_table",
            severity="critical",
            confidence=0.95,
            detector_id="baas.open_table",
            source=config.project_url,
            evidence=Evidence(
                source=config.project_url,
                snippet=f"Firebase Realtime Database is publicly readable. Top-level keys: {', '.join(top_keys[:10])}",
                redacted_value="firebase:/.json",
                response_status=status,
                request_url=f"{redact_url(config.project_url)}/.json?shallow=true",
            ),
            risk_reason="Firebase Realtime Database has no security rules (or rules allow public read). All data is accessible without authentication.",
            remediation='Set Firebase Security Rules to deny public access: {"rules": {".read": "auth != null", ".write": "auth != null"}}',
            validation_status="confirmed",
            category="baas",
            references=["https://firebase.google.com/docs/database/security"],
        ))
    elif status == 401:
        validation.key_valid = False

    # Probe Firebase Storage
    for bucket in config.storage_buckets[:BUCKET_PROBE_CAP]:
        try:
            storage_resp = prober("GET", f"https://firebasestorage.googleapis.com/v0/b/{bucket}/o?maxResults=1", {})
        except Exception:
            continue
        if storage_resp.get("status_code") == 200:
            items = (storage_resp.get("body") or {}).get("items", [])
            validation.accessible_buckets.append(BaaSProbeResult(
                probe_type="firebase_storage", target=bucket, status="confirmed",
                http_status=200, row_count=len(items),
            ))
            validation.findings.append(Finding(
                type="baas_open_storage",
                severity="high",
                confidence=0.9,
                detector_id="baas.open_storage",
                source=config.project_url,
                evidence=Evidence(
                    source=config.project_url,
                    snippet=f"Firebase Storage bucket '{bucket}' is publicly listable.",
                    redacted_value=f"bucket:{bucket}",
                    response_status=200,
                ),
                risk_reason=f"Firebase Storage bucket '{bucket}' allows public listing. Objects can be enumerated and downloaded.",
                remediation="Set Storage security rules: allow read, write: if request.auth != null;",
                validation_status="confirmed",
                category="baas",
            ))

    return validation


# ---------------------------------------------------------------------------
# Wave 4.3 — Appwrite & PocketBase validation
# ---------------------------------------------------------------------------

def _validate_appwrite(config: BaaSConfig, prober: BaaSProber) -> BaaSValidation:
    validation = BaaSValidation(provider="appwrite", project_url_redacted=redact_url(config.project_url))
    headers: Dict[str, str] = {}
    if config.api_key:
        headers["X-Appwrite-Project"] = config.api_key

    try:
        resp = prober("GET", f"{config.project_url}/databases", headers)
    except Exception:
        return validation

    status = resp.get("status_code", 0)
    if status == 200:
        validation.key_valid = True
        dbs = (resp.get("body") or {}).get("databases", [])
        for db in dbs[:5]:
            db_id = db.get("$id", "")
            try:
                col_resp = prober("GET", f"{config.project_url}/databases/{db_id}/collections", headers)
            except Exception:
                continue
            if col_resp.get("status_code") == 200:
                cols = (col_resp.get("body") or {}).get("collections", [])
                for col in cols[:TABLE_PROBE_CAP]:
                    col_id = col.get("$id", "")
                    col_name = col.get("name", col_id)
                    validation.open_tables.append(BaaSProbeResult(
                        probe_type="appwrite_collection", target=col_name,
                        status="confirmed", http_status=200,
                    ))
                    validation.findings.append(Finding(
                        type="baas_open_table", severity="high", confidence=0.9,
                        detector_id="baas.open_table", source=config.project_url,
                        evidence=Evidence(source=config.project_url,
                            snippet=f"Appwrite collection '{col_name}' accessible.",
                            redacted_value=f"collection:{col_name}"),
                        risk_reason=f"Appwrite collection '{col_name}' is accessible without authentication.",
                        remediation="Set collection-level permissions in the Appwrite console.",
                        validation_status="confirmed", category="baas",
                    ))
    return validation


def _validate_pocketbase(config: BaaSConfig, prober: BaaSProber) -> BaaSValidation:
    validation = BaaSValidation(provider="pocketbase", project_url_redacted=redact_url(config.project_url))

    try:
        resp = prober("GET", f"{config.project_url}/api/collections", {})
    except Exception:
        return validation

    status = resp.get("status_code", 0)
    if status == 200:
        validation.key_valid = True
        items = (resp.get("body") or {}).get("items", resp.get("body") if isinstance(resp.get("body"), list) else [])
        for col in items[:TABLE_PROBE_CAP]:
            col_name = col.get("name", "") if isinstance(col, dict) else str(col)
            if not col_name:
                continue
            try:
                rec_resp = prober("GET", f"{config.project_url}/api/collections/{col_name}/records?perPage=1", {})
            except Exception:
                continue
            if rec_resp.get("status_code") == 200:
                validation.open_tables.append(BaaSProbeResult(
                    probe_type="pocketbase_collection", target=col_name,
                    status="confirmed", http_status=200,
                ))
                validation.findings.append(Finding(
                    type="baas_open_table", severity="high", confidence=0.9,
                    detector_id="baas.open_table", source=config.project_url,
                    evidence=Evidence(source=config.project_url,
                        snippet=f"PocketBase collection '{col_name}' readable without auth.",
                        redacted_value=f"collection:{col_name}"),
                    risk_reason=f"PocketBase collection '{col_name}' has no list/view API rules. Anyone can read all records.",
                    remediation=f"Set API rules for the '{col_name}' collection in PocketBase admin.",
                    validation_status="confirmed", category="baas",
                ))
    return validation


def _finding(
    finding_type: str,
    severity: str,
    config: BaaSConfig,
    risk_reason: str,
    remediation: str,
    validation_status: str = "lead",
) -> Finding:
    return Finding(
        type=finding_type,
        severity=severity,
        confidence=0.7,
        detector_id=f"baas.{finding_type}",
        source=config.project_url,
        evidence=Evidence(
            source=config.project_url,
            redacted_value=redact_value(config.api_key),
        ),
        risk_reason=risk_reason,
        remediation=remediation,
        validation_status=validation_status,
        category="baas",
    )
