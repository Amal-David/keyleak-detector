"""Tests for BaaS active validation engine (Wave 4.1).

All HTTP probes are mocked via injectable ``prober`` callables.
No network requests are made.
"""

from __future__ import annotations

import unittest
from typing import Any, Dict, List

from keyleak.baas_validator import (
    BaaSConfig,
    BaaSProbeResult,
    BaaSValidation,
    TABLE_PROBE_CAP,
    _tables_from_openapi,
    extract_baas_config,
    validate_baas_config,
)
from keyleak.browser_scanner import evaluate_findings_payload


def _mock_prober(responses: Dict[str, Dict[str, Any]]):
    """Build a prober that returns canned responses keyed by URL substring.

    Matches are checked longest-pattern-first so ``/rest/v1/profiles`` is
    preferred over ``/rest/v1/`` when both are present.
    """
    sorted_patterns = sorted(responses.keys(), key=len, reverse=True)

    def prober(method: str, url: str, headers: Dict[str, str]) -> Dict[str, Any]:
        for pattern in sorted_patterns:
            if pattern in url:
                return responses[pattern]
        return {"status_code": 404, "body": None, "headers": {}}

    return prober


class ExtractConfigTests(unittest.TestCase):
    def test_extract_from_js_extraction(self):
        js = {
            "supabase_url": "https://abcdefghijklmnopqrst.supabase.co",
            "supabase_key": "sb_publishable_XXXXXXXXXXXXXXXXXXXXXXXX",
            "tables": ["users", "posts", "users"],
            "rpcs": ["increment_plays"],
            "buckets": ["images"],
        }
        config = extract_baas_config(js_extraction=js)
        assert config is not None
        assert config.provider == "supabase"
        assert config.project_url == "https://abcdefghijklmnopqrst.supabase.co"
        assert config.api_key == "sb_publishable_XXXXXXXXXXXXXXXXXXXXXXXX"
        assert config.tables == ["users", "posts"]
        assert config.rpc_functions == ["increment_plays"]
        assert config.storage_buckets == ["images"]

    def test_extract_from_raw_findings(self):
        findings = [
            {"detector_id": "baas.supabase_url", "value": "https://abcdefghijklmnopqrst.supabase.co"},
            {"detector_id": "baas.supabase_publishable_key", "value": "sb_publishable_XXXXXXXXXXXXXXXXXXXXXXXX"},
        ]
        config = extract_baas_config(raw_findings=findings)
        assert config is not None
        assert config.project_url == "https://abcdefghijklmnopqrst.supabase.co"

    def test_extract_returns_none_without_url(self):
        config = extract_baas_config(raw_findings=[
            {"detector_id": "baas.supabase_publishable_key", "value": "sb_publishable_XXXX"},
        ])
        assert config is None

    def test_extract_returns_none_without_key(self):
        config = extract_baas_config(raw_findings=[
            {"detector_id": "baas.supabase_url", "value": "https://abcdefghijklmnopqrst.supabase.co"},
        ])
        assert config is None

    def test_extract_deduplicates_tables(self):
        js = {
            "supabase_url": "https://abcdefghijklmnopqrst.supabase.co",
            "supabase_key": "sb_publishable_XXXXXXXXXXXXXXXXXXXXXXXX",
            "tables": ["t1", "t2", "t1", "t3", "t2"],
            "rpcs": [],
            "buckets": [],
        }
        config = extract_baas_config(js_extraction=js)
        assert config is not None
        assert config.tables == ["t1", "t2", "t3"]

    def test_extract_jwt_key_from_findings(self):
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InZ2a2xna3RtZGJ5amt4aG9ubmlxIn0.XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
        findings = [
            {"detector_id": "baas.supabase_url", "value": "https://abcdefghijklmnopqrst.supabase.co"},
            {"detector_id": "baas.supabase_anon_key", "value": jwt},
        ]
        config = extract_baas_config(raw_findings=findings)
        assert config is not None
        assert config.api_key == jwt


class ValidateKeyTests(unittest.TestCase):
    def _config(self, **overrides) -> BaaSConfig:
        defaults = {
            "provider": "supabase",
            "project_url": "https://abcdefghijklmnopqrst.supabase.co",
            "api_key": "sb_publishable_XXXXXXXXXXXXXXXXXXXXXXXX",
            "tables": ["users"],
            "rpc_functions": [],
            "storage_buckets": [],
        }
        defaults.update(overrides)
        return BaaSConfig(**defaults)

    def test_valid_key(self):
        prober = _mock_prober({
            "/rest/v1/": {"status_code": 200, "body": None, "headers": {}},
            "/rest/v1/users": {"status_code": 200, "body": [{"id": 1, "name": "alice"}], "headers": {}},
        })
        result = validate_baas_config(self._config(), prober=prober)
        assert result.key_valid is True

    def test_invalid_key_skips_probes(self):
        call_count = {"n": 0}

        def counting_prober(method, url, headers):
            call_count["n"] += 1
            return {"status_code": 401, "body": {"message": "Invalid API key"}, "headers": {}}

        result = validate_baas_config(self._config(), prober=counting_prober)
        assert result.key_valid is False
        assert call_count["n"] == 1
        assert len(result.open_tables) == 0


class OpenTableTests(unittest.TestCase):
    def _config(self, tables=None):
        return BaaSConfig(
            provider="supabase",
            project_url="https://abcdefghijklmnopqrst.supabase.co",
            api_key="sb_publishable_XXXXXXXXXXXXXXXXXXXXXXXX",
            tables=tables or ["profiles", "tracks"],
            rpc_functions=[],
            storage_buckets=[],
        )

    def test_open_table_confirmed(self):
        prober = _mock_prober({
            "/rest/v1/": {"status_code": 200, "body": None, "headers": {}},
            "/rest/v1/profiles": {"status_code": 200, "body": [{"id": 1, "username": "alice"}], "headers": {}},
            "/rest/v1/tracks": {"status_code": 200, "body": [{"id": 1, "title": "Song"}], "headers": {}},
            "/storage/v1/bucket": {"status_code": 403, "body": None, "headers": {}},
        })
        result = validate_baas_config(self._config(), prober=prober)
        assert len(result.open_tables) == 2
        assert result.open_tables[0].status == "confirmed"
        assert result.open_tables[0].columns == ["id", "username"]
        assert any(f.type == "baas_open_table" and f.validation_status == "confirmed" for f in result.findings)

    def test_rls_protected_table(self):
        prober = _mock_prober({
            "/rest/v1/": {"status_code": 200, "body": None, "headers": {}},
            "/rest/v1/profiles": {"status_code": 403, "body": {"message": "permission denied"}, "headers": {}},
            "/storage/v1/bucket": {"status_code": 403, "body": None, "headers": {}},
        })
        result = validate_baas_config(
            self._config(tables=["profiles"]),
            prober=prober,
        )
        assert len(result.open_tables) == 0
        assert len(result.protected_tables) == 1
        assert result.protected_tables[0].status == "denied"

    def test_sensitive_table_is_critical(self):
        prober = _mock_prober({
            "/rest/v1/": {"status_code": 200, "body": None, "headers": {}},
            "/rest/v1/artist_payout_details": {
                "status_code": 200,
                "body": [{"id": 1, "payout_method": "paypal"}],
                "headers": {},
            },
            "/storage/v1/bucket": {"status_code": 403, "body": None, "headers": {}},
        })
        result = validate_baas_config(
            self._config(tables=["artist_payout_details"]),
            prober=prober,
        )
        payout_findings = [f for f in result.findings if "payout" in f.evidence.redacted_value]
        assert payout_findings
        assert payout_findings[0].severity == "critical"

    def test_table_probe_capped(self):
        tables = [f"table_{i}" for i in range(100)]
        probed_tables: List[str] = []

        def tracking_prober(method, url, headers):
            if method == "GET" and "/rest/v1/table_" in url:
                name = url.split("/rest/v1/")[1].split("?")[0]
                probed_tables.append(name)
            return {"status_code": 200, "body": [], "headers": {}}

        result = validate_baas_config(
            self._config(tables=tables),
            prober=tracking_prober,
        )
        assert len(probed_tables) == TABLE_PROBE_CAP


class StorageBucketTests(unittest.TestCase):
    def _config(self, buckets=None):
        return BaaSConfig(
            provider="supabase",
            project_url="https://abcdefghijklmnopqrst.supabase.co",
            api_key="sb_publishable_XXXXXXXXXXXXXXXXXXXXXXXX",
            tables=[],
            rpc_functions=[],
            storage_buckets=buckets or ["images"],
        )

    def test_public_bucket_detected(self):
        prober = _mock_prober({
            "/rest/v1/": {"status_code": 200, "body": None, "headers": {}},
            "/storage/v1/bucket": {
                "status_code": 200,
                "body": [{"name": "images", "public": True}],
                "headers": {},
            },
        })
        result = validate_baas_config(self._config(), prober=prober)
        assert len(result.accessible_buckets) == 1
        assert result.accessible_buckets[0].note == "public"
        assert any(f.type == "baas_open_storage" for f in result.findings)

    def test_listable_bucket_from_client_reference(self):
        prober = _mock_prober({
            "/rest/v1/": {"status_code": 200, "body": None, "headers": {}},
            "/storage/v1/bucket": {"status_code": 200, "body": [], "headers": {}},
            "/storage/v1/object/list/images": {
                "status_code": 200,
                "body": [{"name": "photo.jpg"}],
                "headers": {},
            },
        })
        result = validate_baas_config(self._config(), prober=prober)
        assert len(result.accessible_buckets) == 1
        assert result.accessible_buckets[0].note == "objects listable"


class RPCTests(unittest.TestCase):
    def _config(self, rpcs=None):
        return BaaSConfig(
            provider="supabase",
            project_url="https://abcdefghijklmnopqrst.supabase.co",
            api_key="sb_publishable_XXXXXXXXXXXXXXXXXXXXXXXX",
            tables=[],
            rpc_functions=rpcs or ["increment_plays"],
            storage_buckets=[],
        )

    def test_rpc_surfaced_as_lead(self):
        """RPCs are listed as leads without executing them (no POST probe)."""
        calls: List = []
        base = _mock_prober({
            "/rest/v1/": {"status_code": 200, "body": None, "headers": {}},
            "/storage/v1/bucket": {"status_code": 403, "body": None, "headers": {}},
            "/auth/v1/settings": {"status_code": 401, "body": None, "headers": {}},
        })
        def tracking_prober(method, url, headers, body=None):
            calls.append((method, url))
            return base(method, url, headers)

        result = validate_baas_config(self._config(), prober=tracking_prober)
        assert len(result.callable_rpcs) == 1
        rpc_findings = [f for f in result.findings if f.type == "baas_open_rpc"]
        assert len(rpc_findings) == 1
        assert rpc_findings[0].validation_status == "lead"
        assert rpc_findings[0].confidence < 0.8
        assert not any(m == "POST" and "/rpc/" in u for m, u in calls), "RPC should not be probed via POST"


class CORSTests(unittest.TestCase):
    def _config(self):
        return BaaSConfig(
            provider="supabase",
            project_url="https://abcdefghijklmnopqrst.supabase.co",
            api_key="sb_publishable_XXXXXXXXXXXXXXXXXXXXXXXX",
        )

    def test_cors_wildcard_detected(self):
        prober = _mock_prober({
            "/rest/v1/": {
                "status_code": 200,
                "body": None,
                "headers": {"access-control-allow-origin": "*"},
            },
            "/storage/v1/bucket": {"status_code": 403, "body": None, "headers": {}},
        })
        result = validate_baas_config(self._config(), prober=prober)
        assert result.cors_open is True
        assert any(f.type == "baas_cors_wildcard" for f in result.findings)

    def test_restricted_cors_not_flagged(self):
        prober = _mock_prober({
            "/rest/v1/": {
                "status_code": 200,
                "body": None,
                "headers": {"access-control-allow-origin": "https://example.com"},
            },
            "/storage/v1/bucket": {"status_code": 403, "body": None, "headers": {}},
        })
        result = validate_baas_config(self._config(), prober=prober)
        assert result.cors_open is False


class ProberErrorTests(unittest.TestCase):
    def _config(self):
        return BaaSConfig(
            provider="supabase",
            project_url="https://abcdefghijklmnopqrst.supabase.co",
            api_key="sb_publishable_XXXXXXXXXXXXXXXXXXXXXXXX",
            tables=["t1"],
        )

    def test_prober_exception_handled(self):
        def failing_prober(method, url, headers):
            raise ConnectionError("network down")

        result = validate_baas_config(self._config(), prober=failing_prober)
        assert result.key_valid is False
        assert any("failed" in f.risk_reason for f in result.findings)


class EvaluateFindingsIntegrationTests(unittest.TestCase):
    def test_baas_disabled_skips_validation(self):
        raw = [{"detector_id": "baas.supabase_url", "type": "supabase_url", "severity": "medium",
                "source": "document", "value": "https://abcdefghijklmnopqrst.supabase.co"}]
        report = evaluate_findings_payload(raw, "https://example.com", baas_validate=False)
        assert not any(f.type == "baas_open_table" for f in report.findings)

    def test_baas_with_extraction_and_prober(self):
        raw = []
        js_extraction = {
            "supabase_url": "https://abcdefghijklmnopqrst.supabase.co",
            "supabase_key": "sb_publishable_XXXXXXXXXXXXXXXXXXXXXXXX",
            "tables": ["public_data"],
            "rpcs": [],
            "buckets": [],
        }
        prober = _mock_prober({
            "/rest/v1/": {"status_code": 200, "body": None, "headers": {}},
            "/rest/v1/public_data": {"status_code": 200, "body": [{"id": 1}], "headers": {}},
            "/storage/v1/bucket": {"status_code": 403, "body": None, "headers": {}},
        })
        report = evaluate_findings_payload(
            raw, "https://example.com",
            baas_extraction=js_extraction,
            baas_validate=True,
            baas_prober=prober,
        )
        open_table_findings = [f for f in report.findings if f.type == "baas_open_table"]
        assert len(open_table_findings) == 1
        assert open_table_findings[0].validation_status == "confirmed"


class FirebaseValidationTests(unittest.TestCase):
    def test_open_firebase_db(self):
        config = BaaSConfig(provider="firebase", project_url="https://test-app.firebaseio.com", api_key="AIzaXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")
        prober = _mock_prober({
            "/.json": {"status_code": 200, "body": {"users": True, "posts": True}, "headers": {}},
        })
        result = validate_baas_config(config, prober=prober)
        assert result.key_valid is True
        assert len(result.open_tables) == 1
        assert any(f.type == "baas_open_table" and f.severity == "critical" for f in result.findings)

    def test_closed_firebase_db(self):
        config = BaaSConfig(provider="firebase", project_url="https://test-app.firebaseio.com", api_key="")
        prober = _mock_prober({
            "/.json": {"status_code": 401, "body": {"error": "Permission denied"}, "headers": {}},
        })
        result = validate_baas_config(config, prober=prober)
        assert result.key_valid is False
        assert len(result.open_tables) == 0

    def test_firebase_storage_open(self):
        config = BaaSConfig(provider="firebase", project_url="https://test-app.firebaseio.com", api_key="", storage_buckets=["test-app.appspot.com"])
        prober = _mock_prober({
            "/.json": {"status_code": 401, "body": None, "headers": {}},
            "firebasestorage.googleapis.com": {"status_code": 200, "body": {"items": [{"name": "file.jpg"}]}, "headers": {}},
        })
        result = validate_baas_config(config, prober=prober)
        assert len(result.accessible_buckets) == 1


class AppwriteValidationTests(unittest.TestCase):
    def test_open_appwrite_collections(self):
        config = BaaSConfig(provider="appwrite", project_url="https://cloud.appwrite.io/v1", api_key="project123")
        prober = _mock_prober({
            "/databases": {"status_code": 200, "body": {"databases": [{"$id": "db1"}]}, "headers": {}},
            "/databases/db1/collections": {"status_code": 200, "body": {"collections": [{"$id": "c1", "name": "users"}]}, "headers": {}},
        })
        result = validate_baas_config(config, prober=prober)
        assert result.key_valid is True
        assert len(result.open_tables) == 1

    def test_closed_appwrite(self):
        config = BaaSConfig(provider="appwrite", project_url="https://cloud.appwrite.io/v1", api_key="project123")
        prober = _mock_prober({
            "/databases": {"status_code": 401, "body": None, "headers": {}},
        })
        result = validate_baas_config(config, prober=prober)
        assert result.key_valid is False


class PocketbaseValidationTests(unittest.TestCase):
    def test_open_pocketbase_collections(self):
        config = BaaSConfig(provider="pocketbase", project_url="https://pb.example.com", api_key="")
        prober = _mock_prober({
            "/api/collections": {"status_code": 200, "body": {"items": [{"name": "posts"}]}, "headers": {}},
            "/api/collections/posts/records": {"status_code": 200, "body": {"items": [{"id": "1"}]}, "headers": {}},
        })
        result = validate_baas_config(config, prober=prober)
        assert len(result.open_tables) == 1


class WriteAccessTests(unittest.TestCase):
    def _config(self, tables=None):
        return BaaSConfig(
            provider="supabase",
            project_url="https://abcdefghijklmnopqrst.supabase.co",
            api_key="sb_publishable_XXXXXXXXXXXXXXXXXXXXXXXX",
            tables=tables or ["users"],
        )

    def test_writable_table_confirmed(self):
        def smart_prober(method, url, headers, body=None):
            if method == "GET" and "/rest/v1/" in url and url.endswith("/rest/v1/"):
                return {"status_code": 200, "body": None, "headers": {}}
            if method == "GET" and "/rest/v1/users" in url:
                return {"status_code": 200, "body": [{"id": 1}], "headers": {}}
            if method == "POST" and "/rest/v1/users" in url:
                return {"status_code": 400, "body": {"message": "schema error"}, "headers": {}}
            if "/storage/v1/bucket" in url:
                return {"status_code": 403, "body": None, "headers": {}}
            if "/auth/v1/settings" in url:
                return {"status_code": 401, "body": None, "headers": {}}
            return {"status_code": 404, "body": None, "headers": {}}

        result = validate_baas_config(self._config(), prober=smart_prober, allow_write_probe=True)
        assert result.key_valid is True
        assert len(result.writable_tables) == 1
        assert any(f.type == "baas_writable_table" for f in result.findings)

    def test_write_probe_skipped_by_default_sends_no_post(self):
        """Safety: the default scan is read-only — no POST insert is ever issued."""
        methods = []

        def spy_prober(method, url, headers, body=None):
            methods.append(method)
            if method == "GET" and url.endswith("/rest/v1/"):
                return {"status_code": 200, "body": None, "headers": {}}
            if method == "GET" and "/rest/v1/users" in url:
                return {"status_code": 200, "body": [{"id": 1}], "headers": {}}
            return {"status_code": 404, "body": None, "headers": {}}

        result = validate_baas_config(self._config(), prober=spy_prober)  # default: no opt-in
        assert "POST" not in methods, "read-only scan must not POST to the target"
        assert result.writable_tables == []

    def test_write_blocked_by_rls(self):
        def rls_prober(method, url, headers, body=None):
            if "rest/v1/" in url and method == "GET" and url.endswith("/rest/v1/"):
                return {"status_code": 200, "body": None, "headers": {}}
            if "rest/v1/users" in url and method == "GET":
                return {"status_code": 200, "body": [{"id": 1}], "headers": {}}
            if "rest/v1/users" in url and method == "POST":
                return {"status_code": 403, "body": {"message": "RLS"}, "headers": {}}
            if "/storage/v1/bucket" in url:
                return {"status_code": 403, "body": None, "headers": {}}
            if "/auth/v1/settings" in url:
                return {"status_code": 401, "body": None, "headers": {}}
            return {"status_code": 404, "body": None, "headers": {}}

        result = validate_baas_config(self._config(), prober=rls_prober, allow_write_probe=True)
        assert len(result.writable_tables) == 0
        assert not any(f.type == "baas_writable_table" for f in result.findings)


class AuthFlowTests(unittest.TestCase):
    def test_service_role_key_detected(self):
        import base64
        import json as _json
        header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b'=').decode()
        payload = base64.urlsafe_b64encode(_json.dumps({"role": "service_role", "iss": "supabase", "exp": 9999999999}).encode()).rstrip(b'=').decode()
        sig = "x" * 30
        jwt_key = f"{header}.{payload}.{sig}"

        config = BaaSConfig(provider="supabase", project_url="https://abcdefghijklmnopqrst.supabase.co", api_key=jwt_key)
        prober = _mock_prober({
            "/rest/v1/": {"status_code": 200, "body": None, "headers": {}},
            "/storage/v1/bucket": {"status_code": 200, "body": [], "headers": {}},
            "/auth/v1/settings": {"status_code": 401, "body": None, "headers": {}},
        })
        result = validate_baas_config(config, prober=prober)
        assert any(f.type == "baas_service_role_exposed" for f in result.findings)

    def test_autoconfirm_detected(self):
        config = BaaSConfig(
            provider="supabase",
            project_url="https://abcdefghijklmnopqrst.supabase.co",
            api_key="sb_publishable_XXXXXXXXXXXXXXXXXXXXXXXX",
        )
        prober = _mock_prober({
            "/rest/v1/": {"status_code": 200, "body": None, "headers": {}},
            "/storage/v1/bucket": {"status_code": 403, "body": None, "headers": {}},
            "/auth/v1/settings": {"status_code": 200, "body": {"mailer_autoconfirm": True}, "headers": {}},
        })
        result = validate_baas_config(config, prober=prober)
        assert any(f.type == "baas_no_email_confirmation" for f in result.findings)


class RealtimeAnalysisTests(unittest.TestCase):
    def test_predictable_channel_flagged(self):
        config = BaaSConfig(
            provider="supabase",
            project_url="https://abcdefghijklmnopqrst.supabase.co",
            api_key="sb_publishable_XXXXXXXXXXXXXXXXXXXXXXXX",
        )
        js_extraction = {
            "supabase_url": config.project_url,
            "supabase_key": config.api_key,
            "tables": [],
            "rpcs": [],
            "buckets": [],
            "realtime_channels": ["notifications-user_123", "public-updates"],
        }
        prober = _mock_prober({
            "/rest/v1/": {"status_code": 200, "body": None, "headers": {}},
            "/storage/v1/bucket": {"status_code": 403, "body": None, "headers": {}},
            "/auth/v1/settings": {"status_code": 401, "body": None, "headers": {}},
        })
        result = validate_baas_config(config, prober=prober, js_extraction=js_extraction)
        channel_findings = [f for f in result.findings if f.type == "baas_predictable_channel"]
        assert len(channel_findings) == 1
        assert "notifications" in channel_findings[0].evidence.snippet


class OpenApiTableEnumerationTests(unittest.TestCase):
    """M5: tables exposed by the PostgREST root but NOT named in the bundle (CBSE case)."""

    def test_parse_tables_from_openapi_definitions_and_paths(self):
        body = {
            "definitions": {"users": {}, "payouts": {}},
            "paths": {"/": {}, "/users": {}, "/secret_notes": {}, "/rpc/do_thing": {}, "/{id}": {}},
        }
        names = _tables_from_openapi(body)
        self.assertIn("users", names)
        self.assertIn("payouts", names)
        self.assertIn("secret_notes", names)
        self.assertNotIn("rpc/do_thing", names)   # RPCs excluded
        self.assertNotIn("", names)                # root excluded
        self.assertNotIn("{id}", names)            # parameterized excluded

    def test_parse_handles_non_dict_body(self):
        self.assertEqual(_tables_from_openapi(None), [])
        self.assertEqual(_tables_from_openapi("not json"), [])

    def test_enumerated_only_open_table_is_probed_and_flagged(self):
        # The page never references 'private_messages'; the OpenAPI root exposes it.
        config = BaaSConfig(
            provider="supabase",
            project_url="https://abcdefghijklmnopqrst.supabase.co",
            api_key="anon-key",
            tables=["public_posts"],  # the only table the JS bundle named
        )

        def prober(method, url, headers, body=None):
            if method == "GET" and url.endswith("/rest/v1/"):
                return {"status_code": 200, "headers": {}, "body": {
                    "definitions": {"public_posts": {}, "private_messages": {}},
                }}
            if "/rest/v1/private_messages" in url:
                return {"status_code": 200, "headers": {}, "body": [{"id": 1, "body": "secret"}]}
            if "/rest/v1/public_posts" in url:
                return {"status_code": 200, "headers": {}, "body": [{"id": 1, "title": "hi"}]}
            return {"status_code": 404, "headers": {}, "body": None}

        result = validate_baas_config(config, prober=prober)
        open_names = {r.target for r in result.open_tables}
        # the enumerated-only table was discovered and probed even though the JS never named it
        self.assertIn("private_messages", open_names)
        self.assertIn("public_posts", open_names)
        # the enumerated-only finding is a LEAD with softened, accurate wording
        enum_finding = next(f for f in result.findings
                            if f.type == "baas_open_table" and "private_messages" in f.evidence.redacted_value)
        self.assertEqual(enum_finding.validation_status, "lead")
        self.assertIn("not among the table names extracted", enum_finding.risk_reason)
        self.assertNotIn("no effective RLS", enum_finding.risk_reason)  # not asserted as fact
        # a JS-referenced readable table is a CONFIRMED no-RLS finding
        js_finding = next(f for f in result.findings
                          if f.type == "baas_open_table" and "public_posts" in f.evidence.redacted_value)
        self.assertEqual(js_finding.validation_status, "confirmed")
        self.assertIn("no effective RLS", js_finding.risk_reason)

    def test_empty_array_is_not_an_open_table(self):
        """200 [] = anon role saw no rows = correctly RLS-protected. NOT a finding."""
        config = BaaSConfig(
            provider="supabase",
            project_url="https://abcdefghijklmnopqrst.supabase.co",
            api_key="anon-key",
            tables=["secured"],
        )

        def prober(method, url, headers, body=None):
            if method == "GET" and url.endswith("/rest/v1/"):
                return {"status_code": 200, "headers": {}, "body": {"definitions": {"secured": {}}}}
            if "/rest/v1/secured" in url:
                return {"status_code": 200, "headers": {}, "body": []}  # empty -> protected
            return {"status_code": 404, "headers": {}, "body": None}

        result = validate_baas_config(config, prober=prober)
        self.assertEqual(
            [f for f in result.findings if f.type == "baas_open_table"], [],
            "a 200 empty-array response must not produce an open-table finding",
        )
        self.assertTrue(any(p.target == "secured" and p.status == "empty"
                            for p in result.protected_tables))

    def test_view_gets_view_remediation_not_alter_table(self):
        """A read-only relation (no POST in OpenAPI) is a view; ALTER TABLE is invalid."""
        config = BaaSConfig(
            provider="supabase",
            project_url="https://abcdefghijklmnopqrst.supabase.co",
            api_key="anon-key",
            tables=[],
        )

        def prober(method, url, headers, body=None):
            if method == "GET" and url.endswith("/rest/v1/"):
                # leaderboard exposed as a path with GET only (a view) — no post op
                return {"status_code": 200, "headers": {}, "body": {
                    "paths": {"/leaderboard": {"get": {}}},
                }}
            if "/rest/v1/leaderboard" in url:
                return {"status_code": 200, "headers": {}, "body": [{"rank": 1, "user": "a"}]}
            return {"status_code": 404, "headers": {}, "body": None}

        result = validate_baas_config(config, prober=prober)
        finding = next(f for f in result.findings if f.type == "baas_open_table")
        self.assertIn("view", finding.risk_reason.lower())
        self.assertNotIn("ALTER TABLE", finding.remediation)
        self.assertIn("security_invoker", finding.remediation)

    def test_rpc_prefixed_table_name_survives_parsing(self):
        names = _tables_from_openapi({"definitions": {"rpc_audit_log": {}}, "paths": {"/rpc/do": {"post": {}}}})
        self.assertIn("rpc_audit_log", names)   # a real table, not an RPC
        self.assertNotIn("do", names)           # the actual RPC is excluded (path has /rpc/)

    def test_table_severity_uses_token_boundaries(self):
        from keyleak.baas_validator import _table_severity
        self.assertEqual(_table_severity("authors"), "high")        # not 'auth'
        self.assertEqual(_table_severity("reporting"), "high")      # not 'report'
        self.assertEqual(_table_severity("payout_ledger"), "critical")
        self.assertEqual(_table_severity("admin"), "critical")

    def test_definitions_only_table_is_not_misclassified_as_view(self):
        """Regression: a base table from a paths-less OpenAPI body must get table
        (ALTER TABLE) remediation, not view (security_invoker) remediation."""
        config = BaaSConfig(
            provider="supabase",
            project_url="https://abcdefghijklmnopqrst.supabase.co",
            api_key="anon-key",
            tables=["orders"],
        )

        def prober(method, url, headers, body=None):
            if method == "GET" and url.endswith("/rest/v1/"):
                # definitions-only: insertability unknown -> must default to table
                return {"status_code": 200, "headers": {}, "body": {"definitions": {"orders": {}}}}
            if "/rest/v1/orders" in url:
                return {"status_code": 200, "headers": {}, "body": [{"id": 1, "total": 9}]}
            return {"status_code": 404, "headers": {}, "body": None}

        result = validate_baas_config(config, prober=prober)
        finding = next(f for f in result.findings if f.type == "baas_open_table")
        self.assertIn("ALTER TABLE", finding.remediation)
        self.assertNotIn("security_invoker", finding.remediation)
        self.assertNotIn("view", finding.risk_reason.lower())


if __name__ == "__main__":
    unittest.main()
