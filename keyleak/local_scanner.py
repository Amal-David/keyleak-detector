"""Local file/config scanner for secrets and agent-era exposures."""

from __future__ import annotations

import math
import os
import re
from pathlib import Path
from typing import Iterable, List, Optional, Sequence, Tuple

from .detectors import Detector, categories_for_packs, detectors_for_categories, normalize_packs
from .detectors_ast import detect_worm_shape, is_worm_shape_target
from .detectors_fuzzy import FingerprintHit, load_corpus, match_fingerprints
from .detectors_splittoken import SplitTokenMatch, collect_fragments, find_split_tokens
from .models import Evidence, Finding, confidence_for_severity
from .privacy_filter import scrub_snippet as pii_scrub_snippet
from .redaction import new_run_salt, redact_snippet, redact_value
from .reporting import build_report
from .sourcemaps import SourceMapError, reconstruct_originals


# Lazy: cache the loaded fingerprint corpus across scans within one process.
_FINGERPRINT_CORPUS_CACHE: Optional[List] = None


def _get_fingerprint_corpus():
    global _FINGERPRINT_CORPUS_CACHE
    if _FINGERPRINT_CORPUS_CACHE is None:
        try:
            _FINGERPRINT_CORPUS_CACHE = load_corpus()
        except ValueError:
            _FINGERPRINT_CORPUS_CACHE = []
    return _FINGERPRINT_CORPUS_CACHE


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
SKIP_GENERATED_FILE_SUFFIXES = {
    "extension/lib/detector-info.js",
    "extension/lib/patterns.js",
}


def scan_path(
    path: str,
    includes: Sequence[str] = DEFAULT_INCLUDES,
    profile: str = "launch-gate",
    packs: Optional[Iterable[str]] = None,
    *,
    run_salt: Optional[bytes] = None,
):
    target = Path(path).expanduser().resolve()
    findings: List[Finding] = []
    active_packs = normalize_packs(packs, profile=profile)
    active_includes = _effective_includes(includes, active_packs)
    if run_salt is None:
        run_salt = new_run_salt()

    code_files: List[Path] = []
    for file_path, categories in _iter_candidate_files(target, active_includes):
        findings.extend(
            scan_file(file_path, detectors_for_categories(categories, active_packs), run_salt=run_salt)
        )
        if file_path.suffix.lower() in {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".py"}:
            code_files.append(file_path)

    # Wave 3.4 — cross-file split-token reassembly. Opt-in via env var because
    # the current algorithm is noisy on real-world corpora (any fragment that
    # already starts with a key prefix produces N×M cross-file findings against
    # every other-file fragment). The 313-repo dogfood scan surfaced this at
    # 7M+ findings on cline/cline alone. Slated for redesign in v0.3 with a
    # proper prefix-bridging gate; meanwhile, callers can opt in with
    # ``KEYLEAK_ENABLE_SPLIT_TOKEN=1``.
    if os.environ.get("KEYLEAK_ENABLE_SPLIT_TOKEN") == "1" and len(code_files) >= 2:
        fragments_by_file = collect_fragments(code_files)
        for match in find_split_tokens(fragments_by_file):
            findings.append(_split_token_finding(match))

    # Dependency lifecycle-hook audit (supply-chain). The regex pack skips
    # node_modules, so a malicious dependency's preinstall/postinstall is
    # otherwise invisible. Runs when the leak pack is active and a manifest is
    # present. Read-only.
    if "leak" in active_packs and ((target / "package.json").is_file() or (target / "node_modules").is_dir()):
        from .lifecycle_audit import audit_node_dependencies
        findings.extend(audit_node_dependencies(str(target)))

    return build_report(str(target), findings, scan_mode="local", profile=profile, packs=active_packs)


def _split_token_finding(match) -> Finding:
    snippet = (
        f"{match.fragment_a.file}:{match.fragment_a.line} + "
        f"{match.fragment_b.file}:{match.fragment_b.line} = "
        f"{match.prefix}..."
    )
    return Finding(
        type="split_token_reassembly",
        severity="critical",
        confidence=0.75,
        detector_id="leak.split_token_reassembly",
        source=f"{match.fragment_a.file}+{match.fragment_b.file}",
        evidence=Evidence(
            source=match.fragment_a.file,
            snippet=snippet[:600],
            line=match.fragment_a.line,
            redacted_value=f"{match.prefix}...[reassembled]",
        ),
        risk_reason=(
            f"Two source files contain fragments that concatenate to a string starting with "
            f"{match.prefix!r}. The bundle merges them at runtime; the regex pack sees only the "
            "individual fragments."
        ),
        remediation=(
            "Audit the call site. If the concatenation is intentional, restructure to fetch the "
            "secret server-side. If unintentional, the splitting may be an evasion attempt."
        ),
        validation_status="lead",
        category="leak",
    )


def scan_file(
    file_path: Path,
    detectors: Iterable[Detector],
    *,
    run_salt: Optional[bytes] = None,
) -> List[Finding]:
    try:
        if file_path.stat().st_size > MAX_FILE_BYTES:
            return []
        content = file_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []

    detectors_list = list(detectors)
    findings = scan_text(content, str(file_path), detectors_list, run_salt=run_salt)
    # Wave 2.1 — if this is a JS bundle with a sibling .map or inline source map,
    # re-run detectors against the reconstructed *original* sources so the PR
    # comment surfaces src/components/Auth.tsx:42 instead of a minified
    # one-line bundle. Skip the deobfuscation step for non-JS files.
    if file_path.suffix.lower() in {".js", ".mjs", ".cjs", ".html", ".htm"}:
        try:
            originals = reconstruct_originals(content, bundle_path=file_path)
        except SourceMapError:
            originals = []
        for entry in originals:
            # Tag the reconstructed source with both the original logical name
            # (so the developer can find the line) and the bundle path (so
            # they know which deploy artifact carried it).
            source_id = f"{file_path}#{entry.source_path}"
            findings.extend(scan_text(entry.content, source_id, detectors_list, run_salt=run_salt))
    # Wave 2.2 — capability-triad worm-shape scan on install scripts and
    # node_modules sources. Independent of the regex pack; pure behavioral.
    if is_worm_shape_target(file_path):
        match = detect_worm_shape(content, str(file_path))
        if match is not None:
            findings.append(_worm_shape_finding(match, run_salt=run_salt))
        # Wave 2.3 — fuzzy-hash fingerprint scan on the same targets.
        corpus = _get_fingerprint_corpus()
        if corpus:
            for hit in match_fingerprints(content, corpus):
                findings.append(_fingerprint_finding(str(file_path), hit))
    return findings


def _worm_shape_finding(match, *, run_salt: Optional[bytes] = None) -> Finding:
    summary = (
        f"capability triad in {match.source}: "
        f"env_read line {match.env_read_line}, "
        f"net_egress line {match.net_egress_line}, "
        f"persistence_write line {match.persistence_write_line}"
    )
    evidence = Evidence(
        source=match.source,
        snippet=match.excerpt_window[:600],
        line=match.env_read_line,
        redacted_value=summary[:200],
    )
    finding = Finding(
        type="worm_shape_capability_triad",
        severity="critical",
        confidence=0.85,
        detector_id="leak.worm_shape_capability_triad",
        source=match.source,
        evidence=evidence,
        risk_reason=(
            "A single source exhibits all three Mini Shai-Hulud capabilities: a credential-shaped "
            "env-var read, network egress, and a write into a persistence-relevant directory. "
            "This is the worm payload shape regardless of which strings or hostnames are used."
        ),
        remediation=(
            "Remove the package or vendor the code in-tree. Rotate every credential the install "
            "step could have read. Audit egress logs for the install timeframe."
        ),
        validation_status="lead",
        category="leak",
    )
    return finding


def _fingerprint_finding(source: str, hit: FingerprintHit) -> Finding:
    snippet = (
        f"matched worm fingerprint {hit.name!r} via {hit.matched} "
        f"(score={hit.score:.2f}). References: {', '.join(hit.references) or 'n/a'}"
    )
    return Finding(
        type="worm_fingerprint_match",
        severity="critical",
        confidence=hit.score if hit.matched == "fuzzy" else 0.95,
        detector_id=f"leak.worm_fingerprint.{hit.name}",
        source=source,
        evidence=Evidence(
            source=source,
            snippet=snippet[:600],
            redacted_value=snippet[:200],
        ),
        risk_reason=(
            f"This file matches a known worm payload fingerprint ({hit.name}). "
            f"{hit.description}"
        ),
        remediation=(
            "Treat the host as compromised. Rotate every credential reachable from the affected "
            "machine or CI runner: AWS, GCP, Kubernetes, Vault, GitHub, npm, SSH. Audit egress."
        ),
        validation_status="validated" if hit.matched == "exact" else "lead",
        category="leak",
        references=list(hit.references),
    )


def scan_text(
    content: str,
    source: str,
    detectors: Iterable[Detector],
    *,
    run_salt: Optional[bytes] = None,
) -> List[Finding]:
    findings: List[Finding] = []
    seen = set()
    for detector in detectors:
        regex = detector.compile()
        for match in regex.finditer(content):
            raw_value = match.group(detector.capture_group) if detector.capture_group and match.groups() else match.group(1) if match.groups() else match.group(0)
            if _is_placeholder(raw_value, min_length=detector.min_match_length):
                continue
            # L.3 — database_url placeholder-password gate (skip dev defaults).
            if detector.id == "database_url" and _is_placeholder_db_url(raw_value):
                continue
            # L.4 — Local-dev URL guard: skip findings whose hostname is loopback / .local / .test.
            if _is_local_dev_url(raw_value):
                continue
            # Q.1 — Shannon-entropy filter: dictionary-word matches like
            # `sk-indigo-twilight-color-1` (Skeleton UI class names) shouldn't
            # trip credential detectors.
            min_entropy = getattr(detector, "min_entropy", None)
            if min_entropy is not None and _shannon_entropy(raw_value) < min_entropy:
                continue
            # Q.7 — basic-auth localhost guard: the L.4 generic check misses
            # `https://localhost:'...@` substrings in minified JS where the
            # "port" isn't a clean number. Check the user portion directly.
            if detector.id == "http_basic_auth" and _is_basic_auth_localhost(raw_value):
                continue
            # Q.11 — extend the template-string guard to http_basic_auth.
            # Workflow YAML / install scripts often contain
            # ``http://${USER}:${PASSWORD}@host`` shapes that are interpolated
            # at runtime, not actual creds.
            if detector.id == "http_basic_auth" and any(m in str(raw_value) for m in _TEMPLATE_MARKERS):
                continue
            # Q.8 — bearer/secret tokens that literally start with a "public"
            # prefix are by definition public.
            if detector.id in {"bearer_token", "openai_api_key", "stripe_secret_key"} and _has_public_prefix(raw_value):
                continue
            line = content.count("\n", 0, match.start()) + 1
            snippet = _snippet_for(content, match.start(), match.end())
            # Q.6 + Q.9 — AIza referrer-restricted keys: Google's Firebase /
            # Maps / Analytics keys are designed to live in client code.
            # Downgrade severity if ANY client-side marker (firebaseConfig,
            # gapi, googleapis Maps, gtag, fbq) appears in the *same file* —
            # not just the ±80-char snippet (markers usually live elsewhere
            # in the file).
            effective_severity = detector.severity
            if detector.id == "gemini_api_key" and _looks_like_client_side_aiza(content):
                effective_severity = "medium"
            redacted_value = redact_value(raw_value, run_salt=run_salt)
            key = (detector.canonical_id, source, redacted_value, line)
            if key in seen:
                continue
            seen.add(key)
            # 1. Replace the raw secret with its redacted form in the snippet,
            #    then 2. mask any *adjacent* PII so the report can't carry
            #    third-party emails/phones/cards into auditor hands.
            redacted_snippet = redact_snippet(snippet, raw_value, run_salt=run_salt)
            redacted_snippet = pii_scrub_snippet(redacted_snippet, redacted_value)
            evidence = Evidence(
                source=source,
                snippet=redacted_snippet,
                line=line,
                redacted_value=redacted_value,
            )
            findings.append(
                Finding(
                    type=detector.result_type,
                    severity=effective_severity,
                    confidence=confidence_for_severity(effective_severity, source),
                    detector_id=detector.canonical_id,
                    source=source,
                    evidence=evidence,
                    risk_reason=detector.description,
                    remediation=detector.remediation,
                    validation_status=detector.validation_status,
                    category=detector.pack,
                    references=list(detector.references),
                    remediation_v2=detector.get_remediation().to_dict(),
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
            if _is_generated_file(file_path):
                continue
            categories = _categories_for_file(file_path, includes)
            if categories:
                yield file_path, categories


def _is_generated_file(path: Path) -> bool:
    normalized = str(path).replace(os.sep, "/")
    return any(normalized.endswith(suffix) for suffix in SKIP_GENERATED_FILE_SUFFIXES)


def _matches_include(path: Path, includes: Sequence[str]) -> bool:
    return bool(_categories_for_file(path, includes))


def _categories_for_file(path: Path, includes: Sequence[str]) -> List[str]:
    requested = {include.lower() for include in includes}
    name = path.name.lower()
    full = str(path).lower()
    suffix = path.suffix.lower()

    checks = {
        "env": name.startswith(".env") or name.endswith(".env") or name in {"config.json", "secrets.json"},
        "mcp": "mcp" in name or name in {"claude_desktop_config.json", "codex.json"} or ".cursor" in full,
        "ci": ".github/workflows" in full or name in {".gitlab-ci.yml", "circle.yml", "buildkite.yml"},
        "docker": name in {"dockerfile", "compose.yml", "docker-compose.yml"} or name.endswith(".dockerfile"),
        "sourcemaps": name.endswith((".map", ".js", ".html", ".htm")),
        "logs": name.endswith(".log") or name.endswith(".txt"),
        "code": suffix in {
            ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rb", ".php", ".cs",
            ".rs", ".swift", ".kt", ".sql", ".graphql", ".html", ".htm",
        },
        "tests": (
            "/test" in full
            or "/tests" in full
            or ".spec." in name
            or ".test." in name
            or name.startswith("test_")
            or name.endswith("_test.py")
        ),
        "docs": "/docs/" in full or suffix in {".md", ".rst", ".adoc"},
        "config": suffix in {".json", ".yml", ".yaml", ".toml", ".ini", ".cfg"} or name in {"package.json", "pyproject.toml"},
    }

    return [include for include in requested if checks.get(include, False)]


def _effective_includes(includes: Sequence[str], packs: Tuple[str, ...]) -> Tuple[str, ...]:
    requested = {include.lower() for include in includes}
    requested.update(categories_for_packs(packs))
    return tuple(sorted(requested))


def _snippet_for(content: str, start: int, end: int, radius: int = 80) -> str:
    snippet_start = max(0, start - radius)
    snippet_end = min(len(content), end + radius)
    snippet = content[snippet_start:snippet_end].replace("\n", " ")
    if snippet_start > 0:
        snippet = "..." + snippet
    if snippet_end < len(content):
        snippet = snippet + "..."
    return snippet


# L.3 — placeholder passwords that show up in `postgres://postgres:postgres@...`
# style dev defaults. The 313-repo dogfood produced 323 critical database_url
# findings, the vast majority of them in this dev-default shape. Q.3 expanded
# this with project-name dev defaults the live-URL dogfood surfaced.
_PLACEHOLDER_DB_PASSWORDS = {
    "postgres", "postgresql", "root", "password", "pass", "passwd",
    "hunter2", "changeme", "change-me", "dev", "test", "testing",
    "admin", "default", "secret", "example", "placeholder",
    # Q.3 — additional project-name dev defaults seen in the live dogfood.
    "posthog", "prisma", "hatchet", "convex", "supabase", "redis",
    "mysql", "mongodb", "mongo", "rabbitmq", "kafka", "minio",
    "elastic", "elasticsearch", "clickhouse", "temporal", "appuser",
    "app", "user", "service", "ci", "ci-user", "ci_user",
}

# Q.3 — password suffix patterns that are also placeholders.
_PLACEHOLDER_DB_PASSWORD_SUFFIXES = (
    "_password", "_pass", "_pwd", "_secret", "_credential",
    "-password", "-pass", "-pwd", "-secret",
)

# Q.2 — template / format-string markers in the password component.
# These never appear in a real credential; they always indicate
# interpolation-at-runtime. Q.13 extended with capitalized-braced names.
_TEMPLATE_MARKERS = ("${", "$(", "%s", "%d", "{0}", "{1}", "{{", "<value>", "<your_", "<replace", "{value}")
_BRACED_PLACEHOLDER_RE = re.compile(r"\{[A-Z_][A-Z_0-9]*\}")

# L.3 — database_url regex: postgres://user:pass@host:port/db
_DB_URL_RE = re.compile(
    r"^(?P<scheme>postgres(?:ql)?|mysql2?|mongodb(?:\+srv)?|redis)://"
    r"(?P<user>[^:@/\s]+):"
    r"(?P<password>[^@/\s]+)@"
    r"(?P<host>[^:/?\s]+)",
    re.IGNORECASE,
)


def _is_placeholder_db_url(value: object) -> bool:
    text = str(value or "").strip()
    match = _DB_URL_RE.search(text)
    if not match:
        return False
    user = (match.group("user") or "").strip().lower()
    password = (match.group("password") or "").strip()
    password_lower = password.lower()
    # Q.2 — template/format-string interpolation marker → never a real cred.
    if any(marker in password for marker in _TEMPLATE_MARKERS):
        return True
    if any(marker in user for marker in _TEMPLATE_MARKERS):
        return True
    # Q.13 — capitalized braced placeholders like ``{POSTGRES_PASSWORD}``.
    if _BRACED_PLACEHOLDER_RE.search(password) or _BRACED_PLACEHOLDER_RE.search(match.group("user") or ""):
        return True
    # Q.13 — ALL-CAPS user/password like ``USER``, ``PASSWORD``, ``HOST``.
    raw_user = match.group("user") or ""
    raw_pass = match.group("password") or ""
    if raw_user.isupper() and raw_user.replace("_", "").isalpha():
        return True
    if raw_pass.isupper() and raw_pass.replace("_", "").isalpha():
        return True
    # L.3 — known placeholder password literal.
    if password_lower in _PLACEHOLDER_DB_PASSWORDS:
        return True
    # Q.3 — placeholder password suffixes (`*_password`, `*_pass`, etc.).
    if any(password_lower.endswith(s) for s in _PLACEHOLDER_DB_PASSWORD_SUFFIXES):
        return True
    # Q.4 — user == password is a near-universal dev default
    # (`postgres:postgres@db`, `posthog:posthog@db`, `prisma:prisma@db`).
    if user and user == password_lower:
        return True
    return False


# L.4 — Local-dev URL host guard. Any matched value whose host portion is
# loopback / .local / .test / .lan is almost certainly a dev/test artifact.
# Applies to any detector that captures a URL-shaped value.
_LOCAL_DEV_HOST_RE = re.compile(
    r"://"
    r"(?:[^@/\s]+@)?"
    r"(?P<host>"
    r"localhost|"
    r"127\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
    r"::1|"
    r"\[?::1\]?|"
    r"0\.0\.0\.0|"
    r"host\.docker\.internal|"
    r"[A-Za-z0-9-]+\.(?:local|test|localhost|lan|invalid)"
    r")"
    r"(?::\d+)?"
    r"(?:[/?#]|$)",
    re.IGNORECASE,
)


def _is_local_dev_url(value: object) -> bool:
    text = str(value or "")
    if "://" not in text:
        return False
    return bool(_LOCAL_DEV_HOST_RE.search(text))


# Q.7 — basic-auth-specific localhost guard. The L.4 generic regex requires a
# clean port + path tail, which the minified-JS substrings on workos /
# materialize / glean don't have (e.g., `https://localhost:'...@`). Check the
# user portion of the matched ``http://USER:PASS@`` block directly.
_BASIC_AUTH_USER_RE = re.compile(
    r"https?://(?P<user>[^:@/\s]+):",
    re.IGNORECASE,
)
_BASIC_AUTH_LOCAL_USERS = {
    "localhost", "127.0.0.1", "0.0.0.0", "::1",
    "host.docker.internal",
}


def _is_basic_auth_localhost(value: object) -> bool:
    """Check whether the captured value (either the bare user portion captured
    by the basic-auth regex, or the full ``http://...@`` URL) refers to a
    loopback / local-dev host."""

    text = str(value or "").strip().lower()
    # Case 1: scanner passed in the captured-user group directly.
    if text in _BASIC_AUTH_LOCAL_USERS:
        return True
    if text.endswith((".local", ".test", ".localhost", ".lan", ".invalid")):
        return True
    # Case 2: scanner passed in the full ``http://USER:PASS@`` block.
    match = _BASIC_AUTH_USER_RE.search(text)
    if match:
        user = (match.group("user") or "").strip().lower()
        if user in _BASIC_AUTH_LOCAL_USERS:
            return True
        if user.endswith((".local", ".test", ".localhost", ".lan", ".invalid")):
            return True
    return False


# Q.8 — values that announce themselves as public (``public_key_*``, ``pk_*``,
# ``publishable_*``, ``client_id_*``) shouldn't trip critical secret detectors.
_PUBLIC_PREFIXES = ("public_", "public-", "publishable_", "publishable-", "pk_", "client_id_", "client-id-")


def _has_public_prefix(value: object) -> bool:
    text = str(value or "").strip().lower()
    # The basic_auth / bearer / openai regex may capture a "Bearer foo" or
    # "Authorization: Bearer foo" lead-in; strip it before checking.
    for prefix in ("bearer ", "authorization: bearer ", "bearer:"):
        if text.startswith(prefix):
            text = text[len(prefix):].lstrip()
            break
    return any(text.startswith(p) for p in _PUBLIC_PREFIXES)


# Q.6 — Google's AIza-prefixed keys are often referrer-restricted client keys
# (Firebase, Maps, Analytics, Custom Search). Surface a softer "medium"
# severity when the surrounding snippet has any of these markers. We don't
# fully suppress because un-restricted server keys *do* leak this way too.
_CLIENT_SIDE_AIZA_MARKERS = (
    "firebaseConfig",
    "firebase_config",
    "apiKey",
    "api_key",
    "google_api_key",
    "googleapikey",
    "gapi.client",
    "maps.googleapis.com",
    "googleapis.com/maps",
    "google-analytics.com",
    "googletagmanager.com",
    "googletagservices",
    "firebaseapp",
    "appsforyourdomain",
    "youtube.googleapis.com",
    "GoogleAnalyticsObject",
    "ga(",
    "gtag(",
    "fbq(",
    # Q.12 — OAuth + GIS markers (Google Identity Services).
    "apps.googleusercontent.com",
    "google_client_id",
    "google_project_id",
    "drive_import",
    "google_drive",
    "googledrive",
    "google.accounts.id",
    "accounts.google.com",
    "GIS_CLIENT_ID",
)


def _looks_like_client_side_aiza(snippet: object) -> bool:
    text = str(snippet or "")
    return any(marker.lower() in text.lower() for marker in _CLIENT_SIDE_AIZA_MARKERS)


def _shannon_entropy(value: object) -> float:
    """Shannon entropy in bits/character.

    Dictionary-word matches like ``sk-indigo-twilight-color-1`` have entropy
    around 3.0 bits/char. Real OpenAI / AWS / Stripe keys are ~5.0+ bits/char
    (random alphanumeric). Threshold of 4.0 separates them cleanly.
    """

    text = str(value or "")
    if not text:
        return 0.0
    counts: dict = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1

    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _is_placeholder(value: object, min_length: int = 8) -> bool:
    raw = str(value or "")
    text = raw.strip().lower()
    if min_length > 0 and len(text) < min_length:
        return True
    exact = {"example", "placeholder", "changeme", "dummy", "fake", "test"}
    if text in exact:
        return True
    prefixes = (
        "your_",
        "your-",
        "example_",
        "example-",
        "placeholder_",
        "placeholder-",
        "changeme_",
        "changeme-",
        "dummy_",
        "dummy-",
        "fake_",
        "fake-",
        "test_",
        "test-",
        "xxxx",
        "abcd1234",
    )
    if text.startswith(prefixes):
        return True
    tokens = {token for token in re.split(r"[^a-z0-9]+", text) if token}
    if tokens and tokens.issubset(exact):
        return True
    # Q.13 — well-known placeholder words appearing as a substring of the
    # captured value (``AKIAIOSFODNN7EXAMPLE``, ``ABCDPLACEHOLDER123``, etc.).
    for word in ("example", "placeholder", "changeme", "dummy", "fake"):
        if word in text and len(text) - len(word) < 20:
            return True
    # Q.13 — high single-character repetition is a docs / example placeholder.
    # ``AKIAXXXXXXXXXXXXXXXX``, ``AAAAAAAAAAAAAAAAAAAAA``, etc.
    alnum = re.sub(r"[^a-z0-9]", "", text)
    if alnum and len(alnum) >= 8:
        counts: dict = {}
        for ch in alnum:
            counts[ch] = counts.get(ch, 0) + 1
        most_common_share = max(counts.values()) / len(alnum)
        if most_common_share >= 0.5:
            return True
    # Q.13 — ALL-CAPS-LETTER-ONLY placeholders like ``USER``, ``PASSWORD``,
    # ``POSTGRES_PASSWORD``. Real credentials almost always include digits;
    # require letters-and-underscores only to keep AWS-shaped keys (which are
    # uppercase letters + digits) from being false-positive-suppressed.
    if raw and re.fullmatch(r"[A-Z][A-Z_]*", raw) and "_" in raw or raw in {
        "USER", "USERNAME", "PASSWORD", "PASS", "HOST", "PORT", "DATABASE",
        "DBNAME", "DB", "SECRET", "TOKEN", "API_KEY", "APIKEY",
    }:
        return True
    # Q.13 — capitalized braced placeholder like ``{POSTGRES_PASSWORD}``.
    if re.fullmatch(r"\{[A-Z_][A-Z_0-9]*\}", raw):
        return True
    return False
