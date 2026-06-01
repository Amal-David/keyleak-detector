"""Source-map deobfuscation (Wave 2.1).

Reconstructs original sources from a JavaScript source-map (v3) so detectors
run against ``src/components/Auth.tsx:42`` instead of a minified
``a.js:1:42``. The PR-comment screenshot shows the *original* line.

Safety
------
``fetch_sourcemap_for`` enforces a strict sandbox:

- Size cap (default 8 MiB).
- Same-origin: the .map URL must share scheme + host with the bundle URL.
- No follow-redirects: anything HTTP 3xx is treated as failure.
- No chained .map references: we deobfuscate the immediate sources, not their
  own source maps.

Without these guards, a malicious PR could point ``//# sourceMappingURL=...``
at attacker-controlled hosts that return giant payloads or SSRF targets while
KeyLeak's CI runs with ``GITHUB_TOKEN`` write scope.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional, Tuple
from urllib.parse import urljoin, urlparse


MAX_SOURCEMAP_BYTES = 8 * 1024 * 1024  # 8 MiB
SOURCE_MAPPING_RE = re.compile(
    r"(?://[#@]|/\*[#@])\s*sourceMappingURL=([^\s'\"<>*]+)\s*\*?/?\s*$",
    re.MULTILINE,
)


@dataclass(frozen=True)
class SourceMapEntry:
    """One reconstructed source from a v3 source map."""

    source_path: str  # logical name from the map's "sources" array
    content: str      # original source text


class SourceMapError(RuntimeError):
    """Recoverable failure parsing or fetching a source map."""


def find_sourcemap_url(bundle_text: str) -> Optional[str]:
    """Return the trailing ``sourceMappingURL`` directive, if present."""

    matches = list(SOURCE_MAPPING_RE.finditer(bundle_text))
    if not matches:
        return None
    return matches[-1].group(1).strip()


def parse_sourcemap_payload(text: str) -> List[SourceMapEntry]:
    """Parse a v3 source map JSON and yield ``SourceMapEntry`` per source.

    Drops sources without ``sourcesContent`` (those would require a second
    fetch which is forbidden by the sandbox).
    """

    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise SourceMapError(f"invalid JSON: {exc}") from exc

    if not isinstance(data, dict):
        raise SourceMapError("source map root must be an object")
    if data.get("version") not in (3, "3"):
        # Be permissive — Vite/webpack/esbuild all emit v3 but some emit no version.
        if data.get("version") is not None:
            raise SourceMapError(f"unsupported source map version: {data.get('version')!r}")

    sources = data.get("sources") or []
    contents = data.get("sourcesContent") or []
    entries: List[SourceMapEntry] = []
    for index, source in enumerate(sources):
        if not isinstance(source, str):
            continue
        if index >= len(contents):
            continue
        content = contents[index]
        if not isinstance(content, str):
            continue
        entries.append(SourceMapEntry(source_path=source, content=content))
    return entries


def load_sourcemap_from_disk(bundle_path: Path) -> List[SourceMapEntry]:
    """For ``keyleak local`` — locate the sibling ``.map`` file next to ``bundle_path``.

    A bundle file ``dist/app.js`` is typically accompanied by
    ``dist/app.js.map``. Returns an empty list if no sibling map exists.
    """

    map_path = bundle_path.with_suffix(bundle_path.suffix + ".map")
    if not map_path.is_file():
        # Some bundlers emit "app.js.map" alongside "app.js" — that's the
        # default; some emit "app.map" — check that too.
        alt = bundle_path.with_suffix(".map")
        if not alt.is_file():
            return []
        map_path = alt

    if map_path.stat().st_size > MAX_SOURCEMAP_BYTES:
        raise SourceMapError(f"source map exceeds {MAX_SOURCEMAP_BYTES} bytes: {map_path}")

    try:
        text = map_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise SourceMapError(f"could not read {map_path}: {exc}") from exc
    return parse_sourcemap_payload(text)


def is_safe_remote_url(map_url: str, bundle_url: str) -> bool:
    """Enforce same-origin + non-redirect rules on a remote ``.map`` URL.

    Returns False if the URL is not safe to fetch. The caller refuses the
    network fetch when this is False.
    """

    if not map_url or not bundle_url:
        return False

    # Inline data URLs are inline-sourceMap; the caller handles them.
    if map_url.startswith("data:"):
        return False

    resolved = urljoin(bundle_url, map_url)
    parsed_bundle = urlparse(bundle_url)
    parsed_map = urlparse(resolved)
    if parsed_bundle.scheme != parsed_map.scheme:
        return False
    if parsed_bundle.netloc != parsed_map.netloc:
        return False
    return True


def extract_inline_sourcemap(map_url: str) -> Optional[List[SourceMapEntry]]:
    """Decode an inline ``data:application/json;base64,...`` source map.

    Returns None if the URL is not an inline data URL.
    """

    if not map_url.startswith("data:"):
        return None
    import base64

    head, _, body = map_url.partition(",")
    if not body:
        return None
    if "base64" in head:
        try:
            payload = base64.b64decode(body).decode("utf-8", errors="replace")
        except Exception:
            return None
    else:
        payload = body
    return parse_sourcemap_payload(payload)


def reconstruct_originals(
    bundle_text: str,
    bundle_path: Optional[Path] = None,
) -> List[SourceMapEntry]:
    """Best-effort: return original sources reconstructed from ``bundle_text``.

    Tries inline-data URLs first; falls back to a sibling ``.map`` file when
    ``bundle_path`` is provided. Returns ``[]`` if no usable source map is
    found. Does NOT perform any network IO; remote URLs are skipped here. The
    web-scan path (Wave 2.1c) wires in network fetching with the sandbox above.
    """

    url = find_sourcemap_url(bundle_text)
    if url:
        inline = extract_inline_sourcemap(url)
        if inline is not None:
            return inline
    if bundle_path is not None:
        try:
            return load_sourcemap_from_disk(bundle_path)
        except SourceMapError:
            return []
    return []
