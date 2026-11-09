#!/usr/bin/env python3
"""Build the Chrome extension ZIP and release SHA256SUMS without dependencies.

Runtime files are explicitly listed: tests, local reports, package-manager files
and new files are never published accidentally. Adding a runtime asset requires
updating this list. Literal manifest, HTML and module references are checked;
this is a packager for this extension, not a general JavaScript bundler.
"""

from __future__ import annotations

import argparse
import hashlib
from html.parser import HTMLParser
import io
import json
from pathlib import Path, PurePosixPath
import posixpath
import re
import stat
import tempfile
import tomllib
import zipfile


REPO_ROOT = Path(__file__).resolve().parents[1]
EXTENSION_FILES = (
    "PRIVACY_POLICY.md",
    "content-script.js",
    "devtools/devtools.html",
    "devtools/devtools.js",
    "devtools/panel.html",
    "devtools/panel.js",
    "icons/icon128.png",
    "icons/icon16.png",
    "icons/icon48.png",
    "injector.js",
    "lib/analyzer.js",
    "lib/baas-detector.js",
    "lib/convex-detector.js",
    "lib/detector-info.js",
    "lib/false-positives.js",
    "lib/key-tester.js",
    "lib/learn-panel.js",
    "lib/library-cves.js",
    "lib/local-scanner.js",
    "lib/patterns.js",
    "lib/privacy.js",
    "lib/reference-view.js",
    "lib/reporting.js",
    "lib/url-guard.js",
    "manifest.json",
    "popup/popup.html",
    "popup/popup.js",
    "service-worker.js",
)
MANIFEST_KEYS = {
    "manifest_version", "name", "version", "version_name", "description",
    "permissions", "host_permissions", "optional_permissions", "optional_host_permissions",
    "background", "content_scripts", "action", "devtools_page", "icons",
    "minimum_chrome_version", "homepage_url", "short_name", "author",
    "content_security_policy", "incognito", "offline_enabled",
}
MODULE_REFERENCE = re.compile(
    r"(?m)^\s*(?:import\s+(?:[^;'\"]*?\s+from\s+)?|export\s+[^;'\"]*?\s+from\s+)"
    r"(['\"])([^'\"\r\n]+)\1"
)
LITERAL_CALL = re.compile(r"\b(import|importScripts|chrome\.runtime\.getURL)\s*\(\s*(['\"])([^'\"\r\n]+)\2\s*\)")
PANEL_REFERENCE = re.compile(
    r"\bchrome\.devtools\.panels\.create\s*\(\s*(['\"])[^'\"]*\1\s*,\s*"
    r"(?:null|(['\"])([^'\"]*)\2)\s*,\s*(['\"])([^'\"]+)\4"
)


def read_regular(root: Path, relative: str) -> bytes:
    """Do not follow file or parent-directory links into private local files."""
    current = root
    for part in PurePosixPath(relative).parts:
        current /= part
        if current.is_symlink():
            raise ValueError(f"Refusing to package a symlink: {relative}")
    if not current.is_file():
        raise ValueError(f"Required build input is missing: {relative}")
    return current.read_bytes()


def require_asset(reference: str, source: str, files: dict[str, bytes], *, at_root: bool = False) -> None:
    if not isinstance(reference, str) or not reference or re.search(r"[\\:#?%\s\x00-\x1f]", reference):
        raise ValueError(f"Invalid local asset reference in {source}: {reference!r}")
    if reference.startswith("/"):
        raise ValueError(f"Asset reference must be relative in {source}: {reference}")
    base = "" if at_root else posixpath.dirname(source)
    normalized = posixpath.normpath(posixpath.join(base, reference))
    if normalized.startswith("../") or normalized not in files:
        raise ValueError(f"Asset reference is outside the package allowlist in {source}: {reference}")


def validate_manifest(files: dict[str, bytes]) -> dict:
    manifest = json.loads(files["manifest.json"])
    if not isinstance(manifest, dict) or manifest.get("manifest_version") != 3:
        raise ValueError("The extension package requires a Manifest V3 object")
    unknown = set(manifest) - MANIFEST_KEYS
    if unknown:
        raise ValueError(f"Review new manifest fields and their assets before packaging: {', '.join(sorted(unknown))}")
    version = manifest.get("version")
    if not isinstance(version, str) or not re.fullmatch(r"(?:0|[1-9][0-9]{0,4})(?:\.(?:0|[1-9][0-9]{0,4})){0,3}", version):
        raise ValueError("Invalid Chrome extension version")
    parts = [int(part) for part in version.split(".")]
    if not any(parts) or max(parts) > 65535:
        raise ValueError("Invalid Chrome extension version")
    references = [manifest.get("background", {}).get("service_worker"), manifest.get("devtools_page")]
    background = manifest.get("background", {})
    if set(background) - {"service_worker", "type"}:
        raise ValueError("Unsupported background asset configuration")
    action = manifest.get("action", {})
    if set(action) - {"default_popup", "default_icon", "default_title"}:
        raise ValueError("Unsupported action asset configuration")
    references.append(action.get("default_popup"))
    for icons in (manifest.get("icons", {}), action.get("default_icon", {})):
        references.extend(icons.values() if isinstance(icons, dict) else [icons])
    for script in manifest.get("content_scripts", []):
        references.extend(script.get("js", []))
        references.extend(script.get("css", []))
    for reference in references:
        if reference is not None:
            require_asset(reference, "manifest.json", files, at_root=True)
    return manifest


class AssetHTMLParser(HTMLParser):
    def __init__(self, source: str, files: dict[str, bytes]):
        super().__init__()
        self.source = source
        self.files = files

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        # Links in prose may be external; executable, style and image assets
        # must be local and included. <base> would change relative resolution.
        if tag == "base":
            raise ValueError(f"HTML base elements are unsupported: {self.source}")
        for attribute in ("src", "poster", "data"):
            if attribute in attributes:
                require_asset(attributes[attribute], self.source, self.files)
        if tag == "link" and "href" in attributes:
            require_asset(attributes["href"], self.source, self.files)
        if "srcset" in attributes:
            raise ValueError(f"Review srcset assets before packaging: {self.source}")


def validate_references(files: dict[str, bytes]) -> None:
    for name, content in files.items():
        if name.endswith(".html"):
            parser = AssetHTMLParser(name, files)
            parser.feed(content.decode("utf-8"))
            parser.close()
        if name.endswith((".html", ".css")):
            for match in re.finditer(r"url\(\s*['\"]?([^)'\"\s]+)['\"]?\s*\)", content.decode("utf-8")):
                require_asset(match[1], name, files)
        if not name.endswith(".js"):
            continue
        text = content.decode("utf-8")
        for match in MODULE_REFERENCE.finditer(text):
            if not match[2].startswith(("./", "../")):
                raise ValueError(f"Module imports must be relative: {name}")
            require_asset(match[2], name, files)
        for match in LITERAL_CALL.finditer(text):
            require_asset(match[3], name, files, at_root=match[1] == "chrome.runtime.getURL")
        for match in PANEL_REFERENCE.finditer(text):
            if match[3]:
                require_asset(match[3], name, files, at_root=True)
            require_asset(match[5], name, files, at_root=True)


def python_distributions(root: Path, output: Path) -> dict[str, bytes]:
    """Accept the one expected wheel and sdist, never arbitrary dist files."""
    project = tomllib.loads(read_regular(root, "pyproject.toml").decode("utf-8"))
    version = project["project"]["version"]
    if not isinstance(version, str) or not re.fullmatch(r"[0-9][A-Za-z0-9.!+_-]*", version):
        raise ValueError("Invalid Python distribution version")
    expected = {f"keyleak_detector-{version}-py3-none-any.whl", f"keyleak_detector-{version}.tar.gz"}
    actual = {path.name for pattern in ("*.whl", "*.tar.gz") for path in output.glob(pattern)}
    if actual != expected:
        raise ValueError("Expected exactly the current keyleak_detector wheel and sdist in the output directory")
    return {name: read_regular(output, name) for name in sorted(expected)}


def build_extension(repo_root: Path, output: Path, *, include_python: bool = False) -> dict:
    root = repo_root.resolve()
    # Guard parents before resolve(), which would otherwise conceal a symlink.
    output = output.absolute()
    if any(path.is_symlink() for path in (output, *output.parents)):
        raise ValueError("Build output must not use a symlink")
    output = output.resolve()
    if output == root or output in root.parents or (output.is_relative_to(root) and not output.is_relative_to(root / "dist")):
        raise ValueError("Build output inside the checkout must be under dist/")
    files = {name: read_regular(root, f"extension/{name}") for name in EXTENSION_FILES}
    manifest = validate_manifest(files)
    validate_references(files)
    assets = python_distributions(root, output) if include_python else {}
    archive_name = f"keyleak-detector-extension-v{manifest['version']}.zip"
    archive_buffer = io.BytesIO()
    # Stored entries avoid zlib-version differences. The small archive remains
    # deterministic across OSes, file modes and checkout timestamps.
    with zipfile.ZipFile(archive_buffer, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, content in sorted(files.items()):
            entry = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            entry.create_system = 3
            entry.external_attr = (stat.S_IFREG | 0o644) << 16
            archive.writestr(entry, content)
    assets[archive_name] = archive_buffer.getvalue()
    checksums = "".join(f"{hashlib.sha256(content).hexdigest()}  {name}\n" for name, content in sorted(assets.items()))
    output.mkdir(parents=True, exist_ok=True)
    for name, content in ((archive_name, assets[archive_name]), ("SHA256SUMS", checksums.encode("ascii"))):
        destination = output / name
        if destination.is_symlink() or (destination.exists() and not destination.is_file()):
            raise ValueError(f"Refusing to replace a non-regular output: {name}")
    with tempfile.TemporaryDirectory(prefix=".keyleak-extension-", dir=output) as temporary:
        for name, content in ((archive_name, assets[archive_name]), ("SHA256SUMS", checksums.encode("ascii"))):
            staged = Path(temporary) / name
            staged.write_bytes(content)
            staged.replace(output / name)
    return {"version": manifest["version"], "archive": archive_name, "assets": sorted(assets), "checksums": "SHA256SUMS"}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=REPO_ROOT / "dist", help="Output directory (default: dist/)")
    parser.add_argument("--include-python-distributions", action="store_true", help="Also checksum the current wheel and sdist already in the output directory")
    args = parser.parse_args()
    try:
        result = build_extension(REPO_ROOT, args.output, include_python=args.include_python_distributions)
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(1, f"Extension build failed: {error}\n")
    print(f"Built {result['archive']} and SHA256SUMS in {args.output.resolve()}")


if __name__ == "__main__":
    main()
