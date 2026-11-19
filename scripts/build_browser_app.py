#!/usr/bin/env python3
"""Build the static browser app without bundlers, downloads, or Python packages.

Only the browser entrypoints, runtime modules, shared detector modules and the
existing PHP checker are publishable. Never copy the checkout wholesale: it can
contain local scan reports, credentials, test fixtures and development files.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import tempfile


REPO_ROOT = Path(__file__).resolve().parents[1]
ENGINE_MODULES = ("analyzer.js", "patterns.js", "false-positives.js", "reporting.js")
MANIFEST_NAME = "offline-assets.json"
APPLICATION_ID = "keyleak-browser-app"
CACHE_VERSION_TOKEN = "__KEYLEAK_CACHE_VERSION__"
OFFLINE_ASSETS_TOKEN = "__KEYLEAK_OFFLINE_ASSETS__"


def read_source(root: Path, path: Path) -> bytes:
    """Reject links, including linked parent directories, in published inputs."""
    relative = path.relative_to(root)
    current = root
    for part in relative.parts:
        current /= part
        if current.is_symlink():
            raise ValueError(f"Refusing to publish a symlink: {relative}")
    if not path.is_file():
        raise ValueError(f"Required browser build input is missing: {relative}")
    return path.read_bytes()


def validate_output(root: Path, output: Path) -> None:
    """Do not let --output erase source trees or unrelated existing files."""
    if output == root or output in root.parents:
        raise ValueError("Build output cannot replace the repository or its parents")
    if output.is_relative_to(root) and not output.is_relative_to(root / "dist"):
        raise ValueError("Build output inside the checkout must be under dist/")
    if output.exists():
        if not output.is_dir():
            raise ValueError("Build output is not a directory")
        if any(output.iterdir()):
            try:
                manifest = json.loads((output / MANIFEST_NAME).read_text())
            except (OSError, ValueError):
                manifest = {}
            if manifest.get("application") != APPLICATION_ID:
                raise ValueError("Refusing to replace a nonempty directory not owned by this build")


def build_browser_app(repo_root: Path, output: Path) -> dict:
    root = repo_root.resolve()
    # Resolve after rejecting an explicitly linked output path. A parent link is
    # still safe only if its resolved location passes the source-tree guard.
    if output.is_symlink():
        raise ValueError("Build output must not be a symlink")
    output = output.resolve()
    validate_output(root, output)

    files: dict[str, bytes] = {}
    for name in ("index.html", "styles.css"):
        files[name] = read_source(root, root / "web" / name)
    for name in ("manifest.webmanifest",):
        source = root / "web" / name
        if source.exists():
            files[name] = read_source(root, source)

    runtime_sources = sorted((root / "web" / "src").rglob("*.js"))
    if not runtime_sources:
        raise ValueError("Required browser build input is missing: web/src/*.js")
    for source in runtime_sources:
        relative = source.relative_to(root / "web")
        if any(part.startswith(".") or part in {"node_modules", "tests", "__tests__"}
               for part in relative.parts):
            continue
        if source.name.endswith((".test.js", ".spec.js")):
            continue
        text = read_source(root, source).decode("utf-8")
        files[relative.as_posix()] = text.replace("../../extension/lib/", "../engine/").encode("utf-8")

    for name in ENGINE_MODULES:
        files[f"engine/{name}"] = read_source(root, root / "extension" / "lib" / name)

    # The existing Pages utility remains available at /php-check/ relative to
    # the Pages base path. It has a separate UI and is not in the app cache.
    for name in ("index.html", "checker.js"):
        files[f"php-check/{name}"] = read_source(root, root / "site" / "php-check" / name)
    files["favicon.ico"] = read_source(root, root / "site" / "favicon.ico")
    files[".nojekyll"] = b""

    worker_source = root / "web" / "sw.js"
    worker_template = read_source(root, worker_source).decode("utf-8") if worker_source.exists() else None
    if worker_template is not None:
        for token in (CACHE_VERSION_TOKEN, OFFLINE_ASSETS_TOKEN):
            if token not in worker_template:
                raise ValueError(f"web/sw.js is missing its build placeholder: {token}")

    digest = hashlib.sha256()
    hash_inputs = dict(files)
    if worker_template is not None:
        hash_inputs["sw.js"] = worker_template.encode("utf-8")
    for name, content in sorted(hash_inputs.items()):
        digest.update(name.encode("utf-8") + b"\0")
        digest.update(hashlib.sha256(content).digest())
    version = digest.hexdigest()

    assets = [f"./{name}" for name in sorted(files)
              if name != ".nojekyll" and not name.startswith("php-check/")]
    manifest = {"application": APPLICATION_ID, "version": version, "assets": assets}
    files[MANIFEST_NAME] = (json.dumps(manifest, indent=2) + "\n").encode("utf-8")
    if worker_template is not None:
        files["sw.js"] = worker_template.replace(CACHE_VERSION_TOKEN, version).replace(
            OFFLINE_ASSETS_TOKEN, json.dumps(assets)
        ).encode("utf-8")

    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".keyleak-browser-", dir=output.parent) as temporary:
        staged = Path(temporary) / "site"
        staged.mkdir()
        for name, content in sorted(files.items()):
            destination = staged / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(content)
        # Both directories share a filesystem, so rename cannot fall back to a
        # partial copy. Keep the backup outside staging cleanup in case even
        # restoring it fails; the previous build must remain recoverable.
        backup = None
        if output.exists():
            backup_directory = Path(tempfile.mkdtemp(prefix=".keyleak-browser-backup-", dir=output.parent))
            backup = backup_directory / "site"
            try:
                output.rename(backup)
            except BaseException:
                backup_directory.rmdir()
                raise
        try:
            staged.rename(output)
        except BaseException:
            if backup is not None:
                backup.rename(output)
                backup.parent.rmdir()
            raise
        else:
            if backup is not None:
                shutil.rmtree(backup.parent)
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=REPO_ROOT / "dist" / "browser",
                        help="Output directory; defaults to dist/browser/ in the checkout")
    args = parser.parse_args()
    try:
        manifest = build_browser_app(REPO_ROOT, args.output)
    except (OSError, ValueError) as error:
        parser.exit(1, f"Browser build failed: {error}\n")
    print(f"Built browser app at {args.output.resolve()} (version {manifest['version'][:12]})")


if __name__ == "__main__":
    main()
