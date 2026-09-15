"""Install the Chrome native-messaging manifest for the unpacked extension."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import shlex
import sys
from typing import Iterable

from keyleak import extension_host


EXTENSION_ID_PATTERN = re.compile(r"^[a-p]{32}$")


def browser_locations() -> list[tuple[Path, Path]]:
    if sys.platform == "darwin":
        application_support = Path.home() / "Library" / "Application Support"
        return [
            (
                application_support / "Google" / "Chrome",
                application_support / "Google" / "Chrome" / "NativeMessagingHosts",
            ),
            (
                application_support / "BraveSoftware" / "Brave-Browser",
                application_support / "BraveSoftware" / "Brave-Browser" / "NativeMessagingHosts",
            ),
            (
                application_support / "Microsoft Edge",
                application_support / "Microsoft Edge" / "NativeMessagingHosts",
            ),
        ]
    if sys.platform.startswith("linux"):
        config = Path.home() / ".config"
        return [
            (config / "google-chrome", config / "google-chrome" / "NativeMessagingHosts"),
            (config / "BraveSoftware" / "Brave-Browser", config / "BraveSoftware" / "Brave-Browser" / "NativeMessagingHosts"),
            (config / "microsoft-edge", config / "microsoft-edge" / "NativeMessagingHosts"),
        ]
    raise RuntimeError("Automatic native-host installation currently supports Chromium browsers on macOS and Linux.")


def discover_extension_ids(extension_dir: Path, roots: Iterable[Path] | None = None) -> list[str]:
    expected = extension_dir.expanduser().resolve()
    discovered: set[str] = set()
    for root in roots or [location[0] for location in browser_locations()]:
        if not root.is_dir():
            continue
        for preferences in root.glob("*/Preferences"):
            try:
                payload = json.loads(preferences.read_text(encoding="utf-8"))
            except (OSError, ValueError, TypeError):
                continue
            settings = payload.get("extensions", {}).get("settings", {})
            if not isinstance(settings, dict):
                continue
            for extension_id, config in settings.items():
                if not EXTENSION_ID_PATTERN.fullmatch(str(extension_id)) or not isinstance(config, dict):
                    continue
                raw_path = config.get("path")
                if not isinstance(raw_path, str) or not raw_path:
                    continue
                configured = Path(raw_path).expanduser()
                candidates = [configured.resolve()]
                if not configured.is_absolute():
                    candidates.append((preferences.parent / configured).resolve())
                if expected in candidates:
                    discovered.add(str(extension_id))
    return sorted(discovered)


def build_manifest(extension_ids: Iterable[str], launcher: Path) -> dict[str, object]:
    origins = [f"chrome-extension://{extension_id}/" for extension_id in sorted(set(extension_ids))]
    if not origins or any(not EXTENSION_ID_PATTERN.fullmatch(origin.removeprefix("chrome-extension://").removesuffix("/")) for origin in origins):
        raise ValueError("A valid Chrome extension ID is required.")
    return {
        "name": extension_host.HOST_NAME,
        "description": "Starts the local KeyLeak Docker scanner for explicit full scans.",
        "path": str(launcher.expanduser().resolve()),
        "type": "stdio",
        "allowed_origins": origins,
    }


def install(extension_ids: Iterable[str] = ()) -> tuple[list[Path], list[str]]:
    repo_root = Path(extension_host.__file__).resolve().parents[1]
    extension_dir = repo_root / "extension"
    explicit_ids = set(extension_ids)
    locations = browser_locations()
    ids_by_manifest: dict[Path, set[str]] = {}
    for profile_root, manifest_dir in locations:
        discovered = set(discover_extension_ids(extension_dir, [profile_root]))
        if discovered:
            ids_by_manifest[manifest_dir] = discovered
    if explicit_ids:
        existing_locations = [location for location in locations if location[0].exists()]
        for _, manifest_dir in existing_locations or locations[:1]:
            ids_by_manifest.setdefault(manifest_dir, set()).update(explicit_ids)

    ids = sorted(set().union(*ids_by_manifest.values()) if ids_by_manifest else set())
    if not ids:
        raise RuntimeError(
            "The unpacked KeyLeak extension was not found in a Chromium browser. Load extension/ first, "
            "or pass --extension-id from chrome://extensions."
        )

    install_dir = Path.home() / ".local" / "share" / "keyleak-detector"
    install_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    launcher = install_dir / "chrome-native-host"
    host_script = Path(extension_host.__file__).resolve()
    launcher.write_text(
        "#!/bin/sh\nexec "
        f"{shlex.quote(str(Path(sys.executable).resolve()))} "
        f"{shlex.quote(str(host_script))}\n",
        encoding="utf-8",
    )
    launcher.chmod(0o700)

    manifest_paths = []
    for manifest_dir, browser_ids in ids_by_manifest.items():
        manifest_path = manifest_dir / f"{extension_host.HOST_NAME}.json"
        try:
            manifest_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            manifest_path.write_text(
                json.dumps(build_manifest(browser_ids, launcher), indent=2) + "\n",
                encoding="utf-8",
            )
            manifest_path.chmod(0o600)
            manifest_paths.append(manifest_path)
        except OSError:
            continue
    if not manifest_paths:
        raise RuntimeError("The native-host manifest could not be written to any installed Chromium browser.")
    return manifest_paths, ids


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--extension-id",
        action="append",
        default=[],
        help="Chrome extension ID to authorize; repeat for multiple local profiles.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        manifest_paths, ids = install(args.extension_id)
    except (RuntimeError, ValueError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    print(f"Installed KeyLeak's Chrome startup helper for {', '.join(ids)}.")
    for manifest_path in manifest_paths:
        print(f"Manifest: {manifest_path}")
    print("Reload KeyLeak in chrome://extensions once, then RUN FULL SCAN starts Docker automatically.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
