"""`keyleak watch` — debounced incremental scan on file save (Wave 3.8).

Polls the filesystem (stdlib only — no watchdog dep) every ``poll_interval``
seconds. When any file's ``mtime`` changes, the watched path is re-scanned
and the SARIF report at ``.keyleak/findings.sarif`` is updated. VS Code's
built-in SARIF Problems panel picks it up automatically.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from typing import Dict, Iterable, Optional, Tuple

from .local_scanner import scan_path
from .reporting import format_sarif


DEFAULT_POLL_INTERVAL = 0.5  # seconds
DEFAULT_OUTPUT_PATH = ".keyleak/findings.sarif"
WATCHED_SUFFIXES = (".py", ".js", ".ts", ".tsx", ".jsx", ".mjs", ".cjs", ".json", ".yml", ".yaml", ".env", ".html", ".tf")


def snapshot_mtimes(root: Path) -> Dict[str, float]:
    """Return ``{path: mtime}`` for every file under ``root`` with a watched suffix."""

    mtimes: Dict[str, float] = {}
    skip = {".git", "node_modules", ".keyleak", "__pycache__", "dist", "build"}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip]
        for name in filenames:
            if not name.endswith(WATCHED_SUFFIXES) and not name.startswith(".env"):
                continue
            full = Path(dirpath) / name
            try:
                mtimes[str(full)] = full.stat().st_mtime
            except OSError:
                continue
    return mtimes


def detect_changes(prev: Dict[str, float], curr: Dict[str, float]) -> Tuple[bool, Iterable[str]]:
    """Return (changed?, changed_paths)."""

    changed = []
    for path, mtime in curr.items():
        if prev.get(path) != mtime:
            changed.append(path)
    for path in prev:
        if path not in curr:
            changed.append(path)
    return bool(changed), changed


def run_watch(
    root: Path,
    *,
    output_path: Path,
    poll_interval: float = DEFAULT_POLL_INTERVAL,
    iterations: Optional[int] = None,
) -> int:
    """Watch ``root`` and refresh ``output_path`` on every change.

    ``iterations`` caps the loop count (for tests). ``None`` runs forever.
    """

    output_path.parent.mkdir(parents=True, exist_ok=True)
    prev = snapshot_mtimes(root)
    _write_scan(root, output_path)  # initial scan

    count = 0
    while iterations is None or count < iterations:
        time.sleep(poll_interval)
        curr = snapshot_mtimes(root)
        changed, paths = detect_changes(prev, curr)
        if changed:
            _write_scan(root, output_path)
            prev = curr
            print(f"[keyleak watch] re-scanned ({len(list(paths))} files changed)", file=sys.stderr)
        count += 1
    return 0


def _write_scan(root: Path, output_path: Path) -> None:
    report = scan_path(str(root), profile="ci")
    output_path.write_text(format_sarif(report), encoding="utf-8")


def cli_main(args) -> int:
    root = Path(args.path).expanduser().resolve()
    if not root.is_dir():
        print(f"path is not a directory: {root}", file=sys.stderr)
        return 1
    output_path = Path(args.out) if args.out else (root / DEFAULT_OUTPUT_PATH)
    try:
        return run_watch(
            root,
            output_path=output_path,
            poll_interval=float(args.interval),
            iterations=int(args.iterations) if args.iterations else None,
        )
    except KeyboardInterrupt:
        return 0
