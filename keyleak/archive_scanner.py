"""Time-machine archive scanner (Wave 3.1).

Scans an existing deployment archive (a tarball, zip, or pre-extracted dir)
to answer the IR question: *what shipped to prod on date X?* Wraps the
findings in a chain-of-custody envelope so the artifact is defensible.

Supported inputs:
- ``.tar.gz`` / ``.tgz`` / ``.tar`` tarballs.
- ``.zip`` archives.
- Pre-extracted directories.

Out of scope (intentionally): S3 / Vercel / Netlify API integration. Those
sit on top of this module via small wrappers; this module is the engine.
"""

from __future__ import annotations

import tarfile
import tempfile
import zipfile
from pathlib import Path
from typing import Optional

from .chain_of_custody import build_envelope
from .local_scanner import scan_path
from .models import ScanReport


class ArchiveScanError(RuntimeError):
    pass


def extract_archive(archive_path: Path, dest: Path) -> Path:
    """Extract ``archive_path`` into ``dest``. Returns the directory used."""

    archive_path = Path(archive_path)
    if archive_path.is_dir():
        return archive_path

    suffixes = "".join(archive_path.suffixes).lower()
    if archive_path.suffix.lower() == ".zip":
        with zipfile.ZipFile(archive_path, "r") as zf:
            _safe_extract_zip(zf, dest)
        return dest

    if archive_path.suffix.lower() in {".tar", ".tgz"} or suffixes.endswith(".tar.gz") or suffixes.endswith(".tar.bz2"):
        with tarfile.open(archive_path) as tf:
            _safe_extract_tar(tf, dest)
        return dest

    raise ArchiveScanError(f"Unsupported archive format: {archive_path}")


def _safe_extract_zip(zf: zipfile.ZipFile, dest: Path) -> None:
    dest = dest.resolve()
    for info in zf.infolist():
        target = (dest / info.filename).resolve()
        try:
            target.relative_to(dest)
        except ValueError:
            raise ArchiveScanError(f"Path traversal in zip entry: {info.filename}")
    zf.extractall(dest)


def _safe_extract_tar(tf: tarfile.TarFile, dest: Path) -> None:
    dest = dest.resolve()
    for member in tf.getmembers():
        target = (dest / member.name).resolve()
        try:
            target.relative_to(dest)
        except ValueError:
            raise ArchiveScanError(f"Path traversal in tar entry: {member.name}")
    # Python 3.12+: pass filter='data' for additional safety. We resolve paths
    # ourselves above; the filter argument is a defense-in-depth.
    try:
        tf.extractall(dest, filter="data")
    except TypeError:
        tf.extractall(dest)


def scan_archive(
    archive_path: str,
    *,
    as_of: Optional[str] = None,
    profile: str = "ci",
    signer: str = "anonymous",
    prev_hash: str = "",
) -> dict:
    """Scan ``archive_path`` and return a chain-of-custody envelope.

    ``as_of`` is informational metadata stored on the envelope (e.g. the
    deploy timestamp the archive represents); it does not influence scan
    semantics.
    """

    archive = Path(archive_path).expanduser().resolve()
    if not archive.exists():
        raise ArchiveScanError(f"Archive not found: {archive}")

    with tempfile.TemporaryDirectory() as tmp:
        extracted = extract_archive(archive, Path(tmp))
        report: ScanReport = scan_path(str(extracted), profile=profile)

    report_dict = report.to_dict()
    report_dict["archive_path"] = str(archive)
    report_dict["scan_mode"] = "archive"
    if as_of:
        report_dict["as_of"] = as_of

    return build_envelope(
        report_dict,
        prev_hash=prev_hash,
        signer=signer,
    )
