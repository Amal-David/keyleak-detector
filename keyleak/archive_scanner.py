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

import bz2
import gzip
import lzma
import posixpath
import re
import struct
import tarfile
import tempfile
import zipfile
from pathlib import Path
from typing import Optional

from .chain_of_custody import build_envelope
from .local_scanner import scan_path
from .models import ScanReport, build_coverage


class ArchiveScanError(RuntimeError):
    pass


MAX_BINARY_ARCHIVE_ENTRIES = 10_000
MAX_BINARY_ARCHIVE_MEMBER_BYTES = 100 * 1024 * 1024
MAX_BINARY_ARCHIVE_TOTAL_BYTES = 500 * 1024 * 1024
MAX_BINARY_ARCHIVE_RATIO = 200
MAX_BINARY_ARCHIVE_CENTRAL_DIRECTORY_BYTES = 64 * 1024 * 1024


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


def _member_path(name: str, dest: Path, *, allow_root: bool = False) -> Path:
    """Resolve a normalized archive member path below the extraction root."""
    name = name.replace("\\", "/")
    normalized = posixpath.normpath(name)
    if (
        not name
        or name.startswith("/")
        or (normalized == "." and not allow_root)
        or normalized == ".."
        or normalized.startswith("../")
        or re.match(r"^[A-Za-z]:", normalized)
    ):
        raise ArchiveScanError(f"Unsafe archive member path: {name}")
    target = (dest / Path(*normalized.split("/"))).resolve()
    try:
        target.relative_to(dest.resolve())
    except ValueError:
        raise ArchiveScanError(f"Unsafe archive member path: {name}")
    return target


def _copy_limited(
    source, target: Path, declared_size: int, compressed_size: int, total: int,
) -> int:
    if declared_size < 0 or declared_size > MAX_BINARY_ARCHIVE_MEMBER_BYTES:
        raise ArchiveScanError("Archive member exceeds expanded size limit")
    if declared_size and (
        compressed_size <= 0
        or declared_size > compressed_size * MAX_BINARY_ARCHIVE_RATIO
    ):
        raise ArchiveScanError("Archive member exceeds compression ratio limit")
    if total + declared_size > MAX_BINARY_ARCHIVE_TOTAL_BYTES:
        raise ArchiveScanError("Archive exceeds total expanded size limit")
    target.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    with target.open("wb") as output:
        while True:
            chunk = source.read(1024 * 1024)
            if not chunk:
                break
            written += len(chunk)
            if written > declared_size or written > MAX_BINARY_ARCHIVE_MEMBER_BYTES:
                raise ArchiveScanError("Archive member exceeds expanded size limit")
            output.write(chunk)
    if written != declared_size:
        raise ArchiveScanError("Archive member size did not match its header")
    return total + written


def _preflight_binary_zip(archive_path: Path) -> None:
    """Bound ZIP directory metadata before ZipFile allocates its index."""
    size = archive_path.stat().st_size
    tail_size = min(size, 22 + 0xFFFF)
    with archive_path.open("rb") as archive:
        archive.seek(size - tail_size)
        tail = archive.read(tail_size)

        eocd = tail.rfind(b"PK\x05\x06")
        while eocd >= 0:
            if eocd + 22 <= len(tail):
                comment_size = struct.unpack_from("<H", tail, eocd + 20)[0]
                if eocd + 22 + comment_size == len(tail):
                    break
            eocd = tail.rfind(b"PK\x05\x06", 0, eocd)
        if eocd < 0:
            raise ArchiveScanError("Invalid zip archive: end-of-central-directory record not found")

        eocd_offset = size - tail_size + eocd
        disk_number, directory_disk, disk_entries, entry_count, directory_size, directory_offset = (
            struct.unpack_from("<4H2I", tail, eocd + 4)
        )
        if (
            disk_number != 0
            or directory_disk != 0
            or disk_entries != entry_count
            or entry_count == 0xFFFF
            or directory_size == 0xFFFFFFFF
            or directory_offset == 0xFFFFFFFF
        ):
            raise ArchiveScanError("ZIP64 and multi-disk archives are not supported by bounded scanning")
        if eocd_offset >= 20:
            archive.seek(eocd_offset - 20)
            if archive.read(4) == b"PK\x06\x07":
                raise ArchiveScanError("ZIP64 archives are not supported by bounded scanning")
        if entry_count > MAX_BINARY_ARCHIVE_ENTRIES:
            raise ArchiveScanError("Archive exceeds entry count limit")
        if directory_size > MAX_BINARY_ARCHIVE_CENTRAL_DIRECTORY_BYTES:
            raise ArchiveScanError("Archive central directory exceeds byte limit")
        if directory_offset > eocd_offset:
            raise ArchiveScanError("Invalid zip archive: central directory offset is out of bounds")

        # Walk the bytes up to EOCD rather than trusting the EOCD count/size.
        # This also catches forged low EOCD values while ZipFile has not yet
        # been constructed and allocated its member index.
        position = directory_offset
        actual_entries = 0
        while position < eocd_offset:
            archive.seek(position)
            header = archive.read(46)
            if len(header) < 4:
                raise ArchiveScanError("Invalid zip archive: truncated central directory")
            if header[:4] == b"PK\x05\x05":
                if len(header) < 6:
                    raise ArchiveScanError("Invalid zip archive: truncated central directory signature")
                signature_size = struct.unpack_from("<H", header, 4)[0]
                position += 6 + signature_size
                if position - directory_offset > MAX_BINARY_ARCHIVE_CENTRAL_DIRECTORY_BYTES:
                    raise ArchiveScanError("Archive central directory exceeds byte limit")
                continue
            if len(header) != 46 or header[:4] != b"PK\x01\x02":
                raise ArchiveScanError("Invalid zip archive: malformed central directory")
            compressed, expanded = struct.unpack_from("<II", header, 20)
            disk_start = struct.unpack_from("<H", header, 34)[0]
            local_header_offset = struct.unpack_from("<I", header, 42)[0]
            if (
                compressed == 0xFFFFFFFF
                or expanded == 0xFFFFFFFF
                or disk_start == 0xFFFF
                or local_header_offset == 0xFFFFFFFF
            ):
                raise ArchiveScanError("ZIP64 archives are not supported by bounded scanning")
            name_size, extra_size, comment_size = struct.unpack_from("<HHH", header, 28)
            record_size = 46 + name_size + extra_size + comment_size
            if position + record_size > eocd_offset:
                raise ArchiveScanError("Invalid zip archive: truncated central directory entry")
            actual_entries += 1
            if actual_entries > MAX_BINARY_ARCHIVE_ENTRIES:
                raise ArchiveScanError("Archive exceeds entry count limit")
            position += record_size
            if position - directory_offset > MAX_BINARY_ARCHIVE_CENTRAL_DIRECTORY_BYTES:
                raise ArchiveScanError("Archive central directory exceeds byte limit")

        if position != eocd_offset or actual_entries != entry_count:
            raise ArchiveScanError("Invalid zip archive: central directory does not match its end record")
        if eocd_offset - directory_offset > MAX_BINARY_ARCHIVE_CENTRAL_DIRECTORY_BYTES:
            raise ArchiveScanError("Archive central directory exceeds byte limit")


def _extract_binary_zip(zf: zipfile.ZipFile, dest: Path) -> None:
    infos = zf.infolist()
    if len(infos) > MAX_BINARY_ARCHIVE_ENTRIES:
        raise ArchiveScanError("Archive exceeds entry count limit")
    total = 0
    for info in infos:
        target = _member_path(info.filename, dest, allow_root=info.is_dir())
        mode = (info.external_attr >> 16) & 0xFFFF
        if mode and (mode & 0o170000) == 0o120000:
            raise ArchiveScanError(f"Symlink in zip archive: {info.filename}")
        if info.is_dir():
            target.mkdir(parents=True, exist_ok=True)
            continue
        with zf.open(info, "r") as source:
            total = _copy_limited(source, target, info.file_size, info.compress_size, total)


class _LimitedReader:
    """Read a decompressed stream while enforcing its expanded-byte budget."""

    def __init__(self, source, max_bytes: int, message: str):
        self.source = source
        self.max_bytes = max_bytes
        self.message = message
        self.bytes_read = 0

    def read(self, size: int = -1) -> bytes:
        remaining = self.max_bytes - self.bytes_read
        bounded_size = remaining + 1 if size is None or size < 0 else min(size, remaining + 1)
        data = self.source.read(bounded_size)
        if len(data) > remaining:
            raise ArchiveScanError(self.message)
        self.bytes_read += len(data)
        return data

    def readinto(self, buffer) -> int:
        data = self.read(len(buffer))
        buffer[:len(data)] = data
        return len(data)


def _extract_binary_tar(tf: tarfile.TarFile, dest: Path) -> None:
    total = 0
    member_count = 0
    for member in tf:
        member_count += 1
        if member_count > MAX_BINARY_ARCHIVE_ENTRIES:
            raise ArchiveScanError("Archive exceeds entry count limit")
        target = _member_path(member.name, dest, allow_root=member.isdir())
        if member.issym() or member.islnk():
            raise ArchiveScanError(f"Link in tar archive: {member.name}")
        if member.isdir():
            target.mkdir(parents=True, exist_ok=True)
            continue
        if not member.isfile():
            raise ArchiveScanError(f"Unsupported tar member type: {member.name}")
        source = tf.extractfile(member)
        if source is None:
            raise ArchiveScanError(f"Could not read tar member: {member.name}")
        with source:
            total = _copy_limited(source, target, member.size, member.size, total)


def _extract_binary_archive(archive_path: Path, dest: Path) -> Path:
    suffixes = "".join(archive_path.suffixes).lower()
    if archive_path.suffix.lower() in {".zip", ".apk", ".ipa"}:
        _preflight_binary_zip(archive_path)
        with zipfile.ZipFile(archive_path, "r") as zf:
            _extract_binary_zip(zf, dest)
        return dest
    if archive_path.suffix.lower() in {".tar", ".tgz"} or suffixes.endswith((".tar.gz", ".tar.bz2", ".tar.xz")):
        archive_size = archive_path.stat().st_size
        ratio_limit = archive_size * MAX_BINARY_ARCHIVE_RATIO
        expanded_limit = min(MAX_BINARY_ARCHIVE_TOTAL_BYTES, ratio_limit)
        limit_message = (
            "Archive exceeds compression ratio limit"
            if ratio_limit < MAX_BINARY_ARCHIVE_TOTAL_BYTES
            else "Archive exceeds total expanded size limit"
        )
        if archive_path.suffix.lower() == ".tgz" or suffixes.endswith(".tar.gz"):
            source = gzip.open(archive_path, "rb")
        elif suffixes.endswith(".tar.bz2"):
            source = bz2.open(archive_path, "rb")
        elif suffixes.endswith(".tar.xz"):
            source = lzma.open(archive_path, "rb")
        else:
            source = archive_path.open("rb")
        with source:
            bounded = _LimitedReader(source, expanded_limit, limit_message)
            with tarfile.open(fileobj=bounded, mode="r|") as tf:
                _extract_binary_tar(tf, dest)
        return dest
    raise ArchiveScanError(f"Unsupported archive format: {archive_path}")


def scan_archive(
    archive_path: str,
    *,
    as_of: Optional[str] = None,
    profile: str = "ci",
    signer: str = "anonymous",
    prev_hash: str = "",
    scan_binaries: bool = False,
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
        if scan_binaries and archive.is_dir():
            extracted = archive
            report: ScanReport = scan_path(
                str(extracted), profile=profile, scan_binaries=True,
            )
        elif scan_binaries:
            extraction_incomplete = False
            try:
                extracted = _extract_binary_archive(archive, Path(tmp))
            except ArchiveScanError:
                extraction_incomplete = True
                extracted = Path(tmp)
            report = scan_path(
                str(extracted), profile=profile, scan_binaries=True,
                binary_source_prefix=str(archive),
            )
            if extraction_incomplete:
                coverage = report.extra.get("coverage", {})
                if not isinstance(coverage, dict):
                    coverage = {}
                report.extra["coverage"] = build_coverage(
                    str(coverage.get("scope") or "archive members"),
                    attempted=coverage.get("attempted", 0) + 1,
                    completed=coverage.get("completed", 0),
                    skipped=coverage.get("skipped", 0) + 1,
                    failed=coverage.get("failed", 0),
                    reasons=[
                        *(coverage.get("reasons", []) if isinstance(coverage.get("reasons"), list) else []),
                        "Archive extraction stopped before all entries could be scanned.",
                    ],
                )
                report.extra["archive_extraction_incomplete"] = True
        else:
            extracted = extract_archive(archive, Path(tmp))
            report = scan_path(str(extracted), profile=profile)

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
