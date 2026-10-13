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
import hashlib
import lzma
import os
import posixpath
import re
import struct
import shlex
import tarfile
import tempfile
import zipfile
from pathlib import Path
from typing import Optional

from .chain_of_custody import build_envelope
from .local_scanner import SKIP_DIRS, scan_path
from .models import ScanReport, build_coverage
from .reporting import build_report
from .redaction import new_run_salt


class ArchiveScanError(RuntimeError):
    pass


MAX_BINARY_ARCHIVE_ENTRIES = 10_000
MAX_BINARY_ARCHIVE_MEMBER_BYTES = 100 * 1024 * 1024
MAX_BINARY_ARCHIVE_TOTAL_BYTES = 500 * 1024 * 1024
MAX_BINARY_ARCHIVE_RATIO = 200
MAX_BINARY_ARCHIVE_CENTRAL_DIRECTORY_BYTES = 64 * 1024 * 1024
MAX_ARCHIVE_INPUT_BYTES = 500 * 1024 * 1024
MAX_ARCHIVE_DEPTH = 3


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
    with target.open("xb") as output:
        try:
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
        except (ArchiveScanError, OSError, EOFError, RuntimeError, zipfile.BadZipFile):
            output.close()
            target.unlink(missing_ok=True)
            raise
    return total + written


def _preflight_binary_zip(archive_path: Path, *, remaining_entries: Optional[int] = None) -> None:
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
        if entry_count > MAX_BINARY_ARCHIVE_ENTRIES or (remaining_entries is not None and entry_count > remaining_entries):
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


def _extract_binary_zip(zf: zipfile.ZipFile, dest: Path, budget: dict) -> None:
    infos = zf.infolist()
    if len(infos) > MAX_BINARY_ARCHIVE_ENTRIES:
        raise ArchiveScanError("Archive exceeds entry count limit")
    for info in infos:
        budget["entries"] += 1
        if budget["entries"] > MAX_BINARY_ARCHIVE_ENTRIES:
            raise ArchiveScanError("Archive exceeds aggregate entry count limit")
        target = _member_path(info.filename, dest, allow_root=info.is_dir())
        mode = (info.external_attr >> 16) & 0xFFFF
        if mode and (mode & 0o170000) == 0o120000:
            raise ArchiveScanError(f"Symlink in zip archive: {info.filename}")
        if info.is_dir():
            target.mkdir(parents=True, exist_ok=True)
            continue
        with zf.open(info, "r") as source:
            budget["bytes"] = _copy_limited(source, target, info.file_size, info.compress_size, budget["bytes"])


class _LimitedReader:
    """Read a decompressed stream while enforcing its expanded-byte budget."""

    def __init__(self, source, max_bytes: int, message: str):
        self.source = source
        self.max_bytes = max_bytes
        self.message = message
        self.bytes_read = 0

    def read(self, size: int = -1) -> bytes:
        remaining = self.max_bytes - self.bytes_read
        if remaining < 0:
            raise ArchiveScanError(self.message)
        bounded_size = remaining + 1 if size is None or size < 0 else min(size, remaining + 1)
        data = self.source.read(bounded_size)
        self.bytes_read += len(data)
        if len(data) > remaining:
            raise ArchiveScanError(self.message)
        return data

    def readinto(self, buffer) -> int:
        data = self.read(len(buffer))
        buffer[:len(data)] = data
        return len(data)


def _extract_binary_tar(tf: tarfile.TarFile, dest: Path, budget: dict) -> None:
    for member in tf:
        budget["entries"] += 1
        if budget["entries"] > MAX_BINARY_ARCHIVE_ENTRIES:
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
            budget["bytes"] = _copy_limited(source, target, member.size, member.size, budget["bytes"])


def _extract_binary_archive(archive_path: Path, dest: Path, *, budget: Optional[dict] = None) -> Path:
    if budget is None:
        budget = {"bytes": 0, "entries": 0}
    if budget["bytes"] >= MAX_BINARY_ARCHIVE_TOTAL_BYTES:
        raise ArchiveScanError("Archive exceeds total expanded size limit")
    suffixes = "".join(archive_path.suffixes).lower()
    if archive_path.suffix.lower() in {".zip", ".apk", ".ipa"}:
        _preflight_binary_zip(archive_path, remaining_entries=MAX_BINARY_ARCHIVE_ENTRIES - budget["entries"])
        with zipfile.ZipFile(archive_path, "r") as zf:
            _extract_binary_zip(zf, dest, budget)
        return dest
    if archive_path.suffix.lower() in {".tar", ".tgz"} or suffixes.endswith((".tar.gz", ".tar.bz2", ".tar.xz")):
        archive_size = archive_path.stat().st_size
        ratio_limit = archive_size * MAX_BINARY_ARCHIVE_RATIO
        initial_bytes = budget["bytes"]
        remaining_bytes = MAX_BINARY_ARCHIVE_TOTAL_BYTES - initial_bytes
        expanded_limit = min(remaining_bytes, ratio_limit)
        limit_message = (
            "Archive exceeds compression ratio limit"
            if ratio_limit < remaining_bytes
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
            try:
                with tarfile.open(fileobj=bounded, mode="r|") as tf:
                    _extract_binary_tar(tf, dest, budget)
            finally:
                budget["bytes"] = max(budget["bytes"], initial_bytes + bounded.bytes_read)
        return dest
    raise ArchiveScanError(f"Unsupported archive format: {archive_path}")


def _snapshot_archive(archive: Path, snapshot: Path, limit: int) -> dict:
    digest = hashlib.sha256()
    size = 0
    with archive.open("rb") as original, snapshot.open("xb") as copied:
        while chunk := original.read(1024 * 1024):
            size += len(chunk)
            if size > limit:
                raise ArchiveScanError("Archive input exceeds snapshot byte limit")
            digest.update(chunk)
            copied.write(chunk)
    return {"size_bytes": size, "sha256": digest.hexdigest()}


def _scan_binary_members(archive: Path, source: str, staging: Path, profile: str) -> ScanReport:
    pending = [(archive, source, 0, None)]
    extraction_budget = {"bytes": 0, "entries": 0}
    binary_budget = {"files": 0, "bytes": 0, "work_bytes": 0, "findings": 0}
    run_salt = new_run_salt()
    reports = []
    containers = []
    reasons = []
    inspected = 0
    snapshot_bytes = 0
    cursor = 0
    while cursor < len(pending):
        current, prefix, depth, container = pending[cursor]
        cursor += 1
        root = current if current.is_dir() else staging / str(cursor)
        if not current.is_dir():
            root.mkdir()
            try:
                _extract_binary_archive(current, root, budget=extraction_budget)
                if container is not None:
                    container["status"] = "expanded"
            except (ArchiveScanError, zipfile.BadZipFile, tarfile.TarError, OSError, EOFError, RuntimeError):
                if container is not None:
                    container["status"] = "partial"
                reasons.append("Archive extraction stopped before all entries could be scanned.")
        children = []
        def walk_error(_error):
            reasons.append("Archive member directory could not be read")
        for directory, dirs, files in os.walk(root, followlinks=False, onerror=walk_error):
            relative_parts = Path(directory).relative_to(root).parts
            dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS or d == "node_modules"
                             or (d == "dist" and (not relative_parts or "node_modules" in relative_parts)))
            inspected += len(dirs) + len(files)
            if inspected > MAX_BINARY_ARCHIVE_ENTRIES:
                reasons.append("Archive discovery entry limit reached")
                break
            for name in sorted(files):
                member = Path(directory) / name
                if member.is_symlink():
                    continue
                suffixes = "".join(member.suffixes).lower()
                if not (member.suffix.lower() in {".zip", ".apk", ".ipa", ".tar", ".tgz"}
                        or suffixes.endswith((".tar.gz", ".tar.bz2", ".tar.xz"))):
                    continue
                children.append(member)
                member_source = f"{prefix}!/{member.relative_to(root).as_posix()}" if not current.is_dir() else str(member)
                record = {"source": member_source, "depth": depth + 1}
                containers.append(record)
                if depth >= MAX_ARCHIVE_DEPTH:
                    record["status"] = "depth_limit"
                    reasons.append("Nested archive depth limit reached")
                    continue
                try:
                    remaining = min(MAX_BINARY_ARCHIVE_MEMBER_BYTES, MAX_ARCHIVE_INPUT_BYTES - snapshot_bytes)
                    if member.stat().st_size > remaining:
                        raise ArchiveScanError("Nested archive input exceeds byte limit")
                    snapshot_dir = staging / f"input-{len(containers)}"
                    snapshot_dir.mkdir()
                    snapshot = snapshot_dir / member.name
                    record.update(_snapshot_archive(member, snapshot, remaining))
                    snapshot_bytes += record["size_bytes"]
                    record["status"] = "scheduled"
                    pending.append((snapshot, member_source, depth + 1, record))
                except (OSError, ArchiveScanError):
                    snapshot_bytes = MAX_ARCHIVE_INPUT_BYTES
                    record["status"] = "unreadable"
                    reasons.append("Nested archive input could not be inspected within its limit")
        reports.append(scan_path(
            str(root), profile=profile, scan_binaries=True, run_salt=run_salt,
            binary_source_prefix=prefix if not current.is_dir() else None,
            _binary_budget=binary_budget, _expanded_archives=children,
        ))
    report = build_report(source, [f for item in reports for f in item.findings], scan_mode="archive", profile=profile,
                          packs=reports[0].extra["packs"])
    counts = {key: sum(item.extra["coverage"][key] for item in reports) for key in ("attempted", "completed", "skipped", "failed")}
    counts["attempted"] += len(reasons)
    counts["skipped"] += len(reasons)
    report.extra["coverage"] = build_coverage(
        "archive members and binary strings", **counts,
        reasons=[*reasons, *(reason for item in reports for reason in item.extra["coverage"]["reasons"])],
    )
    report.extra["inventory"] = {key: sum(item.extra["inventory"][key] for item in reports) for key in reports[0].extra["inventory"]}
    report.extra["scan_manifest"] = reports[0].extra["scan_manifest"]
    report.extra["scan_manifest"]["artifacts"] = [artifact for item in reports for artifact in item.extra["scan_manifest"]["artifacts"]]
    report.extra["scan_manifest"]["archives"] = containers
    report.extra["scan_manifest"]["limits"].update(
        archive_depth=MAX_ARCHIVE_DEPTH, archive_entries=MAX_BINARY_ARCHIVE_ENTRIES,
        archive_expanded_bytes=MAX_BINARY_ARCHIVE_TOTAL_BYTES, archive_ratio=MAX_BINARY_ARCHIVE_RATIO,
        archive_member_bytes=MAX_BINARY_ARCHIVE_MEMBER_BYTES, archive_input_bytes=MAX_ARCHIVE_INPUT_BYTES,
    )
    if reasons:
        report.extra["archive_extraction_incomplete"] = True
    return report


def scan_archive(
    archive_path: str,
    *,
    as_of: Optional[str] = None,
    profile: str = "ci",
    signer: str = "anonymous",
    prev_hash: str = "",
    scan_binaries: bool = False,
    fail_on: str = "high",
) -> dict:
    """Scan ``archive_path`` and return a chain-of-custody envelope.

    ``as_of`` is informational metadata stored on the envelope (e.g. the
    deploy timestamp the archive represents); it does not influence scan
    semantics.
    """

    archive = Path(archive_path).expanduser().resolve()
    if not archive.exists():
        raise ArchiveScanError(f"Archive not found: {archive}")

    input_artifact = {"source": str(archive), "kind": "directory" if archive.is_dir() else "archive"}
    with tempfile.TemporaryDirectory() as tmp:
        extraction_root = Path(tmp) / "members"
        extraction_root.mkdir()
        snapshot = archive
        input_limit = False
        if not archive.is_dir():
            if not archive.is_file():
                raise ArchiveScanError("Archive input is not a regular file")
            input_dir = Path(tmp) / "input"
            input_dir.mkdir()
            snapshot = input_dir / archive.name
            try:
                input_artifact.update(_snapshot_archive(archive, snapshot, MAX_ARCHIVE_INPUT_BYTES))
            except ArchiveScanError:
                input_limit = True
                input_artifact["status"] = "input_limit"
            except OSError as exc:
                raise ArchiveScanError("Archive input could not be read") from exc
        if input_limit:
            report = scan_path(str(extraction_root), profile=profile, scan_binaries=scan_binaries)
            report.extra["coverage"] = build_coverage("archive input", attempted=1, completed=0, skipped=1,
                                                       reasons=["Archive input exceeds snapshot byte limit"])
        elif scan_binaries:
            report = _scan_binary_members(snapshot, str(archive), extraction_root, profile)
        else:
            extracted = extract_archive(snapshot, extraction_root)
            report = scan_path(str(extracted), profile=profile,
                               binary_source_prefix=str(archive) if not archive.is_dir() else None)

    report_dict = report.to_dict()
    report_dict["archive_path"] = str(archive)
    report_dict["scan_mode"] = "archive"
    report_dict["target"] = str(archive)
    report_dict["input_artifact"] = input_artifact
    command = ["keyleak", "archive", str(archive), "--launch-profile", profile, "--fail-on", fail_on,
               "--signer", signer]
    if scan_binaries:
        command.append("--scan-binaries")
    if prev_hash:
        command.extend(["--prev-hash", prev_hash])
    if as_of:
        report_dict["as_of"] = as_of
        command.extend(["--as-of", as_of])
    report_dict["retest_command"] = shlex.join(command)

    return build_envelope(
        report_dict,
        prev_hash=prev_hash,
        signer=signer,
    )
