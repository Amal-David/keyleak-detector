"""Bounded, read-only secret scanning for recognized binary artifacts."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable, Iterator, Optional, Tuple

from .detectors import Detector
from .local_scanner import scan_text


MAX_BINARY_FILE_BYTES = 10 * 1024 * 1024
MAX_BINARY_RUNS = 100_000
MAX_RUN_CHARS = 1_000_000
MAX_BINARY_SCAN_WORK_UNITS = 50 * 1024 * 1024
MIN_RUN_CHARS = 4

_BINARY_SUFFIXES = {".dll", ".exe", ".so", ".dylib", ".wasm", ".bin", ".elf", ".macho"}
_MAGIC_PREFIXES = (
    b"\x7fELF",
    b"MZ",
    b"\x00asm",
    b"\xfe\xed\xfa\xce",
    b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf",
    b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",
    b"\xbe\xba\xfe\xca",
)


class BinaryScanLimitError(ValueError):
    def __init__(self, message: str, findings: Optional[list] = None):
        super().__init__(message)
        self.findings = findings or []


def is_binary_candidate(path: Path) -> bool:
    """Return true for known binary suffixes or recognized executable formats."""
    if path.suffix.lower() in _BINARY_SUFFIXES:
        return True
    try:
        with path.open("rb") as source:
            prefix = source.read(4)
    except OSError:
        return False
    return any(prefix.startswith(magic) for magic in _MAGIC_PREFIXES)


def _printable(value: int) -> bool:
    return 9 <= value <= 13 or 0x20 <= value <= 0x7E


def extract_printable_runs(data: bytes) -> Iterator[Tuple[str, int, int]]:
    """Yield printable ASCII/UTF-16 runs as text, byte start, and byte width."""
    work_units = 0
    for width, little_endian in ((1, True), (2, True), (2, False)):
        for alignment in range(width):
            index = alignment
            while index + width <= len(data):
                start = index
                chars = []
                while index + width <= len(data):
                    work_units += 1
                    if work_units > MAX_BINARY_SCAN_WORK_UNITS:
                        raise BinaryScanLimitError("binary scanning work limit reached")
                    unit = data[index:index + width]
                    value = unit[0] if width == 1 else int.from_bytes(unit, "little" if little_endian else "big")
                    if not _printable(value):
                        break
                    chars.append(chr(value))
                    index += width
                    if len(chars) >= MAX_RUN_CHARS:
                        break
                if len(chars) >= MIN_RUN_CHARS:
                    yield "".join(chars), start, width
                index = max(index, start + width)


def scan_binary_bytes(
    data: bytes,
    source: str,
    detectors: Iterable[Detector],
    *,
    run_salt: Optional[bytes] = None,
) -> list:
    """Scan printable strings in bytes without loading or executing the artifact."""
    if len(data) > MAX_BINARY_FILE_BYTES:
        raise ValueError("binary file exceeds per-file size limit")
    findings = []
    detectors = list(detectors)
    runs = 0
    try:
        for text, offset, width in extract_printable_runs(data):
            runs += 1
            if runs > MAX_BINARY_RUNS:
                raise BinaryScanLimitError("binary printable-run limit reached")
            findings.extend(
                scan_text(
                    text,
                    source,
                    detectors,
                    run_salt=run_salt,
                    byte_offset_base=offset,
                    byte_offset_width=width,
                )
            )
    except BinaryScanLimitError as exc:
        raise BinaryScanLimitError(str(exc), findings + exc.findings) from exc
    return findings


def scan_binary_file(
    path: Path,
    detectors: Iterable[Detector],
    *,
    source: Optional[str] = None,
    run_salt: Optional[bytes] = None,
) -> list:
    """Read and scan one bounded binary candidate."""
    try:
        with path.open("rb") as artifact:
            data = artifact.read(MAX_BINARY_FILE_BYTES + 1)
    except OSError:
        raise
    if len(data) > MAX_BINARY_FILE_BYTES:
        raise ValueError("binary file exceeds per-file size limit")
    return scan_binary_bytes(data, source or str(path), detectors, run_salt=run_salt)
