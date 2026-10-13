"""Bounded, read-only secret scanning for recognized binary artifacts."""

from __future__ import annotations

import hashlib
import base64
import binascii
import re
import struct
from collections import deque
from urllib.parse import unquote_to_bytes
from pathlib import Path
from typing import Iterable, Iterator, Optional, Tuple

from .detectors import Detector
from .local_scanner import scan_text


MAX_BINARY_FILE_BYTES = 10 * 1024 * 1024
MAX_BINARY_FILES = 1000
MAX_BINARY_TOTAL_BYTES = 100 * 1024 * 1024
MAX_BINARY_TOTAL_WORK_BYTES = 500 * 1024 * 1024
MAX_BINARY_FINDINGS = 10_000
MAX_BINARY_RUNS = 100_000
MAX_BINARY_SCAN_WORK_UNITS = 50 * 1024 * 1024
MAX_BINARY_REGEX_WORK_UNITS = 1_000_000_000
MIN_RUN_CHARS = 4
MAX_DECODE_DEPTH = 2
MAX_DECODE_WORK_BYTES = 10 * 1024 * 1024
MAX_DECODE_CANDIDATES = 10_000
MAX_ELF_SECTIONS = 4096
_ENCODED_RUNS = (
    ("hex", re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{32,}(?![0-9A-Fa-f])")),
    ("base64", re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/=])")),
    ("percent", re.compile(r"(?:%[0-9A-Fa-f]{2}){4,}")),
)

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


def binary_scan_limits() -> dict:
    return {
        "binary_file_bytes": MAX_BINARY_FILE_BYTES, "binary_files": MAX_BINARY_FILES,
        "binary_total_bytes": MAX_BINARY_TOTAL_BYTES, "binary_total_work_bytes": MAX_BINARY_TOTAL_WORK_BYTES,
        "binary_findings": MAX_BINARY_FINDINGS, "printable_runs": MAX_BINARY_RUNS,
        "extraction_work": MAX_BINARY_SCAN_WORK_UNITS, "detector_work": MAX_BINARY_REGEX_WORK_UNITS,
        "decode_depth": MAX_DECODE_DEPTH, "decode_work_bytes": MAX_DECODE_WORK_BYTES,
        "decode_candidates": MAX_DECODE_CANDIDATES, "elf_sections": MAX_ELF_SECTIONS,
    }


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
    """Yield ASCII-range strings in ASCII, UTF-16 and UTF-32 at every alignment."""
    if len(data) > MAX_BINARY_FILE_BYTES:
        raise ValueError("binary file exceeds per-file size limit")
    work_units = 0
    for width, little_endian in ((1, True), (2, True), (2, False), (4, True), (4, False)):
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
                if len(chars) >= MIN_RUN_CHARS:
                    yield "".join(chars), start, width
                index = max(index, start + width)


def _analysis_runs(data: bytes):
    work = 0
    candidates = 0
    for text, offset, width in extract_printable_runs(data):
        encoding = "ascii" if width == 1 else f"utf-{width * 8}{'le' if data[offset] else 'be'}"
        queue = deque([(text, offset, width, {"encoding": encoding, "transforms": []})])
        while queue:
            current, original_offset, current_width, evidence = queue.popleft()
            yield current, original_offset, current_width, evidence
            for transform, pattern in _ENCODED_RUNS:
                for match in pattern.finditer(current):
                    candidates += 1
                    work += len(match[0])
                    if candidates > MAX_DECODE_CANDIDATES or work > MAX_DECODE_WORK_BYTES:
                        raise BinaryScanLimitError("binary decoding work limit reached")
                    try:
                        if transform == "hex":
                            decoded = bytes.fromhex(match[0])
                        elif transform == "base64":
                            decoded = base64.b64decode(match[0], validate=True)
                        else:
                            decoded = unquote_to_bytes(match[0])
                    except (ValueError, binascii.Error):
                        continue
                    if len(decoded) < MIN_RUN_CHARS or not all(_printable(value) for value in decoded):
                        continue
                    if len(evidence["transforms"]) >= MAX_DECODE_DEPTH:
                        raise BinaryScanLimitError("binary decoding depth limit reached")
                    outer_offset = original_offset if evidence["transforms"] else offset + match.start() * width
                    outer_length = evidence.get("encoded_length", len(match[0]) * width)
                    step = {"encoding": transform, "input_offset": match.start(), "input_length": len(match[0])}
                    derived = {"encoding": encoding, "encoded_length": outer_length,
                               "transforms": [*evidence["transforms"], step]}
                    queue.append((decoded.decode("ascii"), outer_offset, 1, derived))


def _elf_layout(data: bytes) -> dict:
    """Read bounded ELF32/64 headers and section ranges, without loading code."""
    if not data.startswith(b"\x7fELF"):
        return {"status": "not_applicable"}
    if len(data) < 16 or data[4] not in (1, 2) or data[5] not in (1, 2) or data[6] != 1:
        return {"format": "ELF", "status": "unsupported", "reason": "Unsupported ELF identification"}
    bits = 32 if data[4] == 1 else 64
    endian = "<" if data[5] == 1 else ">"
    header_format = endian + ("HHIIIIIHHHHHH" if bits == 32 else "HHIQQQIHHHHHH")
    section_format = endian + ("IIIIIIIIII" if bits == 32 else "IIQQQQIIQQ")
    try:
        header = struct.unpack_from(header_format, data, 16)
        section_offset, header_size, section_size, section_count = header[5], header[7], header[10], header[11]
        if header[2] != 1 or header_size < 16 + struct.calcsize(header_format) or header_size > len(data):
            raise ValueError
        if section_count > MAX_ELF_SECTIONS or (section_offset and not section_count):
            return {"format": "ELF", "status": "unsupported", "reason": "ELF extended or excessive section count"}
        if section_count and (not section_offset or section_size < struct.calcsize(section_format)
                              or section_offset + section_size * section_count > len(data)):
            raise ValueError
        sections = []
        for index in range(1, section_count):
            section = struct.unpack_from(section_format, data, section_offset + index * section_size)
            kind, flags, address, start, size = section[1:6]
            if kind != 8 and (start > len(data) or size > len(data) - start):
                raise ValueError
            sections.append({"index": index, "type": kind, "flags": flags, "virtual_address": address,
                             "file_offset": start, "size_bytes": size})
        return {"format": "ELF", "status": "parsed", "bits": bits,
                "byte_order": "little" if endian == "<" else "big", "machine": header[1],
                "section_count": section_count, "sections": sections}
    except (struct.error, ValueError):
        return {"format": "ELF", "status": "malformed", "reason": "Malformed ELF header or section range"}


def scan_binary_bytes(
    data: bytes,
    source: str,
    detectors: Iterable[Detector],
    *,
    run_salt: Optional[bytes] = None,
    max_findings: int = MAX_BINARY_FINDINGS,
    artifact_metadata: Optional[dict] = None,
) -> list:
    """Scan printable strings in bytes without loading or executing the artifact."""
    if len(data) > MAX_BINARY_FILE_BYTES:
        raise ValueError("binary file exceeds per-file size limit")
    findings = []
    detectors = list(detectors)
    runs = 0
    regex_work_units = 0
    findings_by_location = {}
    finding_run_lengths = []
    layout = _elf_layout(data)
    if artifact_metadata is not None:
        artifact_metadata["native_layout"] = {key: value for key, value in layout.items() if key != "sections"}
    try:
        for text, offset, width, extraction in _analysis_runs(data):
            runs += 1
            if runs > MAX_BINARY_RUNS:
                raise BinaryScanLimitError("binary printable-run limit reached")
            remaining_findings = max_findings - len(findings)
            if remaining_findings <= 0:
                raise BinaryScanLimitError("binary finding limit reached", findings)
            regex_work_units += len(text) * len(detectors)
            if regex_work_units > MAX_BINARY_REGEX_WORK_UNITS:
                raise BinaryScanLimitError("binary detector work limit reached", findings)
            run_findings = scan_text(
                    text,
                    source,
                    detectors,
                    run_salt=run_salt,
                    byte_offset_base=offset,
                    byte_offset_width=width,
                    max_findings=remaining_findings,
                    extraction=extraction,
                )
            for finding in run_findings:
                for section in layout.get("sections", []):
                    start = section["file_offset"]
                    if (section["type"] != 8 and start <= finding.evidence.byte_offset
                            and finding.evidence.byte_offset + finding.evidence.byte_length <= start + section["size_bytes"]):
                        finding.evidence.extraction["section_index"] = section["index"]
                        finding.evidence.extraction["section_file_offset"] = start
                        finding.evidence.extraction["section_size_bytes"] = section["size_bytes"]
                        if section["flags"] & 2:
                            finding.evidence.extraction["virtual_address"] = section["virtual_address"] + finding.evidence.byte_offset - start
                        break
                if width == 1:
                    findings.append(finding)
                    finding_run_lengths.append(len(text))
                    continue

                identity = (
                    finding.detector_id,
                    finding.source,
                    finding.evidence.redacted_value,
                    finding.evidence.line,
                )
                byte_offset = finding.evidence.byte_offset
                locations = findings_by_location.setdefault(identity, {})
                overlapping = next(
                    (locations[offset] for offset in range(byte_offset - width + 1, byte_offset + width)
                     if offset in locations),
                    None,
                )
                if overlapping is None:
                    index = len(findings)
                    findings.append(finding)
                    finding_run_lengths.append(len(text))
                    locations[byte_offset] = index
                elif len(text) > finding_run_lengths[overlapping]:
                    previous_offset = findings[overlapping].evidence.byte_offset
                    del locations[previous_offset]
                    locations[byte_offset] = overlapping
                    findings[overlapping] = finding
                    finding_run_lengths[overlapping] = len(text)
            if len(run_findings) >= remaining_findings:
                raise BinaryScanLimitError("binary finding limit reached", findings)
        if layout["status"] in {"malformed", "unsupported"}:
            raise BinaryScanLimitError(layout["reason"], findings)
    except BinaryScanLimitError as exc:
        raise BinaryScanLimitError(str(exc), findings) from exc
    return findings


def scan_binary_file(
    path: Path,
    detectors: Iterable[Detector],
    *,
    source: Optional[str] = None,
    run_salt: Optional[bytes] = None,
    max_findings: int = MAX_BINARY_FINDINGS,
    artifact_metadata: Optional[dict] = None,
    budget: Optional[dict] = None,
) -> list:
    """Read and scan one bounded binary candidate."""
    size = path.stat().st_size
    if size > MAX_BINARY_FILE_BYTES:
        raise ValueError("binary file exceeds per-file size limit")
    read_limit = MAX_BINARY_FILE_BYTES
    if budget is not None:
        if budget["files"] >= MAX_BINARY_FILES or budget["bytes"] >= MAX_BINARY_TOTAL_BYTES or budget["work_bytes"] >= MAX_BINARY_TOTAL_WORK_BYTES:
            raise BinaryScanLimitError("bounded binary scan file or byte limit reached")
        max_findings = min(max_findings, MAX_BINARY_FINDINGS - budget["findings"])
        if max_findings <= 0:
            raise BinaryScanLimitError("bounded binary finding limit reached")
        read_limit = min(read_limit, MAX_BINARY_TOTAL_BYTES - budget["bytes"],
                         (MAX_BINARY_TOTAL_WORK_BYTES - budget["work_bytes"]) // 5)
        if size > read_limit:
            raise BinaryScanLimitError("bounded binary scan file or byte limit reached")
    with path.open("rb") as artifact:
        data = artifact.read(read_limit + 1)
    if budget is not None:
        budget["files"] += 1
        budget["bytes"] += len(data)
        budget["work_bytes"] += len(data) * 5
    if len(data) > MAX_BINARY_FILE_BYTES:
        raise ValueError("binary file exceeds per-file size limit")
    if len(data) > read_limit:
        raise BinaryScanLimitError("bounded binary scan file or byte limit reached")
    if artifact_metadata is not None:
        artifact_metadata.update(size_bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
    try:
        findings = scan_binary_bytes(data, source or str(path), detectors, run_salt=run_salt,
                                     max_findings=max_findings, artifact_metadata=artifact_metadata)
    except BinaryScanLimitError as exc:
        if budget is not None:
            budget["findings"] += len(exc.findings)
        raise
    if budget is not None:
        budget["findings"] += len(findings)
    return findings
