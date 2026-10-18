"""A small defensive boundary shared by every AI adapter.

Never call the CLI, network scanners, provider validators, archive readers, or
source-map loaders here. Only explicitly supplied UTF-8 text is analyzed.
"""

from __future__ import annotations

import asyncio
import os
import json
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

import regex

from ..detectors import DETECTORS
from ..local_scanner import scan_text

MAX_INPUT_BYTES = 128 * 1024
MAX_FINDINGS = 100
MAX_FILES = 32
SCAN_SECONDS = 3.0
REGEX_SECONDS = 0.05
FILE_READ_SECONDS = 3.0

_MESSAGES = {
    "invalid_arguments": "Arguments do not match this tool's schema.",
    "unknown_tool": "This tool is unavailable.",
    "input_too_large": "Input exceeds the 128 KiB UTF-8 limit.",
    "invalid_text": "Input must be valid UTF-8 text without NUL characters.",
    "file_not_granted": "The host has not granted this file ID.",
    "file_unavailable": "The granted file cannot be read safely.",
    "busy": "The local scanner is busy; retry after the current call finishes.",
    "cancelled": "The scan was cancelled.",
    "scan_failed": "The local scan could not complete.",
}


def error(code: str) -> dict[str, Any]:
    """Return a static error that cannot reflect private input or filesystem paths."""
    return {"ok": False, "error": {"code": code, "message": _MESSAGES[code]}}


class _Cancelled(Exception):
    """Internal cooperative cancellation signal; never serialized."""


class _BoundedPattern:
    """Apply timeout and cancellation to the existing detector matching loop."""

    def __init__(self, pattern: str, cancel: threading.Event, deadline: float):
        self.pattern = regex.compile(pattern, regex.IGNORECASE | regex.MULTILINE)
        self.cancel = cancel
        self.deadline = deadline

    def finditer(self, content: str):
        """Yield matches while bounding one detector's total regex execution time."""
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError
        for match in self.pattern.finditer(content, timeout=min(REGEX_SECONDS, remaining)):
            if self.cancel.is_set():
                raise _Cancelled
            if time.monotonic() >= self.deadline:
                raise TimeoutError
            yield match


class _BoundedDetector:
    """Reuse registry metadata and scanner filters with a timeout-capable matcher."""

    def __init__(self, detector, cancel: threading.Event, deadline: float):
        self.detector = detector
        self.cancel = cancel
        self.deadline = deadline

    def __getattr__(self, name):
        return getattr(self.detector, name)

    def compile(self):
        """Compile the bundled expression with the existing regex dependency."""
        return _BoundedPattern(self.detector.pattern, self.cancel, self.deadline)


class KeyLeakTools:
    """Host-owned file grants; models cannot change grants, paths, or limits.

    With no grants, this service is text-only and needs no filesystem root.
    File grants are relative POSIX paths beneath a trusted operator-selected
    root. File access fails closed where descriptor-relative no-follow opens
    are unavailable. Do not expose a shared instance to unrelated tenants.
    """

    def __init__(self, *, root: str | Path | None = None, files: tuple[str, ...] = ()):
        if len(files) > MAX_FILES or len(set(files)) != len(files):
            raise ValueError("Invalid file grants.")
        self._root_fd = None
        self._files: dict[str, tuple[str, ...]] = {}
        self._slot = threading.Lock()
        self._async_admission = threading.Lock()
        self._closed = False
        self._reader_process = None
        if files:
            if root is None or os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
                raise ValueError("Safe file grants require a POSIX root.")
            parts = []
            for name in files:
                if not isinstance(name, str) or not name or len(name.encode("utf-8", errors="replace")) > 4096 or "\\" in name or "\x00" in name:
                    raise ValueError("Invalid file grants.")
                split = tuple(name.split("/"))
                if len(split) > 32 or any(p in ("", ".", "..") for p in split):
                    raise ValueError("Invalid file grants.")
                parts.append(split)
            try:
                # Operator-controlled root is pinned for the life of the service.
                self._root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            except (OSError, ValueError, TypeError):
                raise ValueError("The file-grant root cannot be opened safely.") from None
            self._files = {f"file_{i + 1}": p for i, p in enumerate(parts)}

    def close(self) -> None:
        """Release the pinned root after all active calls have finished."""
        with self._slot:
            self._closed = True
            self._stop_reader()
            if self._root_fd is not None:
                os.close(self._root_fd)
                self._root_fd = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def capabilities(self) -> dict[str, Any]:
        """Describe limits without exposing paths, contents, or environment values."""
        return {
            "ok": True,
            "mode": "local_static_only",
            "input_limit_bytes": MAX_INPUT_BYTES,
            "finding_limit": MAX_FINDINGS,
            "file_ids": list(self._files),
            "network_access": False,
            "credential_validation": False,
            "raw_values": False,
        }

    def call(self, name: str, arguments: Any, *, cancel: threading.Event | None = None) -> dict:
        """Validate, execute, and serialize one bounded call without logging input."""
        if not isinstance(name, str) or name not in {"keyleak_capabilities", "keyleak_scan_text", "keyleak_scan_file"}:
            return error("unknown_tool")
        required = {"keyleak_capabilities": set(), "keyleak_scan_text": {"text"}, "keyleak_scan_file": {"file_id"}}[name]
        if type(arguments) is not dict or set(arguments) != required:
            return error("invalid_arguments")
        if any(type(v) is not str for v in arguments.values()):
            return error("invalid_arguments")
        cancel = cancel if cancel is not None else threading.Event()
        if cancel.is_set():
            return error("cancelled")
        if not self._slot.acquire(blocking=False):
            return error("busy")
        try:
            if self._closed:
                return error("scan_failed")
            if self._reader_process is not None:
                if self._reader_process.poll() is None:
                    return error("busy")
                self._stop_reader()
            if name == "keyleak_capabilities":
                return self.capabilities()
            if name == "keyleak_scan_file":
                file_id = arguments["file_id"]
                if file_id not in self._files:
                    return error("file_not_granted")
                content = self._read_file(file_id, cancel)
                if isinstance(content, dict):
                    return content
                source_id = file_id
            else:
                content = arguments["text"]
                source_id = "provided_text"
            if len(content) > MAX_INPUT_BYTES:
                return error("input_too_large")
            try:
                size = len(content.encode("utf-8"))
            except UnicodeError:
                return error("invalid_text")
            if size > MAX_INPUT_BYTES:
                return error("input_too_large")
            if "\x00" in content:
                return error("invalid_text")
            return self._scan(content, source_id, size, cancel)
        except _Cancelled:
            return error("cancelled")
        except Exception:
            # Exception text and tracebacks may contain raw input or filenames.
            return error("scan_failed")
        finally:
            self._slot.release()

    async def call_async(self, name: str, arguments: Any) -> dict:
        """Keep the event loop responsive and stop matching when a client cancels."""
        if not self._async_admission.acquire(blocking=False):
            return error("busy")
        cancel = threading.Event()
        try:
            return await asyncio.to_thread(self.call, name, arguments, cancel=cancel)
        finally:
            cancel.set()
            self._async_admission.release()

    def _stop_reader(self) -> None:
        """Terminate a snapshot helper without an unbounded wait on stuck I/O."""
        process = self._reader_process
        if process is None:
            return
        if process.poll() is None:
            process.kill()
        try:
            process.communicate(timeout=0.2)
        except subprocess.TimeoutExpired:
            # A kernel-level uninterruptible read can outlive SIGKILL. Keep
            # this one helper tracked; refuse new work until it is reaped.
            return
        self._reader_process = None

    def _read_file(self, file_id: str, cancel: threading.Event) -> str | dict:
        """Snapshot a granted file in an isolated, cancellable read-only helper."""
        payload = json.dumps(self._files[file_id], ensure_ascii=True).encode("ascii")
        if len(payload) > 8192:
            return error("file_unavailable")
        deadline = time.monotonic() + FILE_READ_SECONDS
        try:
            process = subprocess.Popen(
                [sys.executable, "-I", str(Path(__file__).with_name("_file_reader.py")), str(self._root_fd)],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                env={}, pass_fds=(self._root_fd,), close_fds=True,
            )
            self._reader_process = process
            first = True
            while True:
                if cancel.is_set():
                    raise _Cancelled
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return error("file_unavailable")
                try:
                    data, _ = process.communicate(input=payload if first else None, timeout=min(remaining, 0.05))
                    break
                except subprocess.TimeoutExpired:
                    first = False
            if process.returncode == 3 or len(data) > MAX_INPUT_BYTES:
                return error("input_too_large")
            if process.returncode != 0:
                return error("file_unavailable")
            return data.decode("utf-8", errors="strict")
        except UnicodeError:
            return error("invalid_text")
        except OSError:
            return error("file_unavailable")
        finally:
            self._stop_reader()

    def _scan(self, content: str, source_id: str, size: int, cancel: threading.Event) -> dict:
        """Project only trusted registry fields and numeric positions into results."""
        findings = []
        reasons = set()
        completed = 0
        detectors = [d for d in DETECTORS if d.pack == "leak"]
        deadline = time.monotonic() + SCAN_SECONDS
        # Never honor a deterministic redaction salt from the environment.
        salt = os.urandom(32)
        for detector in detectors:
            if cancel.is_set():
                raise _Cancelled
            if time.monotonic() >= deadline:
                reasons.add("time_limit")
                break
            try:
                found = scan_text(content, "provided_input", [_BoundedDetector(detector, cancel, deadline)], run_salt=salt,
                                  max_findings=MAX_FINDINGS + 1 - len(findings), minimal_evidence=True)
                for finding in found:
                    findings.append({
                        "detector_id": detector.canonical_id,
                        "severity": finding.severity,
                        "line": finding.evidence.line,
                        "value": "[redacted]",
                        "remediation": detector.remediation,
                        "validation": "static_match_only",
                    })
                completed += 1
            except TimeoutError:
                reasons.add("detector_time_limit")
            if len(findings) > MAX_FINDINGS:
                reasons.add("finding_limit")
                findings = findings[:MAX_FINDINGS]
                break
        if cancel.is_set():
            raise _Cancelled
        return {
            "ok": True,
            "source_id": source_id,
            "input_bytes": size,
            "complete": not reasons,
            "incomplete_reasons": sorted(reasons),
            "detectors_completed": completed,
            "detectors_total": len(detectors),
            "findings": findings,
            "finding_count": len(findings),
            "assessment": "findings_detected" if findings else "no_findings_detected" if not reasons else "incomplete",
            "notice": "Static pattern matches only. No credential was tested. This is not a security certification.",
        }
