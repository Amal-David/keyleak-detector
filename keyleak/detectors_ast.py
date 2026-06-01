"""Behavioral worm-shape detector (Wave 2.2).

Catches the Mini Shai-Hulud capability triad inside an npm install script
(``prepare``/``preinstall``/``postinstall``) or in any JS/TS file under
``node_modules/.../*.js``:

  (a) **env-var read** matching ``/TOKEN|SECRET|KEY|NPM|GH|AWS|OIDC/``
  (b) **network egress**: ``fetch``, ``https`` / ``http``, ``dgram``,
      ``child_process.spawn`` of ``curl`` / ``wget`` / ``nc`` / ``python``
  (c) **persistence write** to ``~/.config``, ``~/Library/LaunchAgents``,
      ``~/.local/share``, ``~/.ssh``, ``/etc/systemd``

If a single source exhibits all three within ``MAX_CAPABILITY_WINDOW_LINES``
of each other, it is flagged as ``critical`` regardless of which specific
strings or hostnames are used. This is behavioral coverage — the next worm
variant can rotate every string and still trip the triad.

The detector is intentionally syntactic-not-semantic. We don't try to follow
imports or evaluate conditionals. A real worm has all three capabilities in
the same file; that's the bar this guard enforces.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional


MAX_CAPABILITY_WINDOW_LINES = 200  # generous window — variants stretch the payload


# ----- Capability detectors (each finds one shape, returns line numbers) -----

_ENV_READ_RE = re.compile(
    r"(?:process\.env|os\.environ|getenv|Deno\.env|Bun\.env)"
    r"[\.\[]"
    r"['\"]?"
    r"([A-Za-z0-9_-]*(?:TOKEN|SECRET|KEY|NPM|GH|GITHUB|AWS|OIDC|CREDENTIAL|API)[A-Za-z0-9_-]*)"
    r"['\"]?",
    re.IGNORECASE,
)

_NET_EGRESS_RE = re.compile(
    r"\b(?:"
    r"fetch\s*\(|"
    r"axios\s*\.|"
    r"https?\.request\s*\(|"
    r"require\(['\"]https?['\"]\)|"
    r"import\s+[\w*\s{},]+from\s+['\"]https?['\"]|"
    r"require\(['\"]dgram['\"]\)|"
    r"net\.(?:connect|createConnection)\s*\(|"
    r"child_process[\s\S]{0,40}(?:spawn|exec)\s*\(\s*['\"](?:curl|wget|nc|python|python3|sh|bash)['\"]"
    r")"
)

_PERSISTENCE_WRITE_RE = re.compile(
    r"(?:fs|node:fs)[\s\S]{0,40}(?:writeFile|appendFile|createWriteStream|"
    r"writeFileSync|appendFileSync)[\s\S]{0,200}?"
    r"(?:"
    r"~/\.config|~/Library/LaunchAgents|~/Library/LaunchDaemons|"
    r"~/\.local/share|~/\.ssh|~/\.aws/credentials|"
    r"/etc/systemd|com\.user\.[\w.-]+\.plist"
    r")",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class CapabilityHit:
    capability: str  # "env_read" | "net_egress" | "persistence_write"
    line: int
    excerpt: str


def find_capabilities(text: str) -> List[CapabilityHit]:
    """Return every capability hit in ``text`` with its line number."""

    hits: List[CapabilityHit] = []
    for capability, regex in (
        ("env_read", _ENV_READ_RE),
        ("net_egress", _NET_EGRESS_RE),
        ("persistence_write", _PERSISTENCE_WRITE_RE),
    ):
        for match in regex.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            excerpt = _line_at(text, match.start())
            hits.append(CapabilityHit(capability=capability, line=line, excerpt=excerpt))
    return hits


@dataclass(frozen=True)
class WormShapeMatch:
    source: str
    env_read_line: int
    net_egress_line: int
    persistence_write_line: int
    excerpt_window: str


def detect_worm_shape(text: str, source: str) -> Optional[WormShapeMatch]:
    """Return a ``WormShapeMatch`` if env-read + net-egress + write coexist."""

    hits = find_capabilities(text)
    by_cap = {"env_read": [], "net_egress": [], "persistence_write": []}
    for hit in hits:
        by_cap[hit.capability].append(hit)

    if not all(by_cap.values()):
        return None

    # Look for any window of size MAX_CAPABILITY_WINDOW_LINES that contains
    # at least one hit from each capability. Earliest-line combination wins.
    for env_hit in by_cap["env_read"]:
        for net_hit in by_cap["net_egress"]:
            for write_hit in by_cap["persistence_write"]:
                lines = [env_hit.line, net_hit.line, write_hit.line]
                if max(lines) - min(lines) <= MAX_CAPABILITY_WINDOW_LINES:
                    window_start = min(lines)
                    window_end = max(lines)
                    excerpt = _slice_lines(text, window_start, window_end)
                    return WormShapeMatch(
                        source=source,
                        env_read_line=env_hit.line,
                        net_egress_line=net_hit.line,
                        persistence_write_line=write_hit.line,
                        excerpt_window=excerpt,
                    )
    return None


# ----- Integration helpers used by ``scan_file`` ----------------------------

_TARGET_SUFFIXES = (".js", ".mjs", ".cjs", ".ts", ".tsx", ".sh", ".py")


def is_worm_shape_target(path: Path) -> bool:
    """Whether the AST detector should run on ``path``.

    Targets: any source file under ``node_modules/`` or any file named
    ``package.json`` (because ``scripts.prepare`` literal strings count).
    """

    full = str(path).replace("\\", "/")
    if path.name == "package.json":
        return True
    parts_lower = [part.lower() for part in path.parts]
    if "node_modules" in parts_lower and path.suffix.lower() in _TARGET_SUFFIXES:
        return True
    if "/node_modules/" in full and path.suffix.lower() in _TARGET_SUFFIXES:
        return True
    return False


# ----- Internals -----------------------------------------------------------

def _line_at(text: str, offset: int, radius: int = 80) -> str:
    """Return a short snippet centered on ``offset``."""

    start = max(0, offset - radius)
    end = min(len(text), offset + radius)
    return text[start:end].replace("\n", " ").strip()


def _slice_lines(text: str, start_line: int, end_line: int) -> str:
    lines = text.splitlines()
    start = max(0, start_line - 1)
    end = min(len(lines), end_line)
    return "\n".join(lines[start:end])
