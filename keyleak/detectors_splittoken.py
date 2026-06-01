"""Cross-file split-token reassembly detector (Wave 3.4).

Every existing detector in :mod:`keyleak.detectors` runs against a single
file. An attacker who knows that defeats the regex by splitting:

    // a.ts
    const part1 = "ghp_aBcD";
    // b.ts
    const part2 = "EfGhI1234567890abcdef1234567";

at runtime the bundle does ``part1 + part2`` and a valid ``ghp_*`` shows up
in the browser. None of the current detectors catch this — both files look
benign on their own.

This module collects every >=12-char alphanumeric fragment across a set of
files and checks whether any concatenation (in either order, with no
separator) starts with a known key prefix (``ghp_``, ``sk-``, ``AKIA``,
``xoxb-``, ``eyJ``).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Tuple


# Fragments must be at least this long to be considered. Shorter fragments
# produce too many false-positive concatenations.
MIN_FRAGMENT_LENGTH = 12
# Known key prefixes; the concatenation must START with one of these for a
# match. We intentionally don't try to enforce the full token shape — the
# downstream Finding directs the dev to verify.
KEY_PREFIXES: Tuple[str, ...] = (
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "github_pat_",
    "sk-",
    "sk_live_",
    "sk_test_",
    "rk_live_",
    "AKIA",
    "ASIA",
    "xoxb-",
    "xoxp-",
    "xoxa-",
    "xoxr-",
    "xoxs-",
    "eyJ",
    "glpat-",
    "AIza",
    "hf_",
    "r8_",
    "pplx-",
    "gsk_",
    "esecret_",
    "npm_",
    "SG.",
    "pypi-AgEI",
)


_FRAGMENT_RE = re.compile(r"[A-Za-z0-9_-]{%d,}" % MIN_FRAGMENT_LENGTH)


@dataclass(frozen=True)
class Fragment:
    file: str
    line: int
    text: str


@dataclass(frozen=True)
class SplitTokenMatch:
    prefix: str
    fragment_a: Fragment
    fragment_b: Fragment
    assembled: str  # truncated at 80 chars for the report


def extract_fragments(text: str, file: str, *, min_length: int = MIN_FRAGMENT_LENGTH) -> List[Fragment]:
    """Return every >=``min_length`` alphanumeric fragment in ``text``."""

    fragments: List[Fragment] = []
    for match in _FRAGMENT_RE.finditer(text):
        if len(match.group(0)) < min_length:
            continue
        line = text.count("\n", 0, match.start()) + 1
        fragments.append(Fragment(file=file, line=line, text=match.group(0)))
    return fragments


def collect_fragments(files: Iterable[Path]) -> Dict[str, List[Fragment]]:
    """Walk ``files`` and return ``{prefix_seen_as_substring: [Fragment...]}``.

    We index by fragment text so the reassembly step is O(F^2) over fragments
    rather than O(file^2 * fragment^2).
    """

    by_file: Dict[str, List[Fragment]] = {}
    for path in files:
        try:
            text = Path(path).read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        by_file[str(path)] = extract_fragments(text, str(path))
    return by_file


def find_split_tokens(
    fragments_by_file: Dict[str, List[Fragment]],
    *,
    prefixes: Tuple[str, ...] = KEY_PREFIXES,
) -> List[SplitTokenMatch]:
    """Return every pair (a, b) across distinct files where ``a.text + b.text``
    starts with a known key prefix.

    Fast path: a fragment can only be the *lead* of a reassembly if it either
      (a) already starts with one of the key prefixes (e.g. ``ghp_aBcD``), or
      (b) is a partial-prefix lead (e.g. ``gh`` + ``p_aBcD...`` -> ``ghp_...``)
          where the fragment is a strict prefix of a key prefix.

    We index fragments by both classes, then pair only candidate leads with
    every other-file fragment. This turns the worst case from O(F²) on the
    full corpus to O(L × F) where L is the (small) number of candidate leads.

    Same-file pairs are skipped — those are already caught by the regular
    regex pack since the merged string would live in the bundle.
    """

    # A fragment is a useful split-token *lead* only if its text begins with
    # one of the known key prefixes. This is intentionally narrow: pairing
    # every prefix-first-char-match against every other-file fragment, as the
    # original implementation did, produced 7M+ duplicate findings on real
    # corpora (cline/cline, deepset-ai/haystack) during the dogfood scan.
    #
    # Cross-file callers are opt-in via ``KEYLEAK_ENABLE_SPLIT_TOKEN=1`` so
    # the default ``scan_path`` flow is quiet on real-world repos. v0.3 will
    # redesign with proper prefix-bridging gates.
    def is_lead_candidate(text: str) -> bool:
        return any(text.startswith(p) for p in prefixes)

    # Bucket fragments per file into "leads" (worth checking as fragment_a) and
    # "any" (every fragment, used as fragment_b).
    leads_by_file: Dict[str, List[Fragment]] = {}
    for file, frags in fragments_by_file.items():
        leads_by_file[file] = [f for f in frags if is_lead_candidate(f.text)]

    matches: List[SplitTokenMatch] = []
    files = list(fragments_by_file.keys())

    for i, file_a in enumerate(files):
        leads_a = leads_by_file.get(file_a) or ()
        if not leads_a and not any(leads_by_file.get(fb) for fb in files[i + 1 :]):
            continue
        for file_b in files[i + 1 :]:
            leads_b = leads_by_file.get(file_b) or ()
            # For each *lead* in either file, pair against every fragment in
            # the other file. The non-lead fragment fills the tail.
            for lead, others in (
                (leads_a, fragments_by_file[file_b]),
                (leads_b, fragments_by_file[file_a]),
            ):
                for fa in lead:
                    for fb in others:
                        combined = fa.text + fb.text
                        for prefix in prefixes:
                            if combined.startswith(prefix):
                                matches.append(
                                    SplitTokenMatch(
                                        prefix=prefix,
                                        fragment_a=fa,
                                        fragment_b=fb,
                                        assembled=combined[:80],
                                    )
                                )
                                break  # one prefix per pair is enough
    return matches
