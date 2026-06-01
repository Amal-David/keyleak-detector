"""`keyleak demo` — first-finding-in-60-seconds onboarding.

Runs ``keyleak local`` against the bundled vulnerable fixture
(``fixtures/vulnerable-demo/``) and prints a redacted Markdown report. The
goal is "pip install → first real finding" without the user having to point
KeyLeak at their own repo.
"""

from __future__ import annotations

import sys
from pathlib import Path

from .local_scanner import scan_path
from .reporting import format_markdown, report_to_text


FIXTURE_PATH = Path(__file__).resolve().parent.parent / "fixtures" / "vulnerable-demo"


def cli_main(args) -> int:
    target = Path(getattr(args, "path", "") or FIXTURE_PATH)
    if not target.is_dir():
        print(
            f"demo fixture not found at {target}.\n"
            "Pass --path to point at any directory you want to demo against.",
            file=sys.stderr,
        )
        return 1

    print(f"KeyLeak demo: scanning {target}\n")
    report = scan_path(str(target), profile="ci")
    if getattr(args, "markdown", False):
        print(format_markdown(report))
    else:
        print(report_to_text(report))
        print()
        print(
            "Next steps:\n"
            "  - `keyleak local . --launch-profile ci --fail-on high` against your own repo.\n"
            "  - `keyleak self-audit .` to harden the launch-gate workflow itself.\n"
            "  - `keyleak explain <detector_id>` to see remediation guidance.\n"
        )
    return 0
