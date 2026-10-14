"""Explicit-consent policy for optional external-tool installation.

This module does not install anything or infer consent from the environment.
Packagers can set KEYLEAK_MANAGED_INSTALL=1 to veto runtime installation;
KEYLEAK_NO_AUTO_INSTALL retains the existing operator opt-out.
"""

from __future__ import annotations

import argparse
import os
from collections.abc import Mapping

_FALSE_VALUES = frozenset({"", "0", "false", "no", "off"})


def tool_install_allowed(
    *, requested: bool = False, environ: Mapping[str, str] | None = None
) -> bool:
    """Require explicit consent and honor both environment vetoes.

    Unknown nonempty veto values disable installation too. A misspelled
    packager setting must not silently enable installation. This is a
    configuration policy, not a sandbox against an operator changing it.
    """
    if requested is not True:
        return False
    settings = os.environ if environ is None else environ
    return all(
        settings.get(name, "").strip().lower() in _FALSE_VALUES
        for name in ("KEYLEAK_NO_AUTO_INSTALL", "KEYLEAK_MANAGED_INSTALL")
    )


def add_tool_install_flags(parser: argparse.ArgumentParser) -> None:
    """Keep the legacy no_auto_install field, but make consent opt-in."""
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--auto-install",
        dest="no_auto_install",
        action="store_false",
        help=(
            "Allow installation of missing subfinder (off by default). "
            "KEYLEAK_NO_AUTO_INSTALL=1 or KEYLEAK_MANAGED_INSTALL=1 vetoes this."
        ),
    )
    group.add_argument(
        "--no-auto-install",
        dest="no_auto_install",
        action="store_true",
        help=(
            "Never install subfinder (the default); use available discovery "
            "tools and crt.sh + DNS."
        ),
    )
    # Explicitly set this after both actions; store_false otherwise supplies
    # an implicit default of True and future action reordering can be subtle.
    parser.set_defaults(no_auto_install=True)
