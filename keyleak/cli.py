"""Command-line interface for KeyLeak Detector."""

from __future__ import annotations

import argparse
import sys
from typing import Any, Dict, List, Optional

import requests

from .local_scanner import DEFAULT_INCLUDES, scan_path
from .models import ScanReport
from .reporting import (
    build_report,
    fail_threshold_met,
    format_json,
    format_markdown,
    format_sarif,
    report_to_text,
)
from .suppressions import apply_suppressions


DEFAULT_SERVER = "http://127.0.0.1:5002"


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "local":
        report = scan_path(args.path, includes=_split_includes(args.include))
        return _emit_report(report, args)

    if args.command == "scan":
        try:
            report = _scan_url(args)
        except requests.RequestException as exc:
            print(
                f"Unable to reach KeyLeak web scanner at {args.server}: {exc}\n"
                "Start it with `poetry run python app.py` or `docker compose up -d`.",
                file=sys.stderr,
            )
            return 1
        return _emit_report(report, args)

    parser.print_help()
    return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="keyleak",
        description="Local runtime leak detector for modern web apps.",
    )
    subparsers = parser.add_subparsers(dest="command")

    scan = subparsers.add_parser("scan", help="Scan a running web app through the local KeyLeak web scanner.")
    scan.add_argument("url")
    scan.add_argument("--server", default=DEFAULT_SERVER)
    scan.add_argument("--profile", default="browser", choices=["browser", "authenticated"])
    scan.add_argument("--bearer", default="")
    scan.add_argument("--cookie", default="")
    scan.add_argument("--fail-on", default="high", choices=["low", "medium", "high", "critical"])
    scan.add_argument("--baseline", default="", help="Suppress findings already present in a previous KeyLeak JSON report.")
    scan.add_argument("--allowlist", default="", help="Suppress known findings from a JSON or line-based allowlist.")
    _add_format_flags(scan)

    local = subparsers.add_parser("local", help="Scan local files for secrets, MCP configs, source maps, and CI leaks.")
    local.add_argument("path")
    local.add_argument("--include", default=",".join(DEFAULT_INCLUDES))
    local.add_argument("--fail-on", default="high", choices=["low", "medium", "high", "critical"])
    local.add_argument("--baseline", default="", help="Suppress findings already present in a previous KeyLeak JSON report.")
    local.add_argument("--allowlist", default="", help="Suppress known findings from a JSON or line-based allowlist.")
    _add_format_flags(local)

    return parser


def _scan_url(args: argparse.Namespace):
    payload = _scan_request_payload(args)
    response = requests.post(
        f"{args.server.rstrip('/')}/scan",
        json=payload,
        timeout=900,
    )
    response.raise_for_status()
    data = response.json()
    if isinstance(data.get("report"), dict):
        return ScanReport.from_dict(data["report"])
    return build_report(
        args.url,
        data.get("findings", []),
        scan_mode=data.get("scan_mode", args.profile),
        attack_vectors=data.get("attack_vectors"),
    )


def _scan_request_payload(args: argparse.Namespace) -> Dict[str, Any]:
    bearer = (args.bearer or "").strip()
    cookie = (args.cookie or "").strip()
    auth_config: Dict[str, Any] = {"mode": "none"}
    scan_mode = "basic"
    if bearer or cookie or args.profile == "authenticated":
        scan_mode = "extensive"
        auth_config = {
            "mode": "both" if bearer and cookie else "bearer" if bearer else "cookie" if cookie else "none",
            "bearer_token": bearer,
            "cookie": cookie,
        }
    return {"url": args.url, "scan_mode": scan_mode, "auth_config": auth_config}


def _emit_report(report, args: argparse.Namespace) -> int:
    try:
        report = apply_suppressions(
            report,
            baseline_path=getattr(args, "baseline", ""),
            allowlist_path=getattr(args, "allowlist", ""),
        )
    except (OSError, ValueError) as exc:
        print(f"Unable to load suppression file: {exc}", file=sys.stderr)
        return 1

    if getattr(args, "json", False):
        print(format_json(report))
    elif getattr(args, "sarif", False):
        print(format_sarif(report))
    elif getattr(args, "markdown", False):
        print(format_markdown(report))
    else:
        print(report_to_text(report))

    return 2 if fail_threshold_met(report, args.fail_on) else 0


def _add_format_flags(parser: argparse.ArgumentParser) -> None:
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--json", action="store_true", help="Emit KeyLeak JSON report.")
    group.add_argument("--sarif", action="store_true", help="Emit SARIF 2.1.0 report.")
    group.add_argument("--markdown", action="store_true", help="Emit Markdown report.")


def _split_includes(value: str):
    return [part.strip() for part in value.split(",") if part.strip()]


if __name__ == "__main__":
    raise SystemExit(main())
