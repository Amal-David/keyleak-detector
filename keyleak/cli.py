"""Command-line interface for KeyLeak Detector."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Dict, List, Optional

import requests

from pathlib import Path

from .detectors import DETECTOR_PACKS, normalize_packs
from .local_scanner import DEFAULT_INCLUDES, scan_path
from .models import ScanReport
from .reporting import (
    build_report,
    fail_threshold_met,
    format_html,
    format_json,
    format_markdown,
    format_sarif,
    report_to_text,
)
from .offline_guard import install_socket_block, print_egress_banner
from .self_audit import run_self_audit
from .suppressions import apply_suppressions


DEFAULT_SERVER = "http://127.0.0.1:5002"


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if getattr(args, "offline", False):
        install_socket_block()
        print_egress_banner()

    if args.command == "local":
        try:
            packs = normalize_packs(_split_optional_csv(args.packs), profile=args.launch_profile)
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 1
        report = scan_path(args.path, includes=_split_includes(args.include), profile=args.launch_profile, packs=packs)
        return _emit_report(report, args)

    if args.command == "scan":
        try:
            report = _scan_url(args)
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 1
        except requests.RequestException as exc:
            print(
                f"Unable to reach KeyLeak web scanner at {args.server}: {exc}\n"
                "Start it with `poetry run python app.py` or `docker compose up -d`.",
                file=sys.stderr,
            )
            return 1
        return _emit_report(report, args)

    if args.command == "self-audit":
        repo_root = Path(getattr(args, "path", ".") or ".").resolve()
        report = run_self_audit(repo_root)
        return _emit_report(report, args)

    if args.command == "explain":
        from .detectors import find_detector
        import json as _json

        canonical_id = args.detector_id
        if not canonical_id:
            print("explain requires a detector canonical_id (e.g. leak.openai_api_key)", file=sys.stderr)
            return 1
        detector = find_detector(canonical_id)
        if detector is None:
            print(f"unknown detector: {canonical_id}", file=sys.stderr)
            return 1
        card = detector.get_remediation().to_dict()
        if getattr(args, "json", False):
            print(_json.dumps(card, indent=2, sort_keys=True))
        else:
            lines = [
                f"# KeyLeak Remediation: {canonical_id}",
                "",
                f"**What leaked**: {card['what_leaked']}",
                "",
                f"**Why it matters**: {card['why_it_matters']}",
                "",
                "**Fix steps**:",
            ]
            for index, step in enumerate(card["fix_steps"] or ["(no steps documented)"], start=1):
                lines.append(f"  {index}. {step}")
            if card["verify_command"]:
                lines.extend(["", f"**Verify**: `{card['verify_command']}`"])
            print("\n".join(lines))
        return 0

    if args.command == "diff":
        from .diff import diff_reports, load_report

        try:
            baseline = load_report(Path(args.baseline_report))
            current = load_report(Path(args.current_report))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"Could not load reports: {exc}", file=sys.stderr)
            return 1
        report = diff_reports(baseline, current)
        return _emit_report(report, args)

    if args.command == "feed":
        from .feeds import build_manifest, query_osv_malicious
        import json as _json

        if args.feed_command == "sync":
            try:
                entries = query_osv_malicious(ecosystem=args.ecosystem)
            except Exception as exc:
                print(f"feed sync failed: {exc}", file=sys.stderr)
                return 1
            document = build_manifest(entries)
            out_path = Path(args.out) if args.out else None
            if out_path:
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_text(_json.dumps(document, indent=2, sort_keys=True), encoding="utf-8")
                print(f"Wrote {out_path} ({len(entries)} entries)")
            else:
                print(_json.dumps(document, indent=2, sort_keys=True))
            return 0
        print("Unknown feed command", file=sys.stderr)
        return 1

    if args.command == "archive":
        from .archive_scanner import scan_archive, ArchiveScanError
        import json as _json

        try:
            envelope = scan_archive(
                args.archive,
                as_of=args.as_of or None,
                profile=args.launch_profile,
                signer=args.signer,
                prev_hash=args.prev_hash,
            )
        except ArchiveScanError as exc:
            print(f"archive scan failed: {exc}", file=sys.stderr)
            return 1
        if args.out:
            Path(args.out).write_text(_json.dumps(envelope, indent=2, sort_keys=True), encoding="utf-8")
            print(f"Wrote {args.out}")
        else:
            print(_json.dumps(envelope, indent=2, sort_keys=True))
        from .reporting import fail_threshold_met
        from .models import ScanReport as _ScanReport
        report = _ScanReport.from_dict(envelope.get("report") or {})
        return 2 if fail_threshold_met(report, args.fail_on) else 0

    if args.command == "watch":
        from .watch import cli_main as watch_main

        return watch_main(args)

    if args.command == "doctor":
        from .doctor import cli_main as doctor_main

        return doctor_main(args)

    if args.command == "demo":
        from .demo import cli_main as demo_main

        return demo_main(args)

    if args.command == "browser-scan":
        try:
            from .browser_scanner import run_browser_scan
        except ImportError as exc:
            print(f"browser-scan requires Playwright: {exc}", file=sys.stderr)
            return 1
        try:
            extra_tables = _split_optional_csv(args.baas_tables)
            report = run_browser_scan(
                args.url,
                auth_state_path=args.auth_state or None,
                scan_budget_seconds=int(args.scan_budget),
                headless=not args.headed,
                baas_validate=args.baas_validate,
                baas_tables=extra_tables,
            )
        except Exception as exc:
            print(f"browser-scan failed: {exc}", file=sys.stderr)
            return 1
        return _emit_report(report, args)

    if args.command == "site-scan":
        try:
            from .site_scanner import scan_site
        except ImportError as exc:
            print(f"site-scan requires Playwright: {exc}", file=sys.stderr)
            return 1
        try:
            extra_tables = _split_optional_csv(args.baas_tables)
            report = scan_site(
                args.domain,
                depth=int(args.depth),
                max_pages=int(args.max_pages),
                max_subdomains=int(args.max_subdomains),
                headless=not args.headed,
                baas_validate=args.baas_validate,
                baas_tables=extra_tables,
                scan_budget_seconds=int(args.scan_budget),
                launch_profile=args.launch_profile,
                offline=getattr(args, "offline", False),
            )
        except Exception as exc:
            print(f"site-scan failed: {exc}", file=sys.stderr)
            return 1
        return _emit_report(report, args)

    if args.command == "disclose":
        from .disclose import cli as disclose_cli

        return disclose_cli(args)

    if args.command == "allowlist-diff":
        from .allowlist_diff import audit_pr_diff

        try:
            base_text = ""
            if args.base_allowlist and args.base_allowlist != "/dev/null":
                base_text = Path(args.base_allowlist).read_text(encoding="utf-8")
            head_text = Path(args.head_allowlist).read_text(encoding="utf-8")
            changed = [
                Path(line.strip())
                for line in Path(args.changed_files).read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
        except OSError as exc:
            print(f"Unable to read allowlist-diff inputs: {exc}", file=sys.stderr)
            return 1
        report = audit_pr_diff(Path(args.repo_root), base_text, head_text, changed)
        return _emit_report(report, args)

    parser.print_help()
    return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="keyleak",
        description="Local runtime leak detector for modern web apps.",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Refuse any outbound socket. Only loopback connections allowed.",
    )
    parser.add_argument(
        "--no-default-suppressions",
        action="store_true",
        help=(
            "Disable the built-in fixture-path suppressions "
            "(.env.example, /fixtures/, /tests/, docker-compose.yml, etc.). "
            "Default is to suppress; use this flag to see EVERY finding."
        ),
    )
    subparsers = parser.add_subparsers(dest="command")

    scan = subparsers.add_parser("scan", help="Scan a running web app through the local KeyLeak web scanner.")
    scan.add_argument("url")
    scan.add_argument("--server", default=DEFAULT_SERVER)
    scan.add_argument("--profile", default="browser", choices=["browser", "authenticated"])
    scan.add_argument("--launch-profile", default="launch-gate", choices=["launch-gate", "local-dev", "bug-bounty", "ci", "full"])
    scan.add_argument("--packs", default="", help=f"Comma-separated detector packs. Available: {', '.join(DETECTOR_PACKS)}")
    scan.add_argument("--bearer", default="")
    scan.add_argument("--cookie", default="")
    scan.add_argument("--bearer-b", default="", help="Second throwaway user's bearer token for access-control comparison.")
    scan.add_argument("--cookie-b", default="", help="Second throwaway user's cookie for access-control comparison.")
    scan.add_argument("--fail-on", default="high", choices=["low", "medium", "high", "critical"])
    scan.add_argument("--baseline", default="", help="Suppress findings already present in a previous KeyLeak JSON report.")
    scan.add_argument("--allowlist", default="", help="Suppress known findings from a JSON or line-based allowlist.")
    _add_format_flags(scan)

    local = subparsers.add_parser("local", help="Scan local files for secrets, MCP configs, source maps, and CI leaks.")
    local.add_argument("path")
    local.add_argument("--include", default=",".join(DEFAULT_INCLUDES))
    local.add_argument("--launch-profile", default="launch-gate", choices=["launch-gate", "local-dev", "bug-bounty", "ci", "full"])
    local.add_argument("--packs", default="", help=f"Comma-separated detector packs. Available: {', '.join(DETECTOR_PACKS)}")
    local.add_argument("--fail-on", default="high", choices=["low", "medium", "high", "critical"])
    local.add_argument("--baseline", default="", help="Suppress findings already present in a previous KeyLeak JSON report.")
    local.add_argument("--allowlist", default="", help="Suppress known findings from a JSON or line-based allowlist.")
    _add_format_flags(local)

    self_audit = subparsers.add_parser(
        "self-audit",
        help="Audit KeyLeak's own repo for supply-chain hygiene (tag pins, dangerous triggers, lockfile, CODEOWNERS).",
    )
    self_audit.add_argument("path", nargs="?", default=".")
    self_audit.add_argument("--fail-on", default="high", choices=["low", "medium", "high", "critical"])
    self_audit.add_argument("--baseline", default="")
    self_audit.add_argument("--allowlist", default="")
    _add_format_flags(self_audit)

    explain = subparsers.add_parser(
        "explain",
        help="Print the structured Remediation card for a detector (Wave 1.6 contract).",
    )
    explain.add_argument("detector_id", help="canonical id, e.g. leak.openai_api_key")
    explain.add_argument("--json", action="store_true", help="Emit the card as JSON.")

    diff_cmd = subparsers.add_parser(
        "diff",
        help="Surface findings new in <current> relative to <baseline>. (Wave 3.3)",
    )
    diff_cmd.add_argument("baseline_report", help="Path to baseline JSON or SARIF report.")
    diff_cmd.add_argument("current_report", help="Path to current JSON or SARIF report.")
    diff_cmd.add_argument("--fail-on", default="high", choices=["low", "medium", "high", "critical"])
    diff_cmd.add_argument("--baseline", default="")
    diff_cmd.add_argument("--allowlist", default="")
    _add_format_flags(diff_cmd)

    feed = subparsers.add_parser(
        "feed",
        help="Manage the signed IOC feed (Wave 3.2).",
    )
    feed_sub = feed.add_subparsers(dest="feed_command")
    feed_sync = feed_sub.add_parser("sync", help="Pull OSV.dev MAL- advisories and emit a signed manifest.")
    feed_sync.add_argument("--ecosystem", default="npm", help="OSV ecosystem to query (npm, PyPI, Maven, ...).")
    feed_sync.add_argument("--out", default="", help="Write the manifest here. Default: keyleak/data/ioc_feed.json.")

    archive = subparsers.add_parser(
        "archive",
        help="Scan a deployment archive (tar/zip/dir) and emit a chain-of-custody envelope (Wave 3.1).",
    )
    archive.add_argument("archive", help="Path to a .tar.gz / .zip / directory.")
    archive.add_argument("--as-of", default="", help="Optional deploy timestamp to embed in the envelope.")
    archive.add_argument("--launch-profile", default="ci", choices=["launch-gate", "local-dev", "bug-bounty", "ci", "full"])
    archive.add_argument("--signer", default="anonymous")
    archive.add_argument("--prev-hash", default="", help="self_hash of the previous envelope in the chain.")
    archive.add_argument("--out", default="", help="Write the envelope to this file instead of stdout.")
    archive.add_argument("--fail-on", default="high", choices=["low", "medium", "high", "critical"])

    watch_cmd = subparsers.add_parser(
        "watch",
        help="Debounced incremental scan on file save; emits SARIF for VS Code (Wave 3.8).",
    )
    watch_cmd.add_argument("path", nargs="?", default=".")
    watch_cmd.add_argument("--out", default="", help="Path to SARIF output; default .keyleak/findings.sarif.")
    watch_cmd.add_argument("--interval", default="0.5", help="Poll interval in seconds.")
    watch_cmd.add_argument("--iterations", default="0", help="Cap iterations (0 = forever).")

    doctor = subparsers.add_parser(
        "doctor",
        help="Run env checks (Python, Playwright, mitmproxy, Node, network, allowlist).",
    )
    doctor.add_argument("--json", action="store_true")

    site_scan = subparsers.add_parser(
        "site-scan",
        help=(
            "Full Site Scan: enumerate subdomains (crt.sh + DNS) and crawl every page of a "
            "domain for secrets and BaaS misconfigurations. Authorized targets only."
        ),
    )
    site_scan.add_argument("domain", help="Domain or URL to scan (e.g., example.com)")
    site_scan.add_argument("--depth", default="3", help="Link crawl depth per host (default: 3).")
    site_scan.add_argument("--max-pages", default="100", help="Maximum pages to scan (default: 100).")
    site_scan.add_argument("--max-subdomains", default="25", help="Maximum subdomains to scan (default: 25).")
    site_scan.add_argument("--launch-profile", default="launch-gate", choices=["launch-gate", "local-dev", "bug-bounty", "ci", "full"])
    site_scan.add_argument("--scan-budget", default="30", help="Per-page timeout in seconds.")
    site_scan.add_argument("--headed", action="store_true", help="Show browser windows.")
    site_scan.add_argument("--baas-validate", action="store_true", help="Enable active BaaS validation probes.")
    site_scan.add_argument("--baas-tables", default="", help="Extra table names to probe.")
    site_scan.add_argument("--fail-on", default="high", choices=["low", "medium", "high", "critical"])
    site_scan.add_argument("--baseline", default="")
    site_scan.add_argument("--allowlist", default="")
    _add_format_flags(site_scan)

    demo = subparsers.add_parser(
        "demo",
        help="Scan the bundled vulnerable fixture and print a remediation report.",
    )
    demo.add_argument("--path", default="", help="Override the fixture path.")
    demo.add_argument("--markdown", action="store_true")

    browser_scan = subparsers.add_parser(
        "browser-scan",
        help="Headless Playwright runner that injects the analyzer and scans live SPAs (Wave 2.4).",
    )
    browser_scan.add_argument("url")
    browser_scan.add_argument("--auth-state", default="", help="Path to Playwright storageState.json for authenticated scans.")
    browser_scan.add_argument("--scan-budget", default="30", help="Per-page timeout in seconds.")
    browser_scan.add_argument("--headed", action="store_true", help="Show the browser window (debugging).")
    browser_scan.add_argument("--baas-validate", action="store_true", help="Enable active BaaS (Supabase/Firebase) validation probes against detected endpoints.")
    browser_scan.add_argument("--baas-tables", default="", help="Comma-separated extra table names to probe during BaaS validation.")
    browser_scan.add_argument("--fail-on", default="high", choices=["low", "medium", "high", "critical"])
    browser_scan.add_argument("--baseline", default="")
    browser_scan.add_argument("--allowlist", default="")
    _add_format_flags(browser_scan)

    disclose = subparsers.add_parser(
        "disclose",
        help="Emit a signed disclosure packet for a third-party-credential finding.",
    )
    disclose.add_argument("finding_id", help="Finding.id from a KeyLeak JSON report.")
    disclose.add_argument("--from-report", required=True, help="Path to keyleak JSON report.")
    disclose.add_argument("--out", default="", help="Write to this file instead of stdout.")
    disclose.add_argument("--reporter", default="anonymous", help="Reporter handle to embed in the packet.")
    disclose.add_argument(
        "--signature-mode",
        default="hmac-sha256",
        choices=["none", "hmac-sha256", "cosign"],
        help="hmac-sha256 requires KEYLEAK_DISCLOSE_KEY; cosign requires the cosign binary.",
    )

    allowlist_diff = subparsers.add_parser(
        "allowlist-diff",
        help="Provenance gate: detect a PR that ships a payload and an allowlist entry suppressing it in the same diff.",
    )
    allowlist_diff.add_argument("--repo-root", default=".")
    allowlist_diff.add_argument("--base-allowlist", required=True)
    allowlist_diff.add_argument("--head-allowlist", required=True)
    allowlist_diff.add_argument("--changed-files", required=True)
    allowlist_diff.add_argument("--fail-on", default="critical", choices=["low", "medium", "high", "critical"])
    allowlist_diff.add_argument("--baseline", default="")
    allowlist_diff.add_argument("--allowlist", default="")
    _add_format_flags(allowlist_diff)

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
    bearer_b = (getattr(args, "bearer_b", "") or "").strip()
    cookie_b = (getattr(args, "cookie_b", "") or "").strip()
    auth_config: Dict[str, Any] = {"mode": "none"}
    scan_mode = "basic"
    if bearer or cookie or args.profile == "authenticated":
        scan_mode = "extensive"
        auth_config = {
            "mode": "both" if bearer and cookie else "bearer" if bearer else "cookie" if cookie else "none",
            "bearer_token": bearer,
            "cookie": cookie,
        }
    payload = {
        "url": args.url,
        "scan_mode": scan_mode,
        "auth_config": auth_config,
        "launch_profile": getattr(args, "launch_profile", "launch-gate"),
        "packs": normalize_packs(
            _split_optional_csv(getattr(args, "packs", "")),
            profile=getattr(args, "launch_profile", "launch-gate"),
            surface="web",
        ),
    }
    if bearer_b or cookie_b:
        payload["comparison_auth_config"] = {
            "mode": "both" if bearer_b and cookie_b else "bearer" if bearer_b else "cookie",
            "bearer_token": bearer_b,
            "cookie": cookie_b,
        }
    return payload


def _emit_report(report, args: argparse.Namespace) -> int:
    try:
        report = apply_suppressions(
            report,
            baseline_path=getattr(args, "baseline", ""),
            allowlist_path=getattr(args, "allowlist", ""),
            apply_defaults=not getattr(args, "no_default_suppressions", False),
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
    elif getattr(args, "html", False):
        print(format_html(report))
    else:
        print(report_to_text(report))

    return 2 if fail_threshold_met(report, args.fail_on) else 0


def _add_format_flags(parser: argparse.ArgumentParser) -> None:
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--json", action="store_true", help="Emit KeyLeak JSON report.")
    group.add_argument("--sarif", action="store_true", help="Emit SARIF 2.1.0 report.")
    group.add_argument("--markdown", action="store_true", help="Emit Markdown report.")
    group.add_argument("--html", action="store_true", help="Emit self-contained HTML report.")


def _split_includes(value: str):
    return [part.strip() for part in value.split(",") if part.strip()]


def _split_optional_csv(value: str):
    if not value:
        return None
    return [part.strip() for part in value.split(",") if part.strip()]


if __name__ == "__main__":
    raise SystemExit(main())
