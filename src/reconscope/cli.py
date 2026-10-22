"""Command-line interface for reconscope.

Two subcommands:

* ``validate-scope`` loads a scope file and prints what it authorizes, without touching the
  network -- a safe way to review an engagement before running it;
* ``scan`` runs the enumeration against the authorized targets and writes JSON and/or HTML.

Both start from a scope file, which is the only thing that grants authority to scan anything.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from . import __version__
from .report import to_html, to_json
from .scanner import ScanConfig, run_scan
from .scope import Scope, ScopeError, expand_targets

_AUTHORIZED_USE = (
    "reconscope sends traffic only to hosts your scope file authorizes. "
    "Scanning systems you do not have explicit written permission to test may be illegal."
)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="reconscope",
        description="Scope-bounded network and service enumeration for authorized assessments.",
        epilog=_AUTHORIZED_USE,
    )
    parser.add_argument("--version", action="version", version=f"reconscope {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    validate = sub.add_parser("validate-scope", help="Load a scope file and print what it allows.")
    validate.add_argument("scope", type=Path, help="Path to the YAML scope file.")

    scan = sub.add_parser("scan", help="Enumerate the authorized targets.")
    scan.add_argument("--scope", type=Path, required=True, help="Path to the YAML scope file.")
    scan.add_argument(
        "targets",
        nargs="*",
        help="Hosts or networks to scan (must be in scope). Defaults to every allowed host.",
    )
    scan.add_argument("--json", type=Path, dest="json_out", help="Write the JSON report to this path.")
    scan.add_argument("--html", type=Path, dest="html_out", help="Write the HTML report to this path.")
    scan.add_argument("--timeout", type=float, default=3.0, help="Per-connection timeout (seconds).")
    return parser


def _cmd_validate(scope_path: Path) -> int:
    scope = Scope.from_file(scope_path)
    summary = scope.summary()
    print(f"Scope OK: {scope_path}")
    print(f"  Authorization : {summary['authorization']}")
    print(f"  Allowed names : {', '.join(summary['allow_names']) or '(none)'}")
    print(f"  Allowed nets  : {', '.join(summary['allow_networks']) or '(none)'}")
    print(f"  Denied        : {', '.join(summary['deny_names'] + summary['deny_networks']) or '(none)'}")
    print(f"  Ports in scope: {summary['ports_in_scope']}")
    print(
        f"  Rate          : {summary['rate']['max_concurrency']} concurrent, "
        f"{summary['rate']['requests_per_second']}/s"
    )
    return 0


def _print_summary(report_counts: dict[str, int], host_count: int, refused: int) -> None:
    print(
        f"Scanned {host_count} host(s); "
        f"findings: high={report_counts['high']} medium={report_counts['medium']} "
        f"low={report_counts['low']} info={report_counts['info']}; "
        f"{refused} target(s) refused as out of scope.",
        file=sys.stderr,
    )


def _cmd_scan(args: argparse.Namespace) -> int:
    scope = Scope.from_file(args.scope)
    raw_targets = args.targets or scope.default_targets()
    targets = expand_targets(raw_targets)
    if not targets:
        print("No targets to scan.", file=sys.stderr)
        return 2

    print(_AUTHORIZED_USE, file=sys.stderr)
    report = asyncio.run(run_scan(scope, targets, ScanConfig(timeout=args.timeout)))

    if args.json_out:
        args.json_out.write_text(to_json(report), encoding="utf-8")
        print(f"Wrote {args.json_out}", file=sys.stderr)
    if args.html_out:
        args.html_out.write_text(to_html(report), encoding="utf-8")
        print(f"Wrote {args.html_out}", file=sys.stderr)
    if not args.json_out and not args.html_out:
        print(to_json(report))

    _print_summary(report.finding_counts(), len(report.hosts), len(report.refused))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "validate-scope":
            return _cmd_validate(args.scope)
        if args.command == "scan":
            return _cmd_scan(args)
    except ScopeError as exc:
        print(f"Scope error: {exc}", file=sys.stderr)
        return 2
    except FileNotFoundError as exc:
        print(f"File not found: {exc.filename}", file=sys.stderr)
        return 2
    return 1  # pragma: no cover - argparse requires a subcommand


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
