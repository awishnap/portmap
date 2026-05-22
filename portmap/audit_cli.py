"""CLI sub-commands for the audit log (list, clear)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from portmap.audit import DEFAULT_AUDIT_PATH, clear_log, read_log


def build_audit_parser(sub: "argparse._SubParsersAction") -> argparse.ArgumentParser:  # type: ignore[type-arg]
    p = sub.add_parser("audit", help="View or manage the portmap audit log")
    p.add_argument(
        "--log",
        metavar="FILE",
        default=str(DEFAULT_AUDIT_PATH),
        help="Path to audit log (default: %(default)s)",
    )
    cmds = p.add_subparsers(dest="audit_cmd")

    lst = cmds.add_parser("list", help="Print audit log entries")
    lst.add_argument("--event", metavar="TYPE", help="Filter by event type (scan|alert)")
    lst.add_argument("--json", dest="as_json", action="store_true", help="Output as JSON array")

    cmds.add_parser("clear", help="Delete the audit log")
    return p


def run_audit(args: argparse.Namespace) -> int:
    log_path = Path(args.log)

    if args.audit_cmd == "clear":
        clear_log(log_path)
        print(f"Audit log cleared: {log_path}")
        return 0

    # default: list
    entries = read_log(log_path)
    if hasattr(args, "event") and args.event:
        entries = [e for e in entries if e.get("event") == args.event]

    if not entries:
        print("No audit entries found.")
        return 0

    if getattr(args, "as_json", False):
        print(json.dumps(entries, indent=2))
    else:
        for e in entries:
            ts = e.get("ts", "?")
            event = e.get("event", "?")
            detail = {k: v for k, v in e.items() if k not in ("ts", "event")}
            detail_str = "  ".join(f"{k}={v}" for k, v in detail.items())
            print(f"[{ts}] {event.upper():6s}  {detail_str}")
    return 0


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="portmap-audit")
    sub = parser.add_subparsers(dest="audit_cmd")
    build_audit_parser(sub)  # registers nested sub-commands under a flat parser for standalone use

    # Simpler standalone invocation: portmap-audit list / portmap-audit clear
    parser.add_argument("--log", metavar="FILE", default=str(DEFAULT_AUDIT_PATH))
    parser.add_argument("--event", metavar="TYPE")
    parser.add_argument("--json", dest="as_json", action="store_true")
    cmds = parser.add_subparsers(dest="audit_cmd")
    cmds.add_parser("list")
    cmds.add_parser("clear")

    args = parser.parse_args(argv)
    if args.audit_cmd is None:
        parser.print_help()
        sys.exit(0)
    sys.exit(run_audit(args))


if __name__ == "__main__":  # pragma: no cover
    main()
