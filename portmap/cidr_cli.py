"""CLI sub-command for CIDR-based filtering and summarisation."""

from __future__ import annotations

import argparse
import json
import sys
from typing import List

from portmap.cidr import CIDRFilter, apply_filter, summarise
from portmap.scanner import PortEntry, scan_ports


def build_cidr_parser(sub: argparse._SubParsersAction) -> argparse.ArgumentParser:  # type: ignore[type-arg]
    p = sub.add_parser("cidr", help="Filter scan results by CIDR range")
    p.add_argument("--allow", metavar="CIDR", nargs="*", default=[],
                   help="Only include hosts within these CIDR blocks")
    p.add_argument("--deny", metavar="CIDR", nargs="*", default=[],
                   help="Exclude hosts within these CIDR blocks")
    p.add_argument("--summarise", action="store_true",
                   help="Print per-prefix entry counts instead of full table")
    p.add_argument("--format", choices=["text", "json"], default="text")
    p.add_argument("--ports", metavar="PORTS", default=None,
                   help="Port range to scan, e.g. 1-1024")
    return p


def _render_text(entries: List[PortEntry]) -> str:
    if not entries:
        return "No matching entries."
    lines = [f"{e.host}:{e.port}/{e.protocol}  {e.label()}" for e in entries]
    return "\n".join(lines)


def _render_json(entries: List[PortEntry]) -> str:
    rows = [
        {"host": e.host, "port": e.port, "protocol": e.protocol,
         "label": e.label(), "status": e.status}
        for e in entries
    ]
    return json.dumps(rows, indent=2)


def run_cidr(args: argparse.Namespace, entries: List[PortEntry] | None = None) -> int:
    if entries is None:
        ports = None
        if args.ports:
            lo, _, hi = args.ports.partition("-")
            ports = (int(lo), int(hi)) if hi else (int(lo), int(lo))
        entries = scan_ports(port_range=ports)

    try:
        cidr_filter = CIDRFilter(allow=args.allow, deny=args.deny)
    except ValueError as exc:
        print(f"Invalid CIDR: {exc}", file=sys.stderr)
        return 1

    filtered = apply_filter(entries, cidr_filter)

    if args.summarise:
        summary = summarise(filtered)
        if args.format == "json":
            print(json.dumps(summary, indent=2))
        else:
            for prefix, count in sorted(summary.items()):
                print(f"{prefix}  {count} entry/entries")
        return 0

    if args.format == "json":
        print(_render_json(filtered))
    else:
        print(_render_text(filtered))
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(prog="portmap-cidr")
    sub = parser.add_subparsers(dest="command")
    build_cidr_parser(sub)
    args = parser.parse_args()
    if args.command is None:
        parser.print_help()
        sys.exit(0)
    sys.exit(run_cidr(args))


if __name__ == "__main__":  # pragma: no cover
    main()
