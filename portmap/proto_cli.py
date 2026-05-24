"""CLI sub-command: portmap proto — show protocol info for ports."""
from __future__ import annotations

import argparse
import json
import sys
from typing import List

from portmap.proto import ProtoInfo, identify


def build_proto_parser(sub: argparse._SubParsersAction) -> argparse.ArgumentParser:  # type: ignore[type-arg]
    p = sub.add_parser("proto", help="Identify application-layer protocols for given ports")
    p.add_argument(
        "ports",
        nargs="+",
        type=int,
        metavar="PORT",
        help="One or more port numbers to identify",
    )
    p.add_argument(
        "--transport",
        default="tcp",
        choices=["tcp", "udp"],
        help="Transport layer (default: tcp)",
    )
    p.add_argument(
        "--format",
        dest="fmt",
        default="text",
        choices=["text", "json"],
        help="Output format (default: text)",
    )
    return p


def _render_text(results: List[ProtoInfo]) -> str:
    if not results:
        return "No results."
    header = f"{'PORT':<8} {'TRANSPORT':<10} {'PROTOCOL':<20} {'ENCRYPTED'}"
    sep = "-" * len(header)
    rows = [header, sep]
    for r in results:
        enc = "yes" if r.encrypted is True else ("no" if r.encrypted is False else "?")
        proto = r.app_proto or "unknown"
        rows.append(f"{r.port:<8} {r.transport:<10} {proto:<20} {enc}")
    return "\n".join(rows)


def _render_json(results: List[ProtoInfo]) -> str:
    data = [
        {
            "port": r.port,
            "transport": r.transport,
            "app_proto": r.app_proto,
            "encrypted": r.encrypted,
            "display": r.display(),
        }
        for r in results
    ]
    return json.dumps(data, indent=2)


def run_proto(args: argparse.Namespace) -> None:
    results = [identify(p, args.transport) for p in args.ports]
    if args.fmt == "json":
        print(_render_json(results))
    else:
        print(_render_text(results))


def main() -> None:  # pragma: no cover
    parser = argparse.ArgumentParser(prog="portmap-proto")
    sub = parser.add_subparsers(dest="cmd")
    build_proto_parser(sub)
    args = parser.parse_args()
    if args.cmd is None:
        parser.print_help()
        sys.exit(1)
    run_proto(args)
