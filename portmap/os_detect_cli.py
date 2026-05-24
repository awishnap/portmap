"""CLI interface for OS detection."""
from __future__ import annotations

import argparse
import json
import sys

from portmap.os_detect import OSResult, enrich
from portmap.scanner import scan_ports


def build_os_parser(sub: argparse._SubParsersAction) -> argparse.ArgumentParser:  # type: ignore[type-arg]
    p = sub.add_parser("os", help="Guess OS for hosts on open ports")
    p.add_argument("--ports", default=None, help="Comma-separated port list")
    p.add_argument("--timeout", type=float, default=1.0, help="Per-port timeout")
    p.add_argument("--format", choices=["text", "json"], default="text")
    return p


def _render_text(results: list[OSResult]) -> str:
    if not results:
        return "No results."
    lines = [f"{'PORT':<8} {'PROTO':<6} {'OS GUESS'}",
             "-" * 40]
    for r in results:
        lines.append(
            f"{r.entry.port:<8} {r.entry.protocol:<6} {r.display()}"
        )
    return "\n".join(lines)


def _render_json(results: list[OSResult]) -> str:
    out = [
        {
            "port": r.entry.port,
            "protocol": r.entry.protocol,
            "os_guess": r.os_guess,
            "method": r.method,
            "confidence": r.confidence,
        }
        for r in results
    ]
    return json.dumps(out, indent=2)


def run_os(args: argparse.Namespace) -> None:
    port_range = None
    if args.ports:
        port_range = [int(p) for p in args.ports.split(",")]

    entries = scan_ports(ports=port_range)
    results = enrich(entries, timeout=args.timeout)

    if args.format == "json":
        print(_render_json(results))
    else:
        print(_render_text(results))


def main() -> None:  # pragma: no cover
    parser = argparse.ArgumentParser(prog="portmap-os")
    sub = parser.add_subparsers(dest="command")
    build_os_parser(sub)
    args = parser.parse_args()
    if args.command is None:
        parser.print_help()
        sys.exit(1)
    run_os(args)


if __name__ == "__main__":  # pragma: no cover
    main()
