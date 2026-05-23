"""CLI sub-command: portmap service  — look up service metadata for ports."""

from __future__ import annotations

import argparse
import json
import sys

from portmap.service_map import lookup, tier, enrich_entries
from portmap.scanner import scan_ports


def build_service_parser(sub: argparse._SubParsersAction) -> argparse.ArgumentParser:  # type: ignore[type-arg]
    p = sub.add_parser("service", help="Look up service names for open ports")
    p.add_argument("ports", nargs="*", type=int, metavar="PORT",
                   help="Ports to look up (default: scan all open ports)")
    p.add_argument("--format", choices=["text", "json"], default="text")
    return p


def _render_text(rows: list[dict]) -> str:
    if not rows:
        return "No services found."
    lines = [f"{'PORT':<8} {'PROTOCOL':<10} {'SERVICE':<20} {'TIER':<12} LABEL"]
    lines.append("-" * 60)
    for r in rows:
        lines.append(
            f"{r['port']:<8} {r['protocol']:<10} {(r['service'] or '?'):<20} {r['tier']:<12} {r['label'] or ''}"
        )
    return "\n".join(lines)


def run_service(args: argparse.Namespace) -> int:
    if args.ports:
        from portmap.scanner import PortEntry
        entries = []
        for p in args.ports:
            info_lookup = lookup(p)
            entries.append(PortEntry(
                port=p, protocol="tcp", status="unknown",
                pid=None, process=None,
            ))
        rows = enrich_entries(entries)
    else:
        entries = scan_ports()
        rows = enrich_entries(entries)

    if args.format == "json":
        print(json.dumps(rows, indent=2))
    else:
        print(_render_text(rows))
    return 0


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="portmap-service")
    sub = parser.add_subparsers(dest="cmd")
    build_service_parser(sub)
    args = parser.parse_args(argv)
    if args.cmd is None:
        parser.print_help()
        sys.exit(1)
    sys.exit(run_service(args))


if __name__ == "__main__":
    main()
