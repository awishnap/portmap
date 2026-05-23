"""CLI sub-command: portmap resolve — enrich scan results with DNS/service names."""

from __future__ import annotations

import argparse
import json
import sys

from portmap.scanner import scan_ports
from portmap.resolve import resolve_all


def build_resolve_parser(parent: argparse._SubParsersAction | None = None) -> argparse.ArgumentParser:  # type: ignore[type-arg]
    kwargs = dict(description="Resolve hostnames and service names for open ports.")
    if parent is not None:
        parser = parent.add_parser("resolve", **kwargs)
    else:
        parser = argparse.ArgumentParser(prog="portmap-resolve", **kwargs)

    parser.add_argument("--ports", default="1-1024", help="Port range to scan (default: 1-1024)")
    parser.add_argument("--host", default="127.0.0.1", help="Host to scan")
    parser.add_argument("--no-dns", action="store_true", help="Skip reverse DNS lookup")
    parser.add_argument("--timeout", type=float, default=1.0, help="DNS timeout in seconds")
    parser.add_argument("--format", choices=["text", "json"], default="text", dest="fmt")
    return parser


def run_resolve(args: argparse.Namespace) -> int:
    from portmap.cli import parse_port_range

    ports = parse_port_range(args.ports)
    entries = scan_ports(ports, host=args.host)
    resolved = resolve_all(entries, dns=not args.no_dns, timeout=args.timeout)

    if args.fmt == "json":
        out = [
            {
                "host": r.entry.host,
                "port": r.entry.port,
                "protocol": r.entry.protocol,
                "label": r.entry.label,
                "hostname": r.hostname,
                "service": r.service,
            }
            for r in resolved
        ]
        print(json.dumps(out, indent=2))
    else:
        if not resolved:
            print("No open ports found.")
            return 0
        header = f"{'HOST':<16} {'PORT':<7} {'PROTO':<6} {'SERVICE':<14} {'HOSTNAME':<30} LABEL"
        print(header)
        print("-" * len(header))
        for r in resolved:
            print(
                f"{r.entry.host:<16} {r.entry.port:<7} {r.entry.protocol:<6}"
                f" {r.display_service:<14} {r.display_host:<30} {r.entry.label or ''}"
            )
    return 0


def main() -> None:  # pragma: no cover
    parser = build_resolve_parser()
    args = parser.parse_args()
    sys.exit(run_resolve(args))


if __name__ == "__main__":  # pragma: no cover
    main()
