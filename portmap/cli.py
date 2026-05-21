"""Command-line interface for portmap."""

import argparse
import sys

from portmap.scanner import scan_ports
from portmap.formatter import render


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="portmap",
        description="Fast local service discovery tool — scans and labels open ports.",
    )
    parser.add_argument(
        "-p", "--ports",
        metavar="RANGE",
        default="1-65535",
        help="Port range to scan, e.g. '1-1024' or '80,443,8080' (default: 1-65535)",
    )
    parser.add_argument(
        "-f", "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host to scan (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output",
    )
    return parser


def parse_port_range(spec: str) -> list[int]:
    """Parse a port specification string into a list of port numbers."""
    ports: list[int] = []
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            start, _, end = part.partition("-")
            try:
                ports.extend(range(int(start), int(end) + 1))
            except ValueError:
                raise ValueError(f"Invalid port range: '{part}'")
        else:
            try:
                ports.append(int(part))
            except ValueError:
                raise ValueError(f"Invalid port number: '{part}'")
    invalid = [p for p in ports if not (1 <= p <= 65535)]
    if invalid:
        raise ValueError(f"Ports out of range (1-65535): {invalid[:5]}")
    return ports


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        port_list = parse_port_range(args.ports)
    except ValueError as exc:
        parser.error(str(exc))

    entries = scan_ports(host=args.host, ports=port_list)
    output = render(entries, fmt=args.format, color=not args.no_color)
    print(output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
