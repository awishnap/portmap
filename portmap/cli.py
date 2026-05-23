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
    """Parse a port specification string into a list of port numbers.

    Accepts comma-separated ports and/or hyphen-delimited ranges.

    Examples:
        "80"          -> [80]
        "80,443"      -> [80, 443]
        "1-1024"      -> [1, 2, ..., 1024]
        "22,80,8000-8080" -> [22, 80, 8000, 8001, ..., 8080]

    Raises:
        ValueError: If any part of the spec is not a valid port number or range,
                    or if any port falls outside the 1-65535 range.
    """
    ports: list[int] = []
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            start, _, end = part.partition("-")
            try:
                start_int, end_int = int(start), int(end)
            except ValueError:
                raise ValueError(f"Invalid port range: '{part}'")
            if start_int > end_int:
                raise ValueError(
                    f"Port range start must not exceed end: '{part}'"
                )
            ports.extend(range(start_int, end_int + 1))
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
