"""CLI interface for port uptime tracking."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import List

from portmap.scanner import scan_ports
from portmap.uptime import UptimeResult, measure, _DEFAULT_STATE_PATH


def build_uptime_parser(sub: "argparse._SubParsersAction") -> argparse.ArgumentParser:  # type: ignore[type-arg]
    p = sub.add_parser("uptime", help="Show how long each port has been continuously open")
    p.add_argument("--format", choices=["text", "json"], default="text")
    p.add_argument("--state", default=str(_DEFAULT_STATE_PATH), help="Path to uptime state file")
    p.add_argument("--ports", default=None, help="Comma-separated ports or ranges to filter")
    return p


def _render_text(results: List[UptimeResult]) -> None:
    if not results:
        print("No open ports tracked.")
        return
    header = f"{'PORT':<8} {'PROTO':<6} {'UPTIME':<16} {'FIRST SEEN'}"
    print(header)
    print("-" * len(header))
    for r in results:
        import datetime
        first = datetime.datetime.fromtimestamp(r.first_seen).strftime("%Y-%m-%d %H:%M:%S")
        print(f"{r.port:<8} {r.protocol:<6} {r.display():<16} {first}")


def _render_json(results: List[UptimeResult]) -> None:
    data = [
        {
            "port": r.port,
            "protocol": r.protocol,
            "first_seen": r.first_seen,
            "last_seen": r.last_seen,
            "uptime_seconds": r.uptime_seconds,
            "uptime_display": r.display(),
        }
        for r in results
    ]
    print(json.dumps(data, indent=2))


def run_uptime(args: argparse.Namespace) -> None:
    entries = scan_ports()
    if args.ports:
        from portmap.cli import parse_port_range
        allowed = set(parse_port_range(args.ports))
        entries = [e for e in entries if e.port in allowed]
    results = measure(entries, path=Path(args.state))
    if args.format == "json":
        _render_json(results)
    else:
        _render_text(results)


def main() -> None:
    parser = argparse.ArgumentParser(prog="portmap-uptime")
    sub = parser.add_subparsers(dest="command")
    build_uptime_parser(sub)
    args = parser.parse_args()
    run_uptime(args)


if __name__ == "__main__":
    main()
