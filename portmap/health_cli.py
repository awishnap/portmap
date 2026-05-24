"""CLI sub-command: portmap health — probe ports and report reachability."""
from __future__ import annotations

import argparse
import json
import sys
from typing import List

from portmap.health import HealthResult, check
from portmap.scanner import scan_ports


def build_health_parser(sub: "argparse._SubParsersAction") -> argparse.ArgumentParser:  # type: ignore[type-arg]
    p = sub.add_parser("health", help="probe TCP ports for reachability")
    p.add_argument("--host", default="127.0.0.1", help="target host (default: 127.0.0.1)")
    p.add_argument("--ports", nargs="+", type=int, metavar="PORT",
                   help="explicit list of ports to probe (default: scan open ports)")
    p.add_argument("--timeout", type=float, default=2.0, metavar="SEC",
                   help="connection timeout in seconds (default: 2.0)")
    p.add_argument("--format", choices=["text", "json"], default="text",
                   dest="fmt", help="output format")
    p.add_argument("--only-down", action="store_true",
                   help="show only unreachable ports")
    return p


def _render_text(results: List[HealthResult], only_down: bool) -> str:
    lines = []
    for r in results:
        if only_down and r.reachable:
            continue
        lines.append(r.display())
    return "\n".join(lines) if lines else "(no results)"


def _render_json(results: List[HealthResult], only_down: bool) -> str:
    rows = []
    for r in results:
        if only_down and r.reachable:
            continue
        rows.append({
            "host": r.host,
            "port": r.port,
            "protocol": r.protocol,
            "status": r.status,
            "latency_ms": r.latency_ms,
            "error": r.error,
        })
    return json.dumps(rows, indent=2)


def run_health(args: argparse.Namespace) -> None:
    if args.ports:
        results = [check(args.host, p, timeout=args.timeout) for p in args.ports]
    else:
        entries = scan_ports()
        results = [check(args.host, e.port, e.protocol, args.timeout) for e in entries]

    if args.fmt == "json":
        print(_render_json(results, args.only_down))
    else:
        print(_render_text(results, args.only_down))


def main() -> None:  # pragma: no cover
    parser = argparse.ArgumentParser(prog="portmap-health")
    sub = parser.add_subparsers(dest="cmd")
    build_health_parser(sub)
    args = parser.parse_args()
    if args.cmd is None:
        parser.print_help()
        sys.exit(1)
    run_health(args)
