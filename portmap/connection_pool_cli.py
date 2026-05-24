"""CLI interface for connection pool inspection."""
from __future__ import annotations

import argparse
import json
import sys
from typing import List

from portmap.connection_pool import PoolEntry, measure


def build_pool_parser(sub: argparse._SubParsersAction) -> argparse.ArgumentParser:  # type: ignore[type-arg]
    p = sub.add_parser("pool", help="Show connection pool stats for ports")
    p.add_argument("ports", nargs="+", type=int, help="Port numbers to inspect")
    p.add_argument("--protocol", default="tcp", choices=["tcp", "udp"], help="Protocol (default: tcp)")
    p.add_argument("--format", dest="fmt", default="text", choices=["text", "json"])
    p.add_argument("--min-connections", type=int, default=0, dest="min_conn",
                   help="Only show ports with at least this many connections")
    return p


def _render_text(results: List[PoolEntry]) -> str:
    if not results:
        return "No results."
    header = f"{'PORT':<8} {'PROTO':<6} {'TOTAL':<7} {'STATE'}"
    sep = "-" * 50
    rows = [header, sep]
    for r in results:
        rows.append(f"{r.port:<8} {r.protocol:<6} {r.total:<7} {r.display_state()}")
    return "\n".join(rows)


def _render_json(results: List[PoolEntry]) -> str:
    data = [
        {
            "port": r.port,
            "protocol": r.protocol,
            "pid": r.pid,
            "process": r.process,
            "established": r.established,
            "time_wait": r.time_wait,
            "close_wait": r.close_wait,
            "total": r.total,
        }
        for r in results
    ]
    return json.dumps(data, indent=2)


def run_pool(args: argparse.Namespace) -> None:
    results = [measure(p, args.protocol) for p in args.ports]
    results = [r for r in results if r.total >= args.min_conn]
    out = _render_json(results) if args.fmt == "json" else _render_text(results)
    print(out)


def main() -> None:  # pragma: no cover
    parser = argparse.ArgumentParser(prog="portmap-pool")
    sub = parser.add_subparsers(dest="cmd")
    build_pool_parser(sub)
    args = parser.parse_args()
    if args.cmd is None:
        parser.print_help()
        sys.exit(1)
    run_pool(args)


if __name__ == "__main__":  # pragma: no cover
    main()
