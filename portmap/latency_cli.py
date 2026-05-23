"""CLI sub-command: portmap latency — measure TCP connect latency for scanned ports."""
from __future__ import annotations

import argparse
import json
import sys
from typing import List

from portmap.latency import LatencyResult, enrich
from portmap.scanner import scan_ports


def build_latency_parser(sub: "argparse._SubParsersAction") -> argparse.ArgumentParser:  # type: ignore[type-arg]
    p = sub.add_parser("latency", help="Measure TCP connect latency for open ports")
    p.add_argument("--host", default="127.0.0.1", help="Host to probe (default: 127.0.0.1)")
    p.add_argument("--ports", default="1-1024", help="Port range to scan (default: 1-1024)")
    p.add_argument("--timeout", type=float, default=1.0, help="Connect timeout in seconds (default: 1.0)")
    p.add_argument("--format", choices=["text", "json"], default="text", dest="fmt")
    return p


def _render_text(results: List[LatencyResult]) -> str:
    if not results:
        return "No results."
    lines = []
    header = f"{'HOST:PORT/PROTO':<30} {'LATENCY':>12}"
    lines.append(header)
    lines.append("-" * len(header))
    for r in results:
        label = f"{r.host}:{r.port}/{r.protocol}"
        value = f"{r.latency_ms:.2f} ms" if r.latency_ms is not None else "timeout"
        lines.append(f"{label:<30} {value:>12}")
    return "\n".join(lines)


def _render_json(results: List[LatencyResult]) -> str:
    data = [
        {
            "host": r.host,
            "port": r.port,
            "protocol": r.protocol,
            "latency_ms": r.latency_ms,
        }
        for r in results
    ]
    return json.dumps(data, indent=2)


def run_latency(args: argparse.Namespace) -> int:
    from portmap.cli import parse_port_range

    ports = parse_port_range(args.ports)
    entries = scan_ports(ports)
    results = enrich(entries, host=args.host, timeout=args.timeout)

    if args.fmt == "json":
        print(_render_json(results))
    else:
        print(_render_text(results))
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(prog="portmap-latency")
    sub = parser.add_subparsers(dest="cmd")
    build_latency_parser(sub)
    args = parser.parse_args()
    sys.exit(run_latency(args))


if __name__ == "__main__":
    main()
