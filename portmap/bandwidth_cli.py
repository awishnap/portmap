"""CLI sub-command: portmap bandwidth — probe throughput on selected ports."""
from __future__ import annotations

import argparse
import json
import sys
from typing import Optional

from portmap.bandwidth import BandwidthResult, probe
from portmap.scanner import scan_ports


def build_bandwidth_parser(sub: Optional[argparse._SubParsersAction] = None) -> argparse.ArgumentParser:
    desc = "Estimate bandwidth / response size for open TCP ports."
    if sub is not None:
        p = sub.add_parser("bandwidth", help=desc)
    else:
        p = argparse.ArgumentParser(prog="portmap bandwidth", description=desc)
    p.add_argument("--host", default="127.0.0.1", help="Target host (default: 127.0.0.1)")
    p.add_argument("--ports", nargs="+", type=int, metavar="PORT", help="Explicit port list")
    p.add_argument("--timeout", type=float, default=2.0, help="Socket timeout in seconds")
    p.add_argument("--format", choices=["text", "json"], default="text", dest="fmt")
    return p


def _render_text(results: list[BandwidthResult]) -> str:
    if not results:
        return "No results."
    lines = [f"{'PORT':<8} {'PROTO':<6} {'RESULT'}", "-" * 40]
    for r in results:
        lines.append(f"{r.port:<8} {r.protocol:<6} {r.display()}")
    return "\n".join(lines)


def _render_json(results: list[BandwidthResult]) -> str:
    rows = [
        {
            "port": r.port,
            "protocol": r.protocol,
            "host": r.host,
            "bytes_received": r.bytes_received,
            "elapsed_ms": r.elapsed_ms,
            "display": r.display(),
        }
        for r in results
    ]
    return json.dumps(rows, indent=2)


def run_bandwidth(args: argparse.Namespace) -> int:
    host: str = args.host
    timeout: float = args.timeout
    fmt: str = args.fmt

    if args.ports:
        ports = args.ports
    else:
        entries = scan_ports()
        ports = [e.port for e in entries if e.protocol.lower() == "tcp"]

    results = [probe(host, port, "tcp", timeout) for port in ports]

    if fmt == "json":
        print(_render_json(results))
    else:
        print(_render_text(results))
    return 0


def main() -> None:  # pragma: no cover
    parser = build_bandwidth_parser()
    args = parser.parse_args()
    sys.exit(run_bandwidth(args))


if __name__ == "__main__":  # pragma: no cover
    main()
