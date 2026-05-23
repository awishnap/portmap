"""CLI sub-command: portmap traceroute — probe hop paths to open-port hosts."""
from __future__ import annotations

import argparse
import json
import sys
from typing import List

from portmap.traceroute import TracerouteResult, probe


def build_traceroute_parser(subparsers=None) -> argparse.ArgumentParser:
    desc = "Traceroute to one or more hosts and display hop information."
    if subparsers is not None:
        p = subparsers.add_parser("traceroute", help=desc)
    else:
        p = argparse.ArgumentParser(prog="portmap traceroute", description=desc)
    p.add_argument("hosts", nargs="+", metavar="HOST", help="Target host(s) to probe")
    p.add_argument("--max-hops", type=int, default=30, metavar="N", help="Maximum TTL (default 30)")
    p.add_argument("--timeout", type=float, default=1.0, metavar="SEC", help="Per-hop timeout in seconds")
    p.add_argument("--format", choices=["text", "json"], default="text", dest="fmt")
    return p


def _render_text(results: List[TracerouteResult]) -> str:
    lines: List[str] = []
    for r in results:
        lines.append(f"=== {r.host} ({r.hop_count} hops, reached={r.reached}) ===")
        for hop in r.hops:
            lines.append("  " + hop.display())
        lines.append("")
    return "\n".join(lines).rstrip()


def _render_json(results: List[TracerouteResult]) -> str:
    out = []
    for r in results:
        out.append({
            "host": r.host,
            "reached": r.reached,
            "hop_count": r.hop_count,
            "hops": [
                {"ttl": h.ttl, "address": h.address, "rtt_ms": h.rtt_ms}
                for h in r.hops
            ],
        })
    return json.dumps(out, indent=2)


def run_traceroute(args: argparse.Namespace) -> int:
    results: List[TracerouteResult] = []
    for host in args.hosts:
        try:
            r = probe(host, max_hops=args.max_hops, timeout=args.timeout)
            results.append(r)
        except Exception as exc:  # noqa: BLE001
            print(f"[error] {host}: {exc}", file=sys.stderr)

    if args.fmt == "json":
        print(_render_json(results))
    else:
        print(_render_text(results))
    return 0


def main() -> None:  # pragma: no cover
    parser = build_traceroute_parser()
    sys.exit(run_traceroute(parser.parse_args()))


if __name__ == "__main__":  # pragma: no cover
    main()
