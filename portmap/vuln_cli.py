"""CLI sub-command: portmap vuln — show vulnerability hints for open ports."""
from __future__ import annotations

import argparse
import json
import sys
from typing import List

from portmap.scanner import scan_ports
from portmap.vuln import VulnResult, enrich, flagged


def build_vuln_parser(sub: "argparse._SubParsersAction") -> argparse.ArgumentParser:
    p = sub.add_parser("vuln", help="Show known vulnerability hints for open ports")
    p.add_argument("--ports", default=None, help="Comma-separated ports to check (default: scan all)")
    p.add_argument("--protocol", default="tcp", choices=["tcp", "udp"], help="Protocol filter")
    p.add_argument("--only-flagged", action="store_true", help="Show only ports with advisories")
    p.add_argument("--format", choices=["text", "json"], default="text", dest="fmt")
    return p


def _render_text(pairs: list) -> str:
    if not pairs:
        return "No advisories found."
    lines = []
    for entry, result in pairs:
        lines.append(result.display())
    return "\n".join(lines)


def _render_json(pairs: list) -> str:
    out = []
    for entry, result in pairs:
        out.append({
            "port": result.port,
            "protocol": result.protocol,
            "process": entry.process,
            "advisories": result.advisories,
        })
    return json.dumps(out, indent=2)


def run_vuln(args: argparse.Namespace) -> int:
    if args.ports:
        try:
            port_list = [int(p.strip()) for p in args.ports.split(",")]
        except ValueError:
            print("ERROR: --ports must be comma-separated integers", file=sys.stderr)
            return 1
    else:
        port_list = None

    entries = scan_ports(ports=port_list, protocol=args.protocol)

    pairs = flagged(entries) if args.only_flagged else enrich(entries)

    output = _render_json(pairs) if args.fmt == "json" else _render_text(pairs)
    print(output)
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(prog="portmap-vuln")
    sub = parser.add_subparsers(dest="cmd")
    build_vuln_parser(sub)
    args = parser.parse_args()
    sys.exit(run_vuln(args))


if __name__ == "__main__":
    main()
