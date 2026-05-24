"""CLI sub-command: portmap socket-state — display socket states for open ports."""
from __future__ import annotations

import argparse
import json
from typing import Optional

from portmap.scanner import scan_ports
from portmap import socket_state as ss


def build_socket_state_parser(sub: argparse._SubParsersAction) -> argparse.ArgumentParser:  # type: ignore[type-arg]
    p = sub.add_parser(
        "socket-state",
        help="Show normalised socket states for open ports",
    )
    p.add_argument("--ports", metavar="RANGE", default=None, help="Port range, e.g. 1-1024")
    p.add_argument("--proto", choices=["tcp", "udp", "all"], default="all")
    p.add_argument("--active-only", action="store_true", help="Only show active sockets")
    p.add_argument("--format", choices=["text", "json"], default="text")
    return p


def _render_text(entries: list) -> str:
    if not entries:
        return "No matching sockets found."
    lines = [f"{'PORT':<8} {'PROTO':<6} {'STATE':<20} {'PROCESS'}",
             "-" * 55]
    for e in entries:
        state_obj: Optional[ss.SocketStateResult] = getattr(e, "socket_state", None)
        state_str = state_obj.display() if state_obj else "unknown"
        proc = getattr(e, "process", None) or ""
        lines.append(f"{e.port:<8} {e.protocol:<6} {state_str:<20} {proc}")
    return "\n".join(lines)


def _render_json(entries: list) -> str:
    rows = []
    for e in entries:
        state_obj: Optional[ss.SocketStateResult] = getattr(e, "socket_state", None)
        rows.append({
            "port": e.port,
            "protocol": e.protocol,
            "state": state_obj.normalised if state_obj else None,
            "is_active": state_obj.is_active if state_obj else None,
            "is_closing": state_obj.is_closing if state_obj else None,
            "process": getattr(e, "process", None),
        })
    return json.dumps(rows, indent=2)


def run_socket_state(args: argparse.Namespace) -> None:
    port_range = None
    if args.ports:
        lo, _, hi = args.ports.partition("-")
        port_range = (int(lo), int(hi)) if hi else (int(lo), int(lo))

    proto = None if args.proto == "all" else args.proto
    entries = scan_ports(port_range=port_range, protocol=proto)
    entries = ss.enrich(entries)

    if args.active_only:
        entries = [e for e in entries if getattr(getattr(e, "socket_state", None), "is_active", False)]

    if args.format == "json":
        print(_render_json(entries))
    else:
        print(_render_text(entries))


def main() -> None:  # pragma: no cover
    parser = argparse.ArgumentParser(prog="portmap-socket-state")
    sub = parser.add_subparsers(dest="cmd")
    build_socket_state_parser(sub)
    args = parser.parse_args()
    run_socket_state(args)


if __name__ == "__main__":  # pragma: no cover
    main()
