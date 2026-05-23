"""CLI sub-command: portmap group — display port entries grouped by category."""

from __future__ import annotations

import argparse
import json
from typing import List

from portmap.group import group_entries, group_by, list_groups
from portmap.group_builtins import register_all
from portmap.scanner import PortEntry, scan_ports


def build_group_parser(parent: argparse._SubParsersAction) -> argparse.ArgumentParser:  # type: ignore[type-arg]
    p = parent.add_parser("group", help="Group open ports by category")
    p.add_argument("--by", choices=["registry", "protocol", "process"], default="registry",
                   help="Grouping strategy (default: registry)")
    p.add_argument("--format", choices=["text", "json"], default="text",
                   dest="fmt", help="Output format")
    p.add_argument("--list-groups", action="store_true",
                   help="List registered group names and exit")
    return p


def _render_text(groups: dict) -> None:  # type: ignore[type-arg]
    for name, group in groups.items():
        if not group.entries:
            continue
        print(f"[{name}]  ({len(group)} port(s))")
        for e in group:
            proc = f" — {e.process}" if e.process else ""
            print(f"  {e.host}:{e.port}/{e.protocol}{proc}")
        print()


def _render_json(groups: dict) -> None:  # type: ignore[type-arg]
    out = {}
    for name, group in groups.items():
        out[name] = [
            {"host": e.host, "port": e.port, "protocol": e.protocol,
             "process": e.process, "pid": e.pid, "label": e.label}
            for e in group
        ]
    print(json.dumps(out, indent=2))


def run_group(args: argparse.Namespace) -> None:
    register_all()

    if args.list_groups:
        for name in list_groups():
            print(name)
        return

    entries: List[PortEntry] = scan_ports()

    if args.by == "registry":
        groups = group_entries(entries)
    elif args.by == "protocol":
        groups = group_by(entries, lambda e: e.protocol)
    else:  # process
        groups = group_by(entries, lambda e: e.process or "(unknown)")

    if args.fmt == "json":
        _render_json(groups)
    else:
        _render_text(groups)


def main() -> None:
    parser = argparse.ArgumentParser(prog="portmap-group")
    sub = parser.add_subparsers(dest="cmd")
    build_group_parser(sub)
    args = parser.parse_args()
    run_group(args)


if __name__ == "__main__":  # pragma: no cover
    main()
