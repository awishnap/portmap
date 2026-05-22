"""CLI sub-commands for managing port tags."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from portmap import tag as tag_module
from portmap.tag_config import (
    default_tags_path,
    load_tag_rules,
    save_tag_rules,
    apply_rules,
)
from portmap.scanner import scan_ports


def build_tag_parser(parent: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
    p = parent.add_parser("tag", help="Manage custom port tags")
    sub = p.add_subparsers(dest="tag_cmd", required=True)

    # list
    sub.add_parser("list", help="Show current tag store")

    # add-rule
    ar = sub.add_parser("add-rule", help="Append a tagging rule to config")
    ar.add_argument("--port", type=int, help="Match port number")
    ar.add_argument("--protocol", choices=["tcp", "udp"], help="Match protocol")
    ar.add_argument("--process", help="Match process name (substring)")
    ar.add_argument("--tags", required=True, help="Comma-separated tags to apply")
    ar.add_argument("--config", type=Path, help="Path to tags config file")

    # apply
    ap = sub.add_parser("apply", help="Apply tag rules to current scan and print results")
    ap.add_argument("--config", type=Path, help="Path to tags config file")
    ap.add_argument("--ports", default="1-1024", help="Port range to scan")
    ap.add_argument("--format", choices=["text", "json"], default="text")


def _run_list() -> None:
    d = tag_module.tags_to_dict()
    if not d:
        print("No tags stored.")
        return
    for key, tags in sorted(d.items()):
        print(f"{key}: {', '.join(tags)}")


def _run_add_rule(args: argparse.Namespace) -> None:
    cfg = args.config or default_tags_path()
    rules = load_tag_rules(cfg)
    rule: dict = {"tags": [t.strip() for t in args.tags.split(",")]}
    if args.port:
        rule["port"] = args.port
    if args.protocol:
        rule["protocol"] = args.protocol
    if args.process:
        rule["process"] = args.process
    rules.append(rule)
    save_tag_rules(rules, cfg)
    print(f"Rule added. Total rules: {len(rules)}")


def _run_apply(args: argparse.Namespace) -> None:
    from portmap.cli import parse_port_range

    ports = parse_port_range(args.ports)
    entries = scan_ports(ports)
    cfg = args.config or default_tags_path()
    rules = load_tag_rules(cfg)
    apply_rules(entries, rules)

    if args.format == "json":
        out = [
            {"port": e.port, "protocol": e.protocol,
             "process": e.process, "tags": sorted(tag_module.get_tags(e))}
            for e in entries
        ]
        print(json.dumps(out, indent=2))
    else:
        for e in entries:
            tags = tag_module.get_tags(e)
            tag_str = f"[{', '.join(sorted(tags))}]" if tags else ""
        print(f"  {e.port}/{e.protocol}  {e.process or ''}  {tag_str}")


def run_tag(args: argparse.Namespace) -> None:
    if args.tag_cmd == "list":
        _run_list()
    elif args.tag_cmd == "add-rule":
        _run_add_rule(args)
    elif args.tag_cmd == "apply":
        _run_apply(args)
    else:
        print(f"Unknown tag sub-command: {args.tag_cmd}", file=sys.stderr)
        sys.exit(1)
