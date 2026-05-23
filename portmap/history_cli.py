"""CLI sub-commands for scan history management."""

from __future__ import annotations

import argparse
import json
import sys

import portmap.history as history_mod
from portmap.history import default_history_dir, list_entries, prune


def build_history_parser(sub: "argparse._SubParsersAction") -> argparse.ArgumentParser:  # type: ignore[type-arg]
    p = sub.add_parser("history", help="Manage scan history")
    sp = p.add_subparsers(dest="history_cmd", required=True)

    ls = sp.add_parser("list", help="List stored scan snapshots")
    ls.add_argument("--dir", default=None, help="History directory")
    ls.add_argument("--format", choices=["text", "json"], default="text")
    ls.add_argument("--limit", type=int, default=0, help="Show only the N most recent (0 = all)")

    pr = sp.add_parser("prune", help="Delete oldest entries")
    pr.add_argument("--dir", default=None, help="History directory")
    pr.add_argument("--keep", type=int, default=50, help="Number of entries to keep")

    return p


def _run_list(args: argparse.Namespace) -> None:
    hdir = args.dir or default_history_dir()
    entries = list_entries(hdir)
    if args.limit > 0:
        entries = entries[-args.limit :]

    if args.format == "json":
        out = [
            {
                "saved_at": e.saved_at,
                "host": e.snapshot.host,
                "port_count": len(e.snapshot.entries),
            }
            for e in entries
        ]
        print(json.dumps(out, indent=2))
    else:
        if not entries:
            print("No history entries found.")
            return
        print(f"{'#':<4}  {'Saved At':<32}  {'Host':<20}  Ports")
        print("-" * 70)
        for idx, e in enumerate(entries, 1):
            print(f"{idx:<4}  {e.saved_at:<32}  {e.snapshot.host:<20}  {len(e.snapshot.entries)}")


def _run_prune(args: argparse.Namespace) -> None:
    hdir = args.dir or default_history_dir()
    deleted = prune(keep=args.keep, history_dir=hdir)
    print(f"Pruned {deleted} entr{'y' if deleted == 1 else 'ies'} (keeping up to {args.keep}).")


def run_history(args: argparse.Namespace) -> None:
    if args.history_cmd == "list":
        _run_list(args)
    elif args.history_cmd == "prune":
        _run_prune(args)
    else:
        print(f"Unknown history command: {args.history_cmd}", file=sys.stderr)
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(prog="portmap-history")
    sub = parser.add_subparsers(dest="cmd")
    build_history_parser(sub)
    args = parser.parse_args()
    run_history(args)


if __name__ == "__main__":
    main()
