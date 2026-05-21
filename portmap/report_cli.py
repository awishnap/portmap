"""CLI integration for report generation (used as a sub-command or standalone)."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from portmap.snapshot import load_snapshot
from portmap.snapshot_diff import compare
from portmap.report import render_markdown, render_html, save_report


def build_report_parser(parent: argparse._SubParsersAction | None = None) -> argparse.ArgumentParser:
    kwargs = dict(
        description="Generate an HTML or Markdown report from a portmap snapshot."
    )
    if parent is not None:
        parser = parent.add_parser("report", **kwargs)
    else:
        parser = argparse.ArgumentParser(prog="portmap-report", **kwargs)

    parser.add_argument("snapshot", help="Path to snapshot JSON file.")
    parser.add_argument(
        "--format",
        choices=["markdown", "html"],
        default="markdown",
        dest="fmt",
        help="Output format (default: markdown).",
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Write report to this file (default: print to stdout).",
    )
    parser.add_argument(
        "--compare",
        default=None,
        metavar="PREV_SNAPSHOT",
        help="Compare against a previous snapshot and include diff in report.",
    )
    return parser


def run_report(args: argparse.Namespace) -> int:
    """Execute the report command. Returns exit code."""
    snap_path = Path(args.snapshot)
    if not snap_path.exists():
        print(f"error: snapshot file not found: {snap_path}", file=sys.stderr)
        return 1

    try:
        snapshot = load_snapshot(snap_path)
    except Exception as exc:
        print(f"error: could not load snapshot: {exc}", file=sys.stderr)
        return 1

    diff = None
    if args.compare:
        prev_path = Path(args.compare)
        if not prev_path.exists():
            print(f"error: previous snapshot not found: {prev_path}", file=sys.stderr)
            return 1
        try:
            prev = load_snapshot(prev_path)
            diff = compare(prev, snapshot)
        except Exception as exc:
            print(f"warning: could not compute diff: {exc}", file=sys.stderr)

    if args.fmt == "html":
        content = render_html(snapshot, diff=diff)
    else:
        content = render_markdown(snapshot, diff=diff)

    if args.output:
        out = save_report(content, args.output)
        print(f"Report saved to {out}")
    else:
        print(content, end="")

    return 0


def main() -> None:  # pragma: no cover
    parser = build_report_parser()
    args = parser.parse_args()
    sys.exit(run_report(args))


if __name__ == "__main__":  # pragma: no cover
    main()
