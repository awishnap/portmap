"""CLI interface for comparing two snapshots and displaying a diff."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from portmap.snapshot import load_snapshot
from portmap.snapshot_diff import compare, SnapshotDiff


def build_diff_parser(parent: argparse._SubParsersAction | None = None) -> argparse.ArgumentParser:
    description = "Compare two portmap snapshots and show what changed."
    if parent is not None:
        parser = parent.add_parser("diff", help=description)
    else:
        parser = argparse.ArgumentParser(prog="portmap-diff", description=description)

    parser.add_argument("baseline", type=Path, help="Path to the baseline snapshot (JSON).")
    parser.add_argument("current", type=Path, help="Path to the current snapshot (JSON).")
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        dest="fmt",
        help="Output format (default: text).",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        default=False,
        help="Disable ANSI colour in text output.",
    )
    return parser


def _render_text(diff: SnapshotDiff, *, color: bool = True) -> str:
    lines: list[str] = []
    green = "\033[32m" if color else ""
    red = "\033[31m" if color else ""
    reset = "\033[0m" if color else ""

    if not diff.has_changes():
        lines.append("No changes detected.")
        return "\n".join(lines)

    for entry in diff.appeared:
        lines.append(f"{green}+ {entry.port}/{entry.protocol}  {entry.label}{reset}")
    for entry in diff.disappeared:
        lines.append(f"{red}- {entry.port}/{entry.protocol}  {entry.label}{reset}")
    for entry in diff.changed:
        lines.append(f"~ {entry.port}/{entry.protocol}  {entry.label}")

    summary = diff.summary()
    lines.append(f"\nSummary: {summary['appeared']} appeared, "
                 f"{summary['disappeared']} disappeared, "
                 f"{summary['changed']} changed.")
    return "\n".join(lines)


def _render_json(diff: SnapshotDiff) -> str:
    summary = diff.summary()
    payload = {
        "has_changes": diff.has_changes(),
        "summary": summary,
        "appeared": [{"port": e.port, "protocol": e.protocol, "label": e.label} for e in diff.appeared],
        "disappeared": [{"port": e.port, "protocol": e.protocol, "label": e.label} for e in diff.disappeared],
        "changed": [{"port": e.port, "protocol": e.protocol, "label": e.label} for e in diff.changed],
    }
    return json.dumps(payload, indent=2)


def run_diff(args: argparse.Namespace) -> int:
    try:
        baseline = load_snapshot(args.baseline)
        current = load_snapshot(args.current)
    except (FileNotFoundError, KeyError, ValueError) as exc:
        print(f"Error loading snapshots: {exc}", file=sys.stderr)
        return 1

    diff = compare(baseline, current)

    if args.fmt == "json":
        print(_render_json(diff))
    else:
        print(_render_text(diff, color=not args.no_color))

    return 0 if not diff.has_changes() else 2


def main() -> None:
    parser = build_diff_parser()
    args = parser.parse_args()
    sys.exit(run_diff(args))


if __name__ == "__main__":
    main()
