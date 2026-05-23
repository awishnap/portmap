"""CLI interface for comparing two snapshots side-by-side.

Provides a `portmap compare` sub-command that loads two snapshot files,
runs a diff, and renders the result as text or JSON.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from portmap.snapshot import load_snapshot
from portmap.snapshot_diff import compare, SnapshotDiff


# ---------------------------------------------------------------------------
# Rendering helpers
# ---------------------------------------------------------------------------

def _render_text(diff: SnapshotDiff) -> str:
    """Return a human-readable comparison summary."""
    lines: list[str] = []

    lines.append(f"Baseline : {diff.before.host}  [{diff.before.timestamp}]")
    lines.append(f"Current  : {diff.after.host}  [{diff.after.timestamp}]")
    lines.append("")

    if not diff.has_changes():
        lines.append("No changes detected.")
        return "\n".join(lines)

    if diff.appeared:
        lines.append(f"  + Appeared ({len(diff.appeared)}):")
        for e in diff.appeared:
            lines.append(f"      +  :{e.port}/{e.protocol}  {e.label()}")

    if diff.disappeared:
        lines.append(f"  - Disappeared ({len(diff.disappeared)}):")
        for e in diff.disappeared:
            lines.append(f"      -  :{e.port}/{e.protocol}  {e.label()}")

    if diff.changed:
        lines.append(f"  ~ Changed ({len(diff.changed)}):")
        for before_e, after_e in diff.changed:
            lines.append(
                f"      ~  :{before_e.port}/{before_e.protocol}  "
                f"{before_e.label()} -> {after_e.label()}"
            )

    lines.append("")
    lines.append(diff.summary())
    return "\n".join(lines)


def _render_json(diff: SnapshotDiff) -> str:
    """Return a JSON representation of the diff."""

    def _entry_dict(e) -> dict:
        return {
            "port": e.port,
            "protocol": e.protocol,
            "status": e.status,
            "pid": e.pid,
            "process": e.process,
            "label": e.label(),
        }

    payload = {
        "before": {
            "host": diff.before.host,
            "timestamp": diff.before.timestamp,
        },
        "after": {
            "host": diff.after.host,
            "timestamp": diff.after.timestamp,
        },
        "has_changes": diff.has_changes(),
        "summary": diff.summary(),
        "appeared": [_entry_dict(e) for e in diff.appeared],
        "disappeared": [_entry_dict(e) for e in diff.disappeared],
        "changed": [
            {"before": _entry_dict(b), "after": _entry_dict(a)}
            for b, a in diff.changed
        ],
    }
    return json.dumps(payload, indent=2)


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_compare_parser(sub: "argparse._SubParsersAction | None" = None) -> argparse.ArgumentParser:
    """Build (and optionally register) the compare sub-command parser."""
    kwargs = dict(
        description="Compare two portmap snapshots and show what changed.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    if sub is not None:
        parser = sub.add_parser("compare", **kwargs)
    else:
        parser = argparse.ArgumentParser(prog="portmap compare", **kwargs)

    parser.add_argument("before", metavar="BEFORE", help="Path to the older snapshot file.")
    parser.add_argument("after", metavar="AFTER", help="Path to the newer snapshot file.")
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        dest="fmt",
        help="Output format (default: text).",
    )
    parser.add_argument(
        "--exit-code",
        action="store_true",
        help="Exit with code 1 when changes are detected.",
    )
    return parser


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run_compare(args: argparse.Namespace) -> int:
    """Execute the compare command; return an exit code."""
    before_path = Path(args.before)
    after_path = Path(args.after)

    for p in (before_path, after_path):
        if not p.exists():
            print(f"Error: snapshot file not found: {p}", file=sys.stderr)
            return 2

    before_snap = load_snapshot(before_path)
    after_snap = load_snapshot(after_path)

    diff = compare(before_snap, after_snap)

    if args.fmt == "json":
        print(_render_json(diff))
    else:
        print(_render_text(diff))

    if args.exit_code and diff.has_changes():
        return 1
    return 0


def main(argv: list[str] | None = None) -> None:  # pragma: no cover
    """Standalone entry point for `portmap-compare`."""
    parser = build_compare_parser()
    args = parser.parse_args(argv)
    sys.exit(run_compare(args))


if __name__ == "__main__":  # pragma: no cover
    main()
