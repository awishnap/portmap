"""Generate human-readable HTML or Markdown summary reports from snapshots."""

from __future__ import annotations

import datetime
from pathlib import Path
from typing import List

from portmap.snapshot import Snapshot
from portmap.snapshot_diff import SnapshotDiff, compare


def _md_table_header() -> str:
    lines = [
        "| Port | Protocol | Status | Process | PID | Label |",
        "|------|----------|--------|---------|-----|-------|",
    ]
    return "\n".join(lines)


def _md_table_row(entry: dict) -> str:
    return (
        f"| {entry.get('port', '')} "
        f"| {entry.get('protocol', '')} "
        f"| {entry.get('status', '')} "
        f"| {entry.get('process', '') or ''} "
        f"| {entry.get('pid', '') or ''} "
        f"| {entry.get('label', '') or ''} |"
    )


def render_markdown(snapshot: Snapshot, diff: SnapshotDiff | None = None) -> str:
    """Render a Markdown report for a snapshot, optionally including diff info."""
    lines: List[str] = []
    ts = snapshot.timestamp or "unknown"
    lines.append(f"# portmap Report")
    lines.append(f"")
    lines.append(f"**Captured:** {ts}  ")
    lines.append(f"**Host:** {snapshot.host}  ")
    lines.append(f"**Entries:** {len(snapshot.entries)}  ")
    lines.append("")

    if diff and diff.has_changes():
        summary = diff.summary()
        lines.append("## Changes Since Last Snapshot")
        lines.append("")
        lines.append(f"- Appeared: {summary['appeared']}")
        lines.append(f"- Disappeared: {summary['disappeared']}")
        lines.append(f"- Changed: {summary['changed']}")
        lines.append("")

    lines.append("## Open Ports")
    lines.append("")
    lines.append(_md_table_header())
    for entry in snapshot.entries:
        lines.append(_md_table_row(entry if isinstance(entry, dict) else entry.__dict__))

    return "\n".join(lines) + "\n"


def render_html(snapshot: Snapshot, diff: SnapshotDiff | None = None) -> str:
    """Render a minimal HTML report for a snapshot."""
    ts = snapshot.timestamp or "unknown"
    rows = ""
    for e in snapshot.entries:
        d = e if isinstance(e, dict) else e.__dict__
        rows += (
            f"<tr><td>{d.get('port','')}</td><td>{d.get('protocol','')}</td>"
            f"<td>{d.get('status','')}</td><td>{d.get('process','') or ''}</td>"
            f"<td>{d.get('pid','') or ''}</td><td>{d.get('label','') or ''}</td></tr>\n"
        )

    diff_section = ""
    if diff and diff.has_changes():
        s = diff.summary()
        diff_section = (
            f"<h2>Changes</h2><ul>"
            f"<li>Appeared: {s['appeared']}</li>"
            f"<li>Disappeared: {s['disappeared']}</li>"
            f"<li>Changed: {s['changed']}</li></ul>"
        )

    return (
        f"<!DOCTYPE html><html><head><title>portmap Report</title></head><body>\n"
        f"<h1>portmap Report</h1>\n"
        f"<p><strong>Captured:</strong> {ts} &nbsp; "
        f"<strong>Host:</strong> {snapshot.host} &nbsp; "
        f"<strong>Entries:</strong> {len(snapshot.entries)}</p>\n"
        f"{diff_section}"
        f"<h2>Open Ports</h2>\n"
        f"<table border='1'><thead><tr>"
        f"<th>Port</th><th>Protocol</th><th>Status</th>"
        f"<th>Process</th><th>PID</th><th>Label</th>"
        f"</tr></thead><tbody>\n{rows}</tbody></table>\n"
        f"</body></html>\n"
    )


def save_report(content: str, path: str | Path) -> Path:
    """Write report content to a file and return the resolved path."""
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(content, encoding="utf-8")
    return out.resolve()
