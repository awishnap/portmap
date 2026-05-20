"""Formatter module: renders PortEntry results as a table or JSON output."""

import json
from typing import Literal
from portmap.scanner import PortEntry


COLUMNS = ["PORT", "PROTO", "STATUS", "PID", "PROCESS", "ADDRESS"]
COL_WIDTHS = [6, 5, 8, 7, 22, 16]


def _row(entry: PortEntry) -> list[str]:
    return [
        str(entry.port),
        entry.protocol.upper(),
        entry.status,
        str(entry.pid) if entry.pid is not None else "-",
        entry.process_name or "-",
        entry.local_address,
    ]


def format_table(entries: list[PortEntry]) -> str:
    """Render entries as a fixed-width ASCII table."""
    lines: list[str] = []

    header = "".join(col.ljust(w) for col, w in zip(COLUMNS, COL_WIDTHS))
    separator = "-" * sum(COL_WIDTHS)
    lines.append(header)
    lines.append(separator)

    for entry in entries:
        row = _row(entry)
        lines.append("".join(cell.ljust(w) for cell, w in zip(row, COL_WIDTHS)))

    if not entries:
        lines.append("  (no listening ports found)")

    return "\n".join(lines)


def format_json(entries: list[PortEntry], indent: int = 2) -> str:
    """Render entries as a JSON string."""
    data = [
        {
            "port": e.port,
            "protocol": e.protocol,
            "status": e.status,
            "pid": e.pid,
            "process_name": e.process_name,
            "process_cmdline": e.process_cmdline,
            "local_address": e.local_address,
            "label": e.label(),
        }
        for e in entries
    ]
    return json.dumps(data, indent=indent)


def render(
    entries: list[PortEntry],
    output_format: Literal["table", "json"] = "table",
) -> str:
    """Dispatch to the appropriate formatter."""
    if output_format == "json":
        return format_json(entries)
    return format_table(entries)
