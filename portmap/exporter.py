"""Export scan results to various file formats (JSON, CSV, Markdown)."""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from typing import List, Literal

from portmap.scanner import PortEntry

ExportFormat = Literal["json", "csv", "markdown"]

FORMAT_EXTENSIONS: dict[str, str] = {
    "json": ".json",
    "csv": ".csv",
    "markdown": ".md",
}


def export_json(entries: List[PortEntry], indent: int = 2) -> str:
    """Serialize port entries to a JSON string."""
    data = [
        {
            "port": e.port,
            "proto": e.proto,
            "state": e.state,
            "pid": e.pid,
            "process": e.process,
            "label": e.label,
        }
        for e in entries
    ]
    return json.dumps(data, indent=indent)


def export_csv(entries: List[PortEntry]) -> str:
    """Serialize port entries to a CSV string."""
    buf = io.StringIO()
    writer = csv.DictWriter(
        buf,
        fieldnames=["port", "proto", "state", "pid", "process", "label"],
        lineterminator="\n",
    )
    writer.writeheader()
    for e in entries:
        writer.writerow(
            {
                "port": e.port,
                "proto": e.proto,
                "state": e.state,
                "pid": e.pid or "",
                "process": e.process or "",
                "label": e.label,
            }
        )
    return buf.getvalue()


def export_markdown(entries: List[PortEntry]) -> str:
    """Serialize port entries to a Markdown table string."""
    header = "| Port | Proto | State | PID | Process | Label |"
    separator = "|------|-------|-------|-----|---------|-------|"
    rows = [
        f"| {e.port} | {e.proto} | {e.state} | {e.pid or ''} | {e.process or ''} | {e.label} |"
        for e in entries
    ]
    return "\n".join([header, separator] + rows)


def save(entries: List[PortEntry], path: str | Path, fmt: ExportFormat) -> Path:
    """Write exported content to *path* and return the resolved Path.

    If *path* has no suffix, the appropriate file extension for *fmt* is
    appended automatically (e.g. ``report`` becomes ``report.json``).
    """
    dispatch = {"json": export_json, "csv": export_csv, "markdown": export_markdown}
    if fmt not in dispatch:
        raise ValueError(f"Unsupported format: {fmt!r}. Choose from {list(dispatch)}.")
    content = dispatch[fmt](entries)  # type: ignore[operator]
    out = Path(path)
    if not out.suffix:
        out = out.with_suffix(FORMAT_EXTENSIONS[fmt])
    out.write_text(content, encoding="utf-8")
    return out.resolve()
