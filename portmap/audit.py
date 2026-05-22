"""Audit log: records scan events and alert results to a structured log file."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from portmap.alert import AlertResult

DEFAULT_AUDIT_PATH = Path(os.path.expanduser("~/.portmap/audit.log"))


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _audit_entry(event: str, detail: dict) -> dict:
    return {"ts": _now_iso(), "event": event, **detail}


def log_scan(path: Path = DEFAULT_AUDIT_PATH, *, host: str = "localhost", port_count: int = 0) -> None:
    """Append a scan-completed event to the audit log."""
    entry = _audit_entry("scan", {"host": host, "ports_found": port_count})
    _append(path, entry)


def log_alerts(
    results: List[AlertResult],
    path: Path = DEFAULT_AUDIT_PATH,
    *,
    host: str = "localhost",
) -> None:
    """Append one audit record per matched alert result."""
    for result in results:
        if result.matched:
            entry = _audit_entry(
                "alert",
                {
                    "host": host,
                    "rule": result.rule_name,
                    "port": result.entry.port,
                    "protocol": result.entry.protocol,
                    "process": result.entry.process,
                },
            )
            _append(path, entry)


def read_log(path: Path = DEFAULT_AUDIT_PATH) -> List[dict]:
    """Return all audit entries from *path*; returns empty list if missing."""
    if not path.exists():
        return []
    entries: List[dict] = []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return entries


def clear_log(path: Path = DEFAULT_AUDIT_PATH) -> None:
    """Delete the audit log file if it exists."""
    if path.exists():
        path.unlink()


def _append(path: Path, entry: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry) + "\n")
