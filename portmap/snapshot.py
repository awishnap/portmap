"""Snapshot capture, serialisation, and persistence for portmap."""

from __future__ import annotations

import json
import socket
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from portmap.scanner import PortEntry, scan_ports


@dataclass
class Snapshot:
    host: str
    ts: str
    entries: list[PortEntry] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Serialisation helpers
# ---------------------------------------------------------------------------

def to_dict(snapshot: Snapshot) -> dict[str, Any]:
    return {
        "host": snapshot.host,
        "ts": snapshot.ts,
        "meta": snapshot.meta,
        "entries": [
            {
                "port": e.port,
                "protocol": e.protocol,
                "pid": e.pid,
                "process": e.process,
                "status": e.status,
                "label": e.label,
            }
            for e in snapshot.entries
        ],
    }


def from_dict(data: dict[str, Any]) -> Snapshot:
    entries = [
        PortEntry(
            port=row["port"],
            protocol=row.get("protocol", "tcp"),
            pid=row.get("pid"),
            process=row.get("process"),
            status=row.get("status", "LISTEN"),
            label=row.get("label", ""),
        )
        for row in data.get("entries", [])
    ]
    return Snapshot(
        host=data["host"],
        ts=data["ts"],
        entries=entries,
        meta=data.get("meta", {}),
    )


# ---------------------------------------------------------------------------
# Capture
# ---------------------------------------------------------------------------

def capture(
    ports: list[int] | None = None,
    protocols: list[str] | None = None,
) -> Snapshot:
    """Scan live ports and return a Snapshot."""
    entries = scan_ports(ports=ports, protocols=protocols)
    return Snapshot(
        host=socket.gethostname(),
        ts=datetime.now(timezone.utc).isoformat(),
        entries=entries,
    )


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

def save_snapshot(snapshot: Snapshot, path: Path) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(to_dict(snapshot), indent=2), encoding="utf-8")


def load_snapshot(path: Path) -> Snapshot:
    path = Path(path)
    data = json.loads(path.read_text(encoding="utf-8"))
    return from_dict(data)
