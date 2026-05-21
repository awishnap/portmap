"""Snapshot management: capture and compare port scan states."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import List, Optional

from portmap.scanner import PortEntry
from portmap.cache import write, read


@dataclass
class Snapshot:
    timestamp: float
    entries: List[PortEntry]
    label: str = ""
    meta: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "label": self.label,
            "meta": self.meta,
            "entries": [
                {
                    "port": e.port,
                    "protocol": e.protocol,
                    "pid": e.pid,
                    "process": e.process,
                    "status": e.status,
                }
                for e in self.entries
            ],
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Snapshot":
        entries = [
            PortEntry(
                port=r["port"],
                protocol=r["protocol"],
                pid=r.get("pid"),
                process=r.get("process"),
                status=r.get("status", "LISTEN"),
            )
            for r in data.get("entries", [])
        ]
        return cls(
            timestamp=data["timestamp"],
            entries=entries,
            label=data.get("label", ""),
            meta=data.get("meta", {}),
        )


def capture(entries: List[PortEntry], label: str = "", meta: Optional[dict] = None) -> Snapshot:
    """Create a new snapshot from a list of PortEntry objects."""
    return Snapshot(
        timestamp=time.time(),
        entries=list(entries),
        label=label,
        meta=meta or {},
    )


def save_snapshot(snapshot: Snapshot, path: str) -> None:
    """Persist a snapshot to disk via the cache layer."""
    write(snapshot.to_dict(), path)


def load_snapshot(path: str) -> Optional[Snapshot]:
    """Load a snapshot from disk; returns None if not found."""
    data = read(path)
    if data is None:
        return None
    return Snapshot.from_dict(data)
