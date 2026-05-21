"""Simple file-based cache for scan results to avoid redundant re-scans."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import List, Optional

from portmap.scanner import PortEntry

_DEFAULT_CACHE_PATH = Path.home() / ".cache" / "portmap" / "last_scan.json"
_DEFAULT_TTL = 30.0  # seconds


def _serialize(entries: List[PortEntry]) -> dict:
    return {
        "timestamp": time.time(),
        "entries": [
            {
                "port": e.port,
                "proto": e.proto,
                "state": e.state,
                "pid": e.pid,
                "process": e.process,
            }
            for e in entries
        ],
    }


def _deserialize(data: dict) -> List[PortEntry]:
    return [
        PortEntry(
            port=r["port"],
            proto=r["proto"],
            state=r["state"],
            pid=r.get("pid"),
            process=r.get("process"),
        )
        for r in data["entries"]
    ]


def write(entries: List[PortEntry], path: Path = _DEFAULT_CACHE_PATH) -> None:
    """Persist *entries* to the cache file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(_serialize(entries), indent=2), encoding="utf-8")


def read(path: Path = _DEFAULT_CACHE_PATH, ttl: float = _DEFAULT_TTL) -> Optional[List[PortEntry]]:
    """Return cached entries if the cache file exists and is within *ttl* seconds.

    Returns ``None`` when the cache is missing, unreadable, or stale.
    """
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        age = time.time() - data.get("timestamp", 0)
        if age > ttl:
            return None
        return _deserialize(data)
    except (json.JSONDecodeError, KeyError, TypeError):
        return None


def invalidate(path: Path = _DEFAULT_CACHE_PATH) -> None:
    """Remove the cache file if it exists."""
    try:
        path.unlink()
    except FileNotFoundError:
        pass
