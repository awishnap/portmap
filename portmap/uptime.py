"""Port uptime tracking: measure how long a port has been continuously open."""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional
import json

from portmap.scanner import PortEntry

_DEFAULT_STATE_PATH = Path.home() / ".portmap" / "uptime_state.json"


@dataclass
class UptimeResult:
    port: int
    protocol: str
    first_seen: float          # epoch seconds
    last_seen: float           # epoch seconds
    uptime_seconds: float

    def display(self) -> str:
        h = int(self.uptime_seconds // 3600)
        m = int((self.uptime_seconds % 3600) // 60)
        s = int(self.uptime_seconds % 60)
        return f"{h:02d}h {m:02d}m {s:02d}s"


def _state_key(port: int, protocol: str) -> str:
    return f"{port}/{protocol}"


def load_state(path: Path = _DEFAULT_STATE_PATH) -> Dict[str, float]:
    """Load persisted first-seen timestamps keyed by 'port/proto'."""
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return {}


def save_state(state: Dict[str, float], path: Path = _DEFAULT_STATE_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=2))


def measure(entries: List[PortEntry], path: Path = _DEFAULT_STATE_PATH) -> List[UptimeResult]:
    """Return uptime results for each entry, persisting first-seen times."""
    state = load_state(path)
    now = time.time()
    results: List[UptimeResult] = []

    active_keys = set()
    for entry in entries:
        key = _state_key(entry.port, entry.protocol)
        active_keys.add(key)
        if key not in state:
            state[key] = now
        first = state[key]
        results.append(UptimeResult(
            port=entry.port,
            protocol=entry.protocol,
            first_seen=first,
            last_seen=now,
            uptime_seconds=now - first,
        ))

    # prune ports no longer open
    for key in list(state.keys()):
        if key not in active_keys:
            del state[key]

    save_state(state, path)
    return results


def enrich(entries: List[PortEntry], path: Path = _DEFAULT_STATE_PATH) -> Dict[int, UptimeResult]:
    """Return a mapping of port -> UptimeResult for quick lookup."""
    results = measure(entries, path)
    return {r.port: r for r in results}
