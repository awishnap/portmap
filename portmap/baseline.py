"""Baseline management: capture, compare, and persist a known-good port state."""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from portmap.scanner import PortEntry

_DEFAULT_PATH = Path.home() / ".portmap" / "baseline.json"


@dataclass
class BaselineDiff:
    new_ports: List[PortEntry]
    removed_ports: List[PortEntry]

    @property
    def has_changes(self) -> bool:
        return bool(self.new_ports or self.removed_ports)

    def summary(self) -> str:
        lines = []
        for e in self.new_ports:
            lines.append(f"  + {e.port}/{e.protocol}  {e.label}")
        for e in self.removed_ports:
            lines.append(f"  - {e.port}/{e.protocol}  {e.label}")
        return "\n".join(lines) if lines else "No changes from baseline."


def _entry_key(entry: PortEntry) -> str:
    return f"{entry.port}/{entry.protocol}"


def save_baseline(entries: List[PortEntry], path: Path = _DEFAULT_PATH) -> None:
    """Persist *entries* as the new baseline."""
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "entries": [asdict(e) for e in entries],
    }
    path.write_text(json.dumps(payload, indent=2))


def load_baseline(path: Path = _DEFAULT_PATH) -> Optional[List[PortEntry]]:
    """Return the saved baseline entries, or *None* if no baseline exists."""
    if not path.exists():
        return None
    data = json.loads(path.read_text())
    return [PortEntry(**e) for e in data["entries"]]


def compare_to_baseline(
    current: List[PortEntry],
    baseline: List[PortEntry],
) -> BaselineDiff:
    """Return ports that appeared or disappeared relative to *baseline*."""
    baseline_keys = {_entry_key(e): e for e in baseline}
    current_keys = {_entry_key(e): e for e in current}

    new_ports = [current_keys[k] for k in current_keys if k not in baseline_keys]
    removed_ports = [baseline_keys[k] for k in baseline_keys if k not in current_keys]

    return BaselineDiff(new_ports=new_ports, removed_ports=removed_ports)
