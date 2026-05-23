"""Port scan history: store, retrieve, and summarise past scan results."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional

from portmap.snapshot import Snapshot, to_dict, from_dict

_DEFAULT_HISTORY_DIR = os.path.join(os.path.expanduser("~"), ".portmap", "history")


@dataclass
class HistoryEntry:
    snapshot: Snapshot
    saved_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


def default_history_dir() -> str:
    return _DEFAULT_HISTORY_DIR


def _entry_path(history_dir: str, saved_at: str) -> str:
    safe = saved_at.replace(":", "-").replace("+", "_")
    return os.path.join(history_dir, f"{safe}.json")


def save_entry(entry: HistoryEntry, history_dir: str = _DEFAULT_HISTORY_DIR) -> str:
    """Persist a HistoryEntry to disk. Returns the file path written."""
    os.makedirs(history_dir, exist_ok=True)
    path = _entry_path(history_dir, entry.saved_at)
    payload = {"saved_at": entry.saved_at, "snapshot": to_dict(entry.snapshot)}
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
    return path


def load_entry(path: str) -> HistoryEntry:
    """Load a single HistoryEntry from a JSON file."""
    with open(path, "r", encoding="utf-8") as fh:
        payload = json.load(fh)
    snapshot = from_dict(payload["snapshot"])
    return HistoryEntry(snapshot=snapshot, saved_at=payload["saved_at"])


def list_entries(history_dir: str = _DEFAULT_HISTORY_DIR) -> List[HistoryEntry]:
    """Return all history entries sorted oldest-first."""
    if not os.path.isdir(history_dir):
        return []
    paths = sorted(
        (p for p in os.listdir(history_dir) if p.endswith(".json")),
    )
    entries: List[HistoryEntry] = []
    for name in paths:
        try:
            entries.append(load_entry(os.path.join(history_dir, name)))
        except (KeyError, ValueError, OSError):
            continue
    return entries


def prune(keep: int = 50, history_dir: str = _DEFAULT_HISTORY_DIR) -> int:
    """Remove oldest entries so that at most *keep* entries remain.

    Returns the number of files deleted.
    """
    if not os.path.isdir(history_dir):
        return 0
    paths = sorted(
        p for p in os.listdir(history_dir) if p.endswith(".json")
    )
    to_delete = paths[: max(0, len(paths) - keep)]
    for name in to_delete:
        try:
            os.remove(os.path.join(history_dir, name))
        except OSError:
            pass
    return len(to_delete)
