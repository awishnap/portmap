"""Compute human-readable diffs between two Snapshots."""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Tuple

from portmap.snapshot import Snapshot
from portmap.scanner import PortEntry


@dataclass
class SnapshotDiff:
    added: List[PortEntry]
    removed: List[PortEntry]
    changed: List[Tuple[PortEntry, PortEntry]]  # (before, after)

    @property
    def has_changes(self) -> bool:
        return bool(self.added or self.removed or self.changed)

    def summary(self) -> str:
        parts = []
        if self.added:
            parts.append(f"+{len(self.added)} added")
        if self.removed:
            parts.append(f"-{len(self.removed)} removed")
        if self.changed:
            parts.append(f"~{len(self.changed)} changed")
        return ", ".join(parts) if parts else "no changes"


def _entry_key(e: PortEntry) -> Tuple[int, str]:
    return (e.port, e.protocol)


def compare(before: Snapshot, after: Snapshot) -> SnapshotDiff:
    """Diff two snapshots and return added, removed, and changed entries."""
    before_map = {_entry_key(e): e for e in before.entries}
    after_map = {_entry_key(e): e for e in after.entries}

    added = [after_map[k] for k in after_map if k not in before_map]
    removed = [before_map[k] for k in before_map if k not in after_map]

    changed: List[Tuple[PortEntry, PortEntry]] = []
    for k in before_map:
        if k in after_map:
            b, a = before_map[k], after_map[k]
            if b.pid != a.pid or b.process != a.process or b.status != a.status:
                changed.append((b, a))

    return SnapshotDiff(added=added, removed=removed, changed=changed)
