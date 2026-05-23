"""Port grouping — cluster PortEntry objects into named groups by shared attributes."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, List

from portmap.scanner import PortEntry

# Registry maps group-name -> predicate
_GROUPS: Dict[str, Callable[[PortEntry], bool]] = {}


@dataclass
class PortGroup:
    name: str
    entries: List[PortEntry] = field(default_factory=list)

    def __len__(self) -> int:
        return len(self.entries)

    def __iter__(self):
        return iter(self.entries)


def register_group(name: str, predicate: Callable[[PortEntry], bool]) -> None:
    """Register a named group with a membership predicate."""
    if not callable(predicate):
        raise TypeError(f"predicate for group '{name}' must be callable")
    _GROUPS[name] = predicate


def unregister_group(name: str) -> None:
    """Remove a registered group (no-op if absent)."""
    _GROUPS.pop(name, None)


def list_groups() -> List[str]:
    """Return names of all registered groups."""
    return list(_GROUPS.keys())


def group_entries(entries: List[PortEntry]) -> Dict[str, PortGroup]:
    """Partition *entries* into every registered group.

    An entry can appear in multiple groups.  Entries that match no group
    are collected under the special key ``"ungrouped"``.
    """
    result: Dict[str, PortGroup] = {name: PortGroup(name) for name in _GROUPS}
    ungrouped: PortGroup = PortGroup("ungrouped")

    for entry in entries:
        matched = False
        for name, predicate in _GROUPS.items():
            if predicate(entry):
                result[name].entries.append(entry)
                matched = True
        if not matched:
            ungrouped.entries.append(entry)

    result["ungrouped"] = ungrouped
    return result


def group_by(entries: List[PortEntry], key: Callable[[PortEntry], str]) -> Dict[str, PortGroup]:
    """Ad-hoc grouping: partition *entries* by the string returned by *key*."""
    result: Dict[str, PortGroup] = {}
    for entry in entries:
        bucket = key(entry)
        if bucket not in result:
            result[bucket] = PortGroup(bucket)
        result[bucket].entries.append(entry)
    return result
