"""Tag management for port entries — attach, remove, and filter by custom tags."""

from __future__ import annotations

from typing import Dict, List, Set

from portmap.scanner import PortEntry

# Internal tag store: maps (port, protocol) -> set of tags
_tag_store: Dict[tuple, Set[str]] = {}


def _key(entry: PortEntry) -> tuple:
    return (entry.port, entry.protocol)


def add_tag(entry: PortEntry, tag: str) -> None:
    """Attach a tag to a port entry."""
    k = _key(entry)
    _tag_store.setdefault(k, set()).add(tag.strip().lower())


def remove_tag(entry: PortEntry, tag: str) -> None:
    """Remove a tag from a port entry (no-op if absent)."""
    k = _key(entry)
    if k in _tag_store:
        _tag_store[k].discard(tag.strip().lower())


def get_tags(entry: PortEntry) -> Set[str]:
    """Return all tags associated with a port entry."""
    return frozenset(_tag_store.get(_key(entry), set()))


def clear_tags(entry: PortEntry) -> None:
    """Remove all tags from a port entry."""
    _tag_store.pop(_key(entry), None)


def filter_by_tag(entries: List[PortEntry], tag: str) -> List[PortEntry]:
    """Return entries that have the given tag."""
    needle = tag.strip().lower()
    return [e for e in entries if needle in _tag_store.get(_key(e), set())]


def tags_to_dict() -> Dict[str, List[str]]:
    """Serialise tag store as a plain dict (port:proto -> sorted tag list)."""
    return {
        f"{port}:{proto}": sorted(tags)
        for (port, proto), tags in _tag_store.items()
        if tags
    }


def tags_from_dict(data: Dict[str, List[str]]) -> None:
    """Restore tag store from a previously serialised dict."""
    _tag_store.clear()
    for key_str, tag_list in data.items():
        port_str, proto = key_str.split(":")
        _tag_store[(int(port_str), proto)] = set(tag_list)
