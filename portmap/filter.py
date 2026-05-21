"""Filter and query utilities for PortEntry results."""

from __future__ import annotations

from typing import Callable, Iterable, List, Optional

from portmap.scanner import PortEntry


def by_port_range(entries: Iterable[PortEntry], low: int, high: int) -> List[PortEntry]:
    """Return entries whose local port falls within [low, high]."""
    return [e for e in entries if low <= e.port <= high]


def by_process(entries: Iterable[PortEntry], name: str) -> List[PortEntry]:
    """Return entries whose process name contains *name* (case-insensitive)."""
    needle = name.lower()
    return [
        e for e in entries
        if e.process and needle in e.process.lower()
    ]


def by_pid(entries: Iterable[PortEntry], pid: int) -> List[PortEntry]:
    """Return entries owned by the given PID."""
    return [e for e in entries if e.pid == pid]


def by_label(entries: Iterable[PortEntry], label: str) -> List[PortEntry]:
    """Return entries whose label contains *label* (case-insensitive)."""
    needle = label.lower()
    return [e for e in entries if needle in e.label.lower()]


def by_protocol(entries: Iterable[PortEntry], proto: str) -> List[PortEntry]:
    """Return entries matching the given protocol ('tcp' or 'udp')."""
    proto = proto.lower()
    return [e for e in entries if e.proto.lower() == proto]


def apply_filters(
    entries: Iterable[PortEntry],
    filters: Iterable[Callable[[List[PortEntry]], List[PortEntry]]],
) -> List[PortEntry]:
    """Apply a sequence of filter callables in order."""
    result: List[PortEntry] = list(entries)
    for f in filters:
        result = f(result)
    return result


def build_filter(
    port_range: Optional[tuple[int, int]] = None,
    process: Optional[str] = None,
    pid: Optional[int] = None,
    label: Optional[str] = None,
    proto: Optional[str] = None,
) -> Callable[[List[PortEntry]], List[PortEntry]]:
    """Return a single composite filter function from optional criteria."""
    def _filter(entries: List[PortEntry]) -> List[PortEntry]:
        result = list(entries)
        if port_range is not None:
            result = by_port_range(result, *port_range)
        if process is not None:
            result = by_process(result, process)
        if pid is not None:
            result = by_pid(result, pid)
        if label is not None:
            result = by_label(result, label)
        if proto is not None:
            result = by_protocol(result, proto)
        return result
    return _filter
