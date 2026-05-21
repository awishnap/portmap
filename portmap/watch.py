"""Continuous port-watch mode: re-scans at an interval and highlights diffs."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Set, Tuple

from portmap.scanner import PortEntry, scan_ports


@dataclass
class WatchDiff:
    """Difference between two consecutive scans."""

    appeared: List[PortEntry] = field(default_factory=list)
    disappeared: List[PortEntry] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return bool(self.appeared or self.disappeared)


def _key(entry: PortEntry) -> Tuple[int, str]:
    return (entry.port, entry.proto)


def diff(previous: List[PortEntry], current: List[PortEntry]) -> WatchDiff:
    """Compute which ports appeared or disappeared between two snapshots."""
    prev_map: Dict[Tuple[int, str], PortEntry] = {_key(e): e for e in previous}
    curr_map: Dict[Tuple[int, str], PortEntry] = {_key(e): e for e in current}

    prev_keys: Set[Tuple[int, str]] = set(prev_map)
    curr_keys: Set[Tuple[int, str]] = set(curr_map)

    appeared = [curr_map[k] for k in (curr_keys - prev_keys)]
    disappeared = [prev_map[k] for k in (prev_keys - curr_keys)]
    return WatchDiff(appeared=sorted(appeared, key=lambda e: e.port),
                     disappeared=sorted(disappeared, key=lambda e: e.port))


def watch(
    ports: Optional[List[int]] = None,
    interval: float = 2.0,
    on_diff: Optional[Callable[[WatchDiff, List[PortEntry]], None]] = None,
    iterations: Optional[int] = None,
    _scan_fn: Callable[..., List[PortEntry]] = scan_ports,
) -> None:
    """Poll for port changes, calling *on_diff* whenever the snapshot changes.

    Parameters
    ----------
    ports:      restrict scan to these ports (``None`` → all)
    interval:   seconds between scans
    on_diff:    callback(diff, current_entries); defaults to a print summary
    iterations: stop after this many scans (``None`` → run forever)
    _scan_fn:   injectable scan function (for testing)
    """
    if on_diff is None:
        on_diff = _default_on_diff

    previous: List[PortEntry] = []
    count = 0

    while iterations is None or count < iterations:
        current = _scan_fn(ports=ports)
        d = diff(previous, current)
        if d.has_changes:
            on_diff(d, current)
        previous = current
        count += 1
        if iterations is None or count < iterations:
            time.sleep(interval)


def _default_on_diff(d: WatchDiff, current: List[PortEntry]) -> None:  # pragma: no cover
    for e in d.appeared:
        print(f"  [+] {e.port}/{e.proto}  {e.process or ''}  {e.label}")
    for e in d.disappeared:
        print(f"  [-] {e.port}/{e.proto}  {e.process or ''}  {e.label}")
