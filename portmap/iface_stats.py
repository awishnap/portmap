"""Network interface traffic statistics collection."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional

import psutil


@dataclass
class IfaceStats:
    name: str
    bytes_sent: int
    bytes_recv: int
    packets_sent: int
    packets_recv: int
    errin: int
    errout: int
    dropin: int
    dropout: int

    def display_sent(self) -> str:
        return _human(self.bytes_sent)

    def display_recv(self) -> str:
        return _human(self.bytes_recv)

    def error_rate(self) -> Optional[float]:
        total = self.packets_sent + self.packets_recv
        if total == 0:
            return None
        return (self.errin + self.errout) / total

    def drop_rate(self) -> Optional[float]:
        total = self.packets_sent + self.packets_recv
        if total == 0:
            return None
        return (self.dropin + self.dropout) / total


def _human(n: int) -> str:
    """Format byte count as a human-readable string."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n //= 1024
    return f"{n:.1f} PB"


def collect(names: Optional[List[str]] = None) -> Dict[str, IfaceStats]:
    """Return IfaceStats for all (or selected) interfaces."""
    raw: Dict[str, psutil._common.snetio] = psutil.net_io_counters(pernic=True)
    result: Dict[str, IfaceStats] = {}
    for name, counters in raw.items():
        if names and name not in names:
            continue
        result[name] = IfaceStats(
            name=name,
            bytes_sent=counters.bytes_sent,
            bytes_recv=counters.bytes_recv,
            packets_sent=counters.packets_sent,
            packets_recv=counters.packets_recv,
            errin=counters.errin,
            errout=counters.errout,
            dropin=counters.dropin,
            dropout=counters.dropout,
        )
    return result


def enrich(entries: List[IfaceStats], names: Optional[List[str]] = None) -> Dict[str, IfaceStats]:
    """Collect fresh stats and merge with provided interface names."""
    want = names or [e.name for e in entries]
    return collect(want)
