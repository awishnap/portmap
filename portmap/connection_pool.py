"""Connection pool tracker — monitors active connection counts per port."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

import psutil

from portmap.scanner import PortEntry


@dataclass
class PoolEntry:
    port: int
    protocol: str
    pid: Optional[int]
    process: Optional[str]
    established: int
    time_wait: int
    close_wait: int
    total: int

    def display_state(self) -> str:
        parts = []
        if self.established:
            parts.append(f"ESTAB={self.established}")
        if self.time_wait:
            parts.append(f"TIME_WAIT={self.time_wait}")
        if self.close_wait:
            parts.append(f"CLOSE_WAIT={self.close_wait}")
        return ", ".join(parts) if parts else "idle"


def _count_states(conns: list) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for c in conns:
        s = (c.status or "UNKNOWN").upper()
        counts[s] = counts.get(s, 0) + 1
    return counts


def measure(port: int, protocol: str = "tcp") -> PoolEntry:
    """Return connection pool stats for a single port."""
    kind = protocol.lower()
    try:
        conns = psutil.net_connections(kind=kind)
    except (psutil.AccessDenied, OSError):
        conns = []

    relevant = [c for c in conns if c.laddr and c.laddr.port == port]
    counts = _count_states(relevant)

    pid: Optional[int] = None
    process: Optional[str] = None
    for c in relevant:
        if c.pid:
            pid = c.pid
            try:
                process = psutil.Process(pid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
            break

    established = counts.get("ESTABLISHED", 0)
    time_wait = counts.get("TIME_WAIT", 0)
    close_wait = counts.get("CLOSE_WAIT", 0)
    total = sum(counts.values())

    return PoolEntry(
        port=port,
        protocol=kind,
        pid=pid,
        process=process,
        established=established,
        time_wait=time_wait,
        close_wait=close_wait,
        total=total,
    )


def enrich(entries: List[PortEntry]) -> List[PoolEntry]:
    """Enrich a list of PortEntry objects with connection pool data."""
    return [measure(e.port, e.protocol) for e in entries]
