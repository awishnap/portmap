"""TCP connect latency measurement for open ports."""
from __future__ import annotations

import socket
import time
from dataclasses import dataclass
from typing import List, Optional

from portmap.scanner import PortEntry


@dataclass
class LatencyResult:
    port: int
    protocol: str
    host: str
    latency_ms: Optional[float]  # None means unreachable / timed out

    def display(self) -> str:
        if self.latency_ms is None:
            return f"{self.host}:{self.port}/{self.protocol}  timeout"
        return f"{self.host}:{self.port}/{self.protocol}  {self.latency_ms:.2f} ms"


def measure(host: str, port: int, timeout: float = 1.0) -> Optional[float]:
    """Return TCP connect latency in milliseconds, or None on failure."""
    try:
        start = time.perf_counter()
        with socket.create_connection((host, port), timeout=timeout):
            pass
        elapsed = time.perf_counter() - start
        return round(elapsed * 1000, 3)
    except (OSError, socket.timeout):
        return None


def probe(entry: PortEntry, host: str = "127.0.0.1", timeout: float = 1.0) -> LatencyResult:
    """Probe a single PortEntry and return a LatencyResult."""
    latency = measure(host, entry.port, timeout=timeout) if entry.protocol == "tcp" else None
    return LatencyResult(
        port=entry.port,
        protocol=entry.protocol,
        host=host,
        latency_ms=latency,
    )


def enrich(entries: List[PortEntry], host: str = "127.0.0.1", timeout: float = 1.0) -> List[LatencyResult]:
    """Probe all entries and return latency results in the same order."""
    return [probe(e, host=host, timeout=timeout) for e in entries]
