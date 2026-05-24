"""Port health checking — TCP reachability probes with status classification."""
from __future__ import annotations

import socket
from dataclasses import dataclass, field
from typing import Optional, List

from portmap.scanner import PortEntry


@dataclass
class HealthResult:
    port: int
    protocol: str
    host: str
    reachable: bool
    latency_ms: Optional[float]  # None when not reachable
    error: Optional[str] = field(default=None)

    @property
    def status(self) -> str:
        """Human-readable status string."""
        return "up" if self.reachable else "down"

    def display(self) -> str:
        if self.reachable and self.latency_ms is not None:
            return f"{self.host}:{self.port}/{self.protocol} {self.status} ({self.latency_ms:.1f} ms)"
        return f"{self.host}:{self.port}/{self.protocol} {self.status}"


def check(host: str, port: int, protocol: str = "tcp", timeout: float = 2.0) -> HealthResult:
    """Probe a single TCP port and return a HealthResult."""
    if protocol.lower() != "tcp":
        return HealthResult(port=port, protocol=protocol, host=host,
                            reachable=False, latency_ms=None,
                            error="only TCP probes are supported")
    import time
    try:
        start = time.perf_counter()
        with socket.create_connection((host, port), timeout=timeout):
            elapsed = (time.perf_counter() - start) * 1000
        return HealthResult(port=port, protocol=protocol, host=host,
                            reachable=True, latency_ms=round(elapsed, 2))
    except OSError as exc:
        return HealthResult(port=port, protocol=protocol, host=host,
                            reachable=False, latency_ms=None, error=str(exc))


def enrich(entries: List[PortEntry], host: str = "127.0.0.1",
           timeout: float = 2.0) -> List[HealthResult]:
    """Run health checks against a list of PortEntry objects."""
    return [check(host, e.port, e.protocol, timeout) for e in entries]
