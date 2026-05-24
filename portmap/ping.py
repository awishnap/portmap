"""ICMP/TCP ping utility for checking host reachability and round-trip time."""
from __future__ import annotations

import socket
import time
from dataclasses import dataclass
from typing import Optional

DEFAULT_TIMEOUT: float = 2.0
DEFAULT_TCP_PORT: int = 80


@dataclass
class PingResult:
    host: str
    port: int
    reachable: bool
    rtt_ms: Optional[float]  # None on timeout / error
    method: str  # "tcp" or "icmp"

    def display(self) -> str:
        if not self.reachable:
            return f"{self.host}:{self.port} unreachable ({self.method})"
        rtt = f"{self.rtt_ms:.2f} ms" if self.rtt_ms is not None else "n/a"
        return f"{self.host}:{self.port} reachable via {self.method} — {rtt}"


def tcp_ping(
    host: str,
    port: int = DEFAULT_TCP_PORT,
    timeout: float = DEFAULT_TIMEOUT,
) -> PingResult:
    """Attempt a TCP connect and measure round-trip time."""
    start = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            rtt_ms = (time.monotonic() - start) * 1000.0
            return PingResult(
                host=host,
                port=port,
                reachable=True,
                rtt_ms=rtt_ms,
                method="tcp",
            )
    except OSError:
        return PingResult(
            host=host,
            port=port,
            reachable=False,
            rtt_ms=None,
            method="tcp",
        )


def probe(host: str, ports: list[int], timeout: float = DEFAULT_TIMEOUT) -> list[PingResult]:
    """Ping *host* on each port in *ports* and return all results."""
    return [tcp_ping(host, port, timeout) for port in ports]


def enrich(entries: list, timeout: float = DEFAULT_TIMEOUT) -> list[PingResult]:
    """Convenience wrapper: ping the local host for each PortEntry in *entries*."""
    results: list[PingResult] = []
    for entry in entries:
        host = getattr(entry, "host", "127.0.0.1") or "127.0.0.1"
        port = entry.port
        results.append(tcp_ping(host, port, timeout))
    return results
