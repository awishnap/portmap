"""Bandwidth estimation: measure bytes-per-second throughput on open ports."""
from __future__ import annotations

import socket
import time
from dataclasses import dataclass
from typing import Optional

from portmap.scanner import PortEntry

_PROBE_PAYLOAD = b"HEAD / HTTP/1.0\r\n\r\n"
_RECV_SIZE = 4096
_DEFAULT_TIMEOUT = 2.0


@dataclass
class BandwidthResult:
    port: int
    protocol: str
    host: str
    bytes_received: Optional[int]  # None on timeout / error
    elapsed_ms: Optional[float]

    def display(self) -> str:
        if self.bytes_received is None or self.elapsed_ms is None:
            return "timeout"
        if self.elapsed_ms == 0:
            return "0 ms"
        bps = self.bytes_received / (self.elapsed_ms / 1000.0)
        return f"{bps:,.0f} B/s  ({self.bytes_received} B in {self.elapsed_ms:.1f} ms)"


def measure(
    host: str,
    port: int,
    timeout: float = _DEFAULT_TIMEOUT,
    payload: bytes = _PROBE_PAYLOAD,
) -> tuple[Optional[int], Optional[float]]:
    """Return (bytes_received, elapsed_ms) or (None, None) on failure."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            t0 = time.monotonic()
            try:
                sock.sendall(payload)
            except OSError:
                pass
            data = b""
            try:
                chunk = sock.recv(_RECV_SIZE)
                while chunk:
                    data += chunk
                    sock.settimeout(0.1)
                    try:
                        chunk = sock.recv(_RECV_SIZE)
                    except (socket.timeout, BlockingIOError):
                        break
            except OSError:
                pass
            elapsed_ms = (time.monotonic() - t0) * 1000
            return len(data), elapsed_ms
    except OSError:
        return None, None


def probe(
    host: str,
    port: int,
    protocol: str = "tcp",
    timeout: float = _DEFAULT_TIMEOUT,
) -> BandwidthResult:
    bytes_received, elapsed_ms = measure(host, port, timeout)
    return BandwidthResult(
        port=port,
        protocol=protocol,
        host=host,
        bytes_received=bytes_received,
        elapsed_ms=elapsed_ms,
    )


def enrich(
    entries: list[PortEntry],
    host: str = "127.0.0.1",
    timeout: float = _DEFAULT_TIMEOUT,
) -> list[tuple[PortEntry, BandwidthResult]]:
    """Return each entry paired with its BandwidthResult."""
    results = []
    for entry in entries:
        if entry.protocol.lower() == "tcp":
            result = probe(host, entry.port, entry.protocol, timeout)
        else:
            result = BandwidthResult(
                port=entry.port,
                protocol=entry.protocol,
                host=host,
                bytes_received=None,
                elapsed_ms=None,
            )
        results.append((entry, result))
    return results
