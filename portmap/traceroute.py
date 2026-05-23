"""Lightweight traceroute / hop-count probe for discovered ports."""
from __future__ import annotations

import socket
import time
from dataclasses import dataclass, field
from typing import List, Optional

from portmap.scanner import PortEntry

_MAX_HOPS = 30
_TIMEOUT = 1.0
_PORT = 33434  # classic UDP traceroute destination port


@dataclass
class HopResult:
    ttl: int
    address: Optional[str]
    rtt_ms: Optional[float]

    def display(self) -> str:
        addr = self.address or "*"
        rtt = f"{self.rtt_ms:.2f} ms" if self.rtt_ms is not None else "timeout"
        return f"{self.ttl:>3}  {addr:<20}  {rtt}"


@dataclass
class TracerouteResult:
    host: str
    hops: List[HopResult] = field(default_factory=list)
    reached: bool = False

    @property
    def hop_count(self) -> int:
        return len(self.hops)


def probe(host: str, max_hops: int = _MAX_HOPS, timeout: float = _TIMEOUT) -> TracerouteResult:
    """Run a UDP/ICMP traceroute toward *host* and return structured hop data."""
    result = TracerouteResult(host=host)
    dest_ip = socket.gethostbyname(host)

    recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    recv_sock.settimeout(timeout)

    send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)

    try:
        for ttl in range(1, max_hops + 1):
            send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
            t0 = time.perf_counter()
            send_sock.sendto(b"", (dest_ip, _PORT))
            try:
                _, addr_info = recv_sock.recvfrom(512)
                rtt = (time.perf_counter() - t0) * 1000
                hop_addr = addr_info[0]
            except socket.timeout:
                hop_addr = None
                rtt = None

            result.hops.append(HopResult(ttl=ttl, address=hop_addr, rtt_ms=rtt))

            if hop_addr == dest_ip:
                result.reached = True
                break
    finally:
        send_sock.close()
        recv_sock.close()

    return result


def enrich(entry: PortEntry, **kwargs) -> Optional[TracerouteResult]:
    """Attach a traceroute result to a port entry's remote address if available."""
    host = getattr(entry, "remote_address", None) or getattr(entry, "address", None)
    if not host or host in ("0.0.0.0", "::", "127.0.0.1", "::1"):
        return None
    try:
        return probe(host, **kwargs)
    except (OSError, socket.error):
        return None
