"""Network interface enumeration and binding address resolution."""

from __future__ import annotations

import socket
import dataclasses
from typing import List, Optional

try:
    import psutil
    _HAS_PSUTIL = True
except ImportError:  # pragma: no cover
    _HAS_PSUTIL = False


@dataclasses.dataclass
class NetworkInterface:
    name: str
    addresses: List[str]
    is_loopback: bool
    is_up: bool

    def primary_address(self) -> Optional[str]:
        """Return the first non-link-local IPv4 address, or None."""
        for addr in self.addresses:
            if addr.startswith("169.254"):
                continue
            try:
                socket.inet_aton(addr)
                return addr
            except OSError:
                continue
        return None


def _loopback_names() -> frozenset:
    return frozenset({"lo", "lo0", "loopback"})


def list_interfaces() -> List[NetworkInterface]:
    """Return all network interfaces available on the host."""
    if not _HAS_PSUTIL:
        # Minimal fallback: hostname-based single entry
        try:
            host = socket.gethostname()
            addr = socket.gethostbyname(host)
        except OSError:
            addr = "127.0.0.1"
        return [
            NetworkInterface(
                name="default",
                addresses=[addr],
                is_loopback=(addr == "127.0.0.1"),
                is_up=True,
            )
        ]

    results: List[NetworkInterface] = []
    stats = psutil.net_if_stats()
    addrs = psutil.net_if_addrs()

    for name, addr_list in addrs.items():
        ipv4 = [
            a.address
            for a in addr_list
            if a.family == socket.AF_INET
        ]
        stat = stats.get(name)
        is_up = bool(stat and stat.isup)
        is_loopback = name.lower() in _loopback_names()
        results.append(
            NetworkInterface(
                name=name,
                addresses=ipv4,
                is_loopback=is_loopback,
                is_up=is_up,
            )
        )

    return results


def active_interfaces(include_loopback: bool = False) -> List[NetworkInterface]:
    """Return only interfaces that are up and optionally exclude loopback."""
    return [
        iface
        for iface in list_interfaces()
        if iface.is_up and (include_loopback or not iface.is_loopback)
    ]


def resolve_bind_address(interface_name: str) -> Optional[str]:
    """Return the primary IPv4 address for a named interface, or None."""
    for iface in list_interfaces():
        if iface.name == interface_name:
            return iface.primary_address()
    return None
