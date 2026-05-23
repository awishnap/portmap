"""Service map: resolve well-known port numbers to human-readable service names
and categorise them by tier (system, registered, dynamic)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

# Curated well-known services beyond what socket.getservbyport provides
_WELL_KNOWN: dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    3306: "mysql",
    5432: "postgresql",
    6379: "redis",
    27017: "mongodb",
    8080: "http-alt",
    8443: "https-alt",
    9200: "elasticsearch",
    5672: "amqp",
    15672: "rabbitmq-mgmt",
    2181: "zookeeper",
    9092: "kafka",
}


@dataclass(frozen=True)
class ServiceInfo:
    port: int
    name: str
    tier: str  # "system" | "registered" | "dynamic"


def tier(port: int) -> str:
    """Return the IANA tier for a port number."""
    if port < 1024:
        return "system"
    if port < 49152:
        return "registered"
    return "dynamic"


def lookup(port: int) -> Optional[ServiceInfo]:
    """Return ServiceInfo for *port*, or None if unknown."""
    name = _WELL_KNOWN.get(port)
    if name is None:
        import socket
        try:
            name = socket.getservbyport(port)
        except OSError:
            return None
    return ServiceInfo(port=port, name=name, tier=tier(port))


def enrich_entries(entries: list) -> list[dict]:
    """Return a list of dicts augmenting each PortEntry with service metadata."""
    result = []
    for entry in entries:
        info = lookup(entry.port)
        result.append({
            "port": entry.port,
            "protocol": entry.protocol,
            "label": entry.label,
            "service": info.name if info else None,
            "tier": info.tier if info else tier(entry.port),
        })
    return result
