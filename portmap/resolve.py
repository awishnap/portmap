"""DNS reverse-lookup and service-name resolution for open ports."""

from __future__ import annotations

import socket
from dataclasses import dataclass, field
from typing import Optional

from portmap.scanner import PortEntry


@dataclass
class ResolvedEntry:
    """A PortEntry enriched with hostname and service name."""

    entry: PortEntry
    hostname: Optional[str] = None
    service: Optional[str] = None
    resolve_error: Optional[str] = None

    @property
    def display_host(self) -> str:
        return self.hostname or self.entry.host

    @property
    def display_service(self) -> str:
        return self.service or str(self.entry.port)


def reverse_lookup(host: str, timeout: float = 1.0) -> Optional[str]:
    """Return the PTR hostname for *host*, or None on failure."""
    old = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        name, _, _ = socket.gethostbyaddr(host)
        return name
    except (socket.herror, socket.gaierror, OSError):
        return None
    finally:
        socket.setdefaulttimeout(old)


def service_name(port: int, protocol: str = "tcp") -> Optional[str]:
    """Return the IANA service name for *port*/*protocol*, or None."""
    try:
        return socket.getservbyport(port, protocol.lower())
    except (OSError, OverflowError):
        return None


def resolve(entry: PortEntry, dns: bool = True, timeout: float = 1.0) -> ResolvedEntry:
    """Resolve a single PortEntry into a ResolvedEntry."""
    hostname: Optional[str] = None
    error: Optional[str] = None

    if dns:
        try:
            hostname = reverse_lookup(entry.host, timeout=timeout)
        except Exception as exc:  # pragma: no cover
            error = str(exc)

    svc = service_name(entry.port, entry.protocol)
    return ResolvedEntry(entry=entry, hostname=hostname, service=svc, resolve_error=error)


def resolve_all(
    entries: list[PortEntry],
    dns: bool = True,
    timeout: float = 1.0,
) -> list[ResolvedEntry]:
    """Resolve every entry in *entries* and return the enriched list."""
    return [resolve(e, dns=dns, timeout=timeout) for e in entries]
