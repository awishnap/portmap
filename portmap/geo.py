"""Optional GeoIP enrichment for resolved entries."""
from __future__ import annotations

import socket
from dataclasses import dataclass, field
from typing import Optional

from portmap.scanner import PortEntry


@dataclass
class GeoEntry:
    """A PortEntry enriched with geographic metadata."""

    entry: PortEntry
    country: Optional[str] = None
    city: Optional[str] = None
    asn: Optional[str] = None
    raw: dict = field(default_factory=dict)

    @property
    def display_location(self) -> str:
        parts = [p for p in (self.city, self.country) if p]
        return ", ".join(parts) if parts else "unknown"


def _loopback_or_private(ip: str) -> bool:
    """Return True when the address is loopback or RFC-1918 private."""
    try:
        packed = socket.inet_aton(ip)
    except OSError:
        return True  # treat un-parseable addresses as private
    b = list(packed)
    return (
        b[0] == 127
        or b[0] == 10
        or (b[0] == 172 and 16 <= b[1] <= 31)
        or (b[0] == 192 and b[1] == 168)
    )


def lookup(ip: str, provider: Optional[object] = None) -> dict:
    """Return geo metadata dict for *ip*.

    *provider* may be any object with a ``city(ip)`` method that returns an
    object compatible with the ``geoip2`` ``CityResponse``.  When *provider*
    is ``None`` or the address is private/loopback the function returns an
    empty dict rather than raising.
    """
    if provider is None or _loopback_or_private(ip):
        return {}
    try:
        response = provider.city(ip)
        return {
            "country": getattr(getattr(response, "country", None), "name", None),
            "city": getattr(getattr(response, "city", None), "name", None),
            "asn": str(getattr(getattr(response, "autonomous_system_number", None), "__str__", lambda: "")()),
        }
    except Exception:
        return {}


def enrich(entry: PortEntry, provider: Optional[object] = None) -> GeoEntry:
    """Wrap *entry* in a :class:`GeoEntry` with geo metadata looked up from
    the entry's ``host`` field."""
    raw = lookup(entry.host, provider)
    return GeoEntry(
        entry=entry,
        country=raw.get("country"),
        city=raw.get("city"),
        asn=raw.get("asn"),
        raw=raw,
    )


def enrich_all(
    entries: list[PortEntry], provider: Optional[object] = None
) -> list[GeoEntry]:
    """Enrich a list of entries, returning a :class:`GeoEntry` for each."""
    return [enrich(e, provider) for e in entries]
