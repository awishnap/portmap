"""CIDR range utilities for filtering and matching port entries by IP address."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import List, Optional

from portmap.scanner import PortEntry


@dataclass
class CIDRFilter:
    """A set of CIDR blocks used to include or exclude entries."""

    allow: List[str] = field(default_factory=list)
    deny: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        # Validate all blocks up front
        for block in self.allow + self.deny:
            ipaddress.ip_network(block, strict=False)


def _parse_network(cidr: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    return ipaddress.ip_network(cidr, strict=False)


def _addr(entry: PortEntry) -> Optional[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Return the IP address object for an entry's host, or None on failure."""
    try:
        return ipaddress.ip_address(entry.host)
    except ValueError:
        return None


def matches_any(entry: PortEntry, cidrs: List[str]) -> bool:
    """Return True if the entry's host falls within any of the given CIDR blocks."""
    addr = _addr(entry)
    if addr is None:
        return False
    return any(addr in _parse_network(c) for c in cidrs)


def apply_filter(entries: List[PortEntry], cidr_filter: CIDRFilter) -> List[PortEntry]:
    """Filter entries according to allow/deny CIDR lists.

    - If *allow* is non-empty, only entries whose host matches are kept.
    - Entries whose host matches any *deny* block are then removed.
    """
    result = entries
    if cidr_filter.allow:
        result = [e for e in result if matches_any(e, cidr_filter.allow)]
    if cidr_filter.deny:
        result = [e for e in result if not matches_any(e, cidr_filter.deny)]
    return result


def summarise(entries: List[PortEntry]) -> dict:
    """Return a dict mapping each unique /24 (or /48 for IPv6) prefix to entry count."""
    counts: dict = {}
    for entry in entries:
        addr = _addr(entry)
        if addr is None:
            continue
        if isinstance(addr, ipaddress.IPv4Address):
            net = ipaddress.ip_network(f"{addr}/24", strict=False)
        else:
            net = ipaddress.ip_network(f"{addr}/48", strict=False)
        key = str(net)
        counts[key] = counts.get(key, 0) + 1
    return counts
