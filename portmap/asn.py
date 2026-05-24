"""ASN (Autonomous System Number) lookup for IP addresses."""
from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field
from typing import Optional, List

from portmap.scanner import PortEntry


@dataclass
class ASNResult:
    ip: str
    asn: Optional[str] = None
    org: Optional[str] = None
    country: Optional[str] = None
    error: Optional[str] = None

    def display(self) -> str:
        if self.error:
            return f"{self.ip}  error: {self.error}"
        parts = [self.ip]
        if self.asn:
            parts.append(f"AS{self.asn}")
        if self.org:
            parts.append(self.org)
        if self.country:
            parts.append(f"[{self.country}]")  
        return "  ".join(parts) if len(parts) > 1 else f"{self.ip}  unknown"


def _is_private(ip: str) -> bool:
    """Return True if the address is loopback or RFC-1918 private."""
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_loopback or addr.is_private
    except ValueError:
        return False


def _cymru_query(ip: str) -> ASNResult:
    """Query Team Cymru's DNS-based ASN lookup service."""
    try:
        addr = ipaddress.ip_address(ip)
        reversed_ip = ".".join(reversed(addr.exploded.split(".")))
        hostname = f"{reversed_ip}.origin.asn.cymru.com"
        txt = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_DGRAM)
        # Fallback: use a raw TXT lookup via nslookup-style resolution
        # In real usage this would be a dnspython TXT lookup; we simulate here.
        _ = txt  # not used directly; kept for socket reachability check
        return ASNResult(ip=ip, error="dns-txt-unsupported")
    except OSError as exc:
        return ASNResult(ip=ip, error=str(exc))


def lookup(ip: str, *, timeout: float = 2.0) -> ASNResult:  # noqa: ARG001
    """Look up ASN information for *ip*.

    Returns a local/private sentinel for RFC-1918 / loopback addresses
    without making a network request.
    """
    if _is_private(ip):
        return ASNResult(ip=ip, asn=None, org="private", country="--")
    return _cymru_query(ip)


def enrich(entries: List[PortEntry]) -> List[ASNResult]:
    """Return an :class:`ASNResult` for every unique remote address in *entries*."""
    seen: dict[str, ASNResult] = {}
    results: List[ASNResult] = []
    for entry in entries:
        ip = entry.host
        if ip not in seen:
            seen[ip] = lookup(ip)
        results.append(seen[ip])
    return results
