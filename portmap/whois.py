"""WHOIS lookup enrichment for remote IP addresses found in port entries."""

from __future__ import annotations

import socket
import re
from dataclasses import dataclass, field
from typing import Optional, List

from portmap.scanner import PortEntry

_WHOIS_PORT = 43
_WHOIS_HOST = "whois.iana.org"
_TIMEOUT = 5.0
_BUFSIZE = 4096


@dataclass
class WhoisResult:
    ip: str
    org: Optional[str] = None
    country: Optional[str] = None
    cidr: Optional[str] = None
    raw: str = ""

    def display(self) -> str:
        parts = []
        if self.org:
            parts.append(self.org)
        if self.country:
            parts.append(self.country)
        if self.cidr:
            parts.append(self.cidr)
        return " | ".join(parts) if parts else "unknown"


def _query(ip: str, server: str = _WHOIS_HOST, timeout: float = _TIMEOUT) -> str:
    """Send a raw WHOIS query and return the response text."""
    try:
        with socket.create_connection((server, _WHOIS_PORT), timeout=timeout) as sock:
            sock.sendall((ip + "\r\n").encode())
            chunks: List[bytes] = []
            while True:
                chunk = sock.recv(_BUFSIZE)
                if not chunk:
                    break
                chunks.append(chunk)
            return b"".join(chunks).decode(errors="replace")
    except OSError:
        return ""


def _parse(ip: str, raw: str) -> WhoisResult:
    """Extract key fields from raw WHOIS text."""
    result = WhoisResult(ip=ip, raw=raw)
    for line in raw.splitlines():
        lower = line.lower()
        if result.org is None and lower.startswith(("orgname:", "org-name:", "owner:")):
            result.org = line.split(":", 1)[1].strip()
        if result.country is None and re.match(r"^country:\s+", line, re.I):
            result.country = line.split(":", 1)[1].strip().upper()
        if result.cidr is None and re.match(r"^(cidr|inetnum):\s+", line, re.I):
            result.cidr = line.split(":", 1)[1].strip()
    return result


def lookup(ip: str, server: str = _WHOIS_HOST, timeout: float = _TIMEOUT) -> WhoisResult:
    """Perform a WHOIS lookup for *ip* and return a parsed WhoisResult."""
    raw = _query(ip, server=server, timeout=timeout)
    return _parse(ip, raw)


def enrich(entries: List[PortEntry], server: str = _WHOIS_HOST,
           timeout: float = _TIMEOUT) -> List[tuple[PortEntry, WhoisResult]]:
    """Return (entry, whois) pairs for every entry that has a remote address."""
    results = []
    seen: dict[str, WhoisResult] = {}
    for entry in entries:
        addr = entry.addr or ""
        if not addr:
            continue
        if addr not in seen:
            seen[addr] = lookup(addr, server=server, timeout=timeout)
        results.append((entry, seen[addr]))
    return results
