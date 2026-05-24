"""Lightweight CVE / known-vulnerability hints for open ports."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from portmap.scanner import PortEntry

# Minimal built-in advisory database keyed by (port, protocol)
_ADVISORIES: dict[tuple[int, str], list[str]] = {
    (21, "tcp"): ["CVE-2010-4221 (ProFTPD)", "Anonymous FTP may be enabled"],
    (22, "tcp"): ["CVE-2023-38408 (OpenSSH agent forwarding)"],
    (23, "tcp"): ["Telnet transmits credentials in plaintext"],
    (80, "tcp"): ["CVE-2021-41773 (Apache path traversal)"],
    (443, "tcp"): ["CVE-2022-0778 (OpenSSL infinite loop)"],
    (3306, "tcp"): ["CVE-2012-2122 (MySQL auth bypass)"],
    (5432, "tcp"): ["CVE-2019-10164 (PostgreSQL stack overflow)"],
    (6379, "tcp"): ["Redis exposed without auth by default"],
    (27017, "tcp"): ["MongoDB exposed without auth by default"],
    (9200, "tcp"): ["Elasticsearch exposed without auth by default"],
}


@dataclass
class VulnResult:
    port: int
    protocol: str
    advisories: List[str] = field(default_factory=list)

    @property
    def has_advisories(self) -> bool:
        return len(self.advisories) > 0

    def display(self) -> str:
        if not self.advisories:
            return f"{self.port}/{self.protocol}: no known advisories"
        lines = [f"{self.port}/{self.protocol}:"]
        for a in self.advisories:
            lines.append(f"  ! {a}")
        return "\n".join(lines)


def lookup(port: int, protocol: str = "tcp") -> VulnResult:
    """Return known advisories for *port*/*protocol*."""
    key = (port, protocol.lower())
    advisories = list(_ADVISORIES.get(key, []))
    return VulnResult(port=port, protocol=protocol.lower(), advisories=advisories)


def enrich(entries: list[PortEntry]) -> list[tuple[PortEntry, VulnResult]]:
    """Attach a VulnResult to every PortEntry."""
    return [(e, lookup(e.port, e.protocol)) for e in entries]


def flagged(entries: list[PortEntry]) -> list[tuple[PortEntry, VulnResult]]:
    """Return only entries that have at least one advisory."""
    return [(e, r) for e, r in enrich(entries) if r.has_advisories]
