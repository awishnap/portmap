"""OS fingerprinting via TTL analysis and banner heuristics."""
from __future__ import annotations

import socket
import struct
from dataclasses import dataclass, field
from typing import Optional

from portmap.scanner import PortEntry

# TTL-based OS guesses (common default TTL values)
_TTL_MAP: dict[int, str] = {
    64: "Linux / macOS",
    128: "Windows",
    255: "Cisco / Solaris",
}

_BANNER_HINTS: list[tuple[bytes, str]] = [
    (b"OpenSSH", "Linux"),
    (b"Microsoft", "Windows"),
    (b"Ubuntu", "Linux (Ubuntu)"),
    (b"Debian", "Linux (Debian)"),
    (b"FreeBSD", "FreeBSD"),
    (b"Darwin", "macOS"),
]


@dataclass
class OSResult:
    entry: PortEntry
    os_guess: Optional[str] = None
    method: str = "unknown"
    confidence: str = "low"

    def display(self) -> str:
        if self.os_guess:
            return f"{self.os_guess} (via {self.method}, {self.confidence})"
        return "Unknown OS"


def _guess_from_ttl(ttl: int) -> Optional[str]:
    """Return an OS guess based on TTL proximity."""
    for threshold, name in sorted(_TTL_MAP.items()):
        if ttl <= threshold:
            return name
    return None


def _guess_from_banner(banner: bytes) -> Optional[str]:
    """Return an OS guess based on banner content."""
    for hint, os_name in _BANNER_HINTS:
        if hint.lower() in banner.lower():
            return os_name
    return None


def detect(entry: PortEntry, timeout: float = 1.0) -> OSResult:
    """Attempt OS detection by grabbing a banner on the open port."""
    try:
        with socket.create_connection(
            (entry.host, entry.port), timeout=timeout
        ) as sock:
            sock.settimeout(timeout)
            try:
                raw = sock.recv(256)
            except OSError:
                raw = b""

        if raw:
            guess = _guess_from_banner(raw)
            if guess:
                return OSResult(
                    entry=entry,
                    os_guess=guess,
                    method="banner",
                    confidence="medium",
                )
    except OSError:
        pass

    return OSResult(entry=entry)


def enrich(entries: list[PortEntry], timeout: float = 1.0) -> list[OSResult]:
    """Enrich a list of PortEntry objects with OS detection results."""
    return [detect(e, timeout=timeout) for e in entries]
