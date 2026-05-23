"""Service fingerprinting — attempt to identify service banners on open ports."""

from __future__ import annotations

import socket
from dataclasses import dataclass, field
from typing import Optional

from portmap.scanner import PortEntry

_PROBES: dict[str, bytes] = {
    "http": b"HEAD / HTTP/1.0\r\n\r\n",
    "ftp": b"",
    "smtp": b"",
    "generic": b"\r\n",
}

_TIMEOUT = 2.0
_BANNER_LEN = 256


@dataclass
class FingerprintResult:
    port: int
    protocol: str
    banner: Optional[str] = None
    service_hint: Optional[str] = None
    error: Optional[str] = None
    raw: bytes = field(default_factory=bytes, repr=False)


def _detect_hint(banner: str) -> Optional[str]:
    lower = banner.lower()
    hints = [
        ("ssh", "SSH"),
        ("http", "HTTP"),
        ("ftp", "FTP"),
        ("smtp", "SMTP"),
        ("pop3", "POP3"),
        ("imap", "IMAP"),
        ("mysql", "MySQL"),
        ("redis", "Redis"),
        ("postgresql", "PostgreSQL"),
        ("mongodb", "MongoDB"),
    ]
    for keyword, label in hints:
        if keyword in lower:
            return label
    return None


def grab_banner(host: str, port: int, timeout: float = _TIMEOUT) -> FingerprintResult:
    """Connect to *host*:*port* and attempt to read a service banner."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            probe = _PROBES.get("http") if port in (80, 8080, 8000) else _PROBES["generic"]
            if probe:
                sock.sendall(probe)
            raw = sock.recv(_BANNER_LEN)
        banner = raw.decode("utf-8", errors="replace").strip()
        hint = _detect_hint(banner)
        return FingerprintResult(port=port, protocol="tcp", banner=banner, service_hint=hint, raw=raw)
    except OSError as exc:
        return FingerprintResult(port=port, protocol="tcp", error=str(exc))


def enrich(entries: list[PortEntry], host: str = "127.0.0.1", timeout: float = _TIMEOUT) -> list[FingerprintResult]:
    """Fingerprint every TCP entry in *entries* and return results."""
    results: list[FingerprintResult] = []
    for entry in entries:
        if entry.protocol.lower() != "tcp":
            continue
        results.append(grab_banner(host, entry.port, timeout=timeout))
    return results
