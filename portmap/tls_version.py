"""TLS version detection for open ports."""
from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass, field
from typing import List, Optional

from portmap.scanner import PortEntry

_PROTOCOL_LABELS = {
    ssl.TLSVersion.TLSv1: "TLSv1.0",
    ssl.TLSVersion.TLSv1_1: "TLSv1.1",
    ssl.TLSVersion.TLSv1_2: "TLSv1.2",
    ssl.TLSVersion.TLSv1_3: "TLSv1.3",
}

_DEPRECATED = {"TLSv1.0", "TLSv1.1"}


@dataclass
class TLSVersionResult:
    port: int
    host: str
    version: Optional[str]  # e.g. "TLSv1.3" or None if no TLS
    cipher: Optional[str]
    deprecated: bool = field(init=False)

    def __post_init__(self) -> None:
        self.deprecated = self.version in _DEPRECATED

    def display(self) -> str:
        if self.version is None:
            return f"{self.host}:{self.port}  no TLS"
        flag = "  ⚠ deprecated" if self.deprecated else ""
        cipher_str = f"  cipher={self.cipher}" if self.cipher else ""
        return f"{self.host}:{self.port}  {self.version}{cipher_str}{flag}"


def detect(host: str, port: int, timeout: float = 2.0) -> TLSVersionResult:
    """Attempt a TLS handshake and return the negotiated version.

    Args:
        host: Hostname or IP address to connect to.
        port: TCP port number to connect to.
        timeout: Connection timeout in seconds.

    Returns:
        A TLSVersionResult with the negotiated TLS version and cipher suite,
        or version=None if the connection failed or no TLS was detected.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                ver = tls.version()  # e.g. "TLSv1.3"
                cipher_info = tls.cipher()
                cipher_name = cipher_info[0] if cipher_info else None
                return TLSVersionResult(port=port, host=host, version=ver, cipher=cipher_name)
    except (OSError, ssl.SSLError):
        return TLSVersionResult(port=port, host=host, version=None, cipher=None)


def enrich(entries: List[PortEntry], host: str = "127.0.0.1", timeout: float = 2.0) -> List[TLSVersionResult]:
    """Run TLS detection against a list of PortEntry objects.

    Args:
        entries: List of PortEntry objects whose ports will be probed.
        host: Hostname or IP address to connect to for each port.
        timeout: Connection timeout in seconds per port.

    Returns:
        A list of TLSVersionResult objects, one per entry.
    """
    return [detect(host, e.port, timeout=timeout) for e in entries]


def filter_deprecated(results: List[TLSVersionResult]) -> List[TLSVersionResult]:
    """Return only results where a deprecated TLS version was negotiated.

    Useful for quickly identifying ports that need to be upgraded.

    Args:
        results: List of TLSVersionResult objects to filter.

    Returns:
        A list containing only results with deprecated TLS versions.
    """
    return [r for r in results if r.deprecated]
