"""Port scanner module: scans local open TCP/UDP ports and retrieves process context."""

import socket
import psutil
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class PortEntry:
    port: int
    protocol: str
    pid: Optional[int]
    process_name: Optional[str]
    process_cmdline: list[str] = field(default_factory=list)
    status: str = "LISTEN"
    local_address: str = "127.0.0.1"

    def label(self) -> str:
        """Return a human-readable label for this port entry."""
        if self.process_name:
            return f"{self.process_name} (pid={self.pid})"
        return "unknown"


def _get_process_info(pid: Optional[int]) -> tuple[Optional[str], list[str]]:
    """Retrieve process name and command line for a given PID."""
    if pid is None:
        return None, []
    try:
        proc = psutil.Process(pid)
        return proc.name(), proc.cmdline()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None, []


def scan_ports(protocols: list[str] | None = None) -> list[PortEntry]:
    """Scan all listening ports and enrich with process context.

    Args:
        protocols: List of protocols to include, e.g. ['tcp', 'udp'].
                   Defaults to both TCP and UDP.

    Returns:
        List of PortEntry objects sorted by port number.
    """
    if protocols is None:
        protocols = ["tcp", "udp"]

    entries: list[PortEntry] = []
    seen: set[tuple[int, str]] = set()

    kind_map = {
        "tcp": psutil.AF_INET,
        "udp": psutil.AF_INET,
    }

    connections = psutil.net_connections(kind="inet")

    for conn in connections:
        proto = "tcp" if conn.type == socket.SOCK_STREAM else "udp"
        if proto not in protocols:
            continue
        if conn.status not in ("LISTEN", "") and proto == "tcp":
            continue
        if conn.laddr is None:
            continue

        port = conn.laddr.port
        key = (port, proto)
        if key in seen:
            continue
        seen.add(key)

        name, cmdline = _get_process_info(conn.pid)
        entries.append(
            PortEntry(
                port=port,
                protocol=proto,
                pid=conn.pid,
                process_name=name,
                process_cmdline=cmdline,
                status=conn.status or "LISTEN",
                local_address=conn.laddr.ip,
            )
        )

    return sorted(entries, key=lambda e: e.port)
