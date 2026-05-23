"""Built-in group definitions for portmap."""

from __future__ import annotations

from portmap.group import register_group
from portmap.scanner import PortEntry

_WEB_PORTS = {80, 443, 8080, 8443, 3000, 5000}
_DB_PORTS = {3306, 5432, 6379, 27017, 1521, 1433}
_SECURE_PORTS = {22, 443, 8443, 636, 989, 990, 993, 995}


def _web_hook(entry: PortEntry) -> bool:
    return entry.port in _WEB_PORTS


def _database_hook(entry: PortEntry) -> bool:
    return entry.port in _DB_PORTS


def _secure_hook(entry: PortEntry) -> bool:
    return entry.port in _SECURE_PORTS


def _loopback_hook(entry: PortEntry) -> bool:
    return entry.host.startswith("127.") or entry.host == "::1"


def _ephemeral_hook(entry: PortEntry) -> bool:
    """Ports in the common ephemeral range (49152-65535)."""
    return 49152 <= entry.port <= 65535


def register_all() -> None:
    """Register all built-in groups into the global registry."""
    register_group("web", _web_hook)
    register_group("database", _database_hook)
    register_group("secure", _secure_hook)
    register_group("loopback", _loopback_hook)
    register_group("ephemeral", _ephemeral_hook)
