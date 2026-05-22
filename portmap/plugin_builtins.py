"""Built-in enrichment plugins shipped with portmap."""

from __future__ import annotations

from typing import List

from portmap.scanner import PortEntry
from portmap import plugin

# ---------------------------------------------------------------------------
# Well-known service labels
# ---------------------------------------------------------------------------

_WELL_KNOWN: dict[tuple[int, str], str] = {
    (22, "tcp"): "ssh",
    (80, "tcp"): "http",
    (443, "tcp"): "https",
    (3306, "tcp"): "mysql",
    (5432, "tcp"): "postgres",
    (6379, "tcp"): "redis",
    (27017, "tcp"): "mongodb",
    (8080, "tcp"): "http-alt",
    (8443, "tcp"): "https-alt",
    (5672, "tcp"): "amqp",
    (9200, "tcp"): "elasticsearch",
    (2181, "tcp"): "zookeeper",
}


def _well_known_hook(entries: List[PortEntry]) -> List[PortEntry]:
    """Append a well-known service tag to matching entries."""
    result: List[PortEntry] = []
    for entry in entries:
        svc = _WELL_KNOWN.get((entry.port, entry.protocol))
        if svc and svc not in (entry.label or ""):
            # Produce a new PortEntry with an enriched label
            new_label = f"{entry.label} [{svc}]" if entry.label else f"[{svc}]"
            entry = PortEntry(
                port=entry.port,
                protocol=entry.protocol,
                status=entry.status,
                pid=entry.pid,
                process=entry.process,
                label=new_label,
            )
        result.append(entry)
    return result


# ---------------------------------------------------------------------------
# Loopback annotation plugin
# ---------------------------------------------------------------------------

def _loopback_hook(entries: List[PortEntry]) -> List[PortEntry]:
    """Mark entries whose host is a loopback address."""
    result: List[PortEntry] = []
    for entry in entries:
        host = getattr(entry, "host", None) or ""
        if host in ("127.0.0.1", "::1", "localhost"):
            tag = "[loopback]"
            new_label = f"{entry.label} {tag}" if entry.label else tag
            entry = PortEntry(
                port=entry.port,
                protocol=entry.protocol,
                status=entry.status,
                pid=entry.pid,
                process=entry.process,
                label=new_label,
            )
        result.append(entry)
    return result


def register_all() -> None:
    """Register all built-in plugins."""
    plugin.register("well_known", _well_known_hook)
    plugin.register("loopback", _loopback_hook)
