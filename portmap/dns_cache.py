"""DNS resolution cache with TTL-based expiry for portmap."""

from __future__ import annotations

import socket
import time
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple

_DEFAULT_TTL: int = 300  # seconds


@dataclass
class _CacheEntry:
    hostname: Optional[str]
    resolved_at: float
    ttl: int

    def is_expired(self) -> bool:
        return (time.monotonic() - self.resolved_at) > self.ttl


@dataclass
class DNSCache:
    ttl: int = _DEFAULT_TTL
    _store: Dict[str, _CacheEntry] = field(default_factory=dict, init=False, repr=False)

    def __post_init__(self) -> None:
        if self.ttl <= 0:
            raise ValueError("ttl must be a positive integer")

    def resolve(self, ip: str) -> Optional[str]:
        """Return cached hostname for *ip*, refreshing if stale."""
        entry = self._store.get(ip)
        if entry is not None and not entry.is_expired():
            return entry.hostname
        hostname = _reverse_lookup(ip)
        self._store[ip] = _CacheEntry(
            hostname=hostname,
            resolved_at=time.monotonic(),
            ttl=self.ttl,
        )
        return hostname

    def invalidate(self, ip: str) -> None:
        """Remove a single entry from the cache."""
        self._store.pop(ip, None)

    def clear(self) -> None:
        """Flush all cached entries."""
        self._store.clear()

    def stats(self) -> Tuple[int, int]:
        """Return (total, expired) entry counts."""
        total = len(self._store)
        expired = sum(1 for e in self._store.values() if e.is_expired())
        return total, expired


def _reverse_lookup(ip: str) -> Optional[str]:
    """Perform a blocking PTR lookup; return None on failure."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return None


# Module-level shared cache instance.
_default_cache: DNSCache = DNSCache()


def resolve(ip: str, cache: Optional[DNSCache] = None) -> Optional[str]:
    """Resolve *ip* using the provided cache (or the shared default)."""
    return (cache or _default_cache).resolve(ip)


def clear_default_cache() -> None:
    """Clear the shared default cache."""
    _default_cache.clear()
