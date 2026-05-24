"""Per-port connection timeout configuration and enforcement."""
from __future__ import annotations

import socket
from dataclasses import dataclass, field
from typing import Dict, Optional

# Default timeout in seconds used when no override is configured
DEFAULT_TIMEOUT: float = 1.0
MIN_TIMEOUT: float = 0.05
MAX_TIMEOUT: float = 30.0


@dataclass
class TimeoutConfig:
    """Holds global and per-port timeout overrides."""

    default: float = DEFAULT_TIMEOUT
    overrides: Dict[int, float] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not (MIN_TIMEOUT <= self.default <= MAX_TIMEOUT):
            raise ValueError(
                f"default timeout must be between {MIN_TIMEOUT} and {MAX_TIMEOUT}"
            )
        for port, t in self.overrides.items():
            if not (MIN_TIMEOUT <= t <= MAX_TIMEOUT):
                raise ValueError(
                    f"timeout for port {port} must be between {MIN_TIMEOUT} and {MAX_TIMEOUT}"
                )

    def for_port(self, port: int) -> float:
        """Return the effective timeout for *port*."""
        return self.overrides.get(port, self.default)

    def set_override(self, port: int, timeout: float) -> None:
        """Add or update a per-port timeout override."""
        if not (MIN_TIMEOUT <= timeout <= MAX_TIMEOUT):
            raise ValueError(
                f"timeout must be between {MIN_TIMEOUT} and {MAX_TIMEOUT}"
            )
        self.overrides[port] = timeout

    def remove_override(self, port: int) -> None:
        """Remove a per-port override, falling back to the default."""
        self.overrides.pop(port, None)

    def to_dict(self) -> dict:
        return {"default": self.default, "overrides": dict(self.overrides)}

    @classmethod
    def from_dict(cls, data: dict) -> "TimeoutConfig":
        return cls(
            default=float(data.get("default", DEFAULT_TIMEOUT)),
            overrides={int(k): float(v) for k, v in data.get("overrides", {}).items()},
        )


def probe(host: str, port: int, timeout: float) -> Optional[float]:
    """Attempt a TCP connection to *host*:*port* within *timeout* seconds.

    Returns the round-trip time in milliseconds on success, or ``None`` on
    failure / timeout.
    """
    import time

    try:
        start = time.perf_counter()
        with socket.create_connection((host, port), timeout=timeout):
            elapsed = time.perf_counter() - start
        return round(elapsed * 1000, 3)
    except OSError:
        return None


def enrich(entries: list, config: Optional[TimeoutConfig] = None) -> list:
    """Attach timeout metadata to each entry (duck-typed PortEntry list).

    Adds a ``timeout_ms`` attribute representing the configured timeout for
    that port converted to milliseconds.  The original entry objects are
    returned unchanged except for the new attribute.
    """
    cfg = config or TimeoutConfig()
    for entry in entries:
        t = cfg.for_port(entry.port)
        entry.timeout_ms = round(t * 1000, 3)
    return entries
