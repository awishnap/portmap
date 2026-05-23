"""Rate limiting and scan throttle controls for portmap."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class RateLimiter:
    """Token-bucket rate limiter for port scan operations."""

    max_per_second: float
    _tokens: float = field(init=False)
    _last_check: float = field(init=False)

    def __post_init__(self) -> None:
        if self.max_per_second <= 0:
            raise ValueError("max_per_second must be positive")
        self._tokens = self.max_per_second
        self._last_check = time.monotonic()

    def acquire(self) -> None:
        """Block until a token is available."""
        while not self._try_acquire():
            time.sleep(0.01)

    def _try_acquire(self) -> bool:
        now = time.monotonic()
        elapsed = now - self._last_check
        self._last_check = now
        self._tokens = min(
            self.max_per_second,
            self._tokens + elapsed * self.max_per_second,
        )
        if self._tokens >= 1.0:
            self._tokens -= 1.0
            return True
        return False

    @property
    def available(self) -> float:
        """Return current token count (informational)."""
        return self._tokens


@dataclass
class ScanThrottle:
    """High-level throttle wrapper used by the scanner."""

    ports_per_second: float = 500.0
    delay_between_hosts: float = 0.0
    _limiter: Optional[RateLimiter] = field(init=False, default=None)

    def __post_init__(self) -> None:
        self._limiter = RateLimiter(max_per_second=self.ports_per_second)

    def tick(self) -> None:
        """Called once per port probe; enforces rate limit."""
        assert self._limiter is not None
        self._limiter.acquire()

    def host_pause(self) -> None:
        """Optional pause between scanning different hosts."""
        if self.delay_between_hosts > 0:
            time.sleep(self.delay_between_hosts)

    @classmethod
    def unlimited(cls) -> "ScanThrottle":
        """Return a throttle that imposes no meaningful delay."""
        return cls(ports_per_second=1_000_000.0)

    @classmethod
    def from_dict(cls, data: dict) -> "ScanThrottle":
        return cls(
            ports_per_second=float(data.get("ports_per_second", 500.0)),
            delay_between_hosts=float(data.get("delay_between_hosts", 0.0)),
        )

    def to_dict(self) -> dict:
        return {
            "ports_per_second": self.ports_per_second,
            "delay_between_hosts": self.delay_between_hosts,
        }
