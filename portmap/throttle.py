"""Scan throttle: limit how frequently a full port scan can be triggered."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable, Optional


@dataclass
class ThrottleConfig:
    """Configuration for scan throttling."""
    min_interval: float  # minimum seconds between scans
    max_scans_per_minute: int = 60


@dataclass
class Throttle:
    """Stateful throttle gate for scan operations."""
    config: ThrottleConfig
    _last_scan: Optional[float] = field(default=None, init=False, repr=False)
    _scan_times: list = field(default_factory=list, init=False, repr=False)
    _clock: Callable[[], float] = field(default=time.monotonic, init=False, repr=False)

    def __post_init__(self) -> None:
        if self.config.min_interval < 0:
            raise ValueError("min_interval must be non-negative")
        if self.config.max_scans_per_minute <= 0:
            raise ValueError("max_scans_per_minute must be positive")

    def allow(self) -> bool:
        """Return True if a scan is permitted right now."""
        now = self._clock()
        if self._last_scan is not None:
            if now - self._last_scan < self.config.min_interval:
                return False
        # Prune timestamps older than 60 seconds
        cutoff = now - 60.0
        self._scan_times = [t for t in self._scan_times if t > cutoff]
        if len(self._scan_times) >= self.config.max_scans_per_minute:
            return False
        return True

    def record(self) -> None:
        """Record that a scan just occurred."""
        now = self._clock()
        self._last_scan = now
        self._scan_times.append(now)

    def acquire(self) -> bool:
        """Check and record atomically. Returns True if scan is allowed."""
        if self.allow():
            self.record()
            return True
        return False

    def seconds_until_ready(self) -> float:
        """Estimate seconds until the next scan is permitted (0 if ready now)."""
        if self._last_scan is None:
            return 0.0
        now = self._clock()
        wait = self.config.min_interval - (now - self._last_scan)
        return max(0.0, wait)


def make_throttle(min_interval: float = 1.0, max_scans_per_minute: int = 30) -> Throttle:
    """Convenience factory for a Throttle with common defaults."""
    return Throttle(ThrottleConfig(min_interval=min_interval, max_scans_per_minute=max_scans_per_minute))
