"""Retry policy for transient scan/probe failures."""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable, Optional, TypeVar

T = TypeVar("T")

_DEFAULT_DELAYS = (0.1, 0.25, 0.5)  # seconds between attempts


@dataclass
class RetryConfig:
    """Configuration for retry behaviour."""

    max_attempts: int = 3
    delays: tuple[float, ...] = field(default_factory=lambda: _DEFAULT_DELAYS)
    exceptions: tuple[type[Exception], ...] = field(
        default_factory=lambda: (OSError, ConnectionRefusedError, TimeoutError)
    )

    def __post_init__(self) -> None:
        if self.max_attempts < 1:
            raise ValueError("max_attempts must be >= 1")
        if any(d < 0 for d in self.delays):
            raise ValueError("delays must be non-negative")

    def delay_for(self, attempt: int) -> float:
        """Return the sleep duration before *attempt* (0-indexed)."""
        if attempt == 0 or not self.delays:
            return 0.0
        idx = min(attempt - 1, len(self.delays) - 1)
        return self.delays[idx]


@dataclass
class RetryResult:
    """Outcome of a retried call."""

    value: object
    attempts: int
    success: bool
    last_error: Optional[Exception] = None

    def __bool__(self) -> bool:  # pragma: no cover
        return self.success


def with_retry(
    fn: Callable[[], T],
    config: Optional[RetryConfig] = None,
    *,
    _sleep: Callable[[float], None] = time.sleep,
) -> RetryResult:
    """Call *fn* up to *config.max_attempts* times, retrying on allowed exceptions.

    Parameters
    ----------
    fn:
        Zero-argument callable to invoke.
    config:
        :class:`RetryConfig` instance; defaults are used when *None*.
    _sleep:
        Injection point for the sleep function (used in tests).
    """
    cfg = config or RetryConfig()
    last_err: Optional[Exception] = None

    for attempt in range(cfg.max_attempts):
        delay = cfg.delay_for(attempt)
        if delay > 0:
            _sleep(delay)
        try:
            result = fn()
            return RetryResult(value=result, attempts=attempt + 1, success=True)
        except cfg.exceptions as exc:  # type: ignore[misc]
            last_err = exc

    return RetryResult(
        value=None,
        attempts=cfg.max_attempts,
        success=False,
        last_error=last_err,
    )
