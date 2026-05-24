"""Adaptive scan rate controller — adjusts concurrency based on recent error rates."""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Optional

_MIN_WORKERS = 1
_MAX_WORKERS = 256
_WINDOW = 60.0  # seconds


@dataclass
class ScanRateController:
    """Tracks scan outcomes and recommends a worker-count for the next batch."""

    initial_workers: int = 32
    target_error_rate: float = 0.05  # 5 %
    scale_up_factor: float = 1.25
    scale_down_factor: float = 0.75
    min_workers: int = _MIN_WORKERS
    max_workers: int = _MAX_WORKERS

    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)
    _success: int = field(default=0, init=False, repr=False)
    _error: int = field(default=0, init=False, repr=False)
    _window_start: float = field(default_factory=time.monotonic, init=False, repr=False)
    _current_workers: int = field(default=0, init=False, repr=False)

    def __post_init__(self) -> None:
        if not (0.0 < self.target_error_rate < 1.0):
            raise ValueError("target_error_rate must be between 0 and 1 exclusive")
        if self.initial_workers < _MIN_WORKERS:
            raise ValueError("initial_workers must be >= 1")
        self._current_workers = self.initial_workers

    # ------------------------------------------------------------------
    def record_success(self) -> None:
        with self._lock:
            self._success += 1

    def record_error(self) -> None:
        with self._lock:
            self._error += 1

    @property
    def error_rate(self) -> Optional[float]:
        """Current error rate in the observation window; None if no data."""
        with self._lock:
            total = self._success + self._error
            return None if total == 0 else self._error / total

    @property
    def current_workers(self) -> int:
        return self._current_workers

    def recommend(self) -> int:
        """Compute next worker count based on observed error rate and reset counters."""
        with self._lock:
            rate = self.error_rate
            if rate is None:
                return self._current_workers

            if rate > self.target_error_rate:
                next_w = int(self._current_workers * self.scale_down_factor)
            else:
                next_w = int(self._current_workers * self.scale_up_factor)

            self._current_workers = max(self.min_workers, min(self.max_workers, next_w))
            self._success = 0
            self._error = 0
            self._window_start = time.monotonic()
            return self._current_workers

    def reset(self) -> None:
        with self._lock:
            self._success = 0
            self._error = 0
            self._current_workers = self.initial_workers
            self._window_start = time.monotonic()
