"""Tests for portmap.throttle."""

from __future__ import annotations

import pytest
from portmap.throttle import Throttle, ThrottleConfig, make_throttle


def _throttle(min_interval: float = 1.0, max_per_min: int = 10) -> Throttle:
    return make_throttle(min_interval=min_interval, max_scans_per_minute=max_per_min)


def test_invalid_min_interval_raises() -> None:
    with pytest.raises(ValueError, match="min_interval"):
        Throttle(ThrottleConfig(min_interval=-1.0))


def test_invalid_max_scans_raises() -> None:
    with pytest.raises(ValueError, match="max_scans_per_minute"):
        Throttle(ThrottleConfig(min_interval=0.0, max_scans_per_minute=0))


def test_first_scan_always_allowed() -> None:
    t = _throttle(min_interval=5.0)
    assert t.allow() is True


def test_acquire_returns_true_on_first_call() -> None:
    t = _throttle()
    assert t.acquire() is True


def test_second_scan_blocked_within_interval() -> None:
    now = 1000.0
    t = _throttle(min_interval=5.0)
    t._clock = lambda: now
    t.acquire()
    # Still at the same timestamp
    assert t.allow() is False


def test_second_scan_allowed_after_interval() -> None:
    times = iter([1000.0, 1000.0, 1006.0, 1006.0])
    t = _throttle(min_interval=5.0)
    t._clock = lambda: next(times)
    t.acquire()
    assert t.allow() is True


def test_rate_limit_blocks_after_max_scans() -> None:
    counter = [0.0]

    def clock() -> float:
        # Advance by 0.1s each call so min_interval=0 never blocks
        counter[0] += 0.1
        return counter[0]

    t = _throttle(min_interval=0.0, max_per_min=3)
    t._clock = clock
    assert t.acquire() is True
    assert t.acquire() is True
    assert t.acquire() is True
    # Fourth call within 60s window should be blocked
    assert t.acquire() is False


def test_old_scan_times_pruned_outside_window() -> None:
    t = _throttle(min_interval=0.0, max_per_min=2)
    # Inject old timestamps manually (> 60s ago)
    t._scan_times = [1.0, 2.0]  # old, will be pruned
    t._last_scan = 1.0
    t._clock = lambda: 200.0  # now is 200s, so old entries pruned
    assert t.allow() is True


def test_seconds_until_ready_zero_before_first_scan() -> None:
    t = _throttle(min_interval=10.0)
    assert t.seconds_until_ready() == 0.0


def test_seconds_until_ready_after_scan() -> None:
    now = [1000.0]
    t = _throttle(min_interval=10.0)
    t._clock = lambda: now[0]
    t.acquire()
    now[0] = 1003.0
    assert abs(t.seconds_until_ready() - 7.0) < 0.01


def test_seconds_until_ready_zero_when_past_interval() -> None:
    now = [1000.0]
    t = _throttle(min_interval=5.0)
    t._clock = lambda: now[0]
    t.acquire()
    now[0] = 1010.0
    assert t.seconds_until_ready() == 0.0


def test_make_throttle_defaults() -> None:
    t = make_throttle()
    assert t.config.min_interval == 1.0
    assert t.config.max_scans_per_minute == 30
