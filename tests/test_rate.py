"""Tests for portmap.rate — RateLimiter and ScanThrottle."""

from __future__ import annotations

import time

import pytest

from portmap.rate import RateLimiter, ScanThrottle


# ---------------------------------------------------------------------------
# RateLimiter
# ---------------------------------------------------------------------------

class TestRateLimiter:
    def test_invalid_rate_raises(self):
        with pytest.raises(ValueError):
            RateLimiter(max_per_second=0)

    def test_negative_rate_raises(self):
        with pytest.raises(ValueError):
            RateLimiter(max_per_second=-1)

    def test_initial_tokens_equal_max(self):
        rl = RateLimiter(max_per_second=10.0)
        assert rl.available == pytest.approx(10.0)

    def test_acquire_decrements_tokens(self):
        rl = RateLimiter(max_per_second=1000.0)
        rl.acquire()
        assert rl.available < 1000.0

    def test_acquire_multiple_times_does_not_block_fast_limiter(self):
        rl = RateLimiter(max_per_second=10_000.0)
        start = time.monotonic()
        for _ in range(50):
            rl.acquire()
        elapsed = time.monotonic() - start
        # 50 tokens at 10k/s should complete well under 1 s
        assert elapsed < 1.0

    def test_tokens_capped_at_max(self):
        rl = RateLimiter(max_per_second=5.0)
        # Simulate a large time gap by manipulating _last_check
        rl._last_check -= 100.0
        rl._try_acquire()  # triggers refill
        assert rl.available <= 5.0


# ---------------------------------------------------------------------------
# ScanThrottle
# ---------------------------------------------------------------------------

class TestScanThrottle:
    def test_default_ports_per_second(self):
        st = ScanThrottle()
        assert st.ports_per_second == 500.0

    def test_unlimited_has_very_high_rate(self):
        st = ScanThrottle.unlimited()
        assert st.ports_per_second >= 1_000_000.0

    def test_tick_completes_quickly_for_unlimited(self):
        st = ScanThrottle.unlimited()
        start = time.monotonic()
        for _ in range(100):
            st.tick()
        assert time.monotonic() - start < 1.0

    def test_host_pause_skipped_when_zero(self):
        st = ScanThrottle(delay_between_hosts=0.0)
        start = time.monotonic()
        st.host_pause()
        assert time.monotonic() - start < 0.05

    def test_host_pause_waits(self):
        st = ScanThrottle(delay_between_hosts=0.05)
        start = time.monotonic()
        st.host_pause()
        assert time.monotonic() - start >= 0.04

    def test_from_dict_roundtrip(self):
        original = ScanThrottle(ports_per_second=250.0, delay_between_hosts=0.1)
        restored = ScanThrottle.from_dict(original.to_dict())
        assert restored.ports_per_second == pytest.approx(250.0)
        assert restored.delay_between_hosts == pytest.approx(0.1)

    def test_from_dict_defaults(self):
        st = ScanThrottle.from_dict({})
        assert st.ports_per_second == pytest.approx(500.0)
        assert st.delay_between_hosts == pytest.approx(0.0)

    def test_to_dict_keys(self):
        st = ScanThrottle()
        d = st.to_dict()
        assert "ports_per_second" in d
        assert "delay_between_hosts" in d
