"""Tests for portmap.retry and portmap.retry_config."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from portmap.retry import RetryConfig, RetryResult, with_retry
from portmap.retry_config import load_retry_config, save_retry_config


# ---------------------------------------------------------------------------
# RetryConfig
# ---------------------------------------------------------------------------

def test_default_config_max_attempts():
    cfg = RetryConfig()
    assert cfg.max_attempts == 3


def test_invalid_max_attempts_raises():
    with pytest.raises(ValueError):
        RetryConfig(max_attempts=0)


def test_negative_delay_raises():
    with pytest.raises(ValueError):
        RetryConfig(delays=(-0.1,))


def test_delay_for_first_attempt_is_zero():
    cfg = RetryConfig(delays=(0.2, 0.5))
    assert cfg.delay_for(0) == 0.0


def test_delay_for_clamps_to_last():
    cfg = RetryConfig(delays=(0.1, 0.2))
    assert cfg.delay_for(10) == 0.2


def test_delay_for_second_attempt():
    cfg = RetryConfig(delays=(0.1, 0.3))
    assert cfg.delay_for(1) == pytest.approx(0.1)


# ---------------------------------------------------------------------------
# with_retry
# ---------------------------------------------------------------------------

def test_success_on_first_attempt():
    fn = MagicMock(return_value=42)
    result = with_retry(fn, _sleep=lambda _: None)
    assert result.success is True
    assert result.value == 42
    assert result.attempts == 1


def test_success_after_retries():
    calls = []

    def fn():
        calls.append(1)
        if len(calls) < 3:
            raise OSError("transient")
        return "ok"

    result = with_retry(fn, RetryConfig(max_attempts=3), _sleep=lambda _: None)
    assert result.success is True
    assert result.attempts == 3
    assert result.value == "ok"


def test_failure_exhausts_attempts():
    fn = MagicMock(side_effect=OSError("always fails"))
    cfg = RetryConfig(max_attempts=2)
    result = with_retry(fn, cfg, _sleep=lambda _: None)
    assert result.success is False
    assert result.attempts == 2
    assert isinstance(result.last_error, OSError)
    assert fn.call_count == 2


def test_non_retryable_exception_propagates():
    def fn():
        raise ValueError("not retryable")

    with pytest.raises(ValueError):
        with_retry(fn, _sleep=lambda _: None)


def test_sleep_called_between_attempts():
    slept: list[float] = []
    calls = [0]

    def fn():
        calls[0] += 1
        if calls[0] < 2:
            raise OSError()
        return True

    with_retry(fn, RetryConfig(max_attempts=2, delays=(0.5,)), _sleep=slept.append)
    assert len(slept) == 1
    assert slept[0] == pytest.approx(0.5)


def test_no_sleep_on_first_attempt():
    slept: list[float] = []
    with_retry(lambda: 1, _sleep=slept.append)
    assert slept == []


# ---------------------------------------------------------------------------
# retry_config persistence
# ---------------------------------------------------------------------------

def test_save_and_load_roundtrip(tmp_path):
    p = tmp_path / "retry.json"
    cfg = RetryConfig(max_attempts=5, delays=(0.2, 0.4, 0.8))
    save_retry_config(cfg, path=p)
    loaded = load_retry_config(path=p)
    assert loaded.max_attempts == 5
    assert loaded.delays == pytest.approx((0.2, 0.4, 0.8))


def test_load_missing_file_returns_defaults(tmp_path):
    cfg = load_retry_config(path=tmp_path / "nonexistent.json")
    assert cfg.max_attempts == 3


def test_load_corrupt_file_returns_defaults(tmp_path):
    p = tmp_path / "retry.json"
    p.write_text("{invalid json")
    cfg = load_retry_config(path=p)
    assert cfg.max_attempts == 3


def test_save_creates_parent_dirs(tmp_path):
    p = tmp_path / "nested" / "dir" / "retry.json"
    save_retry_config(RetryConfig(), path=p)
    assert p.exists()


def test_saved_file_is_valid_json(tmp_path):
    p = tmp_path / "retry.json"
    save_retry_config(RetryConfig(max_attempts=2, delays=(0.1,)), path=p)
    data = json.loads(p.read_text())
    assert data["max_attempts"] == 2
    assert data["delays"] == [0.1]
