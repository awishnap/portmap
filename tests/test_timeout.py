"""Tests for portmap.timeout."""
from __future__ import annotations

import socket
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from portmap.timeout import (
    DEFAULT_TIMEOUT,
    MAX_TIMEOUT,
    MIN_TIMEOUT,
    TimeoutConfig,
    enrich,
    probe,
)


# ---------------------------------------------------------------------------
# TimeoutConfig
# ---------------------------------------------------------------------------

def test_default_timeout_is_applied():
    cfg = TimeoutConfig()
    assert cfg.for_port(80) == DEFAULT_TIMEOUT


def test_override_takes_precedence():
    cfg = TimeoutConfig(overrides={443: 0.5})
    assert cfg.for_port(443) == 0.5
    assert cfg.for_port(80) == DEFAULT_TIMEOUT


def test_set_override_updates_value():
    cfg = TimeoutConfig()
    cfg.set_override(22, 2.0)
    assert cfg.for_port(22) == 2.0


def test_remove_override_falls_back_to_default():
    cfg = TimeoutConfig(overrides={22: 2.0})
    cfg.remove_override(22)
    assert cfg.for_port(22) == DEFAULT_TIMEOUT


def test_invalid_default_raises():
    with pytest.raises(ValueError):
        TimeoutConfig(default=0.0)


def test_invalid_override_in_constructor_raises():
    with pytest.raises(ValueError):
        TimeoutConfig(overrides={80: 999.0})


def test_set_override_out_of_range_raises():
    cfg = TimeoutConfig()
    with pytest.raises(ValueError):
        cfg.set_override(80, MAX_TIMEOUT + 1)


def test_to_dict_roundtrip():
    cfg = TimeoutConfig(default=1.5, overrides={8080: 0.2})
    d = cfg.to_dict()
    restored = TimeoutConfig.from_dict(d)
    assert restored.default == 1.5
    assert restored.for_port(8080) == pytest.approx(0.2)


def test_from_dict_missing_keys_uses_defaults():
    cfg = TimeoutConfig.from_dict({})
    assert cfg.default == DEFAULT_TIMEOUT
    assert cfg.overrides == {}


# ---------------------------------------------------------------------------
# probe
# ---------------------------------------------------------------------------

def test_probe_returns_float_on_success():
    mock_ctx = MagicMock()
    mock_ctx.__enter__ = MagicMock(return_value=MagicMock())
    mock_ctx.__exit__ = MagicMock(return_value=False)
    with patch("portmap.timeout.socket.create_connection", return_value=mock_ctx):
        result = probe("127.0.0.1", 80, timeout=1.0)
    assert isinstance(result, float)
    assert result >= 0


def test_probe_returns_none_on_oserror():
    with patch(
        "portmap.timeout.socket.create_connection",
        side_effect=OSError("refused"),
    ):
        result = probe("127.0.0.1", 9, timeout=0.1)
    assert result is None


# ---------------------------------------------------------------------------
# enrich
# ---------------------------------------------------------------------------

def _entry(port: int) -> SimpleNamespace:
    return SimpleNamespace(port=port)


def test_enrich_adds_timeout_ms_attribute():
    entries = [_entry(80), _entry(443)]
    cfg = TimeoutConfig(default=1.0, overrides={443: 0.5})
    result = enrich(entries, cfg)
    assert result[0].timeout_ms == pytest.approx(1000.0)
    assert result[1].timeout_ms == pytest.approx(500.0)


def test_enrich_uses_default_config_when_none():
    entries = [_entry(8080)]
    result = enrich(entries)
    assert result[0].timeout_ms == pytest.approx(DEFAULT_TIMEOUT * 1000)


def test_enrich_returns_same_list():
    entries = [_entry(22)]
    result = enrich(entries, TimeoutConfig())
    assert result is entries
