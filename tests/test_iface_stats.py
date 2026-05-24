"""Tests for portmap.iface_stats."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from portmap.iface_stats import IfaceStats, _human, collect


def _counters(**kwargs):
    defaults = dict(
        bytes_sent=0, bytes_recv=0,
        packets_sent=0, packets_recv=0,
        errin=0, errout=0, dropin=0, dropout=0,
    )
    defaults.update(kwargs)
    m = MagicMock()
    for k, v in defaults.items():
        setattr(m, k, v)
    return m


def _stats(**kwargs) -> IfaceStats:
    defaults = dict(
        name="eth0", bytes_sent=0, bytes_recv=0,
        packets_sent=0, packets_recv=0,
        errin=0, errout=0, dropin=0, dropout=0,
    )
    defaults.update(kwargs)
    return IfaceStats(**defaults)


# --- _human ---

def test_human_bytes():
    assert _human(512) == "512.0 B"


def test_human_kilobytes():
    assert _human(2048) == "2.0 KB"


def test_human_megabytes():
    assert _human(3 * 1024 * 1024) == "3.0 MB"


# --- display helpers ---

def test_display_sent_formats():
    s = _stats(bytes_sent=1024)
    assert s.display_sent() == "1.0 KB"


def test_display_recv_formats():
    s = _stats(bytes_recv=2048)
    assert s.display_recv() == "2.0 KB"


# --- error_rate ---

def test_error_rate_none_when_no_packets():
    s = _stats()
    assert s.error_rate() is None


def test_error_rate_zero_when_no_errors():
    s = _stats(packets_sent=100, packets_recv=100)
    assert s.error_rate() == 0.0


def test_error_rate_calculated_correctly():
    s = _stats(packets_sent=100, packets_recv=100, errin=10, errout=10)
    assert s.error_rate() == pytest.approx(0.1)


# --- drop_rate ---

def test_drop_rate_none_when_no_packets():
    s = _stats()
    assert s.drop_rate() is None


def test_drop_rate_calculated_correctly():
    s = _stats(packets_sent=50, packets_recv=50, dropin=5, dropout=5)
    assert s.drop_rate() == pytest.approx(0.1)


# --- collect ---

def test_collect_returns_all_interfaces():
    fake = {"eth0": _counters(bytes_sent=100), "lo": _counters(bytes_recv=200)}
    with patch("portmap.iface_stats.psutil.net_io_counters", return_value=fake):
        result = collect()
    assert "eth0" in result
    assert "lo" in result


def test_collect_filters_by_name():
    fake = {"eth0": _counters(), "lo": _counters()}
    with patch("portmap.iface_stats.psutil.net_io_counters", return_value=fake):
        result = collect(names=["lo"])
    assert "lo" in result
    assert "eth0" not in result


def test_collect_maps_fields_correctly():
    fake = {"eth0": _counters(bytes_sent=999, packets_recv=42)}
    with patch("portmap.iface_stats.psutil.net_io_counters", return_value=fake):
        result = collect()
    assert result["eth0"].bytes_sent == 999
    assert result["eth0"].packets_recv == 42
