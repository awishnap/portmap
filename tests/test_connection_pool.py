"""Tests for portmap.connection_pool."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from portmap.connection_pool import PoolEntry, _count_states, enrich, measure
from portmap.scanner import PortEntry


def _e(port: int = 8080, protocol: str = "tcp") -> PortEntry:
    return PortEntry(port=port, protocol=protocol, pid=None, process=None, status="open")


def _conn(port: int, status: str, pid: int = 0):
    c = MagicMock()
    c.laddr.port = port
    c.status = status
    c.pid = pid
    return c


def test_count_states_empty():
    assert _count_states([]) == {}


def test_count_states_groups_by_status():
    conns = [_conn(80, "ESTABLISHED"), _conn(80, "ESTABLISHED"), _conn(80, "TIME_WAIT")]
    counts = _count_states(conns)
    assert counts["ESTABLISHED"] == 2
    assert counts["TIME_WAIT"] == 1


def test_count_states_normalises_to_upper():
    conns = [_conn(80, "established")]
    counts = _count_states(conns)
    assert "ESTABLISHED" in counts


def test_pool_entry_display_state_idle():
    e = PoolEntry(port=9000, protocol="tcp", pid=None, process=None,
                  established=0, time_wait=0, close_wait=0, total=0)
    assert e.display_state() == "idle"


def test_pool_entry_display_state_with_values():
    e = PoolEntry(port=9000, protocol="tcp", pid=None, process=None,
                  established=3, time_wait=1, close_wait=0, total=4)
    text = e.display_state()
    assert "ESTAB=3" in text
    assert "TIME_WAIT=1" in text
    assert "CLOSE_WAIT" not in text


def test_pool_entry_display_state_close_wait():
    e = PoolEntry(port=9000, protocol="tcp", pid=None, process=None,
                  established=0, time_wait=0, close_wait=2, total=2)
    assert "CLOSE_WAIT=2" in e.display_state()


@patch("portmap.connection_pool.psutil.net_connections")
def test_measure_returns_pool_entry(mock_net):
    mock_net.return_value = [
        _conn(8080, "ESTABLISHED", pid=1234),
        _conn(8080, "TIME_WAIT", pid=0),
    ]
    with patch("portmap.connection_pool.psutil.Process") as mock_proc:
        mock_proc.return_value.name.return_value = "python"
        result = measure(8080, "tcp")

    assert result.port == 8080
    assert result.established == 1
    assert result.time_wait == 1
    assert result.total == 2
    assert result.process == "python"


@patch("portmap.connection_pool.psutil.net_connections")
def test_measure_ignores_other_ports(mock_net):
    mock_net.return_value = [_conn(9090, "ESTABLISHED")]
    result = measure(8080, "tcp")
    assert result.total == 0
    assert result.established == 0


@patch("portmap.connection_pool.psutil.net_connections", side_effect=OSError)
def test_measure_handles_oserror(mock_net):
    result = measure(8080)
    assert result.total == 0


@patch("portmap.connection_pool.psutil.net_connections")
def test_enrich_returns_one_per_entry(mock_net):
    mock_net.return_value = []
    entries = [_e(80), _e(443), _e(8080)]
    results = enrich(entries)
    assert len(results) == 3
    assert {r.port for r in results} == {80, 443, 8080}
