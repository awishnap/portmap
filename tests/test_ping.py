"""Tests for portmap.ping."""
from __future__ import annotations

import socket
from unittest.mock import MagicMock, patch

import pytest

from portmap.ping import (
    DEFAULT_TCP_PORT,
    PingResult,
    enrich,
    probe,
    tcp_ping,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _e(port: int = 8080, host: str = "127.0.0.1"):
    """Minimal fake PortEntry."""
    e = MagicMock()
    e.port = port
    e.host = host
    return e


# ---------------------------------------------------------------------------
# PingResult.display
# ---------------------------------------------------------------------------

def test_display_reachable_shows_rtt():
    r = PingResult(host="localhost", port=80, reachable=True, rtt_ms=3.5, method="tcp")
    text = r.display()
    assert "reachable" in text
    assert "3.50 ms" in text
    assert "tcp" in text


def test_display_unreachable_says_unreachable():
    r = PingResult(host="localhost", port=9999, reachable=False, rtt_ms=None, method="tcp")
    text = r.display()
    assert "unreachable" in text
    assert "9999" in text


def test_display_reachable_no_rtt_shows_na():
    r = PingResult(host="h", port=1, reachable=True, rtt_ms=None, method="tcp")
    assert "n/a" in r.display()


# ---------------------------------------------------------------------------
# tcp_ping — success path
# ---------------------------------------------------------------------------

def test_tcp_ping_returns_reachable_on_success():
    mock_sock = MagicMock()
    mock_sock.__enter__ = lambda s: s
    mock_sock.__exit__ = MagicMock(return_value=False)

    with patch("portmap.ping.socket.create_connection", return_value=mock_sock):
        result = tcp_ping("127.0.0.1", 80)

    assert result.reachable is True
    assert result.rtt_ms is not None
    assert result.rtt_ms >= 0.0
    assert result.method == "tcp"


def test_tcp_ping_returns_unreachable_on_oserror():
    with patch("portmap.ping.socket.create_connection", side_effect=OSError):
        result = tcp_ping("127.0.0.1", 9)

    assert result.reachable is False
    assert result.rtt_ms is None


def test_tcp_ping_uses_default_port_constant():
    """When called without explicit port the default should be DEFAULT_TCP_PORT."""
    with patch("portmap.ping.socket.create_connection", side_effect=OSError) as mock_cc:
        tcp_ping("host")
    args, _ = mock_cc.call_args
    assert args[0] == ("host", DEFAULT_TCP_PORT)


# ---------------------------------------------------------------------------
# probe
# ---------------------------------------------------------------------------

def test_probe_returns_one_result_per_port():
    with patch("portmap.ping.socket.create_connection", side_effect=OSError):
        results = probe("127.0.0.1", [80, 443, 8080])
    assert len(results) == 3
    assert all(isinstance(r, PingResult) for r in results)


def test_probe_empty_ports_returns_empty_list():
    results = probe("127.0.0.1", [])
    assert results == []


# ---------------------------------------------------------------------------
# enrich
# ---------------------------------------------------------------------------

def test_enrich_maps_entries_to_results():
    entries = [_e(80), _e(443)]
    with patch("portmap.ping.socket.create_connection", side_effect=OSError):
        results = enrich(entries)
    assert len(results) == 2
    assert results[0].port == 80
    assert results[1].port == 443


def test_enrich_falls_back_to_loopback_when_host_missing():
    e = MagicMock()
    e.port = 22
    e.host = None  # missing host
    with patch("portmap.ping.socket.create_connection", side_effect=OSError) as mock_cc:
        enrich([e])
    args, _ = mock_cc.call_args
    assert args[0][0] == "127.0.0.1"
