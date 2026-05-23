"""Tests for portmap.latency and portmap.latency_cli."""
from __future__ import annotations

import argparse
from unittest.mock import MagicMock, patch

import pytest

from portmap.latency import LatencyResult, enrich, measure, probe
from portmap.latency_cli import _render_json, _render_text, run_latency
from portmap.scanner import PortEntry


def _e(port: int = 80, protocol: str = "tcp") -> PortEntry:
    return PortEntry(port=port, protocol=protocol, status="open", pid=None, process=None)


# --- LatencyResult ---

def test_latency_result_display_with_value():
    r = LatencyResult(port=80, protocol="tcp", host="127.0.0.1", latency_ms=3.5)
    assert "3.50 ms" in r.display()
    assert "80" in r.display()


def test_latency_result_display_timeout():
    r = LatencyResult(port=80, protocol="tcp", host="127.0.0.1", latency_ms=None)
    assert "timeout" in r.display()


# --- measure ---

def test_measure_returns_float_on_success():
    with patch("portmap.latency.socket.create_connection") as mock_conn:
        mock_conn.return_value.__enter__ = MagicMock(return_value=None)
        mock_conn.return_value.__exit__ = MagicMock(return_value=False)
        result = measure("127.0.0.1", 80, timeout=1.0)
    assert isinstance(result, float)
    assert result >= 0


def test_measure_returns_none_on_oserror():
    with patch("portmap.latency.socket.create_connection", side_effect=OSError):
        result = measure("127.0.0.1", 9999, timeout=0.1)
    assert result is None


# --- probe ---

def test_probe_tcp_calls_measure():
    entry = _e(port=443, protocol="tcp")
    with patch("portmap.latency.measure", return_value=5.0) as mock_m:
        result = probe(entry, host="127.0.0.1")
    mock_m.assert_called_once_with("127.0.0.1", 443, timeout=1.0)
    assert result.latency_ms == 5.0
    assert result.port == 443


def test_probe_udp_skips_measure():
    entry = _e(port=53, protocol="udp")
    with patch("portmap.latency.measure") as mock_m:
        result = probe(entry)
    mock_m.assert_not_called()
    assert result.latency_ms is None


# --- enrich ---

def test_enrich_returns_one_result_per_entry():
    entries = [_e(80), _e(443), _e(53, "udp")]
    with patch("portmap.latency.measure", return_value=2.0):
        results = enrich(entries)
    assert len(results) == 3


def test_enrich_preserves_order():
    entries = [_e(8080), _e(22)]
    with patch("portmap.latency.measure", return_value=1.0):
        results = enrich(entries)
    assert results[0].port == 8080
    assert results[1].port == 22


# --- _render_text ---

def test_render_text_empty():
    assert "No results" in _render_text([])


def test_render_text_shows_latency():
    r = LatencyResult(port=80, protocol="tcp", host="127.0.0.1", latency_ms=1.23)
    out = _render_text([r])
    assert "1.23 ms" in out
    assert "80" in out


def test_render_text_shows_timeout():
    r = LatencyResult(port=80, protocol="tcp", host="127.0.0.1", latency_ms=None)
    assert "timeout" in _render_text([r])


# --- _render_json ---

def test_render_json_structure():
    import json
    r = LatencyResult(port=22, protocol="tcp", host="127.0.0.1", latency_ms=0.5)
    data = json.loads(_render_json([r]))
    assert len(data) == 1
    assert data[0]["port"] == 22
    assert data[0]["latency_ms"] == 0.5


# --- run_latency ---

def test_run_latency_text(capsys):
    args = argparse.Namespace(host="127.0.0.1", ports="80", timeout=1.0, fmt="text")
    with patch("portmap.latency_cli.scan_ports", return_value=[_e(80)]):
        with patch("portmap.latency_cli.enrich", return_value=[
            LatencyResult(port=80, protocol="tcp", host="127.0.0.1", latency_ms=2.0)
        ]):
            rc = run_latency(args)
    assert rc == 0
    captured = capsys.readouterr()
    assert "80" in captured.out


def test_run_latency_json(capsys):
    import json
    args = argparse.Namespace(host="127.0.0.1", ports="80", timeout=1.0, fmt="json")
    with patch("portmap.latency_cli.scan_ports", return_value=[_e(80)]):
        with patch("portmap.latency_cli.enrich", return_value=[
            LatencyResult(port=80, protocol="tcp", host="127.0.0.1", latency_ms=None)
        ]):
            rc = run_latency(args)
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert data[0]["port"] == 80
    assert data[0]["latency_ms"] is None
