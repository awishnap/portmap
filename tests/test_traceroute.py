"""Tests for portmap.traceroute and portmap.traceroute_cli."""
from __future__ import annotations

import socket
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from portmap.traceroute import (
    HopResult,
    TracerouteResult,
    enrich,
    probe,
)
from portmap.traceroute_cli import (
    _render_json,
    _render_text,
    build_traceroute_parser,
    run_traceroute,
)


# ---------------------------------------------------------------------------
# HopResult
# ---------------------------------------------------------------------------

def test_hop_display_with_rtt():
    hop = HopResult(ttl=1, address="10.0.0.1", rtt_ms=3.14)
    text = hop.display()
    assert "10.0.0.1" in text
    assert "3.14 ms" in text
    assert "1" in text


def test_hop_display_timeout():
    hop = HopResult(ttl=2, address=None, rtt_ms=None)
    assert "*" in hop.display()
    assert "timeout" in hop.display()


# ---------------------------------------------------------------------------
# TracerouteResult
# ---------------------------------------------------------------------------

def test_hop_count_reflects_hops():
    r = TracerouteResult(host="example.com")
    r.hops = [HopResult(1, "1.1.1.1", 5.0), HopResult(2, "2.2.2.2", 6.0)]
    assert r.hop_count == 2


def test_reached_defaults_false():
    r = TracerouteResult(host="x")
    assert r.reached is False


# ---------------------------------------------------------------------------
# probe() — socket-level mocking
# ---------------------------------------------------------------------------

def _make_sockets(dest_ip: str):
    """Return (recv_mock, send_mock) that simulate a one-hop route."""
    recv = MagicMock()
    recv.recvfrom.return_value = (b"", (dest_ip, 0))
    send = MagicMock()
    return recv, send


@patch("portmap.traceroute.socket.gethostbyname", return_value="93.184.216.34")
@patch("portmap.traceroute.socket.socket")
def test_probe_reached_on_first_hop(mock_socket_cls, mock_gethostbyname):
    dest = "93.184.216.34"
    recv_mock, send_mock = _make_sockets(dest)
    mock_socket_cls.side_effect = [recv_mock, send_mock]

    result = probe("example.com", max_hops=5, timeout=0.5)

    assert result.reached is True
    assert result.hop_count == 1
    assert result.hops[0].address == dest


@patch("portmap.traceroute.socket.gethostbyname", return_value="10.0.0.1")
@patch("portmap.traceroute.socket.socket")
def test_probe_timeout_hop_has_none_address(mock_socket_cls, _gethostbyname):
    recv_mock = MagicMock()
    recv_mock.recvfrom.side_effect = socket.timeout
    send_mock = MagicMock()
    mock_socket_cls.side_effect = [recv_mock, send_mock]

    result = probe("10.0.0.1", max_hops=1, timeout=0.1)

    assert result.hops[0].address is None
    assert result.hops[0].rtt_ms is None


# ---------------------------------------------------------------------------
# enrich()
# ---------------------------------------------------------------------------

def _e(**kwargs):
    defaults = dict(port=80, protocol="tcp", status="LISTEN", pid=None, process=None)
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


def test_enrich_skips_loopback():
    entry = _e(address="127.0.0.1")
    assert enrich(entry) is None


def test_enrich_skips_wildcard():
    entry = _e(address="0.0.0.0")
    assert enrich(entry) is None


@patch("portmap.traceroute.probe")
def test_enrich_calls_probe_for_public_ip(mock_probe):
    mock_probe.return_value = TracerouteResult(host="8.8.8.8", reached=True)
    entry = _e(remote_address="8.8.8.8")
    result = enrich(entry)
    mock_probe.assert_called_once_with("8.8.8.8")
    assert result.host == "8.8.8.8"


@patch("portmap.traceroute.probe", side_effect=OSError("permission denied"))
def test_enrich_returns_none_on_oserror(mock_probe):
    entry = _e(remote_address="8.8.8.8")
    assert enrich(entry) is None


# ---------------------------------------------------------------------------
# CLI rendering
# ---------------------------------------------------------------------------

def _result_fixture():
    r = TracerouteResult(host="1.2.3.4", reached=True)
    r.hops = [HopResult(1, "10.0.0.1", 2.5), HopResult(2, "1.2.3.4", 4.1)]
    return r


def test_render_text_contains_host():
    text = _render_text([_result_fixture()])
    assert "1.2.3.4" in text


def test_render_text_shows_hop_lines():
    text = _render_text([_result_fixture()])
    assert "10.0.0.1" in text


def test_render_json_is_valid():
    import json
    data = json.loads(_render_json([_result_fixture()]))
    assert isinstance(data, list)
    assert data[0]["host"] == "1.2.3.4"
    assert data[0]["reached"] is True
    assert len(data[0]["hops"]) == 2


def test_run_traceroute_text(capsys):
    parser = build_traceroute_parser()
    args = parser.parse_args(["127.0.0.1", "--max-hops", "1", "--format", "text"])
    with patch("portmap.traceroute_cli.probe") as mock_probe:
        r = TracerouteResult(host="127.0.0.1", reached=True)
        r.hops = [HopResult(1, "127.0.0.1", 0.1)]
        mock_probe.return_value = r
        code = run_traceroute(args)
    assert code == 0
    captured = capsys.readouterr()
    assert "127.0.0.1" in captured.out


def test_run_traceroute_json(capsys):
    parser = build_traceroute_parser()
    args = parser.parse_args(["8.8.8.8", "--format", "json"])
    with patch("portmap.traceroute_cli.probe") as mock_probe:
        mock_probe.return_value = TracerouteResult(host="8.8.8.8", reached=False)
        run_traceroute(args)
    import json
    out = json.loads(capsys.readouterr().out)
    assert out[0]["host"] == "8.8.8.8"


def test_run_traceroute_error_is_printed_to_stderr(capsys):
    parser = build_traceroute_parser()
    args = parser.parse_args(["bad.host"])
    with patch("portmap.traceroute_cli.probe", side_effect=OSError("fail")):
        code = run_traceroute(args)
    assert code == 0
    assert "error" in capsys.readouterr().err
