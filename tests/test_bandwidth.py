"""Tests for portmap.bandwidth."""
from __future__ import annotations

import socket
import threading
from unittest.mock import patch

import pytest

from portmap.bandwidth import BandwidthResult, enrich, measure, probe
from portmap.scanner import PortEntry


def _e(port: int = 8080, proto: str = "tcp") -> PortEntry:
    return PortEntry(port=port, protocol=proto, status="LISTEN", pid=None, process=None)


# ---------------------------------------------------------------------------
# BandwidthResult.display
# ---------------------------------------------------------------------------

def test_display_timeout():
    r = BandwidthResult(port=80, protocol="tcp", host="127.0.0.1",
                        bytes_received=None, elapsed_ms=None)
    assert r.display() == "timeout"


def test_display_zero_elapsed():
    r = BandwidthResult(port=80, protocol="tcp", host="127.0.0.1",
                        bytes_received=10, elapsed_ms=0)
    assert r.display() == "0 ms"


def test_display_with_values():
    r = BandwidthResult(port=80, protocol="tcp", host="127.0.0.1",
                        bytes_received=1000, elapsed_ms=500.0)
    text = r.display()
    assert "B/s" in text
    assert "1,000" in text or "2,000" in text  # 2000 B/s


# ---------------------------------------------------------------------------
# measure — happy path via real loopback server
# ---------------------------------------------------------------------------

def _start_echo_server() -> int:
    """Start a minimal TCP server that sends a fixed response, return port."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def _serve():
        try:
            conn, _ = srv.accept()
            conn.recv(256)
            conn.sendall(b"HTTP/1.0 200 OK\r\n\r\nHello")
            conn.close()
        finally:
            srv.close()

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    return port


def test_measure_returns_bytes_and_elapsed():
    port = _start_echo_server()
    received, elapsed = measure("127.0.0.1", port, timeout=3.0)
    assert received is not None and received > 0
    assert elapsed is not None and elapsed >= 0


def test_measure_returns_none_on_connection_refused():
    received, elapsed = measure("127.0.0.1", 1, timeout=0.5)
    assert received is None
    assert elapsed is None


# ---------------------------------------------------------------------------
# probe
# ---------------------------------------------------------------------------

def test_probe_returns_bandwidth_result():
    port = _start_echo_server()
    result = probe("127.0.0.1", port, protocol="tcp", timeout=3.0)
    assert isinstance(result, BandwidthResult)
    assert result.port == port
    assert result.protocol == "tcp"


def test_probe_timeout_fields_none():
    result = probe("127.0.0.1", 1, timeout=0.2)
    assert result.bytes_received is None
    assert result.elapsed_ms is None


# ---------------------------------------------------------------------------
# enrich
# ---------------------------------------------------------------------------

def test_enrich_skips_udp_entries():
    entries = [_e(port=53, proto="udp")]
    pairs = enrich(entries, host="127.0.0.1", timeout=0.2)
    assert len(pairs) == 1
    entry, result = pairs[0]
    assert result.bytes_received is None  # UDP not probed


def test_enrich_tcp_entry_probed():
    port = _start_echo_server()
    entries = [_e(port=port, proto="tcp")]
    pairs = enrich(entries, host="127.0.0.1", timeout=3.0)
    _, result = pairs[0]
    assert result.bytes_received is not None
