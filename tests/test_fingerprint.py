"""Tests for portmap.fingerprint."""

from __future__ import annotations

import socket
import threading
from unittest.mock import MagicMock, patch

import pytest

from portmap.fingerprint import (
    FingerprintResult,
    _detect_hint,
    enrich,
    grab_banner,
)
from portmap.scanner import PortEntry


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _e(port: int = 8080, protocol: str = "tcp") -> PortEntry:
    return PortEntry(port=port, protocol=protocol, status="LISTEN")


# ---------------------------------------------------------------------------
# _detect_hint
# ---------------------------------------------------------------------------

def test_detect_hint_ssh():
    assert _detect_hint("SSH-2.0-OpenSSH_8.9") == "SSH"


def test_detect_hint_http():
    assert _detect_hint("HTTP/1.1 200 OK") == "HTTP"


def test_detect_hint_mysql():
    assert _detect_hint("5.7.38-MySQL Community Server") == "MySQL"


def test_detect_hint_unknown_returns_none():
    assert _detect_hint("some random noise") is None


# ---------------------------------------------------------------------------
# grab_banner — success path via a real loopback server
# ---------------------------------------------------------------------------

def _start_echo_server(response: bytes) -> tuple[int, threading.Thread]:
    """Bind a TCP server on a random port that sends *response* then closes."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    port = srv.getsockname()[1]
    srv.listen(1)

    def _serve():
        conn, _ = srv.accept()
        conn.sendall(response)
        conn.close()
        srv.close()

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    return port, t


def test_grab_banner_reads_response():
    banner_bytes = b"SSH-2.0-OpenSSH_8.9\r\n"
    port, t = _start_echo_server(banner_bytes)
    t.join(timeout=0)  # let thread start
    result = grab_banner("127.0.0.1", port, timeout=3.0)
    t.join(timeout=3.0)
    assert result.error is None
    assert "SSH" in (result.banner or "")
    assert result.service_hint == "SSH"


def test_grab_banner_connection_refused_returns_error():
    # Port 1 is almost certainly closed on loopback
    result = grab_banner("127.0.0.1", 1, timeout=0.5)
    assert result.error is not None
    assert result.banner is None


# ---------------------------------------------------------------------------
# enrich
# ---------------------------------------------------------------------------

def test_enrich_skips_udp_entries():
    entries = [_e(9999, "udp")]
    with patch("portmap.fingerprint.grab_banner") as mock_grab:
        results = enrich(entries)
    mock_grab.assert_not_called()
    assert results == []


def test_enrich_calls_grab_for_tcp():
    entries = [_e(80, "tcp"), _e(443, "tcp")]
    fake = FingerprintResult(port=80, protocol="tcp", banner="HTTP/1.1 200")
    with patch("portmap.fingerprint.grab_banner", return_value=fake) as mock_grab:
        results = enrich(entries, host="10.0.0.1")
    assert mock_grab.call_count == 2
    assert len(results) == 2


def test_fingerprint_result_defaults():
    r = FingerprintResult(port=22, protocol="tcp")
    assert r.banner is None
    assert r.service_hint is None
    assert r.error is None
    assert r.raw == b""
