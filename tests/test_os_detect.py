"""Tests for portmap.os_detect."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from portmap.os_detect import (
    OSResult,
    _guess_from_banner,
    _guess_from_ttl,
    detect,
    enrich,
)
from portmap.scanner import PortEntry


def _e(port: int = 22, proto: str = "tcp", host: str = "127.0.0.1") -> PortEntry:
    return PortEntry(
        host=host,
        port=port,
        protocol=proto,
        status="open",
        pid=None,
        process=None,
    )


# --- _guess_from_ttl ---

def test_guess_ttl_linux():
    assert _guess_from_ttl(64) == "Linux / macOS"


def test_guess_ttl_windows():
    assert _guess_from_ttl(128) == "Windows"


def test_guess_ttl_low_value_maps_to_linux():
    # TTL of 50 is ≤ 64
    assert _guess_from_ttl(50) == "Linux / macOS"


def test_guess_ttl_very_high_returns_cisco():
    assert _guess_from_ttl(255) == "Cisco / Solaris"


def test_guess_ttl_above_max_returns_none():
    assert _guess_from_ttl(300) is None


# --- _guess_from_banner ---

def test_guess_banner_openssh():
    assert _guess_from_banner(b"SSH-2.0-OpenSSH_8.9") == "Linux"


def test_guess_banner_microsoft():
    assert _guess_from_banner(b"220 Microsoft ESMTP") == "Windows"


def test_guess_banner_ubuntu():
    assert _guess_from_banner(b"Ubuntu/22.04") == "Linux (Ubuntu)"


def test_guess_banner_unknown_returns_none():
    assert _guess_from_banner(b"UNKNOWN SERVER 1.0") is None


def test_guess_banner_case_insensitive():
    assert _guess_from_banner(b"openssh_9.0") == "Linux"


# --- OSResult.display ---

def test_display_with_guess():
    r = OSResult(entry=_e(), os_guess="Linux", method="banner", confidence="medium")
    assert "Linux" in r.display()
    assert "banner" in r.display()


def test_display_no_guess():
    r = OSResult(entry=_e())
    assert r.display() == "Unknown OS"


# --- detect ---

def test_detect_returns_os_result_on_banner(tmp_path):
    banner = b"SSH-2.0-OpenSSH_8.9p1"
    mock_sock = MagicMock()
    mock_sock.__enter__ = lambda s: s
    mock_sock.__exit__ = MagicMock(return_value=False)
    mock_sock.recv.return_value = banner

    with patch("portmap.os_detect.socket.create_connection", return_value=mock_sock):
        result = detect(_e(port=22))

    assert result.os_guess == "Linux"
    assert result.method == "banner"
    assert result.confidence == "medium"


def test_detect_returns_empty_result_on_connection_error():
    with patch(
        "portmap.os_detect.socket.create_connection", side_effect=OSError
    ):
        result = detect(_e(port=9999))

    assert result.os_guess is None
    assert result.method == "unknown"


def test_detect_empty_banner_returns_no_guess():
    mock_sock = MagicMock()
    mock_sock.__enter__ = lambda s: s
    mock_sock.__exit__ = MagicMock(return_value=False)
    mock_sock.recv.return_value = b""

    with patch("portmap.os_detect.socket.create_connection", return_value=mock_sock):
        result = detect(_e(port=80))

    assert result.os_guess is None


# --- enrich ---

def test_enrich_returns_list_of_results():
    entries = [_e(22), _e(80)]
    with patch("portmap.os_detect.detect") as mock_detect:
        mock_detect.side_effect = lambda e, timeout: OSResult(entry=e, os_guess="Linux", method="banner", confidence="medium")
        results = enrich(entries, timeout=0.5)

    assert len(results) == 2
    assert all(r.os_guess == "Linux" for r in results)


def test_enrich_empty_list_returns_empty():
    assert enrich([]) == []
