"""Tests for portmap.tls_version and portmap.tls_version_cli."""
from __future__ import annotations

import argparse
import json
import ssl
from unittest.mock import MagicMock, patch

import pytest

from portmap.tls_version import TLSVersionResult, detect, enrich
from portmap.tls_version_cli import _render_json, _render_text, build_tls_parser, run_tls


def _e(port: int = 8443):
    """Minimal PortEntry-like stub."""
    e = MagicMock()
    e.port = port
    return e


# --- TLSVersionResult ---

def test_deprecated_false_for_tls13():
    r = TLSVersionResult(port=443, host="localhost", version="TLSv1.3", cipher="AES")
    assert r.deprecated is False


def test_deprecated_true_for_tls10():
    r = TLSVersionResult(port=443, host="localhost", version="TLSv1.0", cipher=None)
    assert r.deprecated is True


def test_deprecated_true_for_tls11():
    r = TLSVersionResult(port=443, host="localhost", version="TLSv1.1", cipher=None)
    assert r.deprecated is True


def test_display_no_tls():
    r = TLSVersionResult(port=80, host="127.0.0.1", version=None, cipher=None)
    assert "no TLS" in r.display()


def test_display_with_version_and_cipher():
    r = TLSVersionResult(port=443, host="127.0.0.1", version="TLSv1.3", cipher="ECDHE-RSA-AES256")
    out = r.display()
    assert "TLSv1.3" in out
    assert "ECDHE-RSA-AES256" in out
    assert "deprecated" not in out


def test_display_deprecated_flag():
    r = TLSVersionResult(port=443, host="127.0.0.1", version="TLSv1.0", cipher=None)
    assert "deprecated" in r.display()


# --- detect ---

def test_detect_returns_version_on_success():
    mock_tls = MagicMock()
    mock_tls.__enter__ = lambda s: s
    mock_tls.__exit__ = MagicMock(return_value=False)
    mock_tls.version.return_value = "TLSv1.3"
    mock_tls.cipher.return_value = ("AES256", "TLSv1.3", 256)

    mock_raw = MagicMock()
    mock_raw.__enter__ = lambda s: s
    mock_raw.__exit__ = MagicMock(return_value=False)

    with patch("socket.create_connection", return_value=mock_raw), \
         patch("ssl.SSLContext.wrap_socket", return_value=mock_tls):
        result = detect("127.0.0.1", 443)

    assert result.version == "TLSv1.3"
    assert result.cipher == "AES256"


def test_detect_returns_none_on_oserror():
    with patch("socket.create_connection", side_effect=OSError):
        result = detect("127.0.0.1", 9999)
    assert result.version is None
    assert result.cipher is None


def test_detect_returns_none_on_ssl_error():
    with patch("socket.create_connection", side_effect=ssl.SSLError):
        result = detect("127.0.0.1", 443)
    assert result.version is None


# --- enrich ---

def test_enrich_calls_detect_per_entry():
    entries = [_e(443), _e(8443)]
    fake = TLSVersionResult(port=443, host="h", version="TLSv1.3", cipher=None)
    with patch("portmap.tls_version.detect", return_value=fake) as mock_detect:
        results = enrich(entries, host="h")
    assert mock_detect.call_count == 2
    assert len(results) == 2


# --- CLI render ---

def test_render_text_no_results(capsys):
    _render_text([], deprecated_only=False)
    assert "No results" in capsys.readouterr().out


def test_render_text_shows_port(capsys):
    r = TLSVersionResult(port=443, host="127.0.0.1", version="TLSv1.3", cipher=None)
    _render_text([r], deprecated_only=False)
    assert "443" in capsys.readouterr().out


def test_render_text_deprecated_only_filters(capsys):
    good = TLSVersionResult(port=443, host="h", version="TLSv1.3", cipher=None)
    bad = TLSVersionResult(port=80, host="h", version="TLSv1.0", cipher=None)
    _render_text([good, bad], deprecated_only=True)
    out = capsys.readouterr().out
    assert "80" in out
    assert "443" not in out


def test_render_json_output(capsys):
    r = TLSVersionResult(port=443, host="127.0.0.1", version="TLSv1.2", cipher="AES")
    _render_json([r], deprecated_only=False)
    data = json.loads(capsys.readouterr().out)
    assert data[0]["port"] == 443
    assert data[0]["version"] == "TLSv1.2"


def test_run_tls_text(capsys):
    ns = argparse.Namespace(ports=[443], host="127.0.0.1", timeout=2.0, fmt="text", deprecated_only=False)
    fake = TLSVersionResult(port=443, host="127.0.0.1", version="TLSv1.3", cipher=None)
    with patch("portmap.tls_version_cli.detect", return_value=fake):
        run_tls(ns)
    assert "443" in capsys.readouterr().out


def test_build_tls_parser_registers_subcommand():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd")
    build_tls_parser(sub)
    args = parser.parse_args(["tls", "443", "--host", "10.0.0.1"])
    assert args.ports == [443]
    assert args.host == "10.0.0.1"
