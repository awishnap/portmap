"""Tests for portmap.ssl_check and portmap.ssl_cli."""
from __future__ import annotations

import ssl
import socket
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from portmap.ssl_check import SSLResult, _parse_cert, check, enrich
from portmap.scanner import PortEntry


def _e(port: int = 443) -> PortEntry:
    return PortEntry(port=port, protocol="tcp", status="open", pid=None, process=None)


# ---------------------------------------------------------------------------
# _parse_cert
# ---------------------------------------------------------------------------

def test_parse_cert_extracts_subject_and_issuer():
    cert = {
        "subject": (("commonName", "example.com"),),
        "issuer": (("organizationName", "Let's Encrypt"),),
        "notAfter": "Jan 01 00:00:00 2099 GMT",
    }
    subject, issuer, expires = _parse_cert(cert)
    assert subject == "example.com"
    assert issuer == "Let's Encrypt"
    assert expires is not None
    assert expires.year == 2099


def test_parse_cert_empty_returns_nones():
    subject, issuer, expires = _parse_cert({})
    assert subject is None
    assert issuer is None
    assert expires is None


def test_parse_cert_bad_date_returns_none():
    cert = {"notAfter": "not-a-date"}
    _, _, expires = _parse_cert(cert)
    assert expires is None


# ---------------------------------------------------------------------------
# SSLResult.display
# ---------------------------------------------------------------------------

def test_display_no_ssl():
    r = SSLResult(port=80, host="localhost", has_ssl=False)
    assert "no SSL" in r.display()


def test_display_ssl_error():
    r = SSLResult(port=443, host="localhost", has_ssl=True, error="handshake failed")
    assert "SSL error" in r.display()
    assert "handshake failed" in r.display()


def test_display_valid_cert_shows_days():
    future = datetime.now(tz=timezone.utc) + timedelta(days=60)
    r = SSLResult(port=443, host="localhost", has_ssl=True,
                  subject="example.com", expires=future, days_remaining=60)
    text = r.display()
    assert "60d" in text
    assert "example.com" in text


# ---------------------------------------------------------------------------
# check()
# ---------------------------------------------------------------------------

def _mock_tls_context(cert: dict):
    tls_sock = MagicMock()
    tls_sock.getpeercert.return_value = cert
    tls_sock.__enter__ = lambda s: s
    tls_sock.__exit__ = MagicMock(return_value=False)
    raw_sock = MagicMock()
    raw_sock.__enter__ = lambda s: s
    raw_sock.__exit__ = MagicMock(return_value=False)
    return raw_sock, tls_sock


def test_check_returns_no_ssl_on_connection_error():
    with patch("socket.create_connection", side_effect=OSError):
        result = check("127.0.0.1", 9999)
    assert result.has_ssl is False
    assert result.error is None


def test_check_returns_ssl_error_on_ssl_exception():
    raw_sock = MagicMock()
    raw_sock.__enter__ = lambda s: s
    raw_sock.__exit__ = MagicMock(return_value=False)
    with patch("socket.create_connection", return_value=raw_sock):
        with patch("ssl.SSLContext.wrap_socket", side_effect=ssl.SSLError("bad cert")):
            result = check("127.0.0.1", 443)
    assert result.has_ssl is True
    assert result.error is not None


# ---------------------------------------------------------------------------
# enrich()
# ---------------------------------------------------------------------------

def test_enrich_calls_check_for_each_entry():
    entries = [_e(80), _e(443)]
    with patch("portmap.ssl_check.check") as mock_check:
        mock_check.side_effect = lambda host, port, timeout: SSLResult(
            port=port, host=host, has_ssl=False
        )
        results = enrich(entries, host="localhost")
    assert len(results) == 2
    assert mock_check.call_count == 2


# ---------------------------------------------------------------------------
# CLI rendering
# ---------------------------------------------------------------------------

def test_render_text_only_ssl_hides_plain_http(capsys):
    from portmap.ssl_cli import _render_text
    results = [
        SSLResult(port=80, host="h", has_ssl=False),
        SSLResult(port=443, host="h", has_ssl=True, subject="s",
                  expires=datetime.now(tz=timezone.utc) + timedelta(days=90),
                  days_remaining=90),
    ]
    _render_text(results, only_ssl=True, warn_days=30)
    out = capsys.readouterr().out
    assert "80" not in out
    assert "443" in out


def test_render_text_warns_near_expiry(capsys):
    from portmap.ssl_cli import _render_text
    soon = datetime.now(tz=timezone.utc) + timedelta(days=10)
    results = [SSLResult(port=443, host="h", has_ssl=True, subject="s",
                         expires=soon, days_remaining=10)]
    _render_text(results, only_ssl=False, warn_days=30)
    out = capsys.readouterr().out
    assert "WARNING" in out


def test_render_json_output(capsys):
    import json as _json
    from portmap.ssl_cli import _render_json
    results = [SSLResult(port=443, host="h", has_ssl=True)]
    _render_json(results, only_ssl=False)
    data = _json.loads(capsys.readouterr().out)
    assert len(data) == 1
    assert data[0]["port"] == 443
    assert data[0]["has_ssl"] is True
