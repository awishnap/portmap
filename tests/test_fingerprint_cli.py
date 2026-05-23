"""Tests for portmap.fingerprint_cli."""

from __future__ import annotations

import argparse
import json
from unittest.mock import MagicMock, patch

import pytest

from portmap.fingerprint import FingerprintResult
from portmap.fingerprint_cli import (
    _render_json,
    _render_text,
    _resolve_ports,
    build_fingerprint_parser,
    run_fingerprint,
)
from portmap.scanner import PortEntry


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _result(port: int, banner: str | None = None, hint: str | None = None, error: str | None = None) -> FingerprintResult:
    return FingerprintResult(port=port, protocol="tcp", banner=banner, service_hint=hint, error=error)


def _args(**kwargs) -> argparse.Namespace:
    defaults = {"host": "127.0.0.1", "ports": None, "timeout": 2.0, "fmt": "text"}
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


# ---------------------------------------------------------------------------
# _resolve_ports
# ---------------------------------------------------------------------------

def test_resolve_ports_explicit_list():
    ports = _resolve_ports("80,443,8080", "127.0.0.1")
    assert ports == [80, 443, 8080]


def test_resolve_ports_scans_when_none():
    fake_entries = [
        PortEntry(port=22, protocol="tcp", status="LISTEN"),
        PortEntry(port=53, protocol="udp", status="LISTEN"),
    ]
    with patch("portmap.fingerprint_cli.scan_ports", return_value=fake_entries):
        ports = _resolve_ports(None, "127.0.0.1")
    assert ports == [22]  # only TCP


# ---------------------------------------------------------------------------
# _render_text
# ---------------------------------------------------------------------------

def test_render_text_shows_hint(capsys):
    _render_text([_result(22, banner="SSH-2.0-OpenSSH", hint="SSH")])
    out = capsys.readouterr().out
    assert "[SSH]" in out
    assert "22" in out


def test_render_text_shows_error(capsys):
    _render_text([_result(9999, error="Connection refused")])
    out = capsys.readouterr().out
    assert "ERROR" in out


# ---------------------------------------------------------------------------
# _render_json
# ---------------------------------------------------------------------------

def test_render_json_is_valid_json(capsys):
    _render_json([_result(80, banner="HTTP/1.1 200", hint="HTTP")])
    out = capsys.readouterr().out
    data = json.loads(out)
    assert isinstance(data, list)
    assert data[0]["port"] == 80
    assert data[0]["service_hint"] == "HTTP"


# ---------------------------------------------------------------------------
# run_fingerprint
# ---------------------------------------------------------------------------

def test_run_fingerprint_no_ports_returns_1(capsys):
    with patch("portmap.fingerprint_cli._resolve_ports", return_value=[]):
        code = run_fingerprint(_args())
    assert code == 1


def test_run_fingerprint_text_output(capsys):
    fake = _result(80, banner="HTTP/1.0 200 OK", hint="HTTP")
    with patch("portmap.fingerprint_cli._resolve_ports", return_value=[80]), \
         patch("portmap.fingerprint_cli.grab_banner", return_value=fake):
        code = run_fingerprint(_args(fmt="text"))
    assert code == 0
    out = capsys.readouterr().out
    assert "80" in out


def test_run_fingerprint_json_output(capsys):
    fake = _result(443, banner="HTTP/1.1 301", hint="HTTP")
    with patch("portmap.fingerprint_cli._resolve_ports", return_value=[443]), \
         patch("portmap.fingerprint_cli.grab_banner", return_value=fake):
        code = run_fingerprint(_args(fmt="json"))
    assert code == 0
    data = json.loads(capsys.readouterr().out)
    assert data[0]["port"] == 443


def test_build_fingerprint_parser_registers_subcommand():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd")
    build_fingerprint_parser(sub)
    args = parser.parse_args(["fingerprint", "--host", "10.0.0.1", "--timeout", "1.5"])
    assert args.host == "10.0.0.1"
    assert args.timeout == 1.5
