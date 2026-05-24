"""Tests for portmap.uptime_cli."""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from portmap.scanner import PortEntry
from portmap.uptime import UptimeResult
from portmap.uptime_cli import _render_text, _render_json, run_uptime, build_uptime_parser


def _result(port: int = 80, uptime: float = 3661.0) -> UptimeResult:
    now = time.time()
    return UptimeResult(
        port=port,
        protocol="tcp",
        first_seen=now - uptime,
        last_seen=now,
        uptime_seconds=uptime,
    )


def _args(**kwargs) -> argparse.Namespace:
    defaults = {"format": "text", "state": "/tmp/uptime_test_state.json", "ports": None}
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


# --- _render_text ---

def test_render_text_no_results(capsys):
    _render_text([])
    out = capsys.readouterr().out
    assert "No open ports" in out


def test_render_text_shows_port(capsys):
    _render_text([_result(port=8080)])
    out = capsys.readouterr().out
    assert "8080" in out


def test_render_text_shows_uptime(capsys):
    _render_text([_result(uptime=3661.0)])
    out = capsys.readouterr().out
    assert "01h 01m 01s" in out


def test_render_text_shows_protocol(capsys):
    _render_text([_result()])
    out = capsys.readouterr().out
    assert "tcp" in out


# --- _render_json ---

def test_render_json_valid_json(capsys):
    _render_json([_result(port=443)])
    out = capsys.readouterr().out
    data = json.loads(out)
    assert isinstance(data, list)
    assert data[0]["port"] == 443


def test_render_json_includes_display(capsys):
    _render_json([_result(uptime=7200.0)])
    out = capsys.readouterr().out
    data = json.loads(out)
    assert "uptime_display" in data[0]
    assert data[0]["uptime_display"] == "02h 00m 00s"


# --- run_uptime ---

def _make_entry(port: int) -> PortEntry:
    return PortEntry(port=port, protocol="tcp", status="LISTEN", pid=None, process=None)


def test_run_uptime_text_format(tmp_path, capsys):
    entries = [_make_entry(80)]
    with patch("portmap.uptime_cli.scan_ports", return_value=entries):
        run_uptime(_args(state=str(tmp_path / "state.json")))
    out = capsys.readouterr().out
    assert "80" in out


def test_run_uptime_json_format(tmp_path, capsys):
    entries = [_make_entry(443)]
    with patch("portmap.uptime_cli.scan_ports", return_value=entries):
        run_uptime(_args(format="json", state=str(tmp_path / "state.json")))
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data[0]["port"] == 443


def test_run_uptime_filters_by_ports(tmp_path, capsys):
    entries = [_make_entry(80), _make_entry(443), _make_entry(22)]
    with patch("portmap.uptime_cli.scan_ports", return_value=entries):
        run_uptime(_args(ports="80,443", state=str(tmp_path / "state.json")))
    out = capsys.readouterr().out
    assert "22" not in out
    assert "80" in out
