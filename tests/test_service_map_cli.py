"""Tests for portmap.service_map_cli."""

from __future__ import annotations

import argparse
import json
from unittest.mock import patch, MagicMock

import pytest

from portmap.service_map_cli import _render_text, run_service, build_service_parser


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

class _FakeEntry:
    def __init__(self, port: int, protocol: str = "tcp", label: str | None = None):
        self.port = port
        self.protocol = protocol
        self.label = label


def _args(**kwargs) -> argparse.Namespace:
    defaults = {"ports": [], "format": "text"}
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


# ---------------------------------------------------------------------------
# _render_text
# ---------------------------------------------------------------------------

def test_render_text_no_rows():
    assert _render_text([]) == "No services found."


def test_render_text_contains_service_name():
    rows = [{"port": 80, "protocol": "tcp", "service": "http", "tier": "system", "label": ""}]
    out = _render_text(rows)
    assert "http" in out
    assert "80" in out
    assert "system" in out


def test_render_text_unknown_service_shows_question_mark():
    rows = [{"port": 19999, "protocol": "tcp", "service": None, "tier": "registered", "label": ""}]
    out = _render_text(rows)
    assert "?" in out


# ---------------------------------------------------------------------------
# run_service — explicit ports
# ---------------------------------------------------------------------------

def test_run_service_explicit_ports_text(capsys):
    args = _args(ports=[80, 443], format="text")
    ret = run_service(args)
    captured = capsys.readouterr()
    assert ret == 0
    assert "http" in captured.out or "80" in captured.out


def test_run_service_explicit_ports_json(capsys):
    args = _args(ports=[22], format="json")
    ret = run_service(args)
    captured = capsys.readouterr()
    assert ret == 0
    data = json.loads(captured.out)
    assert isinstance(data, list)
    assert data[0]["port"] == 22


# ---------------------------------------------------------------------------
# run_service — scan path
# ---------------------------------------------------------------------------

def test_run_service_scan_path(capsys):
    fake_entry = _FakeEntry(port=8080, protocol="tcp", label="dev-server")
    with patch("portmap.service_map_cli.scan_ports", return_value=[fake_entry]):
        args = _args(ports=[], format="text")
        ret = run_service(args)
    captured = capsys.readouterr()
    assert ret == 0
    assert "8080" in captured.out


def test_run_service_scan_json_output(capsys):
    fake_entry = _FakeEntry(port=6379, protocol="tcp", label="cache")
    with patch("portmap.service_map_cli.scan_ports", return_value=[fake_entry]):
        args = _args(ports=[], format="json")
        run_service(args)
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data[0]["service"] == "redis"


# ---------------------------------------------------------------------------
# build_service_parser
# ---------------------------------------------------------------------------

def test_build_service_parser_registers_subcommand():
    root = argparse.ArgumentParser()
    sub = root.add_subparsers(dest="cmd")
    build_service_parser(sub)
    args = root.parse_args(["service", "--format", "json", "80"])
    assert args.cmd == "service"
    assert args.format == "json"
    assert args.ports == [80]
