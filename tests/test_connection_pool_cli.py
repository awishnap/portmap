"""Tests for portmap.connection_pool_cli."""
from __future__ import annotations

import argparse
import json
from unittest.mock import patch

import pytest

from portmap.connection_pool import PoolEntry
from portmap.connection_pool_cli import (
    _render_json,
    _render_text,
    build_pool_parser,
    run_pool,
)


def _result(
    port: int = 8080,
    established: int = 2,
    time_wait: int = 0,
    close_wait: int = 0,
    total: int = 2,
) -> PoolEntry:
    return PoolEntry(
        port=port,
        protocol="tcp",
        pid=1234,
        process="gunicorn",
        established=established,
        time_wait=time_wait,
        close_wait=close_wait,
        total=total,
    )


def _args(**kwargs) -> argparse.Namespace:
    defaults = {"ports": [8080], "protocol": "tcp", "fmt": "text", "min_conn": 0}
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


def test_render_text_no_results():
    assert _render_text([]) == "No results."


def test_render_text_contains_port():
    out = _render_text([_result(port=8080)])
    assert "8080" in out


def test_render_text_contains_header():
    out = _render_text([_result()])
    assert "PORT" in out
    assert "TOTAL" in out


def test_render_text_shows_state():
    out = _render_text([_result(established=5, total=5)])
    assert "ESTAB=5" in out


def test_render_json_valid_json():
    out = _render_json([_result()])
    data = json.loads(out)
    assert isinstance(data, list)
    assert data[0]["port"] == 8080


def test_render_json_includes_all_fields():
    out = _render_json([_result(established=3, time_wait=1, close_wait=0, total=4)])
    data = json.loads(out)
    row = data[0]
    assert "established" in row
    assert "time_wait" in row
    assert "close_wait" in row
    assert "process" in row


def test_run_pool_text(capsys):
    with patch("portmap.connection_pool_cli.measure", return_value=_result()):
        run_pool(_args(fmt="text"))
    out = capsys.readouterr().out
    assert "8080" in out


def test_run_pool_json(capsys):
    with patch("portmap.connection_pool_cli.measure", return_value=_result()):
        run_pool(_args(fmt="json"))
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data[0]["port"] == 8080


def test_run_pool_min_conn_filters(capsys):
    with patch("portmap.connection_pool_cli.measure", return_value=_result(total=1)):
        run_pool(_args(min_conn=5))
    out = capsys.readouterr().out
    assert "No results" in out


def test_build_pool_parser_registers_subcommand():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd")
    build_pool_parser(sub)
    args = parser.parse_args(["pool", "8080", "--protocol", "tcp"])
    assert args.ports == [8080]
    assert args.protocol == "tcp"
