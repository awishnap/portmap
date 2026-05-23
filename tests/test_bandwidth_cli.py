"""Tests for portmap.bandwidth_cli."""
from __future__ import annotations

import argparse
from unittest.mock import MagicMock, patch

import pytest

from portmap.bandwidth import BandwidthResult
from portmap.bandwidth_cli import (
    _render_json,
    _render_text,
    build_bandwidth_parser,
    run_bandwidth,
)


def _result(port: int = 80, received: int = 512, elapsed: float = 100.0) -> BandwidthResult:
    return BandwidthResult(
        port=port, protocol="tcp", host="127.0.0.1",
        bytes_received=received, elapsed_ms=elapsed,
    )


def _args(**kwargs) -> argparse.Namespace:
    defaults = dict(host="127.0.0.1", ports=None, timeout=2.0, fmt="text")
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


# ---------------------------------------------------------------------------
# _render_text
# ---------------------------------------------------------------------------

def test_render_text_no_results():
    assert _render_text([]) == "No results."


def test_render_text_contains_port():
    out = _render_text([_result(port=8080)])
    assert "8080" in out


def test_render_text_contains_header():
    out = _render_text([_result()])
    assert "PORT" in out


def test_render_text_timeout_shown():
    r = BandwidthResult(port=22, protocol="tcp", host="127.0.0.1",
                        bytes_received=None, elapsed_ms=None)
    out = _render_text([r])
    assert "timeout" in out


# ---------------------------------------------------------------------------
# _render_json
# ---------------------------------------------------------------------------

def test_render_json_is_valid_list():
    import json
    out = _render_json([_result(port=443)])
    data = json.loads(out)
    assert isinstance(data, list)
    assert data[0]["port"] == 443


def test_render_json_includes_display():
    import json
    out = _render_json([_result()])
    data = json.loads(out)
    assert "display" in data[0]


# ---------------------------------------------------------------------------
# run_bandwidth
# ---------------------------------------------------------------------------

def test_run_bandwidth_explicit_ports(capsys):
    with patch("portmap.bandwidth_cli.probe") as mock_probe:
        mock_probe.return_value = _result(port=9000)
        rc = run_bandwidth(_args(ports=[9000]))
    assert rc == 0
    captured = capsys.readouterr()
    assert "9000" in captured.out


def test_run_bandwidth_scans_when_no_ports(capsys):
    fake_entry = MagicMock(port=80, protocol="tcp")
    with patch("portmap.bandwidth_cli.scan_ports", return_value=[fake_entry]):
        with patch("portmap.bandwidth_cli.probe", return_value=_result(port=80)):
            rc = run_bandwidth(_args(ports=None))
    assert rc == 0


def test_run_bandwidth_json_format(capsys):
    import json
    with patch("portmap.bandwidth_cli.probe", return_value=_result(port=8080)):
        rc = run_bandwidth(_args(ports=[8080], fmt="json"))
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert data[0]["port"] == 8080


# ---------------------------------------------------------------------------
# build_bandwidth_parser
# ---------------------------------------------------------------------------

def test_build_bandwidth_parser_defaults():
    p = build_bandwidth_parser()
    args = p.parse_args([])
    assert args.host == "127.0.0.1"
    assert args.timeout == 2.0
    assert args.fmt == "text"
