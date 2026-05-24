"""Tests for portmap.health_cli."""
from __future__ import annotations

import argparse
import json
from unittest.mock import patch, MagicMock

import pytest

from portmap.health import HealthResult
from portmap.health_cli import _render_text, _render_json, run_health, build_health_parser


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _result(port: int = 80, reachable: bool = True,
            latency: float = 1.0) -> HealthResult:
    return HealthResult(port=port, protocol="tcp", host="127.0.0.1",
                        reachable=reachable,
                        latency_ms=latency if reachable else None,
                        error=None if reachable else "refused")


def _args(**kwargs) -> argparse.Namespace:  # type: ignore[return]
    defaults = dict(host="127.0.0.1", ports=None, timeout=2.0,
                    fmt="text", only_down=False)
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


# ---------------------------------------------------------------------------
# _render_text
# ---------------------------------------------------------------------------

def test_render_text_no_results_empty_list():
    out = _render_text([], only_down=False)
    assert "no results" in out


def test_render_text_shows_up_port():
    out = _render_text([_result(80, reachable=True)], only_down=False)
    assert "up" in out
    assert "80" in out


def test_render_text_only_down_hides_up():
    results = [_result(80, reachable=True), _result(9999, reachable=False)]
    out = _render_text(results, only_down=True)
    assert "9999" in out
    assert "80" not in out


# ---------------------------------------------------------------------------
# _render_json
# ---------------------------------------------------------------------------

def test_render_json_is_valid():
    out = _render_json([_result(443)], only_down=False)
    data = json.loads(out)
    assert isinstance(data, list)
    assert data[0]["port"] == 443
    assert data[0]["status"] == "up"


def test_render_json_only_down_filters():
    results = [_result(80, reachable=True), _result(9999, reachable=False)]
    data = json.loads(_render_json(results, only_down=True))
    assert len(data) == 1
    assert data[0]["port"] == 9999


# ---------------------------------------------------------------------------
# run_health
# ---------------------------------------------------------------------------

def test_run_health_explicit_ports_calls_check(capsys):
    with patch("portmap.health_cli.check") as mock_check:
        mock_check.return_value = _result(8080)
        run_health(_args(ports=[8080]))
    mock_check.assert_called_once_with("127.0.0.1", 8080, timeout=2.0)
    captured = capsys.readouterr()
    assert "8080" in captured.out


def test_run_health_no_ports_scans(capsys):
    from portmap.scanner import PortEntry
    fake_entry = PortEntry(port=22, protocol="tcp", status="LISTEN",
                           pid=None, process=None)
    with patch("portmap.health_cli.scan_ports", return_value=[fake_entry]), \
         patch("portmap.health_cli.check", return_value=_result(22)) as mock_check:
        run_health(_args())
    mock_check.assert_called_once()


def test_run_health_json_format(capsys):
    with patch("portmap.health_cli.check", return_value=_result(80)):
        run_health(_args(ports=[80], fmt="json"))
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data[0]["port"] == 80


# ---------------------------------------------------------------------------
# build_health_parser
# ---------------------------------------------------------------------------

def test_build_health_parser_defaults():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd")
    build_health_parser(sub)
    args = parser.parse_args(["health"])
    assert args.host == "127.0.0.1"
    assert args.timeout == 2.0
    assert args.fmt == "text"
    assert args.only_down is False
