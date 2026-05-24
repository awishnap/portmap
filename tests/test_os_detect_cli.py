"""Tests for portmap.os_detect_cli."""
from __future__ import annotations

import argparse
from unittest.mock import MagicMock, patch

import pytest

from portmap.os_detect import OSResult
from portmap.os_detect_cli import _render_json, _render_text, run_os
from portmap.scanner import PortEntry


def _entry(port: int = 22, proto: str = "tcp") -> PortEntry:
    return PortEntry(
        host="127.0.0.1",
        port=port,
        protocol=proto,
        status="open",
        pid=None,
        process=None,
    )


def _result(
    port: int = 22,
    os_guess: str | None = "Linux",
    method: str = "banner",
    confidence: str = "medium",
) -> OSResult:
    return OSResult(
        entry=_entry(port),
        os_guess=os_guess,
        method=method,
        confidence=confidence,
    )


def _args(**kwargs) -> argparse.Namespace:
    defaults = {"ports": None, "timeout": 1.0, "format": "text"}
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


# --- _render_text ---

def test_render_text_no_results():
    assert _render_text([]) == "No results."


def test_render_text_contains_port():
    out = _render_text([_result(port=22)])
    assert "22" in out


def test_render_text_contains_os_guess():
    out = _render_text([_result(os_guess="Windows")])
    assert "Windows" in out


def test_render_text_unknown_os():
    out = _render_text([_result(os_guess=None, method="unknown", confidence="low")])
    assert "Unknown OS" in out


# --- _render_json ---

def test_render_json_is_list():
    import json
    data = json.loads(_render_json([_result()]))
    assert isinstance(data, list)
    assert len(data) == 1


def test_render_json_fields():
    import json
    data = json.loads(_render_json([_result(port=443, os_guess="Windows")]))
    row = data[0]
    assert row["port"] == 443
    assert row["os_guess"] == "Windows"
    assert "method" in row
    assert "confidence" in row


def test_render_json_null_guess():
    import json
    data = json.loads(_render_json([_result(os_guess=None)]))
    assert data[0]["os_guess"] is None


# --- run_os ---

def test_run_os_text_output(capsys):
    with patch("portmap.os_detect_cli.scan_ports", return_value=[_entry()]):
        with patch("portmap.os_detect_cli.enrich", return_value=[_result()]):
            run_os(_args(format="text"))
    out = capsys.readouterr().out
    assert "22" in out


def test_run_os_json_output(capsys):
    with patch("portmap.os_detect_cli.scan_ports", return_value=[_entry()]):
        with patch("portmap.os_detect_cli.enrich", return_value=[_result()]):
            run_os(_args(format="json"))
    out = capsys.readouterr().out
    assert "port" in out


def test_run_os_passes_port_range():
    with patch("portmap.os_detect_cli.scan_ports", return_value=[]) as mock_scan:
        with patch("portmap.os_detect_cli.enrich", return_value=[]):
            run_os(_args(ports="22,80"))
    mock_scan.assert_called_once_with(ports=[22, 80])
