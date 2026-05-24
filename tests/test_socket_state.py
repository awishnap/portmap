"""Tests for portmap.socket_state and portmap.socket_state_cli."""
from __future__ import annotations

import argparse
from unittest.mock import patch

import pytest

from portmap import socket_state as ss
from portmap.socket_state_cli import _render_text, _render_json, run_socket_state


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class _FakeEntry:
    def __init__(self, port: int, protocol: str = "tcp", status: str = "LISTEN", process: str = "nginx"):
        self.port = port
        self.protocol = protocol
        self.status = status
        self.process = process


# ---------------------------------------------------------------------------
# socket_state.normalise
# ---------------------------------------------------------------------------

def test_normalise_listen():
    assert ss.normalise("LISTEN") == "listening"

def test_normalise_established():
    assert ss.normalise("ESTABLISHED") == "established"

def test_normalise_none_returns_stateless():
    assert ss.normalise(None) == "stateless"

def test_normalise_empty_string_returns_stateless():
    assert ss.normalise("") == "stateless"

def test_normalise_unknown_lowercased():
    assert ss.normalise("WEIRD_STATE") == "weird_state"


# ---------------------------------------------------------------------------
# socket_state.classify
# ---------------------------------------------------------------------------

def test_classify_listen_is_active():
    result = ss.classify("LISTEN")
    assert result.is_active is True
    assert result.is_closing is False

def test_classify_time_wait_is_closing():
    result = ss.classify("TIME_WAIT")
    assert result.is_closing is True
    assert result.is_active is False

def test_classify_closed_neither():
    result = ss.classify("CLOSED")
    assert result.is_active is False
    assert result.is_closing is False

def test_classify_display_active_suffix():
    result = ss.classify("ESTABLISHED")
    assert "[active]" in result.display()

def test_classify_display_closing_suffix():
    result = ss.classify("CLOSE_WAIT")
    assert "[closing]" in result.display()

def test_classify_display_plain_for_closed():
    result = ss.classify("CLOSED")
    assert "[" not in result.display()


# ---------------------------------------------------------------------------
# socket_state.enrich
# ---------------------------------------------------------------------------

def test_enrich_attaches_socket_state():
    entries = [_FakeEntry(80, status="LISTEN")]
    enriched = ss.enrich(entries)
    assert hasattr(enriched[0], "socket_state")
    assert isinstance(enriched[0].socket_state, ss.SocketStateResult)

def test_enrich_preserves_original_entry():
    e = _FakeEntry(443)
    result = ss.enrich([e])
    assert result[0] is e

def test_enrich_empty_list():
    assert ss.enrich([]) == []


# ---------------------------------------------------------------------------
# socket_state_cli._render_text / _render_json
# ---------------------------------------------------------------------------

def test_render_text_no_entries():
    assert "No matching" in _render_text([])

def test_render_text_shows_port():
    e = _FakeEntry(8080, status="LISTEN")
    ss.enrich([e])
    assert "8080" in _render_text([e])

def test_render_json_structure():
    import json
    e = _FakeEntry(22, status="LISTEN")
    ss.enrich([e])
    data = json.loads(_render_json([e]))
    assert data[0]["port"] == 22
    assert data[0]["is_active"] is True

def test_render_json_empty_list():
    import json
    data = json.loads(_render_json([]))
    assert data == []


# ---------------------------------------------------------------------------
# run_socket_state integration
# ---------------------------------------------------------------------------

def _args(**kwargs):
    defaults = {"ports": None, "proto": "all", "active_only": False, "format": "text"}
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


def test_run_socket_state_text(capsys):
    fake = [_FakeEntry(80)]
    with patch("portmap.socket_state_cli.scan_ports", return_value=fake):
        run_socket_state(_args())
    out = capsys.readouterr().out
    assert "80" in out

def test_run_socket_state_active_only_filters(capsys):
    entries = [_FakeEntry(80, status="LISTEN"), _FakeEntry(9999, status="CLOSED")]
    with patch("portmap.socket_state_cli.scan_ports", return_value=entries):
        run_socket_state(_args(active_only=True))
    out = capsys.readouterr().out
    assert "80" in out
    assert "9999" not in out

def test_run_socket_state_json_format(capsys):
    fake = [_FakeEntry(443, status="ESTABLISHED")]
    with patch("portmap.socket_state_cli.scan_ports", return_value=fake):
        run_socket_state(_args(format="json"))
    import json
    data = json.loads(capsys.readouterr().out)
    assert data[0]["port"] == 443
