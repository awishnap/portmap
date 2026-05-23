"""Tests for portmap.resolve and portmap.resolve_cli."""

from __future__ import annotations

import argparse
from unittest.mock import MagicMock, patch

import pytest

from portmap.scanner import PortEntry
from portmap.resolve import (
    ResolvedEntry,
    resolve,
    resolve_all,
    reverse_lookup,
    service_name,
)
from portmap.resolve_cli import build_resolve_parser, run_resolve


def _e(port: int = 80, host: str = "127.0.0.1", proto: str = "tcp") -> PortEntry:
    return PortEntry(host=host, port=port, protocol=proto, pid=None, process=None, label=None)


# ---------------------------------------------------------------------------
# resolve helpers
# ---------------------------------------------------------------------------

def test_service_name_known_port():
    name = service_name(80, "tcp")
    assert name == "http"


def test_service_name_unknown_port():
    assert service_name(19999, "tcp") is None


def test_reverse_lookup_loopback():
    result = reverse_lookup("127.0.0.1", timeout=0.5)
    # May return 'localhost' or None depending on OS resolver — both are valid
    assert result is None or isinstance(result, str)


def test_reverse_lookup_timeout_returns_none():
    with patch("portmap.resolve.socket.gethostbyaddr", side_effect=OSError):
        assert reverse_lookup("10.0.0.1", timeout=0.1) is None


# ---------------------------------------------------------------------------
# resolve / ResolvedEntry
# ---------------------------------------------------------------------------

def test_resolve_sets_service_for_http():
    entry = _e(port=80)
    result = resolve(entry, dns=False)
    assert result.service == "http"
    assert result.hostname is None


def test_resolve_display_host_falls_back_to_ip():
    entry = _e()
    result = resolve(entry, dns=False)
    assert result.display_host == "127.0.0.1"


def test_resolve_display_host_uses_hostname_when_present():
    entry = _e()
    with patch("portmap.resolve.reverse_lookup", return_value="myhost.local"):
        result = resolve(entry, dns=True)
    assert result.display_host == "myhost.local"


def test_resolve_display_service_falls_back_to_port_string():
    entry = _e(port=19999)
    result = resolve(entry, dns=False)
    assert result.display_service == "19999"


def test_resolve_all_returns_correct_count():
    entries = [_e(80), _e(443), _e(22)]
    results = resolve_all(entries, dns=False)
    assert len(results) == 3
    assert all(isinstance(r, ResolvedEntry) for r in results)


def test_resolve_all_empty():
    assert resolve_all([], dns=False) == []


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _args(**kwargs):
    defaults = dict(ports="80", host="127.0.0.1", no_dns=True, timeout=0.5, fmt="text")
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


def test_run_resolve_text_output(capsys):
    with patch("portmap.resolve_cli.scan_ports", return_value=[_e(80)]), \
         patch("portmap.resolve_cli.resolve_all", return_value=[ResolvedEntry(entry=_e(80), service="http")]):
        rc = run_resolve(_args())
    assert rc == 0
    out = capsys.readouterr().out
    assert "http" in out


def test_run_resolve_json_output(capsys):
    with patch("portmap.resolve_cli.scan_ports", return_value=[_e(80)]), \
         patch("portmap.resolve_cli.resolve_all", return_value=[ResolvedEntry(entry=_e(80), service="http")]):
        rc = run_resolve(_args(fmt="json"))
    assert rc == 0
    import json
    data = json.loads(capsys.readouterr().out)
    assert data[0]["service"] == "http"


def test_run_resolve_no_open_ports(capsys):
    with patch("portmap.resolve_cli.scan_ports", return_value=[]), \
         patch("portmap.resolve_cli.resolve_all", return_value=[]):
        rc = run_resolve(_args())
    assert rc == 0
    assert "No open ports" in capsys.readouterr().out


def test_build_resolve_parser_defaults():
    parser = build_resolve_parser()
    args = parser.parse_args([])
    assert args.host == "127.0.0.1"
    assert args.timeout == 1.0
    assert args.fmt == "text"
