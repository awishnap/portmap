"""Tests for portmap.vuln and portmap.vuln_cli."""
from __future__ import annotations

import argparse
import json
from unittest.mock import patch

import pytest

from portmap.scanner import PortEntry
from portmap.vuln import VulnResult, enrich, flagged, lookup
from portmap.vuln_cli import _render_json, _render_text, run_vuln


def _e(port: int, protocol: str = "tcp", process: str = "test") -> PortEntry:
    return PortEntry(port=port, protocol=protocol, status="open", process=process, pid=None)


# --- VulnResult ---

def test_vuln_result_no_advisories_has_advisories_false():
    r = VulnResult(port=9999, protocol="tcp", advisories=[])
    assert not r.has_advisories


def test_vuln_result_with_advisories_has_advisories_true():
    r = VulnResult(port=22, protocol="tcp", advisories=["CVE-2023-38408"])
    assert r.has_advisories


def test_display_no_advisories():
    r = VulnResult(port=9999, protocol="tcp", advisories=[])
    assert "no known advisories" in r.display()


def test_display_with_advisories_contains_bang():
    r = VulnResult(port=22, protocol="tcp", advisories=["CVE-2023-38408"])
    text = r.display()
    assert "!" in text
    assert "CVE-2023-38408" in text


# --- lookup ---

def test_lookup_known_port_returns_advisories():
    r = lookup(22, "tcp")
    assert r.has_advisories
    assert r.port == 22


def test_lookup_unknown_port_empty():
    r = lookup(65000, "tcp")
    assert not r.has_advisories


def test_lookup_protocol_case_insensitive():
    r = lookup(22, "TCP")
    assert r.protocol == "tcp"


def test_lookup_wrong_protocol_no_match():
    # port 22 is only registered for tcp
    r = lookup(22, "udp")
    assert not r.has_advisories


# --- enrich ---

def test_enrich_returns_pair_for_every_entry():
    entries = [_e(22), _e(9999)]
    pairs = enrich(entries)
    assert len(pairs) == 2
    for entry, result in pairs:
        assert isinstance(result, VulnResult)


def test_enrich_empty_list():
    assert enrich([]) == []


# --- flagged ---

def test_flagged_filters_out_clean_ports():
    entries = [_e(22), _e(9999)]
    pairs = flagged(entries)
    ports = [e.port for e, _ in pairs]
    assert 22 in ports
    assert 9999 not in ports


def test_flagged_empty_when_no_advisories():
    assert flagged([_e(9999)]) == []


# --- CLI rendering ---

def test_render_text_empty_returns_no_advisories():
    assert _render_text([]) == "No advisories found."


def test_render_text_contains_port():
    pairs = [(_e(22), lookup(22))]
    assert "22" in _render_text(pairs)


def test_render_json_structure():
    pairs = [(_e(22), lookup(22))]
    data = json.loads(_render_json(pairs))
    assert isinstance(data, list)
    assert data[0]["port"] == 22
    assert "advisories" in data[0]


# --- run_vuln ---

def _args(**kwargs) -> argparse.Namespace:
    defaults = {"ports": None, "protocol": "tcp", "only_flagged": False, "fmt": "text"}
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


def test_run_vuln_invalid_ports_returns_1():
    assert run_vuln(_args(ports="abc")) == 1


def test_run_vuln_returns_0_on_success(capsys):
    fake_entries = [_e(22), _e(9999)]
    with patch("portmap.vuln_cli.scan_ports", return_value=fake_entries):
        rc = run_vuln(_args())
    assert rc == 0


def test_run_vuln_only_flagged_filters(capsys):
    fake_entries = [_e(22), _e(9999)]
    with patch("portmap.vuln_cli.scan_ports", return_value=fake_entries):
        run_vuln(_args(only_flagged=True))
    captured = capsys.readouterr().out
    assert "22" in captured
    assert "9999" not in captured
