"""Tests for portmap.uptime."""
from __future__ import annotations

import json
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from portmap.scanner import PortEntry
from portmap.uptime import (
    UptimeResult,
    _state_key,
    load_state,
    save_state,
    measure,
    enrich,
)


def _e(port: int = 8080, proto: str = "tcp") -> PortEntry:
    return PortEntry(port=port, protocol=proto, status="LISTEN", pid=None, process=None)


# --- UptimeResult ---

def test_display_formats_correctly():
    r = UptimeResult(port=80, protocol="tcp", first_seen=0.0, last_seen=3661.0, uptime_seconds=3661.0)
    assert r.display() == "01h 01m 01s"


def test_display_zero_uptime():
    r = UptimeResult(port=80, protocol="tcp", first_seen=0.0, last_seen=0.0, uptime_seconds=0.0)
    assert r.display() == "00h 00m 00s"


# --- _state_key ---

def test_state_key_format():
    assert _state_key(443, "tcp") == "443/tcp"


# --- load_state / save_state ---

def test_load_state_missing_file_returns_empty(tmp_path):
    assert load_state(tmp_path / "nope.json") == {}


def test_save_and_load_roundtrip(tmp_path):
    p = tmp_path / "state.json"
    save_state({"80/tcp": 1000.0}, p)
    assert load_state(p) == {"80/tcp": 1000.0}


def test_load_state_corrupt_file_returns_empty(tmp_path):
    p = tmp_path / "state.json"
    p.write_text("not json")
    assert load_state(p) == {}


# --- measure ---

def test_measure_creates_entry_for_new_port(tmp_path):
    p = tmp_path / "state.json"
    entries = [_e(80, "tcp")]
    results = measure(entries, path=p)
    assert len(results) == 1
    assert results[0].port == 80
    assert results[0].uptime_seconds >= 0


def test_measure_persists_first_seen(tmp_path):
    p = tmp_path / "state.json"
    t0 = time.time() - 100
    save_state({"80/tcp": t0}, p)
    results = measure([_e(80, "tcp")], path=p)
    assert results[0].uptime_seconds >= 100


def test_measure_prunes_closed_ports(tmp_path):
    p = tmp_path / "state.json"
    save_state({"80/tcp": time.time() - 50, "443/tcp": time.time() - 10}, p)
    measure([_e(443, "tcp")], path=p)
    state = load_state(p)
    assert "80/tcp" not in state
    assert "443/tcp" in state


def test_measure_multiple_entries(tmp_path):
    p = tmp_path / "state.json"
    entries = [_e(80, "tcp"), _e(443, "tcp"), _e(22, "tcp")]
    results = measure(entries, path=p)
    assert len(results) == 3
    ports = {r.port for r in results}
    assert ports == {80, 443, 22}


# --- enrich ---

def test_enrich_returns_dict_keyed_by_port(tmp_path):
    p = tmp_path / "state.json"
    entries = [_e(80, "tcp"), _e(443, "tcp")]
    result = enrich(entries, path=p)
    assert 80 in result
    assert 443 in result
    assert isinstance(result[80], UptimeResult)
