"""Tests for portmap.audit and portmap.audit_cli."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from portmap.alert import AlertResult
from portmap.audit import (
    _audit_entry,
    clear_log,
    log_alerts,
    log_scan,
    read_log,
)
from portmap.scanner import PortEntry


def _e(
    port: int = 8080,
    protocol: str = "tcp",
    status: str = "LISTEN",
    process: str = "python",
    pid: int = 1234,
) -> PortEntry:
    return PortEntry(port=port, protocol=protocol, status=status, process=process, pid=pid)


@pytest.fixture()
def log_path(tmp_path: Path) -> Path:
    return tmp_path / "audit.log"


# --- _audit_entry ---

def test_audit_entry_has_ts_and_event():
    entry = _audit_entry("scan", {"host": "localhost"})
    assert "ts" in entry
    assert entry["event"] == "scan"
    assert entry["host"] == "localhost"


# --- log_scan ---

def test_log_scan_creates_file(log_path: Path):
    log_scan(log_path, host="localhost", port_count=5)
    assert log_path.exists()


def test_log_scan_writes_correct_event(log_path: Path):
    log_scan(log_path, host="myhost", port_count=3)
    entries = read_log(log_path)
    assert len(entries) == 1
    assert entries[0]["event"] == "scan"
    assert entries[0]["host"] == "myhost"
    assert entries[0]["ports_found"] == 3


def test_log_scan_appends(log_path: Path):
    log_scan(log_path, port_count=1)
    log_scan(log_path, port_count=2)
    assert len(read_log(log_path)) == 2


# --- log_alerts ---

def test_log_alerts_only_logs_matched(log_path: Path):
    matched = AlertResult(matched=True, rule_name="open:80", entry=_e(port=80))
    unmatched = AlertResult(matched=False, rule_name="open:443", entry=_e(port=443))
    log_alerts([matched, unmatched], log_path)
    entries = read_log(log_path)
    assert len(entries) == 1
    assert entries[0]["event"] == "alert"
    assert entries[0]["rule"] == "open:80"
    assert entries[0]["port"] == 80


def test_log_alerts_empty_list(log_path: Path):
    log_alerts([], log_path)
    assert read_log(log_path) == []


# --- read_log ---

def test_read_log_missing_file_returns_empty(tmp_path: Path):
    assert read_log(tmp_path / "nonexistent.log") == []


def test_read_log_skips_invalid_lines(log_path: Path):
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_text('{"event": "scan", "ts": "x"}\nnot-json\n')
    entries = read_log(log_path)
    assert len(entries) == 1


# --- clear_log ---

def test_clear_log_removes_file(log_path: Path):
    log_scan(log_path, port_count=1)
    assert log_path.exists()
    clear_log(log_path)
    assert not log_path.exists()


def test_clear_log_noop_when_missing(tmp_path: Path):
    clear_log(tmp_path / "ghost.log")  # should not raise
