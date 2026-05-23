"""Tests for portmap.history and portmap.history_cli."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from unittest.mock import patch

import pytest

from portmap.history import (
    HistoryEntry,
    _entry_path,
    list_entries,
    load_entry,
    prune,
    save_entry,
)
from portmap.snapshot import Snapshot
from portmap.scanner import PortEntry


def _e(port: int = 8080) -> PortEntry:
    return PortEntry(
        port=port,
        protocol="tcp",
        status="open",
        pid=None,
        process=None,
        local_address="127.0.0.1",
    )


def _snap(host: str = "localhost", ports: int = 1) -> Snapshot:
    return Snapshot(
        host=host,
        timestamp=datetime.now(timezone.utc).isoformat(),
        entries=[_e(8000 + i) for i in range(ports)],
    )


# ---------------------------------------------------------------------------
# save / load round-trip
# ---------------------------------------------------------------------------

def test_save_creates_file(tmp_path):
    snap = _snap()
    entry = HistoryEntry(snapshot=snap, saved_at="2024-01-01T00:00:00+00:00")
    path = save_entry(entry, history_dir=str(tmp_path))
    assert os.path.isfile(path)


def test_save_load_roundtrip(tmp_path):
    snap = _snap(host="testhost", ports=3)
    entry = HistoryEntry(snapshot=snap, saved_at="2024-06-15T12:00:00+00:00")
    path = save_entry(entry, history_dir=str(tmp_path))
    loaded = load_entry(path)
    assert loaded.saved_at == entry.saved_at
    assert loaded.snapshot.host == "testhost"
    assert len(loaded.snapshot.entries) == 3


def test_save_file_contains_saved_at(tmp_path):
    snap = _snap()
    entry = HistoryEntry(snapshot=snap, saved_at="2024-03-10T08:30:00+00:00")
    path = save_entry(entry, history_dir=str(tmp_path))
    with open(path) as fh:
        data = json.load(fh)
    assert data["saved_at"] == "2024-03-10T08:30:00+00:00"


# ---------------------------------------------------------------------------
# list_entries
# ---------------------------------------------------------------------------

def test_list_entries_empty_dir(tmp_path):
    assert list_entries(str(tmp_path)) == []


def test_list_entries_missing_dir():
    assert list_entries("/nonexistent/portmap/history") == []


def test_list_entries_sorted_oldest_first(tmp_path):
    for ts in ["2024-01-03T00:00:00+00:00", "2024-01-01T00:00:00+00:00", "2024-01-02T00:00:00+00:00"]:
        save_entry(HistoryEntry(snapshot=_snap(), saved_at=ts), history_dir=str(tmp_path))
    entries = list_entries(str(tmp_path))
    assert len(entries) == 3
    assert entries[0].saved_at < entries[1].saved_at < entries[2].saved_at


# ---------------------------------------------------------------------------
# prune
# ---------------------------------------------------------------------------

def test_prune_removes_oldest(tmp_path):
    for i in range(5):
        ts = f"2024-01-0{i+1}T00:00:00+00:00"
        save_entry(HistoryEntry(snapshot=_snap(), saved_at=ts), history_dir=str(tmp_path))
    deleted = prune(keep=3, history_dir=str(tmp_path))
    assert deleted == 2
    assert len(list_entries(str(tmp_path))) == 3


def test_prune_noop_when_under_limit(tmp_path):
    for i in range(3):
        ts = f"2024-02-0{i+1}T00:00:00+00:00"
        save_entry(HistoryEntry(snapshot=_snap(), saved_at=ts), history_dir=str(tmp_path))
    deleted = prune(keep=10, history_dir=str(tmp_path))
    assert deleted == 0


def test_prune_missing_dir_returns_zero():
    assert prune(keep=5, history_dir="/nonexistent/portmap/history") == 0


# ---------------------------------------------------------------------------
# history_cli
# ---------------------------------------------------------------------------

def test_cli_list_text(tmp_path, capsys):
    from portmap.history_cli import _run_list
    import argparse

    save_entry(HistoryEntry(snapshot=_snap(host="myhost", ports=2), saved_at="2024-05-01T10:00:00+00:00"), history_dir=str(tmp_path))
    args = argparse.Namespace(dir=str(tmp_path), format="text", limit=0)
    _run_list(args)
    out = capsys.readouterr().out
    assert "myhost" in out
    assert "2" in out


def test_cli_list_json(tmp_path, capsys):
    from portmap.history_cli import _run_list
    import argparse

    save_entry(HistoryEntry(snapshot=_snap(host="jsonhost", ports=4), saved_at="2024-05-02T10:00:00+00:00"), history_dir=str(tmp_path))
    args = argparse.Namespace(dir=str(tmp_path), format="json", limit=0)
    _run_list(args)
    data = json.loads(capsys.readouterr().out)
    assert data[0]["host"] == "jsonhost"
    assert data[0]["port_count"] == 4


def test_cli_prune_output(tmp_path, capsys):
    from portmap.history_cli import _run_prune
    import argparse

    for i in range(4):
        ts = f"2024-06-0{i+1}T00:00:00+00:00"
        save_entry(HistoryEntry(snapshot=_snap(), saved_at=ts), history_dir=str(tmp_path))
    args = argparse.Namespace(dir=str(tmp_path), keep=2)
    _run_prune(args)
    out = capsys.readouterr().out
    assert "2" in out
    assert len(list_entries(str(tmp_path))) == 2
