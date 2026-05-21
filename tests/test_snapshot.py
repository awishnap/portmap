"""Tests for portmap.snapshot and portmap.snapshot_diff."""

import time
from unittest.mock import patch, MagicMock

import pytest

from portmap.scanner import PortEntry
from portmap.snapshot import Snapshot, capture, save_snapshot, load_snapshot
from portmap.snapshot_diff import compare, SnapshotDiff


def _e(port=8080, protocol="tcp", pid=1, process="python", status="LISTEN"):
    return PortEntry(port=port, protocol=protocol, pid=pid, process=process, status=status)


# --- Snapshot creation ---

def test_capture_creates_snapshot():
    entries = [_e(8080), _e(9090)]
    snap = capture(entries, label="test", meta={"host": "localhost"})
    assert len(snap.entries) == 2
    assert snap.label == "test"
    assert snap.meta["host"] == "localhost"
    assert snap.timestamp <= time.time()


def test_snapshot_to_dict_roundtrip():
    entries = [_e(3000, pid=42, process="node")]
    snap = capture(entries, label="dev")
    d = snap.to_dict()
    assert d["label"] == "dev"
    assert len(d["entries"]) == 1
    assert d["entries"][0]["port"] == 3000

    restored = Snapshot.from_dict(d)
    assert restored.label == "dev"
    assert restored.entries[0].port == 3000
    assert restored.entries[0].process == "node"


def test_snapshot_from_dict_missing_optional_fields():
    data = {
        "timestamp": 1_000_000.0,
        "entries": [{"port": 80, "protocol": "tcp"}],
    }
    snap = Snapshot.from_dict(data)
    assert snap.entries[0].pid is None
    assert snap.entries[0].status == "LISTEN"


# --- Persistence ---

def test_save_and_load_snapshot():
    entries = [_e(5432, process="postgres")]
    snap = capture(entries, label="db")

    with patch("portmap.snapshot.write") as mock_write, \
         patch("portmap.snapshot.read") as mock_read:
        mock_read.return_value = snap.to_dict()
        save_snapshot(snap, "/tmp/snap.json")
        mock_write.assert_called_once()

        loaded = load_snapshot("/tmp/snap.json")
        assert loaded is not None
        assert loaded.label == "db"
        assert loaded.entries[0].process == "postgres"


def test_load_snapshot_returns_none_when_missing():
    with patch("portmap.snapshot.read", return_value=None):
        result = load_snapshot("/nonexistent/path.json")
        assert result is None


# --- Diff ---

def test_diff_no_changes():
    entries = [_e(8080), _e(9090)]
    s1 = capture(entries)
    s2 = capture(entries)
    diff = compare(s1, s2)
    assert not diff.has_changes
    assert diff.summary() == "no changes"


def test_diff_added():
    s1 = capture([_e(8080)])
    s2 = capture([_e(8080), _e(9000)])
    diff = compare(s1, s2)
    assert len(diff.added) == 1
    assert diff.added[0].port == 9000
    assert not diff.removed
    assert "+1 added" in diff.summary()


def test_diff_removed():
    s1 = capture([_e(8080), _e(9000)])
    s2 = capture([_e(8080)])
    diff = compare(s1, s2)
    assert len(diff.removed) == 1
    assert diff.removed[0].port == 9000
    assert "-1 removed" in diff.summary()


def test_diff_changed_process():
    s1 = capture([_e(8080, pid=10, process="old")])
    s2 = capture([_e(8080, pid=20, process="new")])
    diff = compare(s1, s2)
    assert len(diff.changed) == 1
    before, after = diff.changed[0]
    assert before.process == "old"
    assert after.process == "new"
    assert "~1 changed" in diff.summary()


def test_diff_summary_combined():
    s1 = capture([_e(8080), _e(9000)])
    s2 = capture([_e(8080, pid=99, process="x"), _e(7000)])
    diff = compare(s1, s2)
    summary = diff.summary()
    assert "+" in summary
    assert "-" in summary
