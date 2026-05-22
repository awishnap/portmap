"""Tests for portmap.baseline."""

import json
from pathlib import Path

import pytest

from portmap.baseline import (
    BaselineDiff,
    compare_to_baseline,
    load_baseline,
    save_baseline,
)
from portmap.scanner import PortEntry


def _e(port: int, proto: str = "tcp", process: str = "svc") -> PortEntry:
    return PortEntry(port=port, protocol=proto, status="LISTEN", pid=1, process=process)


# ---------------------------------------------------------------------------
# BaselineDiff
# ---------------------------------------------------------------------------

def test_baseline_diff_no_changes_has_changes_false():
    diff = BaselineDiff(new_ports=[], removed_ports=[])
    assert not diff.has_changes


def test_baseline_diff_has_changes_true_when_new():
    diff = BaselineDiff(new_ports=[_e(8080)], removed_ports=[])
    assert diff.has_changes


def test_baseline_diff_summary_no_changes():
    diff = BaselineDiff(new_ports=[], removed_ports=[])
    assert diff.summary() == "No changes from baseline."


def test_baseline_diff_summary_lists_added_and_removed():
    diff = BaselineDiff(new_ports=[_e(9000)], removed_ports=[_e(8080)])
    summary = diff.summary()
    assert "+" in summary
    assert "-" in summary
    assert "9000" in summary
    assert "8080" in summary


# ---------------------------------------------------------------------------
# compare_to_baseline
# ---------------------------------------------------------------------------

def test_compare_identical_returns_no_changes():
    entries = [_e(80), _e(443)]
    diff = compare_to_baseline(entries, entries)
    assert not diff.has_changes


def test_compare_detects_new_port():
    baseline = [_e(80)]
    current = [_e(80), _e(8080)]
    diff = compare_to_baseline(current, baseline)
    assert len(diff.new_ports) == 1
    assert diff.new_ports[0].port == 8080
    assert diff.removed_ports == []


def test_compare_detects_removed_port():
    baseline = [_e(80), _e(443)]
    current = [_e(80)]
    diff = compare_to_baseline(current, baseline)
    assert len(diff.removed_ports) == 1
    assert diff.removed_ports[0].port == 443
    assert diff.new_ports == []


def test_compare_protocol_distinguishes_entries():
    baseline = [_e(80, proto="tcp")]
    current = [_e(80, proto="udp")]
    diff = compare_to_baseline(current, baseline)
    assert len(diff.new_ports) == 1
    assert len(diff.removed_ports) == 1


# ---------------------------------------------------------------------------
# save_baseline / load_baseline
# ---------------------------------------------------------------------------

def test_save_and_load_roundtrip(tmp_path):
    path = tmp_path / "baseline.json"
    entries = [_e(80), _e(443, proto="tcp", process="nginx")]
    save_baseline(entries, path=path)
    loaded = load_baseline(path=path)
    assert loaded is not None
    assert len(loaded) == 2
    ports = {e.port for e in loaded}
    assert ports == {80, 443}


def test_load_baseline_returns_none_when_missing(tmp_path):
    result = load_baseline(path=tmp_path / "nonexistent.json")
    assert result is None


def test_save_creates_parent_dirs(tmp_path):
    path = tmp_path / "deep" / "nested" / "baseline.json"
    save_baseline([_e(22)], path=path)
    assert path.exists()


def test_saved_file_contains_captured_at(tmp_path):
    path = tmp_path / "baseline.json"
    save_baseline([_e(22)], path=path)
    data = json.loads(path.read_text())
    assert "captured_at" in data
