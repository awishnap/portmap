"""Tests for portmap.schedule."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from portmap.schedule import (
    DEFAULT_INTERVAL,
    _snapshot_path,
    run_once,
    run_loop,
)
from portmap.snapshot import Snapshot
from portmap.scanner import PortEntry
from datetime import datetime


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _make_entry(port: int = 8080, protocol: str = "tcp", pid: int = 1) -> PortEntry:
    return PortEntry(
        port=port,
        protocol=protocol,
        status="LISTEN",
        pid=pid,
        process="test",
        label="test",
    )


def _make_snapshot(entries=None) -> Snapshot:
    return Snapshot(
        host="localhost",
        timestamp=datetime.utcnow().isoformat(),
        entries=entries or [_make_entry()],
    )


# ---------------------------------------------------------------------------
# _snapshot_path
# ---------------------------------------------------------------------------

def test_snapshot_path_creates_directory(tmp_path):
    ts = datetime(2024, 6, 1, 12, 0, 0)
    p = _snapshot_path(tmp_path / "snaps", ts)
    assert p.parent.exists()
    assert p.name == "snapshot_20240601_120000.json"


def test_snapshot_path_format(tmp_path):
    ts = datetime(2025, 1, 15, 8, 5, 3)
    p = _snapshot_path(tmp_path, ts)
    assert "20250115" in p.name
    assert "080503" in p.name


# ---------------------------------------------------------------------------
# run_once
# ---------------------------------------------------------------------------

@patch("portmap.schedule.save_snapshot")
@patch("portmap.schedule.capture")
def test_run_once_returns_summary(mock_capture, mock_save, tmp_path):
    snap = _make_snapshot()
    mock_capture.return_value = snap

    summary = run_once(directory=tmp_path)

    assert "timestamp" in summary
    assert "path" in summary
    assert "alerts" in summary
    assert summary["alerts"] == []
    mock_save.assert_called_once()


@patch("portmap.schedule.save_snapshot")
@patch("portmap.schedule.capture")
def test_run_once_calls_on_diff_callback(mock_capture, mock_save, tmp_path):
    snap = _make_snapshot()
    mock_capture.return_value = snap
    callback = MagicMock()

    run_once(directory=tmp_path, on_diff=callback)

    callback.assert_called_once_with(snap)


@patch("portmap.schedule.save_snapshot")
@patch("portmap.schedule.capture")
def test_run_once_fires_alert_rules(mock_capture, mock_save, tmp_path):
    from portmap.alert import port_open_rule

    entry = _make_entry(port=22)
    snap = _make_snapshot(entries=[entry])
    mock_capture.return_value = snap

    rule = port_open_rule(22, protocol="tcp")
    summary = run_once(directory=tmp_path, alert_rules=[rule])

    assert len(summary["alerts"]) == 1


# ---------------------------------------------------------------------------
# run_loop
# ---------------------------------------------------------------------------

@patch("portmap.schedule.time.sleep")
@patch("portmap.schedule.load_snapshot")
@patch("portmap.schedule.save_snapshot")
@patch("portmap.schedule.capture")
def test_run_loop_respects_max_iterations(mock_capture, mock_save, mock_load, mock_sleep, tmp_path):
    snap = _make_snapshot()
    mock_capture.return_value = snap
    mock_load.return_value = snap

    run_loop(interval=1, directory=tmp_path, max_iterations=3)

    assert mock_capture.call_count == 3


@patch("portmap.schedule.time.sleep")
@patch("portmap.schedule.load_snapshot")
@patch("portmap.schedule.save_snapshot")
@patch("portmap.schedule.capture")
def test_run_loop_sleeps_between_iterations(mock_capture, mock_save, mock_load, mock_sleep, tmp_path):
    snap = _make_snapshot()
    mock_capture.return_value = snap
    mock_load.return_value = snap

    run_loop(interval=5, directory=tmp_path, max_iterations=2)

    # sleep is called between iterations, so once for 2 iterations
    mock_sleep.assert_called_with(5)
    assert mock_sleep.call_count == 1
