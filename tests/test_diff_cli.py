"""Tests for portmap.diff_cli."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from portmap.diff_cli import _render_text, _render_json, run_diff, build_diff_parser
from portmap.snapshot_diff import SnapshotDiff
from portmap.snapshot import Snapshot


def _e(port: int, proto: str = "tcp", label: str = "") -> object:
    from portmap.scanner import PortEntry
    return PortEntry(port=port, protocol=proto, pid=None, process=None, status="LISTEN", label=label)


def _snap(*entries) -> Snapshot:
    import datetime
    return Snapshot(host="localhost", ts=datetime.datetime.utcnow().isoformat(), entries=list(entries))


# --- _render_text ---

def test_render_text_no_changes():
    diff = SnapshotDiff(appeared=[], disappeared=[], changed=[])
    out = _render_text(diff, color=False)
    assert "No changes" in out


def test_render_text_appeared_shows_plus(tmp_path):
    diff = SnapshotDiff(appeared=[_e(8080, label="http")], disappeared=[], changed=[])
    out = _render_text(diff, color=False)
    assert "+" in out
    assert "8080" in out


def test_render_text_disappeared_shows_minus():
    diff = SnapshotDiff(appeared=[], disappeared=[_e(22, label="ssh")], changed=[])
    out = _render_text(diff, color=False)
    assert "-" in out
    assert "22" in out


def test_render_text_summary_line():
    diff = SnapshotDiff(appeared=[_e(80)], disappeared=[_e(443)], changed=[])
    out = _render_text(diff, color=False)
    assert "Summary:" in out
    assert "1 appeared" in out
    assert "1 disappeared" in out


def test_render_text_color_codes_present_by_default():
    diff = SnapshotDiff(appeared=[_e(8080)], disappeared=[], changed=[])
    out = _render_text(diff, color=True)
    assert "\033[" in out


# --- _render_json ---

def test_render_json_structure():
    diff = SnapshotDiff(appeared=[_e(80)], disappeared=[_e(22)], changed=[])
    raw = _render_json(diff)
    data = json.loads(raw)
    assert "has_changes" in data
    assert "appeared" in data
    assert "disappeared" in data
    assert "changed" in data
    assert "summary" in data


def test_render_json_has_changes_true():
    diff = SnapshotDiff(appeared=[_e(80)], disappeared=[], changed=[])
    data = json.loads(_render_json(diff))
    assert data["has_changes"] is True


def test_render_json_has_changes_false():
    diff = SnapshotDiff(appeared=[], disappeared=[], changed=[])
    data = json.loads(_render_json(diff))
    assert data["has_changes"] is False


# --- run_diff ---

def test_run_diff_returns_0_when_no_changes(tmp_path):
    from portmap.snapshot import save_snapshot
    snap = _snap(_e(80))
    p1 = tmp_path / "a.json"
    p2 = tmp_path / "b.json"
    save_snapshot(snap, p1)
    save_snapshot(snap, p2)
    args = SimpleNamespace(baseline=p1, current=p2, fmt="text", no_color=True)
    assert run_diff(args) == 0


def test_run_diff_returns_2_when_changes(tmp_path):
    from portmap.snapshot import save_snapshot
    snap_a = _snap(_e(80))
    snap_b = _snap(_e(443))
    p1 = tmp_path / "a.json"
    p2 = tmp_path / "b.json"
    save_snapshot(snap_a, p1)
    save_snapshot(snap_b, p2)
    args = SimpleNamespace(baseline=p1, current=p2, fmt="text", no_color=True)
    assert run_diff(args) == 2


def test_run_diff_missing_file_returns_1(tmp_path):
    args = SimpleNamespace(
        baseline=tmp_path / "nope.json",
        current=tmp_path / "also_nope.json",
        fmt="text",
        no_color=True,
    )
    assert run_diff(args) == 1


def test_build_diff_parser_defaults():
    parser = build_diff_parser()
    assert parser is not None
