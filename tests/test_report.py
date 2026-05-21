"""Tests for portmap.report — HTML and Markdown report generation."""

import pytest
from pathlib import Path
from unittest.mock import MagicMock

from portmap.report import render_markdown, render_html, save_report
from portmap.snapshot import Snapshot
from portmap.snapshot_diff import SnapshotDiff


def _make_snapshot(entries=None, host="localhost", timestamp="2024-01-01T00:00:00"):
    snap = Snapshot(
        host=host,
        timestamp=timestamp,
        entries=entries or [],
    )
    return snap


def _make_entry(port=8080, protocol="tcp", status="LISTEN", process="python", pid=1234, label="dev"):
    return {
        "port": port,
        "protocol": protocol,
        "status": status,
        "process": process,
        "pid": pid,
        "label": label,
    }


def _make_diff(appeared=0, disappeared=0, changed=0):
    diff = MagicMock(spec=SnapshotDiff)
    diff.has_changes.return_value = appeared + disappeared + changed > 0
    diff.summary.return_value = {
        "appeared": appeared,
        "disappeared": disappeared,
        "changed": changed,
    }
    return diff


# --- render_markdown ---

def test_render_markdown_contains_header():
    snap = _make_snapshot()
    md = render_markdown(snap)
    assert "# portmap Report" in md


def test_render_markdown_contains_host():
    snap = _make_snapshot(host="myhost")
    md = render_markdown(snap)
    assert "myhost" in md


def test_render_markdown_contains_timestamp():
    snap = _make_snapshot(timestamp="2024-06-15T12:00:00")
    md = render_markdown(snap)
    assert "2024-06-15T12:00:00" in md


def test_render_markdown_table_has_entry():
    snap = _make_snapshot(entries=[_make_entry(port=9090)])
    md = render_markdown(snap)
    assert "9090" in md


def test_render_markdown_no_diff_section_when_no_changes():
    snap = _make_snapshot()
    diff = _make_diff()
    md = render_markdown(snap, diff=diff)
    assert "Changes Since Last Snapshot" not in md


def test_render_markdown_diff_section_when_changes():
    snap = _make_snapshot()
    diff = _make_diff(appeared=2, disappeared=1)
    md = render_markdown(snap, diff=diff)
    assert "Changes Since Last Snapshot" in md
    assert "Appeared: 2" in md
    assert "Disappeared: 1" in md


def test_render_markdown_no_diff_arg():
    snap = _make_snapshot(entries=[_make_entry()])
    md = render_markdown(snap)
    assert "Open Ports" in md


# --- render_html ---

def test_render_html_is_valid_html():
    snap = _make_snapshot()
    html = render_html(snap)
    assert "<!DOCTYPE html>" in html
    assert "</html>" in html


def test_render_html_contains_entry_data():
    snap = _make_snapshot(entries=[_make_entry(port=5432, process="postgres")])
    html = render_html(snap)
    assert "5432" in html
    assert "postgres" in html


def test_render_html_diff_section_present_when_changes():
    snap = _make_snapshot()
    diff = _make_diff(appeared=1)
    html = render_html(snap, diff=diff)
    assert "Changes" in html
    assert "Appeared: 1" in html


def test_render_html_no_diff_section_without_changes():
    snap = _make_snapshot()
    diff = _make_diff()
    html = render_html(snap, diff=diff)
    assert "<h2>Changes</h2>" not in html


# --- save_report ---

def test_save_report_writes_file(tmp_path):
    out = tmp_path / "report.md"
    result = save_report("# Hello", out)
    assert result.exists()
    assert result.read_text() == "# Hello"


def test_save_report_creates_parent_dirs(tmp_path):
    out = tmp_path / "sub" / "dir" / "report.html"
    save_report("<html/>", out)
    assert out.exists()


def test_save_report_returns_resolved_path(tmp_path):
    out = tmp_path / "out.md"
    result = save_report("content", out)
    assert result == out.resolve()
