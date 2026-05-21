"""Tests for portmap.exporter — file export functionality."""

from __future__ import annotations

import csv
import io
import json
import textwrap
from pathlib import Path

import pytest

from portmap.exporter import export_csv, export_json, export_markdown, save
from portmap.scanner import PortEntry


def _entry(port: int, proto: str = "tcp", state: str = "LISTEN", pid: int | None = 1234, process: str | None = "python") -> PortEntry:
    return PortEntry(port=port, proto=proto, state=state, pid=pid, process=process)


# ---------------------------------------------------------------------------
# export_json
# ---------------------------------------------------------------------------

def test_export_json_structure():
    entries = [_entry(8080), _entry(443, pid=None, process=None)]
    result = json.loads(export_json(entries))
    assert len(result) == 2
    assert result[0]["port"] == 8080
    assert result[0]["process"] == "python"
    assert result[1]["pid"] is None


def test_export_json_label_included():
    entry = _entry(22, process="sshd")
    result = json.loads(export_json([entry]))
    assert "label" in result[0]


# ---------------------------------------------------------------------------
# export_csv
# ---------------------------------------------------------------------------

def test_export_csv_has_header():
    content = export_csv([_entry(80)])
    first_line = content.splitlines()[0]
    assert "port" in first_line and "process" in first_line


def test_export_csv_row_values():
    content = export_csv([_entry(9000, pid=42, process="myapp")])
    reader = csv.DictReader(io.StringIO(content))
    rows = list(reader)
    assert rows[0]["port"] == "9000"
    assert rows[0]["process"] == "myapp"


def test_export_csv_empty_pid_when_none():
    content = export_csv([_entry(9001, pid=None, process=None)])
    reader = csv.DictReader(io.StringIO(content))
    rows = list(reader)
    assert rows[0]["pid"] == ""
    assert rows[0]["process"] == ""


# ---------------------------------------------------------------------------
# export_markdown
# ---------------------------------------------------------------------------

def test_export_markdown_has_separator():
    content = export_markdown([_entry(3000)])
    lines = content.splitlines()
    assert lines[1].startswith("|---")


def test_export_markdown_row_count():
    entries = [_entry(p) for p in (80, 443, 8080)]
    lines = export_markdown(entries).splitlines()
    # header + separator + 3 data rows
    assert len(lines) == 5


# ---------------------------------------------------------------------------
# save
# ---------------------------------------------------------------------------

def test_save_json(tmp_path):
    out = save([_entry(8000)], tmp_path / "out.json", "json")
    assert out.exists()
    data = json.loads(out.read_text())
    assert data[0]["port"] == 8000


def test_save_csv(tmp_path):
    out = save([_entry(8001)], tmp_path / "out.csv", "csv")
    assert out.suffix == ".csv"
    assert "8001" in out.read_text()


def test_save_markdown(tmp_path):
    out = save([_entry(8002)], tmp_path / "out.md", "markdown")
    assert "|" in out.read_text()


def test_save_invalid_format(tmp_path):
    with pytest.raises(ValueError, match="Unsupported format"):
        save([_entry(1)], tmp_path / "x.txt", "xml")  # type: ignore[arg-type]
