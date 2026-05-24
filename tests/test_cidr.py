"""Tests for portmap.cidr and portmap.cidr_cli."""

from __future__ import annotations

import argparse
import json
from typing import Optional

import pytest

from portmap.cidr import CIDRFilter, apply_filter, matches_any, summarise
from portmap.cidr_cli import _render_json, _render_text, run_cidr
from portmap.scanner import PortEntry


def _e(host: str = "127.0.0.1", port: int = 80, protocol: str = "tcp",
       status: str = "open", pid: Optional[int] = None,
       process: Optional[str] = None) -> PortEntry:
    return PortEntry(host=host, port=port, protocol=protocol,
                     status=status, pid=pid, process=process)


# --- CIDRFilter validation ---

def test_cidr_filter_invalid_block_raises():
    with pytest.raises(ValueError):
        CIDRFilter(allow=["not-a-cidr"])


def test_cidr_filter_valid_blocks_accepted():
    f = CIDRFilter(allow=["10.0.0.0/8"], deny=["10.1.0.0/16"])
    assert f.allow == ["10.0.0.0/8"]


# --- matches_any ---

def test_matches_any_true_when_in_range():
    e = _e(host="192.168.1.50")
    assert matches_any(e, ["192.168.1.0/24"]) is True


def test_matches_any_false_when_outside_range():
    e = _e(host="10.0.0.1")
    assert matches_any(e, ["192.168.1.0/24"]) is False


def test_matches_any_invalid_host_returns_false():
    e = _e(host="not-an-ip")
    assert matches_any(e, ["10.0.0.0/8"]) is False


def test_matches_any_multiple_cidrs_any_match():
    e = _e(host="172.16.0.5")
    assert matches_any(e, ["10.0.0.0/8", "172.16.0.0/12"]) is True


# --- apply_filter ---

def test_apply_filter_empty_allow_keeps_all():
    entries = [_e("10.0.0.1"), _e("192.168.1.1")]
    result = apply_filter(entries, CIDRFilter())
    assert len(result) == 2


def test_apply_filter_allow_restricts():
    entries = [_e("10.0.0.1"), _e("192.168.1.1")]
    result = apply_filter(entries, CIDRFilter(allow=["10.0.0.0/8"]))
    assert len(result) == 1
    assert result[0].host == "10.0.0.1"


def test_apply_filter_deny_removes():
    entries = [_e("10.0.0.1"), _e("10.1.0.1")]
    result = apply_filter(entries, CIDRFilter(deny=["10.1.0.0/16"]))
    assert len(result) == 1
    assert result[0].host == "10.0.0.1"


def test_apply_filter_allow_then_deny():
    entries = [_e("10.0.0.1"), _e("10.1.0.1"), _e("192.168.1.1")]
    f = CIDRFilter(allow=["10.0.0.0/8"], deny=["10.1.0.0/16"])
    result = apply_filter(entries, f)
    assert [e.host for e in result] == ["10.0.0.1"]


# --- summarise ---

def test_summarise_groups_by_prefix():
    entries = [_e("192.168.1.1"), _e("192.168.1.2"), _e("10.0.0.1")]
    s = summarise(entries)
    assert s["192.168.1.0/24"] == 2
    assert s["10.0.0.0/24"] == 1


def test_summarise_invalid_host_skipped():
    entries = [_e("not-an-ip"), _e("10.0.0.1")]
    s = summarise(entries)
    assert len(s) == 1


# --- CLI helpers ---

def test_render_text_empty():
    assert _render_text([]) == "No matching entries."


def test_render_text_contains_host_and_port():
    out = _render_text([_e("127.0.0.1", 8080)])
    assert "127.0.0.1" in out
    assert "8080" in out


def test_render_json_is_valid_json():
    data = json.loads(_render_json([_e("127.0.0.1", 443)]))
    assert isinstance(data, list)
    assert data[0]["port"] == 443


def _args(**kwargs) -> argparse.Namespace:
    defaults = dict(allow=[], deny=[], summarise=False, format="text", ports=None)
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


def test_run_cidr_invalid_cidr_returns_1():
    code = run_cidr(_args(allow=["bad-cidr"]), entries=[_e()])
    assert code == 1


def test_run_cidr_text_output_returns_0(capsys):
    code = run_cidr(_args(), entries=[_e("10.0.0.1", 80)])
    assert code == 0
    out = capsys.readouterr().out
    assert "10.0.0.1" in out


def test_run_cidr_json_output(capsys):
    code = run_cidr(_args(format="json"), entries=[_e("10.0.0.1", 80)])
    assert code == 0
    data = json.loads(capsys.readouterr().out)
    assert data[0]["host"] == "10.0.0.1"


def test_run_cidr_summarise_text(capsys):
    entries = [_e("10.0.0.1"), _e("10.0.0.2")]
    code = run_cidr(_args(summarise=True), entries=entries)
    assert code == 0
    out = capsys.readouterr().out
    assert "10.0.0.0/24" in out


def test_run_cidr_summarise_json(capsys):
    entries = [_e("10.0.0.1")]
    code = run_cidr(_args(summarise=True, format="json"), entries=entries)
    assert code == 0
    data = json.loads(capsys.readouterr().out)
    assert "10.0.0.0/24" in data
