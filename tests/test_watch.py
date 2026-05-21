"""Tests for portmap.watch — diff and continuous-watch logic."""

from __future__ import annotations

from typing import List
from unittest.mock import MagicMock, patch

import pytest

from portmap.scanner import PortEntry
from portmap.watch import WatchDiff, diff, watch


def _e(port: int, proto: str = "tcp") -> PortEntry:
    return PortEntry(port=port, proto=proto, state="LISTEN", pid=None, process=None)


# ---------------------------------------------------------------------------
# diff
# ---------------------------------------------------------------------------

def test_diff_no_changes():
    entries = [_e(80), _e(443)]
    d = diff(entries, entries)
    assert not d.has_changes
    assert d.appeared == []
    assert d.disappeared == []


def test_diff_appeared():
    prev = [_e(80)]
    curr = [_e(80), _e(8080)]
    d = diff(prev, curr)
    assert len(d.appeared) == 1
    assert d.appeared[0].port == 8080
    assert d.disappeared == []


def test_diff_disappeared():
    prev = [_e(80), _e(3000)]
    curr = [_e(80)]
    d = diff(prev, curr)
    assert d.appeared == []
    assert len(d.disappeared) == 1
    assert d.disappeared[0].port == 3000


def test_diff_both():
    prev = [_e(80), _e(443)]
    curr = [_e(80), _e(8080)]
    d = diff(prev, curr)
    assert len(d.appeared) == 1
    assert len(d.disappeared) == 1


def test_diff_proto_distinguishes_entries():
    prev = [_e(80, "tcp")]
    curr = [_e(80, "udp")]
    d = diff(prev, curr)
    assert len(d.appeared) == 1
    assert len(d.disappeared) == 1


# ---------------------------------------------------------------------------
# WatchDiff.has_changes
# ---------------------------------------------------------------------------

def test_watch_diff_has_changes_false():
    assert not WatchDiff().has_changes


def test_watch_diff_has_changes_true():
    assert WatchDiff(appeared=[_e(1)]).has_changes


# ---------------------------------------------------------------------------
# watch
# ---------------------------------------------------------------------------

def test_watch_calls_on_diff_when_change():
    snapshots = [[_e(80)], [_e(80), _e(443)]]
    scan_iter = iter(snapshots)

    received: List[WatchDiff] = []

    def fake_scan(**_):
        return next(scan_iter)

    def on_diff(d, current):
        received.append(d)

    watch(interval=0, on_diff=on_diff, iterations=2, _scan_fn=fake_scan)
    assert len(received) == 1
    assert received[0].appeared[0].port == 443


def test_watch_no_callback_when_no_change():
    scan_fn = MagicMock(return_value=[_e(80)])
    called = []
    watch(interval=0, on_diff=lambda d, c: called.append(d), iterations=3, _scan_fn=scan_fn)
    # First iteration: prev=[] curr=[80] → change; subsequent: no change
    assert len(called) == 1


def test_watch_respects_iterations():
    scan_fn = MagicMock(return_value=[])
    watch(interval=0, on_diff=lambda d, c: None, iterations=5, _scan_fn=scan_fn)
    assert scan_fn.call_count == 5
