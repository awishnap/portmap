"""Tests for portmap.trend module."""

from __future__ import annotations

import datetime
from typing import List

import pytest

from portmap.snapshot import Snapshot
from portmap.scanner import PortEntry
from portmap.trend import analyse, PortTrend, TrendReport


def _entry(port: int, protocol: str = "tcp", pid: int = 1000, label: str = "svc") -> PortEntry:
    return PortEntry(port=port, protocol=protocol, status="LISTEN", pid=pid, process=label, label=label)


def _snap(*entries: PortEntry) -> Snapshot:
    return Snapshot(
        host="localhost",
        timestamp=datetime.datetime.utcnow().isoformat(),
        entries=list(entries),
    )


# ---------------------------------------------------------------------------
# analyse()
# ---------------------------------------------------------------------------

def test_analyse_empty_list_returns_zero():
    report = analyse([])
    assert report.snapshots_analysed == 0
    assert report.trends == []


def test_analyse_single_snapshot_stability_is_one():
    report = analyse([_snap(_entry(8080))])
    assert len(report.trends) == 1
    assert report.trends[0].stability == 1.0


def test_analyse_port_present_in_all_snapshots():
    snaps = [_snap(_entry(80)) for _ in range(5)]
    report = analyse(snaps)
    trend = report.trends[0]
    assert trend.port == 80
    assert trend.snapshots_present == 5
    assert trend.stability == 1.0
    assert trend.appearances == 1  # appeared once at the start


def test_analyse_port_disappears_and_reappears():
    s1 = _snap(_entry(9000))
    s2 = _snap()           # port gone
    s3 = _snap(_entry(9000))  # port back
    report = analyse([s1, s2, s3])
    trend = report.trends[0]
    assert trend.appearances == 2
    assert trend.disappearances == 1
    assert trend.snapshots_present == 2
    assert abs(trend.stability - 2 / 3) < 1e-9


def test_analyse_multiple_ports_sorted_by_port():
    snap = _snap(_entry(443), _entry(80), _entry(8080))
    report = analyse([snap])
    ports = [t.port for t in report.trends]
    assert ports == sorted(ports)


def test_analyse_protocol_distinguishes_ports():
    s1 = _snap(_entry(53, "tcp"), _entry(53, "udp"))
    report = analyse([s1])
    assert len(report.trends) == 2
    keys = {t.key for t in report.trends}
    assert "53/tcp" in keys and "53/udp" in keys


def test_analyse_last_seen_label_updated():
    s1 = _snap(_entry(3000, label="old-svc"))
    s2 = _snap(_entry(3000, label="new-svc"))
    report = analyse([s1, s2])
    assert report.trends[0].last_seen_label == "new-svc"


# ---------------------------------------------------------------------------
# TrendReport helpers
# ---------------------------------------------------------------------------

def test_always_open_filters_correctly():
    snaps = [_snap(_entry(22)) for _ in range(3)]
    report = analyse(snaps)
    assert len(report.always_open()) == 1


def test_unstable_filters_below_threshold():
    s1 = _snap(_entry(5000))
    s2 = _snap()  # gone
    s3 = _snap()  # gone
    s4 = _snap()  # gone
    report = analyse([s1, s2, s3, s4])
    # stability == 0.25, below default 0.8
    assert len(report.unstable()) == 1
    assert len(report.unstable(threshold=0.1)) == 0
