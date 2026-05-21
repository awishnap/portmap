"""Tests for portmap.filter module."""

from __future__ import annotations

from portmap.scanner import PortEntry
from portmap.filter import (
    by_port_range,
    by_process,
    by_pid,
    by_label,
    by_protocol,
    apply_filters,
    build_filter,
)


def _e(port: int, proto: str = "tcp", process: str | None = None, pid: int | None = None) -> PortEntry:
    entry = PortEntry(port=port, proto=proto, pid=pid, process=process, status="LISTEN")
    return entry


ENTRIES = [
    _e(80,   proto="tcp", process="nginx",   pid=100),
    _e(443,  proto="tcp", process="nginx",   pid=100),
    _e(5432, proto="tcp", process="postgres", pid=200),
    _e(6379, proto="tcp", process="redis",   pid=300),
    _e(53,   proto="udp", process="systemd", pid=1),
    _e(9000, proto="tcp", process=None,      pid=None),
]


def test_by_port_range_inclusive():
    result = by_port_range(ENTRIES, 80, 443)
    ports = {e.port for e in result}
    assert ports == {80, 443}


def test_by_port_range_single():
    result = by_port_range(ENTRIES, 5432, 5432)
    assert len(result) == 1
    assert result[0].port == 5432


def test_by_port_range_empty():
    result = by_port_range(ENTRIES, 10000, 20000)
    assert result == []


def test_by_process_case_insensitive():
    result = by_process(ENTRIES, "NGINX")
    assert len(result) == 2
    assert all(e.process == "nginx" for e in result)


def test_by_process_partial_match():
    result = by_process(ENTRIES, "post")
    assert len(result) == 1
    assert result[0].process == "postgres"


def test_by_process_no_match_for_none_process():
    result = by_process(ENTRIES, "unknown")
    assert result == []


def test_by_pid():
    result = by_pid(ENTRIES, 100)
    assert len(result) == 2
    assert all(e.pid == 100 for e in result)


def test_by_pid_not_found():
    result = by_pid(ENTRIES, 9999)
    assert result == []


def test_by_label_contains():
    # label is derived from process name via scanner.label()
    result = by_label(ENTRIES, "nginx")
    assert len(result) >= 1


def test_by_protocol_udp():
    result = by_protocol(ENTRIES, "udp")
    assert len(result) == 1
    assert result[0].port == 53


def test_by_protocol_tcp():
    result = by_protocol(ENTRIES, "tcp")
    assert all(e.proto.lower() == "tcp" for e in result)


def test_apply_filters_chained():
    f1 = lambda es: by_protocol(es, "tcp")
    f2 = lambda es: by_process(es, "nginx")
    result = apply_filters(ENTRIES, [f1, f2])
    assert len(result) == 2


def test_build_filter_combined():
    f = build_filter(port_range=(1, 1000), proto="tcp")
    result = f(list(ENTRIES))
    ports = {e.port for e in result}
    assert 80 in ports and 443 in ports
    assert 5432 not in ports


def test_build_filter_no_criteria_returns_all():
    f = build_filter()
    result = f(list(ENTRIES))
    assert len(result) == len(ENTRIES)
