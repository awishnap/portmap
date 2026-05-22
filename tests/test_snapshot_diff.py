"""Focused unit tests for snapshot_diff.compare edge cases."""

import pytest

from portmap.scanner import PortEntry
from portmap.snapshot import capture
from portmap.snapshot_diff import compare, _entry_key


def _e(port=8080, protocol="tcp", pid=1, process="app", status="LISTEN"):
    return PortEntry(port=port, protocol=protocol, pid=pid, process=process, status=status)


def test_entry_key_uses_port_and_protocol():
    e = _e(443, "tcp")
    assert _entry_key(e) == (443, "tcp")


def test_compare_empty_snapshots():
    s1 = capture([])
    s2 = capture([])
    diff = compare(s1, s2)
    assert not diff.has_changes
    assert diff.added == []
    assert diff.removed == []
    assert diff.changed == []


def test_compare_protocol_distinguishes_entries():
    """TCP and UDP on same port are treated as distinct entries."""
    s1 = capture([_e(53, "tcp")])
    s2 = capture([_e(53, "tcp"), _e(53, "udp")])
    diff = compare(s1, s2)
    assert len(diff.added) == 1
    assert diff.added[0].protocol == "udp"


def test_compare_status_change_detected():
    s1 = capture([_e(8080, status="LISTEN")])
    s2 = capture([_e(8080, status="CLOSE_WAIT")])
    diff = compare(s1, s2)
    assert len(diff.changed) == 1
    assert diff.changed[0][1].status == "CLOSE_WAIT"


def test_compare_unchanged_entry_not_in_changed():
    entry = _e(8080, pid=5, process="srv", status="LISTEN")
    s1 = capture([entry])
    s2 = capture([_e(8080, pid=5, process="srv", status="LISTEN")])
    diff = compare(s1, s2)
    assert diff.changed == []
    assert not diff.has_changes


def test_has_changes_true_when_only_added():
    diff = compare(capture([]), capture([_e(1234)]))
    assert diff.has_changes is True


def test_summary_only_removed():
    diff = compare(capture([_e(1234)]), capture([]))
    assert diff.summary() == "-1 removed"


def test_compare_pid_change_detected():
    """A process restart on the same port (new PID) should appear in changed."""
    s1 = capture([_e(8080, pid=100, process="app")])
    s2 = capture([_e(8080, pid=101, process="app")])
    diff = compare(s1, s2)
    assert len(diff.changed) == 1
    before, after = diff.changed[0]
    assert before.pid == 100
    assert after.pid == 101


def test_compare_process_name_change_detected():
    """A change in process name on the same port should appear in changed."""
    s1 = capture([_e(8080, process="old_app")])
    s2 = capture([_e(8080, process="new_app")])
    diff = compare(s1, s2)
    assert len(diff.changed) == 1
    assert diff.changed[0][0].process == "old_app"
    assert diff.changed[0][1].process == "new_app"
