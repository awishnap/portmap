"""Tests for portmap.group and portmap.group_builtins."""

from __future__ import annotations

import pytest

from portmap.group import (
    PortGroup,
    group_by,
    group_entries,
    list_groups,
    register_group,
    unregister_group,
)
from portmap.group_builtins import register_all
from portmap.scanner import PortEntry


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _e(port: int, host: str = "127.0.0.1", proto: str = "tcp",
       process: str | None = None, pid: int | None = None) -> PortEntry:
    from portmap.scanner import label as _label
    e = PortEntry(host=host, port=port, protocol=proto, process=process, pid=pid)
    e.label = _label(e)
    return e


def _clear_registry():
    from portmap.group import _GROUPS
    _GROUPS.clear()


# ---------------------------------------------------------------------------
# PortGroup dataclass
# ---------------------------------------------------------------------------

def test_port_group_len_and_iter():
    pg = PortGroup("test", [_e(80), _e(443)])
    assert len(pg) == 2
    assert list(pg) == pg.entries


# ---------------------------------------------------------------------------
# register / unregister / list
# ---------------------------------------------------------------------------

def test_register_and_list():
    _clear_registry()
    register_group("web", lambda e: e.port == 80)
    assert "web" in list_groups()


def test_unregister_removes_group():
    _clear_registry()
    register_group("tmp", lambda e: True)
    unregister_group("tmp")
    assert "tmp" not in list_groups()


def test_unregister_missing_is_noop():
    _clear_registry()
    unregister_group("nonexistent")  # must not raise


def test_register_non_callable_raises():
    _clear_registry()
    with pytest.raises(TypeError):
        register_group("bad", "not-a-callable")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# group_entries
# ---------------------------------------------------------------------------

def test_group_entries_places_entry_in_matching_group():
    _clear_registry()
    register_group("web", lambda e: e.port == 80)
    groups = group_entries([_e(80), _e(9999)])
    assert len(groups["web"]) == 1
    assert groups["web"].entries[0].port == 80


def test_group_entries_ungrouped_collects_unmatched():
    _clear_registry()
    register_group("web", lambda e: e.port == 80)
    groups = group_entries([_e(9999)])
    assert len(groups["ungrouped"]) == 1


def test_group_entries_entry_can_appear_in_multiple_groups():
    _clear_registry()
    register_group("all", lambda e: True)
    register_group("high", lambda e: e.port > 1000)
    groups = group_entries([_e(8080)])
    assert len(groups["all"]) == 1
    assert len(groups["high"]) == 1


# ---------------------------------------------------------------------------
# group_by (ad-hoc)
# ---------------------------------------------------------------------------

def test_group_by_protocol():
    entries = [_e(80, proto="tcp"), _e(53, proto="udp"), _e(443, proto="tcp")]
    groups = group_by(entries, lambda e: e.protocol)
    assert len(groups["tcp"]) == 2
    assert len(groups["udp"]) == 1


def test_group_by_returns_port_group_instances():
    groups = group_by([_e(80)], lambda e: "mygroup")
    assert isinstance(groups["mygroup"], PortGroup)


# ---------------------------------------------------------------------------
# Built-in groups
# ---------------------------------------------------------------------------

def test_register_all_creates_expected_groups():
    _clear_registry()
    register_all()
    names = list_groups()
    for expected in ("web", "database", "secure", "loopback", "ephemeral"):
        assert expected in names


def test_builtin_web_group_matches_port_80():
    _clear_registry()
    register_all()
    groups = group_entries([_e(80)])
    assert any(e.port == 80 for e in groups["web"])


def test_builtin_ephemeral_group_matches_high_port():
    _clear_registry()
    register_all()
    groups = group_entries([_e(60000)])
    assert any(e.port == 60000 for e in groups["ephemeral"])
