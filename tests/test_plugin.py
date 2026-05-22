"""Tests for portmap.plugin and portmap.plugin_builtins."""

from __future__ import annotations

import pytest

from portmap.scanner import PortEntry
from portmap import plugin
from portmap import plugin_builtins


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _e(
    port: int = 80,
    protocol: str = "tcp",
    status: str = "open",
    pid: int | None = None,
    process: str | None = None,
    label: str | None = None,
) -> PortEntry:
    return PortEntry(port=port, protocol=protocol, status=status,
                     pid=pid, process=process, label=label)


@pytest.fixture(autouse=True)
def _clear_registry():
    """Ensure a clean plugin registry for every test."""
    plugin.clear()
    yield
    plugin.clear()


# ---------------------------------------------------------------------------
# Registry tests
# ---------------------------------------------------------------------------

def test_register_and_list():
    plugin.register("noop", lambda entries: entries)
    assert "noop" in plugin.list_plugins()


def test_unregister_removes_plugin():
    plugin.register("noop", lambda entries: entries)
    plugin.unregister("noop")
    assert "noop" not in plugin.list_plugins()


def test_register_non_callable_raises():
    with pytest.raises(TypeError):
        plugin.register("bad", "not_a_function")  # type: ignore[arg-type]


def test_apply_unknown_plugin_raises():
    with pytest.raises(KeyError):
        plugin.apply([], plugin_name="ghost")


def test_apply_single_plugin():
    called_with = []

    def hook(entries):
        called_with.extend(entries)
        return entries

    plugin.register("spy", hook)
    entries = [_e(port=22)]
    plugin.apply(entries, plugin_name="spy")
    assert called_with == entries


def test_apply_all_plugins_in_order():
    order: list[str] = []
    plugin.register("first", lambda e: (order.append("first"), e)[1])
    plugin.register("second", lambda e: (order.append("second"), e)[1])
    plugin.apply([])
    assert order == ["first", "second"]


# ---------------------------------------------------------------------------
# Built-in plugin tests
# ---------------------------------------------------------------------------

def test_well_known_labels_http():
    plugin_builtins.register_all()
    entries = [_e(port=80, protocol="tcp")]
    result = plugin.apply(entries, plugin_name="well_known")
    assert "http" in result[0].label


def test_well_known_no_match_leaves_label_unchanged():
    plugin_builtins.register_all()
    entries = [_e(port=9999, protocol="tcp", label="custom")]
    result = plugin.apply(entries, plugin_name="well_known")
    assert result[0].label == "custom"


def test_well_known_preserves_existing_label():
    plugin_builtins.register_all()
    entries = [_e(port=443, protocol="tcp", label="my-service")]
    result = plugin.apply(entries, plugin_name="well_known")
    assert "my-service" in result[0].label
    assert "https" in result[0].label


def test_register_all_registers_expected_plugins():
    plugin_builtins.register_all()
    names = plugin.list_plugins()
    assert "well_known" in names
    assert "loopback" in names
