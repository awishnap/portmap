"""Tests for portmap.network_interface."""

from __future__ import annotations

from unittest.mock import MagicMock, patch
import socket

import pytest

from portmap.network_interface import (
    NetworkInterface,
    _loopback_names,
    list_interfaces,
    active_interfaces,
    resolve_bind_address,
)


# ---------------------------------------------------------------------------
# NetworkInterface helpers
# ---------------------------------------------------------------------------

def test_primary_address_returns_first_valid_ipv4():
    iface = NetworkInterface("eth0", ["192.168.1.10", "10.0.0.1"], False, True)
    assert iface.primary_address() == "192.168.1.10"


def test_primary_address_skips_link_local():
    iface = NetworkInterface("eth0", ["169.254.0.1", "10.0.0.5"], False, True)
    assert iface.primary_address() == "10.0.0.5"


def test_primary_address_none_when_empty():
    iface = NetworkInterface("eth0", [], False, True)
    assert iface.primary_address() is None


def test_loopback_names_contains_lo():
    assert "lo" in _loopback_names()
    assert "lo0" in _loopback_names()
    assert "loopback" in _loopback_names()


# ---------------------------------------------------------------------------
# list_interfaces — psutil available path
# ---------------------------------------------------------------------------

def _make_psutil_mocks():
    """Return (net_if_stats, net_if_addrs) mock return values."""
    addr_eth = MagicMock()
    addr_eth.family = socket.AF_INET
    addr_eth.address = "192.168.1.5"

    addr_lo = MagicMock()
    addr_lo.family = socket.AF_INET
    addr_lo.address = "127.0.0.1"

    stat_eth = MagicMock(isup=True)
    stat_lo = MagicMock(isup=True)

    return (
        {"eth0": stat_eth, "lo": stat_lo},
        {"eth0": [addr_eth], "lo": [addr_lo]},
    )


@patch("portmap.network_interface._HAS_PSUTIL", True)
@patch("portmap.network_interface.psutil")
def test_list_interfaces_returns_both(mock_psutil):
    stats, addrs = _make_psutil_mocks()
    mock_psutil.net_if_stats.return_value = stats
    mock_psutil.net_if_addrs.return_value = addrs
    mock_psutil.AF_INET = socket.AF_INET  # not used directly but kept consistent

    ifaces = list_interfaces()
    names = {i.name for i in ifaces}
    assert "eth0" in names
    assert "lo" in names


@patch("portmap.network_interface._HAS_PSUTIL", True)
@patch("portmap.network_interface.psutil")
def test_list_interfaces_loopback_flag(mock_psutil):
    stats, addrs = _make_psutil_mocks()
    mock_psutil.net_if_stats.return_value = stats
    mock_psutil.net_if_addrs.return_value = addrs

    ifaces = {i.name: i for i in list_interfaces()}
    assert ifaces["lo"].is_loopback is True
    assert ifaces["eth0"].is_loopback is False


# ---------------------------------------------------------------------------
# active_interfaces
# ---------------------------------------------------------------------------

def _make_ifaces():
    return [
        NetworkInterface("eth0", ["10.0.0.1"], False, True),
        NetworkInterface("lo", ["127.0.0.1"], True, True),
        NetworkInterface("eth1", ["10.0.0.2"], False, False),
    ]


@patch("portmap.network_interface.list_interfaces")
def test_active_excludes_loopback_by_default(mock_list):
    mock_list.return_value = _make_ifaces()
    result = active_interfaces()
    names = [i.name for i in result]
    assert "eth0" in names
    assert "lo" not in names
    assert "eth1" not in names  # down


@patch("portmap.network_interface.list_interfaces")
def test_active_includes_loopback_when_requested(mock_list):
    mock_list.return_value = _make_ifaces()
    result = active_interfaces(include_loopback=True)
    names = [i.name for i in result]
    assert "lo" in names


# ---------------------------------------------------------------------------
# resolve_bind_address
# ---------------------------------------------------------------------------

@patch("portmap.network_interface.list_interfaces")
def test_resolve_bind_address_found(mock_list):
    mock_list.return_value = _make_ifaces()
    assert resolve_bind_address("eth0") == "10.0.0.1"


@patch("portmap.network_interface.list_interfaces")
def test_resolve_bind_address_not_found(mock_list):
    mock_list.return_value = _make_ifaces()
    assert resolve_bind_address("wlan99") is None
