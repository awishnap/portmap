"""Tests for portmap.service_map."""

from __future__ import annotations

import pytest
from unittest.mock import patch

from portmap.service_map import ServiceInfo, lookup, tier, enrich_entries


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

class _FakeEntry:
    def __init__(self, port: int, protocol: str = "tcp", label: str | None = None):
        self.port = port
        self.protocol = protocol
        self.label = label


# ---------------------------------------------------------------------------
# tier()
# ---------------------------------------------------------------------------

def test_tier_system():
    assert tier(80) == "system"


def test_tier_boundary_system():
    assert tier(1023) == "system"


def test_tier_registered():
    assert tier(8080) == "registered"


def test_tier_boundary_registered():
    assert tier(49151) == "registered"


def test_tier_dynamic():
    assert tier(55000) == "dynamic"


# ---------------------------------------------------------------------------
# lookup()
# ---------------------------------------------------------------------------

def test_lookup_known_port_returns_service_info():
    info = lookup(80)
    assert isinstance(info, ServiceInfo)
    assert info.name == "http"
    assert info.tier == "system"
    assert info.port == 80


def test_lookup_mysql():
    info = lookup(3306)
    assert info is not None
    assert info.name == "mysql"
    assert info.tier == "registered"


def test_lookup_unknown_port_falls_back_to_socket(monkeypatch):
    import socket
    monkeypatch.setattr(socket, "getservbyport", lambda p: "custom-svc")
    info = lookup(12345)
    assert info is not None
    assert info.name == "custom-svc"


def test_lookup_unknown_port_returns_none_on_oserror(monkeypatch):
    import socket
    monkeypatch.setattr(socket, "getservbyport", lambda p: (_ for _ in ()).throw(OSError()))
    info = lookup(19999)
    assert info is None


# ---------------------------------------------------------------------------
# enrich_entries()
# ---------------------------------------------------------------------------

def test_enrich_entries_known_port():
    entries = [_FakeEntry(port=22, label="ssh-server")]
    rows = enrich_entries(entries)
    assert len(rows) == 1
    assert rows[0]["service"] == "ssh"
    assert rows[0]["tier"] == "system"
    assert rows[0]["label"] == "ssh-server"


def test_enrich_entries_unknown_port_service_is_none(monkeypatch):
    import socket
    monkeypatch.setattr(socket, "getservbyport", lambda p: (_ for _ in ()).throw(OSError()))
    entries = [_FakeEntry(port=19999)]
    rows = enrich_entries(entries)
    assert rows[0]["service"] is None
    assert rows[0]["tier"] == "registered"


def test_enrich_entries_preserves_protocol():
    entries = [_FakeEntry(port=53, protocol="udp")]
    rows = enrich_entries(entries)
    assert rows[0]["protocol"] == "udp"


def test_enrich_entries_multiple():
    entries = [_FakeEntry(80), _FakeEntry(443), _FakeEntry(6379)]
    rows = enrich_entries(entries)
    names = [r["service"] for r in rows]
    assert "http" in names
    assert "https" in names
    assert "redis" in names
