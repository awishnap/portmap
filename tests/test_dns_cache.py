"""Tests for portmap.dns_cache."""

from __future__ import annotations

import time
from unittest.mock import patch

import pytest

from portmap.dns_cache import (
    DNSCache,
    _CacheEntry,
    _reverse_lookup,
    resolve,
    clear_default_cache,
)


# ---------------------------------------------------------------------------
# _CacheEntry
# ---------------------------------------------------------------------------

def test_cache_entry_not_expired_immediately():
    entry = _CacheEntry(hostname="host.local", resolved_at=time.monotonic(), ttl=60)
    assert not entry.is_expired()


def test_cache_entry_expired_after_ttl():
    entry = _CacheEntry(hostname="host.local", resolved_at=time.monotonic() - 120, ttl=60)
    assert entry.is_expired()


# ---------------------------------------------------------------------------
# DNSCache construction
# ---------------------------------------------------------------------------

def test_invalid_ttl_raises():
    with pytest.raises(ValueError):
        DNSCache(ttl=0)


def test_negative_ttl_raises():
    with pytest.raises(ValueError):
        DNSCache(ttl=-5)


# ---------------------------------------------------------------------------
# DNSCache.resolve
# ---------------------------------------------------------------------------

def test_resolve_returns_hostname(monkeypatch):
    monkeypatch.setattr("portmap.dns_cache._reverse_lookup", lambda ip: "myhost.local")
    cache = DNSCache(ttl=60)
    assert cache.resolve("192.168.1.1") == "myhost.local"


def test_resolve_caches_result(monkeypatch):
    calls = []

    def fake_lookup(ip):
        calls.append(ip)
        return "cached.host"

    monkeypatch.setattr("portmap.dns_cache._reverse_lookup", fake_lookup)
    cache = DNSCache(ttl=60)
    cache.resolve("10.0.0.1")
    cache.resolve("10.0.0.1")
    assert len(calls) == 1


def test_resolve_refreshes_expired_entry(monkeypatch):
    calls = []

    def fake_lookup(ip):
        calls.append(ip)
        return "refreshed.host"

    monkeypatch.setattr("portmap.dns_cache._reverse_lookup", fake_lookup)
    cache = DNSCache(ttl=1)
    cache.resolve("10.0.0.2")
    # Manually expire the entry.
    cache._store["10.0.0.2"].resolved_at -= 10
    cache.resolve("10.0.0.2")
    assert len(calls) == 2


def test_resolve_none_on_lookup_failure(monkeypatch):
    monkeypatch.setattr("portmap.dns_cache._reverse_lookup", lambda ip: None)
    cache = DNSCache(ttl=60)
    assert cache.resolve("8.8.8.8") is None


# ---------------------------------------------------------------------------
# DNSCache.invalidate / clear
# ---------------------------------------------------------------------------

def test_invalidate_removes_entry(monkeypatch):
    monkeypatch.setattr("portmap.dns_cache._reverse_lookup", lambda ip: "host")
    cache = DNSCache(ttl=60)
    cache.resolve("1.2.3.4")
    cache.invalidate("1.2.3.4")
    assert "1.2.3.4" not in cache._store


def test_invalidate_missing_key_is_noop():
    cache = DNSCache(ttl=60)
    cache.invalidate("9.9.9.9")  # should not raise


def test_clear_empties_store(monkeypatch):
    monkeypatch.setattr("portmap.dns_cache._reverse_lookup", lambda ip: "host")
    cache = DNSCache(ttl=60)
    cache.resolve("1.1.1.1")
    cache.resolve("2.2.2.2")
    cache.clear()
    total, _ = cache.stats()
    assert total == 0


# ---------------------------------------------------------------------------
# DNSCache.stats
# ---------------------------------------------------------------------------

def test_stats_counts_entries(monkeypatch):
    monkeypatch.setattr("portmap.dns_cache._reverse_lookup", lambda ip: "host")
    cache = DNSCache(ttl=60)
    cache.resolve("1.1.1.1")
    cache.resolve("2.2.2.2")
    total, expired = cache.stats()
    assert total == 2
    assert expired == 0


def test_stats_counts_expired(monkeypatch):
    monkeypatch.setattr("portmap.dns_cache._reverse_lookup", lambda ip: "host")
    cache = DNSCache(ttl=60)
    cache.resolve("3.3.3.3")
    cache._store["3.3.3.3"].resolved_at -= 120
    _, expired = cache.stats()
    assert expired == 1


# ---------------------------------------------------------------------------
# Module-level resolve helper
# ---------------------------------------------------------------------------

def test_module_resolve_uses_default_cache(monkeypatch):
    monkeypatch.setattr("portmap.dns_cache._reverse_lookup", lambda ip: "global.host")
    clear_default_cache()
    result = resolve("5.5.5.5")
    assert result == "global.host"


def test_module_resolve_accepts_custom_cache(monkeypatch):
    monkeypatch.setattr("portmap.dns_cache._reverse_lookup", lambda ip: "custom.host")
    custom = DNSCache(ttl=30)
    result = resolve("6.6.6.6", cache=custom)
    assert result == "custom.host"
