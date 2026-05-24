"""Tests for portmap.asn."""
from __future__ import annotations

from unittest.mock import patch

import pytest

from portmap.asn import ASNResult, _is_private, display, enrich, lookup
from portmap.scanner import PortEntry


def _e(host: str = "93.184.216.34", port: int = 80) -> PortEntry:
    return PortEntry(
        host=host,
        port=port,
        protocol="tcp",
        status="open",
        pid=None,
        process=None,
    )


# ---------------------------------------------------------------------------
# ASNResult.display
# ---------------------------------------------------------------------------

def test_display_all_fields():
    r = ASNResult(ip="1.2.3.4", asn="15169", org="Google LLC", country="US")
    out = r.display()
    assert "1.2.3.4" in out
    assert "AS15169" in out
    assert "Google LLC" in out
    assert "[US]" in out


def test_display_no_fields_shows_unknown():
    r = ASNResult(ip="1.2.3.4")
    assert "unknown" in r.display()


def test_display_error_shows_error():
    r = ASNResult(ip="1.2.3.4", error="timeout")
    out = r.display()
    assert "error" in out
    assert "timeout" in out


# ---------------------------------------------------------------------------
# _is_private
# ---------------------------------------------------------------------------

def test_loopback_is_private():
    assert _is_private("127.0.0.1") is True


def test_rfc1918_is_private():
    assert _is_private("192.168.1.1") is True
    assert _is_private("10.0.0.1") is True
    assert _is_private("172.16.5.5") is True


def test_public_is_not_private():
    assert _is_private("8.8.8.8") is False


def test_invalid_ip_returns_false():
    assert _is_private("not-an-ip") is False


# ---------------------------------------------------------------------------
# lookup
# ---------------------------------------------------------------------------

def test_lookup_private_returns_private_org():
    result = lookup("127.0.0.1")
    assert result.org == "private"
    assert result.country == "--"
    assert result.asn is None


def test_lookup_private_10_block():
    result = lookup("10.10.10.10")
    assert result.org == "private"


def test_lookup_public_returns_asn_result():
    with patch("portmap.asn.socket.getaddrinfo", side_effect=OSError("mock")):
        result = lookup("8.8.8.8")
    assert result.ip == "8.8.8.8"
    assert result.error is not None


# ---------------------------------------------------------------------------
# enrich
# ---------------------------------------------------------------------------

def test_enrich_deduplicates_ips():
    entries = [_e("10.0.0.1", 80), _e("10.0.0.1", 443)]
    results = enrich(entries)
    assert len(results) == 2
    # Both point to same cached result object
    assert results[0] is results[1]


def test_enrich_returns_one_result_per_entry():
    entries = [_e("10.0.0.1"), _e("10.0.0.2")]
    results = enrich(entries)
    assert len(results) == 2
    assert results[0].ip == "10.0.0.1"
    assert results[1].ip == "10.0.0.2"


def test_enrich_empty_list():
    assert enrich([]) == []
