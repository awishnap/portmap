"""Tests for portmap.geo enrichment helpers."""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from portmap.scanner import PortEntry
from portmap.geo import (
    GeoEntry,
    _loopback_or_private,
    lookup,
    enrich,
    enrich_all,
)


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
# _loopback_or_private
# ---------------------------------------------------------------------------


def test_loopback_detected():
    assert _loopback_or_private("127.0.0.1") is True


def test_private_10_detected():
    assert _loopback_or_private("10.0.0.1") is True


def test_private_172_detected():
    assert _loopback_or_private("172.16.5.1") is True


def test_private_192_168_detected():
    assert _loopback_or_private("192.168.1.1") is True


def test_public_ip_not_private():
    assert _loopback_or_private("93.184.216.34") is False


def test_invalid_ip_treated_as_private():
    assert _loopback_or_private("not-an-ip") is True


# ---------------------------------------------------------------------------
# lookup
# ---------------------------------------------------------------------------


def test_lookup_no_provider_returns_empty():
    assert lookup("93.184.216.34", provider=None) == {}


def test_lookup_private_ip_skips_provider():
    provider = MagicMock()
    result = lookup("192.168.0.1", provider=provider)
    assert result == {}
    provider.city.assert_not_called()


def test_lookup_calls_provider_for_public_ip():
    provider = MagicMock()
    response = MagicMock()
    response.country.name = "United States"
    response.city.name = "Norwell"
    response.autonomous_system_number = 15133
    provider.city.return_value = response

    result = lookup("93.184.216.34", provider=provider)

    provider.city.assert_called_once_with("93.184.216.34")
    assert result["country"] == "United States"
    assert result["city"] == "Norwell"


def test_lookup_provider_exception_returns_empty():
    provider = MagicMock()
    provider.city.side_effect = RuntimeError("db error")
    assert lookup("93.184.216.34", provider=provider) == {}


# ---------------------------------------------------------------------------
# enrich / enrich_all
# ---------------------------------------------------------------------------


def test_enrich_returns_geo_entry():
    geo = enrich(_e(), provider=None)
    assert isinstance(geo, GeoEntry)
    assert geo.country is None


def test_enrich_display_location_unknown_when_no_data():
    geo = enrich(_e(), provider=None)
    assert geo.display_location == "unknown"


def test_enrich_display_location_with_data():
    provider = MagicMock()
    response = MagicMock()
    response.country.name = "Germany"
    response.city.name = "Berlin"
    response.autonomous_system_number = 1234
    provider.city.return_value = response

    geo = enrich(_e(), provider=provider)
    assert geo.display_location == "Berlin, Germany"


def test_enrich_all_length_matches_input():
    entries = [_e(port=p) for p in (80, 443, 8080)]
    result = enrich_all(entries, provider=None)
    assert len(result) == 3
    assert all(isinstance(g, GeoEntry) for g in result)
