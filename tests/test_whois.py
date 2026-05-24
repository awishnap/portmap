"""Tests for portmap.whois."""

from __future__ import annotations

from unittest.mock import patch, MagicMock

import pytest

from portmap.scanner import PortEntry
from portmap.whois import WhoisResult, _parse, _query, lookup, enrich


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _e(addr: str = "") -> PortEntry:
    return PortEntry(
        port=80,
        protocol="tcp",
        status="LISTEN",
        pid=None,
        process=None,
        addr=addr,
    )


SAMPLE_RAW = """
OrgName:     Example Corp
Country:     US
CIDR:        203.0.113.0/24
"""


# ---------------------------------------------------------------------------
# WhoisResult.display
# ---------------------------------------------------------------------------

def test_display_all_fields():
    r = WhoisResult(ip="1.2.3.4", org="Acme", country="DE", cidr="1.2.0.0/16")
    assert r.display() == "Acme | DE | 1.2.0.0/16"


def test_display_partial_fields():
    r = WhoisResult(ip="1.2.3.4", org="Acme")
    assert r.display() == "Acme"


def test_display_no_fields_returns_unknown():
    r = WhoisResult(ip="1.2.3.4")
    assert r.display() == "unknown"


# ---------------------------------------------------------------------------
# _parse
# ---------------------------------------------------------------------------

def test_parse_extracts_org():
    result = _parse("203.0.113.1", SAMPLE_RAW)
    assert result.org == "Example Corp"


def test_parse_extracts_country():
    result = _parse("203.0.113.1", SAMPLE_RAW)
    assert result.country == "US"


def test_parse_extracts_cidr():
    result = _parse("203.0.113.1", SAMPLE_RAW)
    assert result.cidr == "203.0.113.0/24"


def test_parse_empty_raw_returns_nones():
    result = _parse("1.2.3.4", "")
    assert result.org is None
    assert result.country is None
    assert result.cidr is None


# ---------------------------------------------------------------------------
# _query (mocked socket)
# ---------------------------------------------------------------------------

def test_query_returns_response_text():
    mock_sock = MagicMock()
    mock_sock.__enter__ = lambda s: s
    mock_sock.__exit__ = MagicMock(return_value=False)
    mock_sock.recv.side_effect = [b"hello whois", b""]

    with patch("portmap.whois.socket.create_connection", return_value=mock_sock):
        result = _query("1.2.3.4")

    assert result == "hello whois"


def test_query_returns_empty_on_oserror():
    with patch("portmap.whois.socket.create_connection", side_effect=OSError):
        result = _query("1.2.3.4")
    assert result == ""


# ---------------------------------------------------------------------------
# lookup
# ---------------------------------------------------------------------------

def test_lookup_returns_whois_result():
    with patch("portmap.whois._query", return_value=SAMPLE_RAW):
        result = lookup("203.0.113.1")
    assert isinstance(result, WhoisResult)
    assert result.org == "Example Corp"


# ---------------------------------------------------------------------------
# enrich
# ---------------------------------------------------------------------------

def test_enrich_skips_entries_without_addr():
    entries = [_e(""), _e("")]
    with patch("portmap.whois.lookup") as mock_lookup:
        pairs = enrich(entries)
    mock_lookup.assert_not_called()
    assert pairs == []


def test_enrich_deduplicates_ip_lookups():
    entries = [_e("1.2.3.4"), _e("1.2.3.4"), _e("5.6.7.8")]
    fake = WhoisResult(ip="1.2.3.4")
    with patch("portmap.whois.lookup", return_value=fake) as mock_lookup:
        pairs = enrich(entries)
    assert mock_lookup.call_count == 2  # two distinct IPs
    assert len(pairs) == 3


def test_enrich_returns_entry_result_pairs():
    e = _e("9.9.9.9")
    fake = WhoisResult(ip="9.9.9.9", org="Quad9")
    with patch("portmap.whois.lookup", return_value=fake):
        pairs = enrich([e])
    assert pairs[0][0] is e
    assert pairs[0][1].org == "Quad9"
