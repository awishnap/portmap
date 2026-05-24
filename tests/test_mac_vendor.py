"""Tests for portmap.mac_vendor."""
import pytest
from portmap.mac_vendor import (
    MACVendorResult,
    _normalise_oui,
    lookup,
    enrich,
)


# ---------------------------------------------------------------------------
# _normalise_oui
# ---------------------------------------------------------------------------

def test_normalise_oui_colon_separated():
    assert _normalise_oui("00:0C:29:AB:CD:EF") == "000C29"


def test_normalise_oui_dash_separated():
    assert _normalise_oui("00-0C-29-AB-CD-EF") == "000C29"


def test_normalise_oui_no_separator():
    assert _normalise_oui("000C29ABCDEF") == "000C29"


def test_normalise_oui_lowercase():
    assert _normalise_oui("08:00:27:11:22:33") == "080027"


def test_normalise_oui_invalid_returns_none():
    assert _normalise_oui("not-a-mac") is None


def test_normalise_oui_empty_returns_none():
    assert _normalise_oui("") is None


# ---------------------------------------------------------------------------
# lookup
# ---------------------------------------------------------------------------

def test_lookup_known_vmware():
    result = lookup("00:0C:29:AA:BB:CC")
    assert result.vendor == "VMware"
    assert result.oui == "000C29"
    assert result.error is None


def test_lookup_known_virtualbox():
    result = lookup("08:00:27:11:22:33")
    assert result.vendor == "VirtualBox"


def test_lookup_unknown_vendor_returns_none_vendor():
    result = lookup("AA:BB:CC:DD:EE:FF")
    assert result.vendor is None
    assert result.oui == "AABBCC"
    assert result.error is None


def test_lookup_invalid_mac_returns_error():
    result = lookup("xyz")
    assert result.error is not None
    assert result.vendor is None


def test_lookup_preserves_original_mac():
    mac = "00:50:56:AA:BB:CC"
    result = lookup(mac)
    assert result.mac == mac


# ---------------------------------------------------------------------------
# MACVendorResult.display
# ---------------------------------------------------------------------------

def test_display_known_vendor():
    r = MACVendorResult(mac="00:0C:29:x", oui="000C29", vendor="VMware")
    assert "VMware" in r.display()
    assert "000C29" in r.display()


def test_display_unknown_vendor():
    r = MACVendorResult(mac="AA:BB:CC:DD:EE:FF", oui="AABBCC", vendor=None)
    assert "unknown vendor" in r.display()


def test_display_error():
    r = MACVendorResult(mac="bad", error="invalid MAC address format")
    assert "error" in r.display()


# ---------------------------------------------------------------------------
# enrich
# ---------------------------------------------------------------------------

def test_enrich_adds_vendor_field():
    ifaces = [{"name": "eth0", "mac": "00:0C:29:AA:BB:CC"}]
    result = enrich(ifaces)
    assert result[0]["vendor"] == "VMware"


def test_enrich_no_mac_passes_through():
    ifaces = [{"name": "lo"}]
    result = enrich(ifaces)
    assert result[0] == {"name": "lo"}


def test_enrich_unknown_mac_vendor_is_none():
    ifaces = [{"name": "eth1", "mac": "AA:BB:CC:11:22:33"}]
    result = enrich(ifaces)
    assert result[0]["vendor"] is None
    assert result[0]["oui"] == "AABBCC"


def test_enrich_does_not_mutate_original():
    original = {"name": "eth0", "mac": "00:0C:29:AA:BB:CC"}
    enrich([original])
    assert "vendor" not in original
