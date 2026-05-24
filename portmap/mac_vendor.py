"""MAC address vendor lookup for network interface enrichment."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

# Partial OUI table for common vendors (first 3 octets, uppercase, no separators)
_OUI_TABLE: dict[str, str] = {
    "000C29": "VMware",
    "000569": "VMware",
    "001C42": "Parallels",
    "005056": "VMware",
    "08002B": "DEC",
    "080027": "VirtualBox",
    "0A0027": "VirtualBox",
    "AC1F6B": "Apple",
    "F0189B": "Apple",
    "3C22FB": "Apple",
    "00155D": "Microsoft Hyper-V",
    "001DD8": "Microsoft",
    "B827EB": "Raspberry Pi Foundation",
    "DC:A6:32": "Raspberry Pi Foundation",
    "E4:5F:01": "Raspberry Pi Foundation",
    "00E04C": "Realtek",
    "001B21": "Intel",
    "8086F2": "Intel",
    "A4C361": "Intel",
    "000D3A": "Microsoft Azure",
    "001517": "Cisco",
    "0019E8": "Cisco",
    "7C2664": "Cisco",
}

_MAC_PATTERN = re.compile(
    r'^([0-9A-Fa-f]{2})[:\-.]?([0-9A-Fa-f]{2})[:\-.]?([0-9A-Fa-f]{2})'
)


@dataclass
class MACVendorResult:
    mac: str
    oui: Optional[str] = None
    vendor: Optional[str] = None
    error: Optional[str] = None

    def display(self) -> str:
        if self.error:
            return f"{self.mac} — error: {self.error}"
        if self.vendor:
            return f"{self.mac} ({self.oui}) — {self.vendor}"
        return f"{self.mac} ({self.oui}) — unknown vendor"


def _normalise_oui(mac: str) -> Optional[str]:
    """Extract and normalise the OUI (first 3 octets) from a MAC address."""
    m = _MAC_PATTERN.match(mac.strip())
    if not m:
        return None
    return "".join(m.groups()).upper()


def lookup(mac: str) -> MACVendorResult:
    """Look up the vendor for a given MAC address using the local OUI table."""
    oui = _normalise_oui(mac)
    if oui is None:
        return MACVendorResult(mac=mac, error="invalid MAC address format")
    vendor = _OUI_TABLE.get(oui)
    return MACVendorResult(mac=mac, oui=oui, vendor=vendor)


def enrich(interfaces: list[dict]) -> list[dict]:
    """Enrich a list of interface dicts with vendor info (expects 'mac' key)."""
    results = []
    for iface in interfaces:
        mac = iface.get("mac")
        if mac:
            result = lookup(mac)
            iface = {**iface, "vendor": result.vendor, "oui": result.oui}
        results.append(iface)
    return results
