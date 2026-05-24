"""Protocol classification and metadata for port entries."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

# Well-known application-layer protocols keyed by (port, transport)
_PROTO_MAP: dict[tuple[int, str], str] = {
    (21, "tcp"): "FTP",
    (22, "tcp"): "SSH",
    (23, "tcp"): "Telnet",
    (25, "tcp"): "SMTP",
    (53, "tcp"): "DNS",
    (53, "udp"): "DNS",
    (67, "udp"): "DHCP",
    (80, "tcp"): "HTTP",
    (110, "tcp"): "POP3",
    (143, "tcp"): "IMAP",
    (389, "tcp"): "LDAP",
    (443, "tcp"): "HTTPS",
    (445, "tcp"): "SMB",
    (465, "tcp"): "SMTPS",
    (514, "udp"): "Syslog",
    (587, "tcp"): "SMTP/Submission",
    (636, "tcp"): "LDAPS",
    (993, "tcp"): "IMAPS",
    (995, "tcp"): "POP3S",
    (1433, "tcp"): "MSSQL",
    (3306, "tcp"): "MySQL",
    (3389, "tcp"): "RDP",
    (5432, "tcp"): "PostgreSQL",
    (5900, "tcp"): "VNC",
    (6379, "tcp"): "Redis",
    (8080, "tcp"): "HTTP-Alt",
    (8443, "tcp"): "HTTPS-Alt",
    (27017, "tcp"): "MongoDB",
}

_ENCRYPTED = frozenset(
    ["SSH", "HTTPS", "SMTPS", "LDAPS", "IMAPS", "POP3S", "HTTPS-Alt"]
)
_CLEARTEXT = frozenset(["FTP", "Telnet", "HTTP", "SMTP", "POP3", "IMAP", "HTTP-Alt"])


@dataclass(frozen=True)
class ProtoInfo:
    port: int
    transport: str  # 'tcp' | 'udp'
    app_proto: Optional[str]
    encrypted: Optional[bool]  # None when unknown

    def display(self) -> str:
        proto = self.app_proto or "unknown"
        if self.encrypted is True:
            flag = " [enc]"
        elif self.encrypted is False:
            flag = " [clear]"
        else:
            flag = ""
        return f"{proto}{flag}"


def identify(port: int, transport: str = "tcp") -> ProtoInfo:
    """Return protocol metadata for *port* / *transport* pair."""
    key = (port, transport.lower())
    app = _PROTO_MAP.get(key)
    if app is None:
        encrypted = None
    elif app in _ENCRYPTED:
        encrypted = True
    elif app in _CLEARTEXT:
        encrypted = False
    else:
        encrypted = None
    return ProtoInfo(port=port, transport=transport.lower(), app_proto=app, encrypted=encrypted)


def enrich(entries: list) -> list:
    """Attach a *proto* attribute to each PortEntry-like object."""
    enriched = []
    for entry in entries:
        info = identify(entry.port, getattr(entry, "protocol", "tcp"))
        object.__setattr__(entry, "proto", info) if hasattr(entry, "__dataclass_fields__") else setattr(entry, "proto", info)
        enriched.append(entry)
    return enriched
