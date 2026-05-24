"""SSL/TLS certificate inspection for open ports."""
from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from portmap.scanner import PortEntry


@dataclass
class SSLResult:
    port: int
    host: str
    has_ssl: bool
    subject: Optional[str] = None
    issuer: Optional[str] = None
    expires: Optional[datetime] = None
    expired: bool = False
    days_remaining: Optional[int] = None
    error: Optional[str] = None

    def display(self) -> str:
        if not self.has_ssl:
            return f"port {self.port}: no SSL"
        if self.error:
            return f"port {self.port}: SSL error — {self.error}"
        exp = self.expires.strftime("%Y-%m-%d") if self.expires else "unknown"
        days = f"{self.days_remaining}d" if self.days_remaining is not None else "?"
        status = "EXPIRED" if self.expired else f"expires {exp} ({days} left)"
        return f"port {self.port}: SSL ok — {self.subject} — {status}"


def _parse_cert(cert: dict) -> tuple[Optional[str], Optional[str], Optional[datetime]]:
    def _rdn(rdns: tuple) -> str:
        return ", ".join(v for rdn in rdns for _, v in rdn)

    subject = _rdn(cert.get("subject", ()))
    issuer = _rdn(cert.get("issuer", ()))
    not_after = cert.get("notAfter")
    expires: Optional[datetime] = None
    if not_after:
        try:
            expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=timezone.utc
            )
        except ValueError:
            pass
    return subject or None, issuer or None, expires


def check(host: str, port: int, timeout: float = 3.0) -> SSLResult:
    """Attempt a TLS handshake and extract certificate metadata."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_OPTIONAL
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                cert = tls.getpeercert()
                subject, issuer, expires = _parse_cert(cert or {})
                now = datetime.now(tz=timezone.utc)
                expired = bool(expires and expires < now)
                days_remaining = (
                    (expires - now).days if expires and not expired else None
                )
                return SSLResult(
                    port=port,
                    host=host,
                    has_ssl=True,
                    subject=subject,
                    issuer=issuer,
                    expires=expires,
                    expired=expired,
                    days_remaining=days_remaining,
                )
    except ssl.SSLError as exc:
        return SSLResult(port=port, host=host, has_ssl=True, error=str(exc))
    except OSError:
        return SSLResult(port=port, host=host, has_ssl=False)


def enrich(entries: list[PortEntry], host: str = "127.0.0.1", timeout: float = 3.0) -> list[SSLResult]:
    """Run SSL checks against a list of PortEntry objects."""
    return [check(host, e.port, timeout=timeout) for e in entries]
