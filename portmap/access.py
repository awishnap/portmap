"""Access control: restrict scanning to allowed hosts/interfaces."""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class AccessPolicy:
    allowed_hosts: List[str] = field(default_factory=list)
    denied_hosts: List[str] = field(default_factory=list)
    allow_loopback: bool = True
    allow_private: bool = True


def _to_network(spec: str) -> ipaddress._BaseNetwork:
    """Parse a host or CIDR string into a network object."""
    try:
        return ipaddress.ip_network(spec, strict=False)
    except ValueError:
        # treat bare host as /32 or /128
        addr = ipaddress.ip_address(spec)
        return ipaddress.ip_network(addr)


def _is_loopback(addr: ipaddress._BaseAddress) -> bool:
    return addr.is_loopback


def _is_private(addr: ipaddress._BaseAddress) -> bool:
    return addr.is_private


def is_allowed(host: str, policy: AccessPolicy) -> bool:
    """Return True if *host* is permitted under *policy*."""
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        # Non-IP hostname: only check explicit allow/deny lists.
        if any(host == h for h in policy.denied_hosts):
            return False
        if policy.allowed_hosts:
            return host in policy.allowed_hosts
        return True

    # Explicit deny wins first.
    for spec in policy.denied_hosts:
        try:
            if addr in _to_network(spec):
                return False
        except ValueError:
            pass

    # Loopback / private shortcircuits.
    if _is_loopback(addr) and not policy.allow_loopback:
        return False
    if _is_private(addr) and not _is_loopback(addr) and not policy.allow_private:
        return False

    # Explicit allow list (if non-empty, act as whitelist).
    if policy.allowed_hosts:
        for spec in policy.allowed_hosts:
            try:
                if addr in _to_network(spec):
                    return True
            except ValueError:
                pass
        return False

    return True


def filter_hosts(hosts: List[str], policy: AccessPolicy) -> List[str]:
    """Return only the hosts permitted by *policy*."""
    return [h for h in hosts if is_allowed(h, policy)]


def default_policy() -> AccessPolicy:
    """Return a permissive default policy."""
    return AccessPolicy()
