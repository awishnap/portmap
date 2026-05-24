"""Socket state classification and enrichment for port entries."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

# Mapping from psutil / system state strings to normalised labels
_STATE_LABELS: dict[str, str] = {
    "LISTEN": "listening",
    "ESTABLISHED": "established",
    "TIME_WAIT": "time_wait",
    "CLOSE_WAIT": "close_wait",
    "SYN_SENT": "syn_sent",
    "SYN_RECV": "syn_recv",
    "FIN_WAIT1": "fin_wait1",
    "FIN_WAIT2": "fin_wait2",
    "LAST_ACK": "last_ack",
    "CLOSING": "closing",
    "CLOSED": "closed",
    "NONE": "stateless",
}

_ACTIVE_STATES = {"listening", "established"}
_CLOSING_STATES = {"time_wait", "close_wait", "fin_wait1", "fin_wait2", "last_ack", "closing"}


@dataclass(frozen=True)
class SocketStateResult:
    raw: Optional[str]
    normalised: str
    is_active: bool
    is_closing: bool

    def display(self) -> str:
        if self.is_active:
            return f"{self.normalised} [active]"
        if self.is_closing:
            return f"{self.normalised} [closing]"
        return self.normalised


def normalise(raw: Optional[str]) -> str:
    """Return a lower-case canonical state name for *raw*."""
    if not raw:
        return "stateless"
    return _STATE_LABELS.get(raw.upper(), raw.lower())


def classify(raw: Optional[str]) -> SocketStateResult:
    """Build a :class:`SocketStateResult` from a raw state string."""
    norm = normalise(raw)
    return SocketStateResult(
        raw=raw,
        normalised=norm,
        is_active=norm in _ACTIVE_STATES,
        is_closing=norm in _CLOSING_STATES,
    )


def enrich(entries: list) -> list:
    """Return a new list where each entry gains a ``socket_state`` attribute.

    Works with any object that exposes a ``status`` attribute (e.g.
    :class:`portmap.scanner.PortEntry`).
    """
    enriched = []
    for entry in entries:
        raw = getattr(entry, "status", None)
        result = classify(raw)
        # Attach without mutating frozen dataclasses — use object.__setattr__
        # if the entry is a plain dataclass, otherwise fall back to a wrapper.
        try:
            object.__setattr__(entry, "socket_state", result)
        except (AttributeError, TypeError):
            pass
        enriched.append(entry)
    return enriched
