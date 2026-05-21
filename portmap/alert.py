"""Alert rules engine: trigger notifications when port conditions are met."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, List, Optional

from portmap.scanner import PortEntry


@dataclass
class AlertRule:
    name: str
    condition: Callable[[PortEntry], bool]
    message: str = ""
    triggered: bool = False


@dataclass
class AlertResult:
    rule_name: str
    entry: PortEntry
    message: str

    def __str__(self) -> str:
        label = self.entry.label or "unknown"
        return (
            f"[ALERT] {self.rule_name}: port {self.entry.port}/{self.entry.protocol} "
            f"({label}) — {self.message}"
        )


def port_open_rule(port: int, protocol: str = "tcp", message: str = "") -> AlertRule:
    """Alert when a specific port becomes open."""
    msg = message or f"Port {port}/{protocol} is open"
    return AlertRule(
        name=f"port_open:{port}/{protocol}",
        condition=lambda e: e.port == port and e.protocol == protocol,
        message=msg,
    )


def process_rule(process_name: str, message: str = "") -> AlertRule:
    """Alert when a process matching the name has an open port."""
    msg = message or f"Process '{process_name}' has an open port"
    return AlertRule(
        name=f"process:{process_name}",
        condition=lambda e: e.process is not None and process_name.lower() in e.process.lower(),
        message=msg,
    )


def evaluate(entries: List[PortEntry], rules: List[AlertRule]) -> List[AlertResult]:
    """Evaluate all rules against all entries; return triggered results."""
    results: List[AlertResult] = []
    for rule in rules:
        for entry in entries:
            if rule.condition(entry):
                rule.triggered = True
                results.append(AlertResult(rule_name=rule.name, entry=entry, message=rule.message))
    return results
