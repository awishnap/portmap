"""Load alert rules from a YAML/JSON config file."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from portmap.alert import AlertRule, port_open_rule, process_rule

_RULE_BUILDERS = {
    "port_open": lambda cfg: port_open_rule(
        port=int(cfg["port"]),
        protocol=cfg.get("protocol", "tcp"),
        message=cfg.get("message", ""),
    ),
    "process": lambda cfg: process_rule(
        process_name=cfg["process"],
        message=cfg.get("message", ""),
    ),
}


def _parse_rule(raw: Dict[str, Any]) -> AlertRule:
    kind = raw.get("type", "")
    builder = _RULE_BUILDERS.get(kind)
    if builder is None:
        raise ValueError(f"Unknown alert rule type: '{kind}'")
    return builder(raw)


def load_rules(path: Path) -> List[AlertRule]:
    """Load alert rules from a JSON config file."""
    text = path.read_text(encoding="utf-8")
    data = json.loads(text)
    raw_rules = data if isinstance(data, list) else data.get("rules", [])
    return [_parse_rule(r) for r in raw_rules]


def default_rules_path() -> Path:
    return Path.home() / ".portmap" / "alerts.json"
