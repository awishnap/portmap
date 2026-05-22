"""Load tag rules from a YAML/JSON config file and apply them to entries."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from portmap.scanner import PortEntry
from portmap import tag as tag_module


def default_tags_path() -> Path:
    return Path.home() / ".portmap" / "tags.json"


def _matches(entry: PortEntry, rule: Dict[str, Any]) -> bool:
    """Return True if entry satisfies all conditions in the rule."""
    if "port" in rule and entry.port != int(rule["port"]):
        return False
    if "protocol" in rule and entry.protocol.lower() != rule["protocol"].lower():
        return False
    if "process" in rule:
        proc = (entry.process or "").lower()
        if rule["process"].lower() not in proc:
            return False
    return True


def apply_rules(entries: List[PortEntry], rules: List[Dict[str, Any]]) -> None:
    """Apply tag rules to a list of entries, mutating the tag store."""
    for rule in rules:
        tags: List[str] = rule.get("tags", [])
        for entry in entries:
            if _matches(entry, rule):
                for t in tags:
                    tag_module.add_tag(entry, t)


def load_tag_rules(path: Path | None = None) -> List[Dict[str, Any]]:
    """Load tag rules from a JSON file; returns empty list if file absent."""
    p = Path(path) if path else default_tags_path()
    if not p.exists():
        return []
    with p.open() as fh:
        data = json.load(fh)
    if isinstance(data, list):
        return data
    return data.get("rules", [])


def save_tag_rules(rules: List[Dict[str, Any]], path: Path | None = None) -> None:
    """Persist tag rules to a JSON file."""
    p = Path(path) if path else default_tags_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w") as fh:
        json.dump({"rules": rules}, fh, indent=2)
