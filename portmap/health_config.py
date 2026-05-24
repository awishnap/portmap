"""Load / save health-check configuration from a JSON file."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, asdict
from typing import Optional


@dataclass
class HealthConfig:
    host: str = "127.0.0.1"
    timeout: float = 2.0
    interval: float = 60.0  # seconds between scheduled checks
    alert_on_down: bool = True

    def __post_init__(self) -> None:
        if self.timeout <= 0:
            raise ValueError("timeout must be positive")
        if self.interval <= 0:
            raise ValueError("interval must be positive")


def default_health_path() -> str:
    base = os.environ.get("PORTMAP_CONFIG_DIR", os.path.expanduser("~/.portmap"))
    return os.path.join(base, "health.json")


def _from_dict(d: dict) -> HealthConfig:  # type: ignore[type-arg]
    return HealthConfig(
        host=d.get("host", "127.0.0.1"),
        timeout=float(d.get("timeout", 2.0)),
        interval=float(d.get("interval", 60.0)),
        alert_on_down=bool(d.get("alert_on_down", True)),
    )


def load_health_config(path: Optional[str] = None) -> HealthConfig:
    path = path or default_health_path()
    if not os.path.exists(path):
        return HealthConfig()
    with open(path, "r", encoding="utf-8") as fh:
        return _from_dict(json.load(fh))


def save_health_config(cfg: HealthConfig, path: Optional[str] = None) -> None:
    path = path or default_health_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(asdict(cfg), fh, indent=2)
