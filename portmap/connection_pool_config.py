"""Configuration for connection pool thresholds and alerting."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Optional


@dataclass
class PoolThreshold:
    """Per-port or global connection count thresholds."""
    warn: int = 50
    critical: int = 200

    def __post_init__(self) -> None:
        if self.warn < 0:
            raise ValueError("warn threshold must be >= 0")
        if self.critical < self.warn:
            raise ValueError("critical threshold must be >= warn threshold")


@dataclass
class PoolConfig:
    global_threshold: PoolThreshold = field(default_factory=PoolThreshold)
    port_overrides: Dict[int, PoolThreshold] = field(default_factory=dict)
    track_protocols: list = field(default_factory=lambda: ["tcp"])

    def threshold_for(self, port: int) -> PoolThreshold:
        return self.port_overrides.get(port, self.global_threshold)


def default_pool_config_path() -> Path:
    return Path.home() / ".portmap" / "pool_config.json"


def _from_dict(data: dict) -> PoolConfig:
    g = data.get("global_threshold", {})
    global_thresh = PoolThreshold(
        warn=g.get("warn", 50),
        critical=g.get("critical", 200),
    )
    overrides: Dict[int, PoolThreshold] = {}
    for k, v in data.get("port_overrides", {}).items():
        overrides[int(k)] = PoolThreshold(warn=v.get("warn", 50), critical=v.get("critical", 200))
    return PoolConfig(
        global_threshold=global_thresh,
        port_overrides=overrides,
        track_protocols=data.get("track_protocols", ["tcp"]),
    )


def load_pool_config(path: Optional[Path] = None) -> PoolConfig:
    p = path or default_pool_config_path()
    if not p.exists():
        return PoolConfig()
    with open(p) as fh:
        return _from_dict(json.load(fh))


def save_pool_config(cfg: PoolConfig, path: Optional[Path] = None) -> None:
    p = path or default_pool_config_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "global_threshold": {"warn": cfg.global_threshold.warn, "critical": cfg.global_threshold.critical},
        "port_overrides": {
            str(k): {"warn": v.warn, "critical": v.critical}
            for k, v in cfg.port_overrides.items()
        },
        "track_protocols": cfg.track_protocols,
    }
    with open(p, "w") as fh:
        json.dump(data, fh, indent=2)
