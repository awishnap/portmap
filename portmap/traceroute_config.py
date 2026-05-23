"""Persist and load traceroute default settings."""
from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict

_DEFAULT_DIR = Path.home() / ".portmap"


@dataclass
class TracerouteConfig:
    max_hops: int = 30
    timeout: float = 1.0
    default_format: str = "text"

    def __post_init__(self) -> None:
        if self.max_hops < 1:
            raise ValueError("max_hops must be >= 1")
        if self.timeout <= 0:
            raise ValueError("timeout must be positive")
        if self.default_format not in ("text", "json"):
            raise ValueError("default_format must be 'text' or 'json'")


def default_traceroute_path() -> Path:
    return _DEFAULT_DIR / "traceroute_config.json"


def _from_dict(data: Dict[str, Any]) -> TracerouteConfig:
    return TracerouteConfig(
        max_hops=int(data.get("max_hops", 30)),
        timeout=float(data.get("timeout", 1.0)),
        default_format=str(data.get("default_format", "text")),
    )


def load_traceroute_config(path: Path | None = None) -> TracerouteConfig:
    """Load config from *path* (or the default location). Returns defaults if missing."""
    p = Path(path) if path else default_traceroute_path()
    if not p.exists():
        return TracerouteConfig()
    try:
        with p.open() as fh:
            return _from_dict(json.load(fh))
    except (json.JSONDecodeError, KeyError, ValueError):
        return TracerouteConfig()


def save_traceroute_config(cfg: TracerouteConfig, path: Path | None = None) -> Path:
    """Persist *cfg* to *path* (or the default location) and return the path used."""
    p = Path(path) if path else default_traceroute_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w") as fh:
        json.dump(asdict(cfg), fh, indent=2)
    return p
