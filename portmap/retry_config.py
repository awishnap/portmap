"""Persist and load :class:`RetryConfig` from a JSON file."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from portmap.retry import RetryConfig


def default_retry_path() -> Path:
    """Return ``~/.portmap/retry.json``."""
    return Path.home() / ".portmap" / "retry.json"


def _from_dict(data: dict) -> RetryConfig:
    max_attempts = int(data.get("max_attempts", 3))
    delays_raw = data.get("delays", [0.1, 0.25, 0.5])
    delays = tuple(float(d) for d in delays_raw)
    return RetryConfig(max_attempts=max_attempts, delays=delays)


def load_retry_config(path: Optional[Path] = None) -> RetryConfig:
    """Load a :class:`RetryConfig` from *path* (falls back to defaults)."""
    p = path or default_retry_path()
    if not p.exists():
        return RetryConfig()
    try:
        data = json.loads(p.read_text())
        return _from_dict(data)
    except (json.JSONDecodeError, ValueError):
        return RetryConfig()


def save_retry_config(config: RetryConfig, path: Optional[Path] = None) -> Path:
    """Persist *config* to *path* as JSON and return the path."""
    p = path or default_retry_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "max_attempts": config.max_attempts,
        "delays": list(config.delays),
    }
    p.write_text(json.dumps(payload, indent=2))
    return p
