"""Persist and load user-defined service name overrides.

Overrides are stored as a simple JSON mapping of port -> name,
allowing users to label non-standard services without modifying
the built-in _WELL_KNOWN table.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional

_DEFAULT_PATH = Path.home() / ".portmap" / "service_overrides.json"


def default_overrides_path() -> Path:
    return _DEFAULT_PATH


def load_overrides(path: Optional[Path] = None) -> dict[int, str]:
    """Load port->name overrides from *path*. Returns empty dict if absent."""
    p = Path(path or default_overrides_path())
    if not p.exists():
        return {}
    try:
        raw = json.loads(p.read_text())
        return {int(k): str(v) for k, v in raw.items()}
    except (json.JSONDecodeError, ValueError):
        return {}


def save_overrides(overrides: dict[int, str], path: Optional[Path] = None) -> None:
    """Persist *overrides* to *path*, creating parent directories as needed."""
    p = Path(path or default_overrides_path())
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({str(k): v for k, v in overrides.items()}, indent=2))


def add_override(port: int, name: str, path: Optional[Path] = None) -> None:
    """Add or update a single override entry."""
    overrides = load_overrides(path)
    overrides[port] = name
    save_overrides(overrides, path)


def remove_override(port: int, path: Optional[Path] = None) -> bool:
    """Remove override for *port*. Returns True if it existed."""
    overrides = load_overrides(path)
    if port not in overrides:
        return False
    del overrides[port]
    save_overrides(overrides, path)
    return True


def apply_overrides(base: dict[int, str], path: Optional[Path] = None) -> dict[int, str]:
    """Return a copy of *base* with user overrides merged in."""
    merged = dict(base)
    merged.update(load_overrides(path))
    return merged
