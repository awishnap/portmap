"""Load NotifyConfig from a TOML or JSON config file."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from portmap.notify import NotifyConfig

_DEFAULT_CONFIG_NAME = "notify.json"


def default_notify_path() -> Path:
    """Return the default path for the notification config file."""
    return Path.home() / ".portmap" / _DEFAULT_CONFIG_NAME


def _from_dict(data: dict) -> NotifyConfig:
    return NotifyConfig(
        webhook_url=data.get("webhook_url"),
        smtp_host=data.get("smtp_host"),
        smtp_port=int(data.get("smtp_port", 587)),
        smtp_user=data.get("smtp_user"),
        smtp_password=data.get("smtp_password"),
        email_from=data.get("email_from"),
        email_to=list(data.get("email_to") or []),
    )


def load_notify_config(path: Optional[Path] = None) -> NotifyConfig:
    """Load a NotifyConfig from *path* (defaults to ~/.portmap/notify.json).

    Returns an empty NotifyConfig if the file does not exist.
    """
    target = Path(path) if path else default_notify_path()
    if not target.exists():
        return NotifyConfig()
    raw = json.loads(target.read_text())
    # Support both a bare object and a {"notify": {...}} wrapper
    if "notify" in raw and isinstance(raw["notify"], dict):
        raw = raw["notify"]
    return _from_dict(raw)


def save_notify_config(cfg: NotifyConfig, path: Optional[Path] = None) -> Path:
    """Persist *cfg* as JSON to *path* (defaults to ~/.portmap/notify.json)."""
    target = Path(path) if path else default_notify_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "webhook_url": cfg.webhook_url,
        "smtp_host": cfg.smtp_host,
        "smtp_port": cfg.smtp_port,
        "smtp_user": cfg.smtp_user,
        "smtp_password": cfg.smtp_password,
        "email_from": cfg.email_from,
        "email_to": cfg.email_to,
    }
    target.write_text(json.dumps(data, indent=2))
    return target
