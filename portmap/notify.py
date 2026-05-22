"""Notification dispatch for portmap alerts and watch events."""

from __future__ import annotations

import json
import smtplib
import urllib.request
from dataclasses import dataclass, field
from email.message import EmailMessage
from typing import List, Optional

from portmap.alert import AlertResult


@dataclass
class NotifyConfig:
    """Configuration for one or more notification channels."""

    webhook_url: Optional[str] = None
    smtp_host: Optional[str] = None
    smtp_port: int = 587
    smtp_user: Optional[str] = None
    smtp_password: Optional[str] = None
    email_from: Optional[str] = None
    email_to: List[str] = field(default_factory=list)


def _build_payload(results: List[AlertResult]) -> dict:
    """Serialise alert results to a plain dict for webhook delivery."""
    return {
        "alerts": [
            {
                "rule": r.rule_name,
                "matched": r.matched,
                "port": r.entry.port,
                "protocol": r.entry.protocol,
                "process": r.entry.process,
                "message": r.message,
            }
            for r in results
            if r.matched
        ]
    }


def send_webhook(url: str, results: List[AlertResult]) -> bool:
    """POST alert results as JSON to *url*. Returns True on HTTP 2xx."""
    payload = json.dumps(_build_payload(results)).encode()
    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return 200 <= resp.status < 300
    except Exception:
        return False


def send_email(cfg: NotifyConfig, results: List[AlertResult]) -> bool:
    """Send a plain-text alert summary via SMTP. Returns True on success."""
    if not cfg.email_to or not cfg.smtp_host:
        return False

    matched = [r for r in results if r.matched]
    if not matched:
        return True  # nothing to send

    body = "portmap alert summary\n" + "=" * 30 + "\n"
    for r in matched:
        body += f"[{r.rule_name}] port {r.entry.port}/{r.entry.protocol} — {r.message}\n"

    msg = EmailMessage()
    msg["Subject"] = f"portmap: {len(matched)} alert(s) fired"
    msg["From"] = cfg.email_from or cfg.smtp_user or "portmap@localhost"
    msg["To"] = ", ".join(cfg.email_to)
    msg.set_content(body)

    try:
        with smtplib.SMTP(cfg.smtp_host, cfg.smtp_port, timeout=10) as server:
            server.starttls()
            if cfg.smtp_user and cfg.smtp_password:
                server.login(cfg.smtp_user, cfg.smtp_password)
            server.send_message(msg)
        return True
    except Exception:
        return False


def dispatch(cfg: NotifyConfig, results: List[AlertResult]) -> dict:
    """Run all configured notification channels and return a status dict."""
    status: dict = {}
    if cfg.webhook_url:
        status["webhook"] = send_webhook(cfg.webhook_url, results)
    if cfg.smtp_host and cfg.email_to:
        status["email"] = send_email(cfg, results)
    return status
