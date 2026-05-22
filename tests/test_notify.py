"""Tests for portmap.notify and portmap.notify_config."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from portmap.alert import AlertResult
from portmap.notify import (
    NotifyConfig,
    _build_payload,
    dispatch,
    send_email,
    send_webhook,
)
from portmap.notify_config import load_notify_config, save_notify_config
from portmap.scanner import PortEntry


def _e(port: int = 8080, protocol: str = "tcp", process: str = "python") -> PortEntry:
    return PortEntry(port=port, protocol=protocol, host="127.0.0.1",
                     status="LISTEN", process=process, pid=1234)


def _result(matched: bool = True, rule: str = "test_rule") -> AlertResult:
    return AlertResult(
        rule_name=rule,
        matched=matched,
        entry=_e(),
        message="port 8080 is open" if matched else "",
    )


# ---------------------------------------------------------------------------
# _build_payload
# ---------------------------------------------------------------------------

def test_build_payload_only_includes_matched():
    results = [_result(matched=True), _result(matched=False)]
    payload = _build_payload(results)
    assert len(payload["alerts"]) == 1


def test_build_payload_fields():
    results = [_result(matched=True, rule="open_check")]
    alert = _build_payload(results)["alerts"][0]
    assert alert["rule"] == "open_check"
    assert alert["port"] == 8080
    assert alert["protocol"] == "tcp"
    assert alert["matched"] is True


# ---------------------------------------------------------------------------
# send_webhook
# ---------------------------------------------------------------------------

def test_send_webhook_returns_true_on_200():
    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)

    with patch("portmap.notify.urllib.request.urlopen", return_value=mock_resp):
        ok = send_webhook("http://example.com/hook", [_result()])
    assert ok is True


def test_send_webhook_returns_false_on_exception():
    with patch("portmap.notify.urllib.request.urlopen", side_effect=OSError("timeout")):
        ok = send_webhook("http://example.com/hook", [_result()])
    assert ok is False


# ---------------------------------------------------------------------------
# send_email
# ---------------------------------------------------------------------------

def test_send_email_returns_false_without_smtp_host():
    cfg = NotifyConfig(email_to=["a@b.com"])
    assert send_email(cfg, [_result()]) is False


def test_send_email_returns_true_when_no_matched_results():
    cfg = NotifyConfig(smtp_host="smtp.example.com", email_to=["a@b.com"])
    assert send_email(cfg, [_result(matched=False)]) is True


def test_send_email_calls_smtp(tmp_path):
    cfg = NotifyConfig(
        smtp_host="smtp.example.com",
        smtp_port=587,
        smtp_user="user",
        smtp_password="pass",
        email_to=["admin@example.com"],
    )
    mock_server = MagicMock()
    mock_server.__enter__ = lambda s: s
    mock_server.__exit__ = MagicMock(return_value=False)

    with patch("portmap.notify.smtplib.SMTP", return_value=mock_server):
        ok = send_email(cfg, [_result(matched=True)])
    assert ok is True
    mock_server.send_message.assert_called_once()


# ---------------------------------------------------------------------------
# dispatch
# ---------------------------------------------------------------------------

def test_dispatch_calls_webhook_when_configured():
    cfg = NotifyConfig(webhook_url="http://hook.example.com")
    with patch("portmap.notify.send_webhook", return_value=True) as mock_wh:
        status = dispatch(cfg, [_result()])
    assert status["webhook"] is True
    mock_wh.assert_called_once()


def test_dispatch_skips_email_when_not_configured():
    cfg = NotifyConfig(webhook_url="http://hook.example.com")
    with patch("portmap.notify.send_webhook", return_value=True):
        status = dispatch(cfg, [_result()])
    assert "email" not in status


# ---------------------------------------------------------------------------
# notify_config load / save
# ---------------------------------------------------------------------------

def test_load_notify_config_missing_file_returns_empty(tmp_path):
    cfg = load_notify_config(tmp_path / "nonexistent.json")
    assert cfg.webhook_url is None
    assert cfg.email_to == []


def test_save_and_load_roundtrip(tmp_path):
    cfg = NotifyConfig(
        webhook_url="http://example.com/wh",
        smtp_host="smtp.example.com",
        email_to=["a@b.com", "c@d.com"],
    )
    p = tmp_path / "notify.json"
    save_notify_config(cfg, p)
    loaded = load_notify_config(p)
    assert loaded.webhook_url == cfg.webhook_url
    assert loaded.smtp_host == cfg.smtp_host
    assert loaded.email_to == cfg.email_to


def test_load_notify_config_wrapped_object(tmp_path):
    p = tmp_path / "notify.json"
    p.write_text(json.dumps({"notify": {"webhook_url": "http://wrapped.example.com"}}))
    cfg = load_notify_config(p)
    assert cfg.webhook_url == "http://wrapped.example.com"
