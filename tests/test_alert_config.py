"""Tests for portmap.alert_config rule loading."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from portmap.alert_config import load_rules
from portmap.scanner import PortEntry


def _write(tmp_path: Path, data) -> Path:
    p = tmp_path / "alerts.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    return p


def _e(port=80, protocol="tcp", process="nginx", pid=99):
    e = PortEntry(port=port, protocol=protocol, pid=pid, process=process, status="LISTEN")
    e.label = process
    return e


def test_load_port_open_rule(tmp_path):
    cfg = [{"type": "port_open", "port": 80, "protocol": "tcp"}]
    rules = load_rules(_write(tmp_path, cfg))
    assert len(rules) == 1
    assert rules[0].condition(_e(port=80, protocol="tcp"))


def test_load_process_rule(tmp_path):
    cfg = [{"type": "process", "process": "nginx"}]
    rules = load_rules(_write(tmp_path, cfg))
    assert rules[0].condition(_e(process="nginx"))


def test_load_rules_wrapped_object(tmp_path):
    cfg = {"rules": [{"type": "port_open", "port": 443}]}
    rules = load_rules(_write(tmp_path, cfg))
    assert len(rules) == 1


def test_load_rules_custom_message(tmp_path):
    cfg = [{"type": "port_open", "port": 22, "message": "SSH detected"}]
    rules = load_rules(_write(tmp_path, cfg))
    assert rules[0].message == "SSH detected"


def test_load_unknown_rule_type_raises(tmp_path):
    cfg = [{"type": "unknown_type", "port": 80}]
    with pytest.raises(ValueError, match="Unknown alert rule type"):
        load_rules(_write(tmp_path, cfg))


def test_load_empty_list(tmp_path):
    rules = load_rules(_write(tmp_path, []))
    assert rules == []
