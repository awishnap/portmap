"""Tests for portmap.alert and portmap.alert_output."""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from portmap.alert import (
    AlertRule,
    AlertResult,
    evaluate,
    port_open_rule,
    process_rule,
)
from portmap.alert_output import render_json, render_text, save_alerts
from portmap.scanner import PortEntry


def _e(port=8080, protocol="tcp", process="python", pid=1234, status="LISTEN"):
    e = PortEntry(port=port, protocol=protocol, pid=pid, process=process, status=status)
    e.label = process
    return e


# --- AlertRule helpers ---

def test_port_open_rule_matches():
    rule = port_open_rule(8080)
    assert rule.condition(_e(port=8080, protocol="tcp"))


def test_port_open_rule_no_match_different_port():
    rule = port_open_rule(9090)
    assert not rule.condition(_e(port=8080))


def test_port_open_rule_protocol_matters():
    rule = port_open_rule(8080, protocol="udp")
    assert not rule.condition(_e(port=8080, protocol="tcp"))


def test_process_rule_case_insensitive():
    rule = process_rule("Python")
    assert rule.condition(_e(process="python3"))


def test_process_rule_no_match():
    rule = process_rule("nginx")
    assert not rule.condition(_e(process="python"))


def test_process_rule_none_process():
    rule = process_rule("nginx")
    entry = _e(process=None)
    entry.process = None
    assert not rule.condition(entry)


# --- evaluate ---

def test_evaluate_returns_matching_results():
    entries = [_e(port=80), _e(port=443)]
    rules = [port_open_rule(80)]
    results = evaluate(entries, rules)
    assert len(results) == 1
    assert results[0].entry.port == 80


def test_evaluate_no_matches_returns_empty():
    entries = [_e(port=8080)]
    rules = [port_open_rule(22)]
    results = evaluate(entries, rules)
    assert results == []


def test_evaluate_marks_rule_triggered():
    rule = port_open_rule(8080)
    assert not rule.triggered
    evaluate([_e(port=8080)], [rule])
    assert rule.triggered


def test_alert_result_str_format():
    entry = _e(port=22, protocol="tcp")
    r = AlertResult(rule_name="port_open:22/tcp", entry=entry, message="SSH open")
    text = str(r)
    assert "22/tcp" in text
    assert "SSH open" in text


# --- render / save ---

def test_render_text_no_results():
    buf = io.StringIO()
    render_text([], buf)
    assert "No alerts" in buf.getvalue()


def test_render_json_structure():
    entry = _e(port=80)
    results = [AlertResult(rule_name="port_open:80/tcp", entry=entry, message="open")]
    buf = io.StringIO()
    render_json(results, buf)
    data = json.loads(buf.getvalue())
    assert data[0]["port"] == 80
    assert data[0]["rule"] == "port_open:80/tcp"


def test_save_alerts_creates_file(tmp_path):
    entry = _e(port=443)
    results = [AlertResult(rule_name="port_open:443/tcp", entry=entry, message="HTTPS")]
    out = tmp_path / "alerts.json"
    save_alerts(results, out, fmt="json")
    assert out.exists()
    data = json.loads(out.read_text())
    assert data[0]["port"] == 443
