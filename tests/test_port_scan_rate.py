"""Tests for portmap.port_scan_rate and portmap.port_scan_rate_cli."""
from __future__ import annotations

import argparse
import json
import pytest

from portmap.port_scan_rate import ScanRateController
from portmap.port_scan_rate_cli import (
    build_scan_rate_parser,
    run_scan_rate,
    _render_status,
)


# ---------------------------------------------------------------------------
# ScanRateController unit tests
# ---------------------------------------------------------------------------

def test_initial_workers_default():
    c = ScanRateController()
    assert c.current_workers == 32


def test_invalid_target_error_rate_raises():
    with pytest.raises(ValueError):
        ScanRateController(target_error_rate=0.0)
    with pytest.raises(ValueError):
        ScanRateController(target_error_rate=1.0)


def test_invalid_initial_workers_raises():
    with pytest.raises(ValueError):
        ScanRateController(initial_workers=0)


def test_error_rate_none_when_no_data():
    c = ScanRateController()
    assert c.error_rate is None


def test_error_rate_zero_when_all_success():
    c = ScanRateController()
    for _ in range(10):
        c.record_success()
    assert c.error_rate == pytest.approx(0.0)


def test_error_rate_one_when_all_errors():
    c = ScanRateController()
    for _ in range(5):
        c.record_error()
    assert c.error_rate == pytest.approx(1.0)


def test_recommend_scales_down_on_high_error_rate():
    c = ScanRateController(initial_workers=100, target_error_rate=0.05)
    for _ in range(50):
        c.record_error()
    workers = c.recommend()
    assert workers < 100


def test_recommend_scales_up_on_low_error_rate():
    c = ScanRateController(initial_workers=10, target_error_rate=0.10)
    for _ in range(100):
        c.record_success()
    workers = c.recommend()
    assert workers > 10


def test_recommend_clamps_to_max():
    c = ScanRateController(initial_workers=200, max_workers=210, scale_up_factor=2.0)
    for _ in range(100):
        c.record_success()
    workers = c.recommend()
    assert workers <= 210


def test_recommend_clamps_to_min():
    c = ScanRateController(initial_workers=2, min_workers=1, scale_down_factor=0.1)
    for _ in range(100):
        c.record_error()
    workers = c.recommend()
    assert workers >= 1


def test_recommend_resets_counters():
    c = ScanRateController()
    for _ in range(10):
        c.record_error()
    c.recommend()
    assert c.error_rate is None


def test_reset_restores_initial_workers():
    c = ScanRateController(initial_workers=16)
    for _ in range(50):
        c.record_success()
    c.recommend()
    c.reset()
    assert c.current_workers == 16
    assert c.error_rate is None


# ---------------------------------------------------------------------------
# CLI tests
# ---------------------------------------------------------------------------

def _ctrl(**kw) -> ScanRateController:
    return ScanRateController(**kw)


def _parse(args: list) -> argparse.Namespace:
    return build_scan_rate_parser().parse_args(args)


def test_render_status_text():
    c = _ctrl()
    for _ in range(8):
        c.record_success()
    for _ in range(2):
        c.record_error()
    out = _render_status(c, "text")
    assert "workers=" in out
    assert "20.00%" in out


def test_render_status_json():
    c = _ctrl()
    c.record_success()
    out = json.loads(_render_status(c, "json"))
    assert "current_workers" in out
    assert out["error_rate"] == pytest.approx(0.0)


def test_cli_status_runs(capsys):
    c = _ctrl()
    args = _parse(["status"])
    rc = run_scan_rate(args, ctrl=c)
    assert rc == 0
    captured = capsys.readouterr()
    assert "workers=" in captured.out


def test_cli_recommend_text(capsys):
    c = _ctrl(initial_workers=20)
    for _ in range(100):
        c.record_success()
    args = _parse(["recommend", "--format", "text"])
    run_scan_rate(args, ctrl=c)
    out = capsys.readouterr().out
    assert "recommended_workers=" in out


def test_cli_recommend_json(capsys):
    c = _ctrl()
    args = _parse(["recommend", "--format", "json"])
    run_scan_rate(args, ctrl=c)
    data = json.loads(capsys.readouterr().out)
    assert "recommended_workers" in data


def test_cli_reset(capsys):
    c = _ctrl(initial_workers=8)
    for _ in range(50):
        c.record_success()
    c.recommend()
    args = _parse(["reset"])
    run_scan_rate(args, ctrl=c)
    assert c.current_workers == 8
    assert "reset" in capsys.readouterr().out.lower()


def test_cli_simulate_json(capsys):
    c = _ctrl(initial_workers=50)
    args = _parse(["simulate", "--success", "80", "--error", "20", "--format", "json"])
    run_scan_rate(args, ctrl=c)
    data = json.loads(capsys.readouterr().out)
    assert data["recommended_workers"] < 50
