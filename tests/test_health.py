"""Tests for portmap.health and portmap.health_config."""
from __future__ import annotations

import socket
import threading
from unittest.mock import patch, MagicMock

import pytest

from portmap.health import HealthResult, check, enrich
from portmap.health_config import HealthConfig, load_health_config, save_health_config
from portmap.scanner import PortEntry


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _e(port: int = 8080, proto: str = "tcp") -> PortEntry:
    return PortEntry(port=port, protocol=proto, status="LISTEN",
                     pid=None, process=None)


# ---------------------------------------------------------------------------
# HealthResult
# ---------------------------------------------------------------------------

def test_health_result_status_up():
    r = HealthResult(port=80, protocol="tcp", host="127.0.0.1",
                     reachable=True, latency_ms=1.5)
    assert r.status == "up"


def test_health_result_status_down():
    r = HealthResult(port=80, protocol="tcp", host="127.0.0.1",
                     reachable=False, latency_ms=None)
    assert r.status == "down"


def test_health_result_display_up():
    r = HealthResult(port=80, protocol="tcp", host="127.0.0.1",
                     reachable=True, latency_ms=3.2)
    assert "up" in r.display()
    assert "3.2" in r.display()


def test_health_result_display_down():
    r = HealthResult(port=9999, protocol="tcp", host="127.0.0.1",
                     reachable=False, latency_ms=None)
    assert "down" in r.display()


# ---------------------------------------------------------------------------
# check()
# ---------------------------------------------------------------------------

def test_check_non_tcp_returns_down():
    r = check("127.0.0.1", 80, protocol="udp")
    assert not r.reachable
    assert r.error is not None


def test_check_success_via_loopback():
    """Spin up a real TCP listener and verify check() returns reachable."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def _accept():
        try:
            conn, _ = srv.accept()
            conn.close()
        except OSError:
            pass

    t = threading.Thread(target=_accept, daemon=True)
    t.start()
    try:
        r = check("127.0.0.1", port)
        assert r.reachable
        assert r.latency_ms is not None
        assert r.latency_ms >= 0
    finally:
        srv.close()
        t.join(timeout=2)


def test_check_failure_returns_down():
    # Port 1 is almost certainly not open.
    r = check("127.0.0.1", 1, timeout=0.2)
    assert not r.reachable
    assert r.latency_ms is None


# ---------------------------------------------------------------------------
# enrich()
# ---------------------------------------------------------------------------

def test_enrich_calls_check_for_each_entry():
    entries = [_e(80), _e(443)]
    with patch("portmap.health.check") as mock_check:
        mock_check.return_value = HealthResult(port=80, protocol="tcp",
                                               host="127.0.0.1",
                                               reachable=True, latency_ms=1.0)
        results = enrich(entries)
    assert mock_check.call_count == 2
    assert len(results) == 2


# ---------------------------------------------------------------------------
# HealthConfig
# ---------------------------------------------------------------------------

def test_health_config_defaults():
    cfg = HealthConfig()
    assert cfg.host == "127.0.0.1"
    assert cfg.timeout == 2.0
    assert cfg.alert_on_down is True


def test_health_config_invalid_timeout():
    with pytest.raises(ValueError):
        HealthConfig(timeout=0)


def test_health_config_invalid_interval():
    with pytest.raises(ValueError):
        HealthConfig(interval=-1)


def test_save_and_load_health_config(tmp_path):
    path = str(tmp_path / "health.json")
    cfg = HealthConfig(host="10.0.0.1", timeout=5.0, interval=30.0,
                       alert_on_down=False)
    save_health_config(cfg, path)
    loaded = load_health_config(path)
    assert loaded.host == "10.0.0.1"
    assert loaded.timeout == 5.0
    assert loaded.interval == 30.0
    assert loaded.alert_on_down is False


def test_load_health_config_missing_file_returns_defaults(tmp_path):
    path = str(tmp_path / "nonexistent.json")
    cfg = load_health_config(path)
    assert cfg.host == "127.0.0.1"
