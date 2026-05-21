"""Tests for portmap.scanner and portmap.formatter modules."""

import json
from unittest.mock import MagicMock, patch
from portmap.scanner import PortEntry, scan_ports, _get_process_info
from portmap.formatter import format_table, format_json, render


# ---------------------------------------------------------------------------
# PortEntry tests
# ---------------------------------------------------------------------------

def test_port_entry_label_with_process():
    entry = PortEntry(port=8080, protocol="tcp", pid=1234, process_name="python")
    assert entry.label() == "python (pid=1234)"


def test_port_entry_label_without_process():
    entry = PortEntry(port=8080, protocol="tcp", pid=None, process_name=None)
    assert entry.label() == "unknown"


# ---------------------------------------------------------------------------
# _get_process_info tests
# ---------------------------------------------------------------------------

def test_get_process_info_valid_pid():
    mock_proc = MagicMock()
    mock_proc.name.return_value = "nginx"
    mock_proc.cmdline.return_value = ["nginx", "-g", "daemon off;"]

    with patch("portmap.scanner.psutil.Process", return_value=mock_proc):
        name, cmdline = _get_process_info(42)

    assert name == "nginx"
    assert cmdline == ["nginx", "-g", "daemon off;"]


def test_get_process_info_none_pid():
    name, cmdline = _get_process_info(None)
    assert name is None
    assert cmdline == []


# ---------------------------------------------------------------------------
# scan_ports tests
# ---------------------------------------------------------------------------

def _make_conn(port, sock_type, status, pid):
    import socket
    conn = MagicMock()
    conn.laddr = MagicMock(port=port, ip="0.0.0.0")
    conn.type = sock_type
    conn.status = status
    conn.pid = pid
    return conn


def test_scan_ports_returns_sorted_entries():
    import socket as _socket
    fake_conns = [
        _make_conn(8080, _socket.SOCK_STREAM, "LISTEN", 100),
        _make_conn(443, _socket.SOCK_STREAM, "LISTEN", 200),
    ]

    with patch("portmap.scanner.psutil.net_connections", return_value=fake_conns), \
         patch("portmap.scanner._get_process_info", return_value=("svc", [])):
        entries = scan_ports(protocols=["tcp"])

    assert [e.port for e in entries] == [443, 8080]


def test_scan_ports_deduplicates():
    import socket as _socket
    fake_conns = [
        _make_conn(9000, _socket.SOCK_STREAM, "LISTEN", 1),
        _make_conn(9000, _socket.SOCK_STREAM, "LISTEN", 1),
    ]

    with patch("portmap.scanner.psutil.net_connections", return_value=fake_conns), \
         patch("portmap.scanner._get_process_info", return_value=("dup", [])):
        entries = scan_ports(protocols=["tcp"])

    assert len(entries) == 1


# ---------------------------------------------------------------------------
# Formatter tests
# ---------------------------------------------------------------------------

def _sample_entries():
    """Return a small list of PortEntry objects for use in formatter tests."""
    return [
        PortEntry(port=80, protocol="tcp", pid=1, process_name="nginx"),
        PortEntry(port=443, protocol="tcp", pid=2, process_name="nginx"),
        PortEntry(port=5432, protocol="tcp", pid=99, process_name="postgres"),
    ]


def test_format_json_contains_all_ports():
    entries = _sample_entries()
    output = format_json(entries)
    data = json.loads(output)
    ports = [item["port"] for item in data]
    assert ports == [80, 443, 5432]


def test_format_json_includes_label():
    entries = _sample_entries()
    output = format_json(entries)
    data = json.loads(output)
    assert data[0]["label"] == "nginx (pid=1)"
