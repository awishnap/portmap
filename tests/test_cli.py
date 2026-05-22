"""Tests for portmap.cli module."""

import json
import pytest
from unittest.mock import patch, MagicMock

from portmap.cli import build_parser, parse_port_range, main
from portmap.scanner import PortEntry


# ---------------------------------------------------------------------------
# parse_port_range
# ---------------------------------------------------------------------------

def test_parse_port_range_single():
    assert parse_port_range("80") == [80]


def test_parse_port_range_list():
    assert parse_port_range("80,443,8080") == [80, 443, 8080]


def test_parse_port_range_range():
    assert parse_port_range("8000-8003") == [8000, 8001, 8002, 8003]


def test_parse_port_range_mixed():
    result = parse_port_range("22,80,443,8000-8002")
    assert result == [22, 80, 443, 8000, 8001, 8002]


def test_parse_port_range_invalid_string():
    with pytest.raises(ValueError, match="Invalid port number"):
        parse_port_range("abc")


def test_parse_port_range_invalid_range():
    with pytest.raises(ValueError, match="Invalid port range"):
        parse_port_range("abc-def")


def test_parse_port_range_out_of_bounds():
    with pytest.raises(ValueError, match="out of range"):
        parse_port_range("0,70000")


# ---------------------------------------------------------------------------
# build_parser defaults
# ---------------------------------------------------------------------------

def test_parser_defaults():
    parser = build_parser()
    args = parser.parse_args([])
    assert args.ports == "1-65535"
    assert args.format == "table"
    assert args.host == "127.0.0.1"
    assert args.no_color is False


def test_parser_custom_args():
    parser = build_parser()
    args = parser.parse_args(["-p", "80,443", "-f", "json", "--host", "0.0.0.0", "--no-color"])
    assert args.ports == "80,443"
    assert args.format == "json"
    assert args.host == "0.0.0.0"
    assert args.no_color is True


# ---------------------------------------------------------------------------
# main()
# ---------------------------------------------------------------------------

def _make_entry(port: int) -> PortEntry:
    return PortEntry(
        port=port,
        protocol="tcp",
        state="LISTEN",
        pid=1234,
        process="python",
        label="Python",
    )


@patch("portmap.cli.scan_ports", return_value=[])
def test_main_no_results(mock_scan, capsys):
    rc = main(["-p", "9999"])
    assert rc == 0
    mock_scan.assert_called_once()


@patch("portmap.cli.scan_ports")
def test_main_table_output(mock_scan, capsys):
    mock_scan.return_value = [_make_entry(80)]
    rc = main(["-p", "80", "--no-color"])
    assert rc == 0
    captured = capsys.readouterr()
    assert "80" in captured.out


@patch("portmap.cli.scan_ports")
def test_main_json_output(mock_scan, capsys):
    mock_scan.return_value = [_make_entry(443)]
    rc = main(["-p", "443", "-f", "json"])
    assert rc == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert isinstance(data, list)
    assert data[0]["port"] == 443


@patch("portmap.cli.scan_ports")
def test_main_json_output_multiple_entries(mock_scan, capsys):
    mock_scan.return_value = [_make_entry(80), _make_entry(443)]
    rc = main(["-p", "80,443", "-f", "json"])
    assert rc == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert len(data) == 2
    ports = [entry["port"] for entry in data]
    assert 80 in ports
    assert 443 in ports
