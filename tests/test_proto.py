"""Tests for portmap.proto and portmap.proto_cli."""
from __future__ import annotations

import json
import argparse

import pytest

from portmap.proto import identify, enrich, ProtoInfo
from portmap.proto_cli import _render_text, _render_json, build_proto_parser, run_proto


# ---------------------------------------------------------------------------
# identify()
# ---------------------------------------------------------------------------

def test_identify_known_tcp_port():
    info = identify(22, "tcp")
    assert info.app_proto == "SSH"
    assert info.encrypted is True


def test_identify_http_is_cleartext():
    info = identify(80, "tcp")
    assert info.app_proto == "HTTP"
    assert info.encrypted is False


def test_identify_unknown_port_returns_none_app():
    info = identify(9999, "tcp")
    assert info.app_proto is None
    assert info.encrypted is None


def test_identify_udp_dns():
    info = identify(53, "udp")
    assert info.app_proto == "DNS"


def test_identify_transport_normalised_to_lower():
    info = identify(443, "TCP")
    assert info.transport == "tcp"
    assert info.app_proto == "HTTPS"


def test_display_encrypted():
    info = identify(443, "tcp")
    assert "[enc]" in info.display()


def test_display_cleartext():
    info = identify(80, "tcp")
    assert "[clear]" in info.display()


def test_display_unknown_no_flag():
    info = identify(9999, "tcp")
    d = info.display()
    assert "[enc]" not in d
    assert "[clear]" not in d
    assert "unknown" in d


# ---------------------------------------------------------------------------
# enrich()
# ---------------------------------------------------------------------------

class _FakeEntry:
    def __init__(self, port: int, protocol: str = "tcp"):
        self.port = port
        self.protocol = protocol


def test_enrich_attaches_proto():
    entries = [_FakeEntry(22), _FakeEntry(80)]
    enriched = enrich(entries)
    assert hasattr(enriched[0], "proto")
    assert enriched[0].proto.app_proto == "SSH"
    assert enriched[1].proto.app_proto == "HTTP"


def test_enrich_returns_same_count():
    entries = [_FakeEntry(p) for p in [22, 80, 443, 9999]]
    assert len(enrich(entries)) == 4


# ---------------------------------------------------------------------------
# CLI rendering
# ---------------------------------------------------------------------------

def _make_results():
    return [identify(22), identify(80), identify(9999)]


def test_render_text_contains_header():
    out = _render_text(_make_results())
    assert "PORT" in out
    assert "PROTOCOL" in out


def test_render_text_shows_ssh():
    out = _render_text([identify(22)])
    assert "SSH" in out
    assert "yes" in out


def test_render_text_empty_list():
    assert _render_text([]) == "No results."


def test_render_json_valid():
    data = json.loads(_render_json(_make_results()))
    assert isinstance(data, list)
    assert data[0]["port"] == 22
    assert "app_proto" in data[0]
    assert "encrypted" in data[0]


def test_run_proto_text(capsys):
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd")
    build_proto_parser(sub)
    args = parser.parse_args(["proto", "22", "80", "--transport", "tcp"])
    run_proto(args)
    out = capsys.readouterr().out
    assert "SSH" in out
    assert "HTTP" in out


def test_run_proto_json(capsys):
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd")
    build_proto_parser(sub)
    args = parser.parse_args(["proto", "443", "--format", "json"])
    run_proto(args)
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data[0]["app_proto"] == "HTTPS"
