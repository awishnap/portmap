"""Tests for portmap.tag and portmap.tag_config."""

import json
import pytest
from pathlib import Path

from portmap.scanner import PortEntry
from portmap import tag as tag_module
from portmap.tag_config import apply_rules, load_tag_rules, save_tag_rules


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _e(port: int, proto: str = "tcp", process: str | None = None) -> PortEntry:
    return PortEntry(port=port, protocol=proto, status="LISTEN",
                     pid=None, process=process, address="127.0.0.1")


@pytest.fixture(autouse=True)
def _reset_store():
    """Wipe tag store before every test."""
    tag_module._tag_store.clear()
    yield
    tag_module._tag_store.clear()


# ---------------------------------------------------------------------------
# tag core
# ---------------------------------------------------------------------------

def test_add_and_get_tag():
    e = _e(8080)
    tag_module.add_tag(e, "web")
    assert "web" in tag_module.get_tags(e)


def test_add_tag_normalises_case():
    e = _e(443)
    tag_module.add_tag(e, "HTTPS")
    assert "https" in tag_module.get_tags(e)


def test_remove_tag():
    e = _e(22)
    tag_module.add_tag(e, "ssh")
    tag_module.remove_tag(e, "ssh")
    assert "ssh" not in tag_module.get_tags(e)


def test_remove_tag_noop_if_absent():
    e = _e(22)
    tag_module.remove_tag(e, "nonexistent")  # should not raise


def test_clear_tags():
    e = _e(80)
    tag_module.add_tag(e, "web")
    tag_module.add_tag(e, "http")
    tag_module.clear_tags(e)
    assert tag_module.get_tags(e) == frozenset()


def test_filter_by_tag():
    entries = [_e(80), _e(443), _e(22)]
    tag_module.add_tag(entries[0], "web")
    tag_module.add_tag(entries[1], "web")
    tag_module.add_tag(entries[2], "ssh")
    result = tag_module.filter_by_tag(entries, "web")
    assert len(result) == 2
    assert entries[2] not in result


def test_tags_to_dict_and_from_dict():
    e = _e(8080)
    tag_module.add_tag(e, "dev")
    d = tag_module.tags_to_dict()
    assert "8080:tcp" in d
    tag_module._tag_store.clear()
    tag_module.tags_from_dict(d)
    assert "dev" in tag_module.get_tags(e)


# ---------------------------------------------------------------------------
# tag_config
# ---------------------------------------------------------------------------

def test_apply_rules_by_port():
    entries = [_e(80), _e(443)]
    rules = [{"port": 80, "tags": ["http"]}]
    apply_rules(entries, rules)
    assert "http" in tag_module.get_tags(entries[0])
    assert "http" not in tag_module.get_tags(entries[1])


def test_apply_rules_by_process():
    entries = [_e(3306, process="mysqld"), _e(5432, process="postgres")]
    rules = [{"process": "mysql", "tags": ["database"]}]
    apply_rules(entries, rules)
    assert "database" in tag_module.get_tags(entries[0])
    assert "database" not in tag_module.get_tags(entries[1])


def test_apply_rules_by_protocol():
    entries = [_e(53, proto="tcp"), _e(53, proto="udp")]
    rules = [{"port": 53, "protocol": "udp", "tags": ["dns"]}]
    apply_rules(entries, rules)
    assert "dns" in tag_module.get_tags(entries[1])
    assert "dns" not in tag_module.get_tags(entries[0])


def test_load_tag_rules_missing_file(tmp_path):
    rules = load_tag_rules(tmp_path / "nonexistent.json")
    assert rules == []


def test_save_and_load_tag_rules(tmp_path):
    path = tmp_path / "tags.json"
    rules = [{"port": 22, "tags": ["ssh"]}]
    save_tag_rules(rules, path)
    loaded = load_tag_rules(path)
    assert loaded == rules


def test_load_tag_rules_list_format(tmp_path):
    path = tmp_path / "tags.json"
    rules = [{"port": 80, "tags": ["web"]}]
    path.write_text(json.dumps(rules))
    loaded = load_tag_rules(path)
    assert loaded == rules
