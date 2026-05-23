"""Tests for portmap.access."""
import pytest

from portmap.access import (
    AccessPolicy,
    default_policy,
    filter_hosts,
    is_allowed,
)


# ---------------------------------------------------------------------------
# default policy
# ---------------------------------------------------------------------------

def test_default_policy_allows_loopback():
    assert is_allowed("127.0.0.1", default_policy()) is True


def test_default_policy_allows_private():
    assert is_allowed("192.168.1.10", default_policy()) is True


def test_default_policy_allows_public():
    assert is_allowed("8.8.8.8", default_policy()) is True


# ---------------------------------------------------------------------------
# loopback control
# ---------------------------------------------------------------------------

def test_deny_loopback_blocks_127():
    policy = AccessPolicy(allow_loopback=False)
    assert is_allowed("127.0.0.1", policy) is False


def test_deny_loopback_does_not_block_private():
    policy = AccessPolicy(allow_loopback=False)
    assert is_allowed("10.0.0.1", policy) is True


# ---------------------------------------------------------------------------
# private control
# ---------------------------------------------------------------------------

def test_deny_private_blocks_10_net():
    policy = AccessPolicy(allow_private=False)
    assert is_allowed("10.0.0.5", policy) is False


def test_deny_private_blocks_192_168():
    policy = AccessPolicy(allow_private=False)
    assert is_allowed("192.168.0.1", policy) is False


def test_deny_private_allows_public():
    policy = AccessPolicy(allow_private=False)
    assert is_allowed("1.1.1.1", policy) is True


# ---------------------------------------------------------------------------
# explicit allow list (whitelist mode)
# ---------------------------------------------------------------------------

def test_allowed_hosts_whitelist_permits_listed():
    policy = AccessPolicy(allowed_hosts=["10.0.0.1"])
    assert is_allowed("10.0.0.1", policy) is True


def test_allowed_hosts_whitelist_blocks_unlisted():
    policy = AccessPolicy(allowed_hosts=["10.0.0.1"])
    assert is_allowed("10.0.0.2", policy) is False


def test_allowed_hosts_cidr_permits_range():
    policy = AccessPolicy(allowed_hosts=["192.168.1.0/24"])
    assert is_allowed("192.168.1.100", policy) is True


def test_allowed_hosts_cidr_blocks_outside_range():
    policy = AccessPolicy(allowed_hosts=["192.168.1.0/24"])
    assert is_allowed("192.168.2.1", policy) is False


# ---------------------------------------------------------------------------
# explicit deny list
# ---------------------------------------------------------------------------

def test_denied_hosts_blocks_specific_ip():
    policy = AccessPolicy(denied_hosts=["8.8.8.8"])
    assert is_allowed("8.8.8.8", policy) is False


def test_denied_hosts_cidr_blocks_range():
    policy = AccessPolicy(denied_hosts=["10.0.0.0/8"])
    assert is_allowed("10.1.2.3", policy) is False


def test_denied_hosts_does_not_affect_other_ips():
    policy = AccessPolicy(denied_hosts=["10.0.0.0/8"])
    assert is_allowed("172.16.0.1", policy) is True


# ---------------------------------------------------------------------------
# hostname (non-IP) handling
# ---------------------------------------------------------------------------

def test_hostname_allowed_by_default():
    assert is_allowed("example.com", default_policy()) is True


def test_hostname_blocked_when_in_denied():
    policy = AccessPolicy(denied_hosts=["example.com"])
    assert is_allowed("example.com", policy) is False


def test_hostname_blocked_when_not_in_allowed_list():
    policy = AccessPolicy(allowed_hosts=["trusted.local"])
    assert is_allowed("other.local", policy) is False


# ---------------------------------------------------------------------------
# filter_hosts
# ---------------------------------------------------------------------------

def test_filter_hosts_removes_denied():
    policy = AccessPolicy(denied_hosts=["10.0.0.1"])
    result = filter_hosts(["10.0.0.1", "10.0.0.2"], policy)
    assert result == ["10.0.0.2"]


def test_filter_hosts_empty_input():
    assert filter_hosts([], default_policy()) == []
