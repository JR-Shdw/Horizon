"""Tests for client_ip - XFF parsing with trusted proxies."""

import ipaddress
from unittest.mock import Mock

import pytest
from api.app import client_ip as ci


def _make_request(host: str | None, headers: dict | None = None) -> Mock:
    r = Mock()
    r.client = Mock(host=host) if host else None
    r.headers = headers or {}
    return r


@pytest.fixture
def trusted(monkeypatch):
    """Override _TRUSTED_PROXIES to a known set for the test."""
    nets = [
        ipaddress.ip_network("10.0.0.1/24"),
        ipaddress.ip_network("172.16.0.1/24"),
    ]
    monkeypatch.setattr(ci, "_TRUSTED_PROXIES", nets)


def test_parse_cidrs_strips_whitespace_and_skips_garbage():
    nets = ci._parse_cidrs(" 10.0.0.0/24, 192.168.0.0/16,  ,bogus, 172.16.0.0/12")
    assert ipaddress.ip_network("10.0.0.0/24") in nets
    assert ipaddress.ip_network("192.168.0.0/16") in nets
    assert ipaddress.ip_network("172.16.0.0/12") in nets
    assert len(nets) == 3


def test_no_trusted_proxies_returns_direct(monkeypatch):
    monkeypatch.setattr(ci, "_TRUSTED_PROXIES", [])
    r = _make_request("203.0.113.5", {"x-forwarded-for": "1.2.3.4"})
    assert ci.get_client_ip(r) == "203.0.113.5"


def test_xff_only_proxy_does_not_become_identity_proxy(monkeypatch):
    xff_proxy = ipaddress.ip_network("172.30.251.0/24")
    monkeypatch.setattr(ci, "_XFF_TRUSTED_PROXIES", [xff_proxy])
    monkeypatch.setattr(ci, "_IDENTITY_TRUSTED_PROXIES", [])
    monkeypatch.setattr(ci, "_TRUSTED_PROXIES", ci._merge_trusted_proxies())

    r = _make_request("172.30.251.5", {"x-forwarded-for": "203.0.113.5"})
    assert ci.get_client_ip(r) == "203.0.113.5"
    assert ci.get_identity_trusted_proxies() == []


def test_untrusted_peer_ignores_xff(trusted):
    r = _make_request("203.0.113.5", {"x-forwarded-for": "1.2.3.4"})
    assert ci.get_client_ip(r) == "203.0.113.5"


def test_overly_broad_proxies_flags_wide_ranges(monkeypatch):
    nets = [
        ipaddress.ip_network("10.0.0.0/8"),  # wide v4
        ipaddress.ip_network("192.168.0.0/16"),  # wide v4
        ipaddress.ip_network("10.0.0.1/32"),  # host, tight
        ipaddress.ip_network("10.0.0.1/24"),  # boundary, tight
        ipaddress.ip_network("fc00::/7"),  # wide v6
    ]
    monkeypatch.setattr(ci, "_TRUSTED_PROXIES", nets)
    assert set(ci.overly_broad_proxies()) == {
        "10.0.0.0/8",
        "192.168.0.0/16",
        "fc00::/7",
    }


def test_trusted_peer_returns_first_untrusted_xff_hop(trusted):
    r = _make_request(
        "10.0.0.1", {"x-forwarded-for": "1.2.3.4, 10.0.0.1, 172.16.0.1"}
    )
    assert ci.get_client_ip(r) == "1.2.3.4"


def test_trusted_peer_no_xff_returns_direct(trusted):
    r = _make_request("10.0.0.1", {})
    assert ci.get_client_ip(r) == "10.0.0.1"


def test_unknown_when_request_client_missing(trusted):
    r = _make_request(None)
    assert ci.get_client_ip(r) == "unknown"


def test_all_xff_trusted_returns_leftmost(trusted):
    """When every hop is trusted, return the leftmost (origin closest)."""
    r = _make_request(
        "10.0.0.1", {"x-forwarded-for": "10.0.0.1, 10.0.0.1, 172.16.0.1"}
    )
    assert ci.get_client_ip(r) == "10.0.0.1"


def test_malformed_xff_hop_skipped(trusted):
    r = _make_request(
        "10.0.0.1", {"x-forwarded-for": "not-an-ip, 1.2.3.4, 10.0.0.1"}
    )
    assert ci.get_client_ip(r) == "1.2.3.4"
