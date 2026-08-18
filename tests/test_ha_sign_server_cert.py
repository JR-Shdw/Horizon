"""cluster_ca.sign_server_cert.

Covers :
- Happy path : returns (cert_pem, key_pem) signed by the cluster CA.
- SAN encoding : IPv4, IPv6, DNS names ; mix accepted.
- EKU : server_auth only (NOT client_auth -- a leaked nginx server
  key must not double as a node identity cert).
- CA chain : the CA's public key verifies the server cert signature.
- BasicConstraints : not a CA.
- Validation : empty SAN both lists rejected ; bad IP rejected ; bad
  DNS rejected ; validity_days <= 0 rejected ; validity_days above
  ceiling rejected.
- Keypair freshness : two calls produce distinct keys.
- Algorithm pinning : Ed25519.
- Validity clamp : default reads cluster_server_cert_validity_days.
"""

import ipaddress
from datetime import timedelta

import pytest
from api.app import cluster_ca
from api.app.config import settings
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.x509.oid import ExtendedKeyUsageOID


@pytest.fixture
def ca_pem() -> tuple[bytes, bytes]:
    cert_pem, key_pem, _fpr = cluster_ca.mint_cluster_ca(
        common_name="test-cluster", validity_days=30
    )
    return cert_pem, key_pem


def _load_cert(pem: bytes) -> x509.Certificate:
    return x509.load_pem_x509_certificate(pem)


def _load_key(pem: bytes) -> Ed25519PrivateKey:
    from cryptography.hazmat.primitives import serialization

    key = serialization.load_pem_private_key(pem, password=None)
    assert isinstance(key, Ed25519PrivateKey)
    return key


def test_returns_pem_pair(ca_pem):
    ca_cert, ca_key = ca_pem
    cert_pem, key_pem = cluster_ca.sign_server_cert(
        ca_cert, ca_key, san_ips=["192.168.10.1"], san_dns=[]
    )
    assert cert_pem.startswith(b"-----BEGIN CERTIFICATE-----")
    assert b"PRIVATE KEY-----" in key_pem


def test_san_includes_ipv4(ca_pem):
    ca_cert, ca_key = ca_pem
    cert_pem, _ = cluster_ca.sign_server_cert(
        ca_cert, ca_key, san_ips=["192.168.10.1"], san_dns=[]
    )
    cert = _load_cert(cert_pem)
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    ips = san.get_values_for_type(x509.IPAddress)
    assert ipaddress.ip_address("192.168.10.1") in ips


def test_san_includes_ipv6(ca_pem):
    ca_cert, ca_key = ca_pem
    cert_pem, _ = cluster_ca.sign_server_cert(
        ca_cert, ca_key, san_ips=["2001:db8::42"], san_dns=[]
    )
    cert = _load_cert(cert_pem)
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    ips = san.get_values_for_type(x509.IPAddress)
    assert ipaddress.ip_address("2001:db8::42") in ips


def test_san_includes_dns(ca_pem):
    ca_cert, ca_key = ca_pem
    cert_pem, _ = cluster_ca.sign_server_cert(
        ca_cert, ca_key, san_ips=[], san_dns=["rhorizon-1", "vault.example.com"]
    )
    cert = _load_cert(cert_pem)
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    dns = san.get_values_for_type(x509.DNSName)
    assert "rhorizon-1" in dns
    assert "vault.example.com" in dns


def test_san_mix_ip_and_dns(ca_pem):
    ca_cert, ca_key = ca_pem
    cert_pem, _ = cluster_ca.sign_server_cert(
        ca_cert,
        ca_key,
        san_ips=["192.168.10.1", "10.0.0.1"],
        san_dns=["rhorizon-1"],
    )
    cert = _load_cert(cert_pem)
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    ips = san.get_values_for_type(x509.IPAddress)
    dns = san.get_values_for_type(x509.DNSName)
    assert ipaddress.ip_address("192.168.10.1") in ips
    assert ipaddress.ip_address("10.0.0.1") in ips
    assert "rhorizon-1" in dns


def test_eku_server_auth_only(ca_pem):
    """A server cert that also carries CLIENT_AUTH collapses the trust
    surface kept apart. Pin SERVER_AUTH only."""
    ca_cert, ca_key = ca_pem
    cert_pem, _ = cluster_ca.sign_server_cert(
        ca_cert, ca_key, san_ips=["10.0.0.1"], san_dns=[]
    )
    cert = _load_cert(cert_pem)
    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    eku_set = set(eku)
    assert ExtendedKeyUsageOID.SERVER_AUTH in eku_set
    assert ExtendedKeyUsageOID.CLIENT_AUTH not in eku_set


def test_signature_verifies_under_ca(ca_pem):
    ca_cert_pem, ca_key_pem = ca_pem
    cert_pem, _ = cluster_ca.sign_server_cert(
        ca_cert_pem, ca_key_pem, san_ips=["10.0.0.1"], san_dns=[]
    )
    ca_cert = _load_cert(ca_cert_pem)
    server_cert = _load_cert(cert_pem)
    ca_pub = ca_cert.public_key()
    assert isinstance(ca_pub, Ed25519PublicKey)
    ca_pub.verify(server_cert.signature, server_cert.tbs_certificate_bytes)


def test_signature_fails_under_wrong_ca(ca_pem):
    ca_cert_pem, ca_key_pem = ca_pem
    cert_pem, _ = cluster_ca.sign_server_cert(
        ca_cert_pem, ca_key_pem, san_ips=["10.0.0.1"], san_dns=[]
    )
    other_cert_pem, _, _ = cluster_ca.mint_cluster_ca(
        common_name="other-cluster", validity_days=30
    )
    other_pub = _load_cert(other_cert_pem).public_key()
    server_cert = _load_cert(cert_pem)
    with pytest.raises(InvalidSignature):
        other_pub.verify(server_cert.signature, server_cert.tbs_certificate_bytes)


def test_basic_constraints_not_ca(ca_pem):
    ca_cert, ca_key = ca_pem
    cert_pem, _ = cluster_ca.sign_server_cert(
        ca_cert, ca_key, san_ips=["10.0.0.1"], san_dns=[]
    )
    cert = _load_cert(cert_pem)
    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert bc.ca is False


def test_validity_bounded_to_validity_days(ca_pem):
    ca_cert, ca_key = ca_pem
    cert_pem, _ = cluster_ca.sign_server_cert(
        ca_cert, ca_key, san_ips=["10.0.0.1"], san_dns=[], validity_days=7
    )
    cert = _load_cert(cert_pem)
    delta = cert.not_valid_after_utc - cert.not_valid_before_utc
    expected = timedelta(days=7, minutes=5)
    assert abs(delta - expected) < timedelta(seconds=2)


def test_default_validity_reads_settings(ca_pem):
    ca_cert, ca_key = ca_pem
    cert_pem, _ = cluster_ca.sign_server_cert(
        ca_cert, ca_key, san_ips=["10.0.0.1"], san_dns=[]
    )
    cert = _load_cert(cert_pem)
    delta = cert.not_valid_after_utc - cert.not_valid_before_utc
    expected = timedelta(days=settings.cluster_server_cert_validity_days, minutes=5)
    assert abs(delta - expected) < timedelta(seconds=2)


def test_two_calls_produce_distinct_keypairs(ca_pem):
    ca_cert, ca_key = ca_pem
    _, key_a = cluster_ca.sign_server_cert(
        ca_cert, ca_key, san_ips=["10.0.0.1"], san_dns=[]
    )
    _, key_b = cluster_ca.sign_server_cert(
        ca_cert, ca_key, san_ips=["10.0.0.1"], san_dns=[]
    )
    assert key_a != key_b


def test_minted_key_is_ed25519(ca_pem):
    ca_cert, ca_key = ca_pem
    _, key_pem = cluster_ca.sign_server_cert(
        ca_cert, ca_key, san_ips=["10.0.0.1"], san_dns=[]
    )
    key = _load_key(key_pem)
    assert isinstance(key, Ed25519PrivateKey)


def test_rejects_empty_san(ca_pem):
    ca_cert, ca_key = ca_pem
    with pytest.raises(cluster_ca.ClusterCaError):
        cluster_ca.sign_server_cert(ca_cert, ca_key, san_ips=[], san_dns=[])


def test_rejects_invalid_ip(ca_pem):
    ca_cert, ca_key = ca_pem
    with pytest.raises(cluster_ca.ClusterCaError):
        cluster_ca.sign_server_cert(ca_cert, ca_key, san_ips=["not-an-ip"], san_dns=[])


@pytest.mark.parametrize(
    "bad_dns",
    [
        "",  # empty
        "-bad.example.com",  # leading hyphen
        "bad-.example.com",  # trailing hyphen on a label
        "a" * 64 + ".example.com",  # label too long
        "a" * 250 + ".example.com",  # name too long
        "spaces are bad",
    ],
)
def test_rejects_invalid_dns(ca_pem, bad_dns):
    ca_cert, ca_key = ca_pem
    with pytest.raises(cluster_ca.ClusterCaError):
        cluster_ca.sign_server_cert(ca_cert, ca_key, san_ips=[], san_dns=[bad_dns])


def test_rejects_zero_or_negative_validity(ca_pem):
    ca_cert, ca_key = ca_pem
    with pytest.raises(cluster_ca.ClusterCaError):
        cluster_ca.sign_server_cert(
            ca_cert, ca_key, san_ips=["10.0.0.1"], san_dns=[], validity_days=0
        )
    with pytest.raises(cluster_ca.ClusterCaError):
        cluster_ca.sign_server_cert(
            ca_cert, ca_key, san_ips=["10.0.0.1"], san_dns=[], validity_days=-1
        )


def test_rejects_validity_above_ceiling(ca_pem):
    ca_cert, ca_key = ca_pem
    ceiling = 4 * settings.cluster_server_cert_validity_days
    with pytest.raises(cluster_ca.ClusterCaError):
        cluster_ca.sign_server_cert(
            ca_cert,
            ca_key,
            san_ips=["10.0.0.1"],
            san_dns=[],
            validity_days=ceiling + 1,
        )


def test_default_validity_not_capped_by_short_node_setting(ca_pem, monkeypatch):
    """Regression: the ceiling tracks the SERVER cadence, not the node one.
    With short node certs (7d) and longer server certs (90d) -- a legitimate
    independent config -- the default-validity mint must still succeed (it
    used to raise because the ceiling was 4*node=28 < 90)."""
    ca_cert, ca_key = ca_pem
    monkeypatch.setattr(settings, "cluster_node_cert_validity_days", 7)
    monkeypatch.setattr(settings, "cluster_server_cert_validity_days", 90)
    cert_pem, _ = cluster_ca.sign_server_cert(
        ca_cert, ca_key, san_ips=["10.0.0.1"], san_dns=[]
    )
    cert = _load_cert(cert_pem)
    span = cert.not_valid_after_utc - cert.not_valid_before_utc
    assert span == timedelta(days=90, minutes=5)


def test_subject_cn_first_dns_or_ip(ca_pem):
    """CN policy : first DNS name if any, otherwise first IP. Nginx does
    not rely on CN (SAN is what matters) but a non-empty CN keeps
    naive tooling happy."""
    from cryptography.x509.oid import NameOID

    ca_cert, ca_key = ca_pem
    cert_pem, _ = cluster_ca.sign_server_cert(
        ca_cert, ca_key, san_ips=["10.0.0.1"], san_dns=["rhorizon-1"]
    )
    cert = _load_cert(cert_pem)
    cns = [a.value for a in cert.subject if a.oid == NameOID.COMMON_NAME]
    assert cns == ["rhorizon-1"]

    cert_pem, _ = cluster_ca.sign_server_cert(
        ca_cert, ca_key, san_ips=["10.0.0.1"], san_dns=[]
    )
    cert = _load_cert(cert_pem)
    cns = [a.value for a in cert.subject if a.oid == NameOID.COMMON_NAME]
    assert cns == ["10.0.0.1"]
