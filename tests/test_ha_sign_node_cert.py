"""cluster_ca.sign_node_cert.

Covers :
- Happy path : returns (cert_pem, key_pem) where the cert is signed
  by the cluster CA, CN = node_uuid, SAN includes source_ip,
  validity bounded by validity_days.
- Cert chain : the issuer's public key (ca_cert) verifies the node
  cert's signature.
- Key freshness : two calls produce distinct keypairs.
- Algorithm pinning : the minted private key is Ed25519.
- IP validation : invalid IP literals raise ClusterCaError.
- IPv6 support : an IPv6 source_ip is encoded into the SAN.
- validity_days rejected when <= 0.
"""

import ipaddress
from datetime import datetime, timedelta, timezone

import pytest
from api.app import cluster_ca
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.x509.oid import NameOID


@pytest.fixture
def ca_pem() -> tuple[bytes, bytes]:
    """Fresh self-signed CA for each test -- no DB / vault dependency."""
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


def test_sign_returns_pem_pair(ca_pem):
    ca_cert, ca_key = ca_pem
    cert_pem, key_pem = cluster_ca.sign_node_cert(
        ca_cert, ca_key, node_uuid="node-uuid-abc", source_ip="10.0.0.1"
    )
    assert cert_pem.startswith(b"-----BEGIN CERTIFICATE-----")
    assert b"PRIVATE KEY-----" in key_pem


def test_sign_cert_cn_matches_node_uuid(ca_pem):
    ca_cert, ca_key = ca_pem
    cert_pem, _ = cluster_ca.sign_node_cert(
        ca_cert, ca_key, node_uuid="node-uuid-xyz", source_ip="10.0.0.1"
    )
    cert = _load_cert(cert_pem)
    cns = [attr.value for attr in cert.subject if attr.oid == NameOID.COMMON_NAME]
    assert cns == ["node-uuid-xyz"]


def test_sign_cert_san_includes_source_ip_v4(ca_pem):
    ca_cert, ca_key = ca_pem
    cert_pem, _ = cluster_ca.sign_node_cert(
        ca_cert, ca_key, node_uuid="uuid", source_ip="192.168.10.1"
    )
    cert = _load_cert(cert_pem)
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    ips = san.get_values_for_type(x509.IPAddress)
    assert ipaddress.ip_address("192.168.10.1") in ips


def test_sign_cert_san_supports_ipv6(ca_pem):
    ca_cert, ca_key = ca_pem
    cert_pem, _ = cluster_ca.sign_node_cert(
        ca_cert, ca_key, node_uuid="uuid", source_ip="2001:db8::1"
    )
    cert = _load_cert(cert_pem)
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    ips = san.get_values_for_type(x509.IPAddress)
    assert ipaddress.ip_address("2001:db8::1") in ips


def test_sign_cert_signature_verifies_under_ca(ca_pem):
    """Independent verification : the CA's public key must successfully
    verify the node cert's tbsCertificate signature."""
    ca_cert_pem, ca_key_pem = ca_pem
    cert_pem, _ = cluster_ca.sign_node_cert(
        ca_cert_pem, ca_key_pem, node_uuid="uuid", source_ip="10.0.0.1"
    )
    ca_cert = _load_cert(ca_cert_pem)
    node_cert = _load_cert(cert_pem)
    ca_pub = ca_cert.public_key()
    assert isinstance(ca_pub, Ed25519PublicKey)
    # Ed25519.verify raises on mismatch, returns None on success.
    ca_pub.verify(node_cert.signature, node_cert.tbs_certificate_bytes)


def test_sign_cert_signature_fails_under_wrong_ca(ca_pem):
    """Sanity : a different CA's public key must NOT verify the cert."""
    ca_cert_pem, ca_key_pem = ca_pem
    cert_pem, _ = cluster_ca.sign_node_cert(
        ca_cert_pem, ca_key_pem, node_uuid="uuid", source_ip="10.0.0.1"
    )
    other_cert_pem, _, _ = cluster_ca.mint_cluster_ca(
        common_name="other-cluster", validity_days=30
    )
    other_pub = _load_cert(other_cert_pem).public_key()
    node_cert = _load_cert(cert_pem)
    with pytest.raises(InvalidSignature):
        other_pub.verify(node_cert.signature, node_cert.tbs_certificate_bytes)


def test_sign_cert_validity_bounded_to_validity_days(ca_pem):
    ca_cert, ca_key = ca_pem
    cert_pem, _ = cluster_ca.sign_node_cert(
        ca_cert, ca_key, node_uuid="uuid", source_ip="10.0.0.1", validity_days=7
    )
    cert = _load_cert(cert_pem)
    now = datetime.now(timezone.utc)
    # Default backdates by 5 minutes (clock skew tolerance).
    assert cert.not_valid_before_utc <= now
    # not_valid_after: not_valid_before should be 7 days + 5 min.
    delta = cert.not_valid_after_utc - cert.not_valid_before_utc
    expected = timedelta(days=7, minutes=5)
    assert abs(delta - expected) < timedelta(seconds=2)


def test_sign_two_calls_produce_distinct_keypairs(ca_pem):
    ca_cert, ca_key = ca_pem
    _, key_pem_a = cluster_ca.sign_node_cert(
        ca_cert, ca_key, node_uuid="uuid", source_ip="10.0.0.1"
    )
    _, key_pem_b = cluster_ca.sign_node_cert(
        ca_cert, ca_key, node_uuid="uuid", source_ip="10.0.0.1"
    )
    assert key_pem_a != key_pem_b


def test_sign_minted_key_is_ed25519(ca_pem):
    ca_cert, ca_key = ca_pem
    _, key_pem = cluster_ca.sign_node_cert(
        ca_cert, ca_key, node_uuid="uuid", source_ip="10.0.0.1"
    )
    # _load_key already asserts Ed25519PrivateKey -- explicit assert
    # here keeps the intent visible at test level.
    key = _load_key(key_pem)
    assert isinstance(key, Ed25519PrivateKey)


def test_sign_basic_constraints_node_is_not_ca(ca_pem):
    """The node cert must NOT be marked CA:TRUE -- otherwise a leaked
    node key could be used to issue further certs the cluster would
    accept under chain validation."""
    ca_cert, ca_key = ca_pem
    cert_pem, _ = cluster_ca.sign_node_cert(
        ca_cert, ca_key, node_uuid="uuid", source_ip="10.0.0.1"
    )
    cert = _load_cert(cert_pem)
    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert bc.ca is False


def test_sign_rejects_invalid_ip(ca_pem):
    ca_cert, ca_key = ca_pem
    with pytest.raises(cluster_ca.ClusterCaError):
        cluster_ca.sign_node_cert(
            ca_cert, ca_key, node_uuid="uuid", source_ip="not-an-ip"
        )


def test_sign_rejects_zero_or_negative_validity(ca_pem):
    ca_cert, ca_key = ca_pem
    with pytest.raises(cluster_ca.ClusterCaError):
        cluster_ca.sign_node_cert(
            ca_cert, ca_key, node_uuid="uuid", source_ip="10.0.0.1", validity_days=0
        )
    with pytest.raises(cluster_ca.ClusterCaError):
        cluster_ca.sign_node_cert(
            ca_cert, ca_key, node_uuid="uuid", source_ip="10.0.0.1", validity_days=-3
        )
