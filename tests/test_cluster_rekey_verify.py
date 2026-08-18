# SPDX-License-Identifier: AGPL-3.0-or-later
"""cluster_rekey._verify_signer_cert: envelope origin-auth.

A node must adopt a rekey envelope only when its signer cert chains to the
cluster CA and is inside its validity window; anything else is rejected (the
S1 fence then quarantines). Pure crypto, no DB.
"""

from datetime import datetime, timedelta, timezone

import pytest
from api.app import cluster_ca, cluster_rekey
from api.app.cluster_mtls import MtlsBadSignatureError
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.x509.oid import NameOID


def _ca():
    cert, key, _fpr = cluster_ca.mint_cluster_ca()
    return cert, key


def test_verify_signer_cert_accepts_ca_signed():
    ca_cert, ca_key = _ca()
    node_cert, _k = cluster_ca.sign_node_cert(ca_cert, ca_key, "uuid-1", "127.0.0.1")
    pub = cluster_rekey._verify_signer_cert(node_cert.decode(), ca_cert, None)
    assert isinstance(pub, Ed25519PublicKey)


def test_verify_signer_cert_rejects_foreign_ca():
    ca_cert, _ca_key = _ca()
    foreign_cert, foreign_key = _ca()
    rogue, _k = cluster_ca.sign_node_cert(
        foreign_cert, foreign_key, "uuid-2", "127.0.0.1"
    )
    with pytest.raises(MtlsBadSignatureError):
        cluster_rekey._verify_signer_cert(rogue.decode(), ca_cert, None)


def test_verify_signer_cert_rejects_expired():
    ca_cert, ca_key = _ca()
    ca_key_obj = cluster_ca.parse_key(ca_key)
    ca_cert_obj = cluster_ca.parse_cert(ca_cert)
    now = datetime.now(timezone.utc)
    expired = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "old")]))
        .issuer_name(ca_cert_obj.subject)
        .public_key(Ed25519PrivateKey.generate().public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=10))
        .not_valid_after(now - timedelta(days=1))
        .sign(ca_key_obj, algorithm=None)
    )
    pem = expired.public_bytes(serialization.Encoding.PEM).decode()
    with pytest.raises(ValueError, match="validity window"):
        cluster_rekey._verify_signer_cert(pem, ca_cert, None)
