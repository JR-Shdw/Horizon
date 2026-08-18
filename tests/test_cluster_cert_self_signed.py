# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""A node must not keep the boot-time self-signed nginx cert forever.

`bootstrap-init.yml` step 3b is `hosts: rhorizon_primary`, so only the primary
is handed a cluster-CA-signed server cert at bootstrap. Every joiner depends on
the renewal loop to replace its placeholder.

That loop used to decide on expiry alone, and the placeholder is deliberately
valid for 10 years -- so `not_after - now` was never inside the renewal
threshold and the joiner kept a cert that chains to nothing. nginx served it
happily and the cluster mTLS it was meant to anchor validated against nothing.

Observed on a lab cluster: two of three nodes served `issuer == subject` certs
with a 2036 expiry while the primary had a proper CA-signed one.
"""

from datetime import datetime, timedelta, timezone

import pytest
from api.app import cluster_cert
from api.app.cluster_cert_renewal import _server_cert_needs_renew
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _cert(subject_cn, issuer_cn=None, days=90):
    """Build a cert. issuer_cn=None -> self-signed (issuer == subject)."""
    key = ec.generate_private_key(ec.SECP256R1())
    subject = _name(subject_cn)
    issuer = _name(issuer_cn) if issuer_cn else subject
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=days))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


def _write(tmp_path, pem, name="server.crt"):
    p = tmp_path / name
    p.write_bytes(pem)
    return str(p)


# --------------------------------------------------------------------------
# cert_is_self_signed
# --------------------------------------------------------------------------


def test_detects_self_signed():
    assert cluster_cert.cert_is_self_signed(_cert("rhorizon-3")) is True


def test_ca_signed_is_not_self_signed():
    pem = _cert("rhorizon-3", issuer_cn="rhorizon-ha-lab")
    assert cluster_cert.cert_is_self_signed(pem) is False


# --------------------------------------------------------------------------
# the renewal decision
# --------------------------------------------------------------------------


def test_long_lived_self_signed_still_renews(tmp_path):
    """The regression: 10 years of validity must not defeat the check."""
    path = _write(tmp_path, _cert("rhorizon-3", days=3650))
    assert _server_cert_needs_renew(path) is True


def test_fresh_ca_signed_does_not_renew(tmp_path):
    path = _write(tmp_path, _cert("rhorizon-3", issuer_cn="rhorizon-ha-lab", days=90))
    assert _server_cert_needs_renew(path) is False


def test_expiring_ca_signed_renews(tmp_path, monkeypatch):
    from api.app import cluster_cert_renewal as ccr

    monkeypatch.setattr(ccr.settings, "cluster_cert_renewal_threshold_days", 30)
    path = _write(tmp_path, _cert("rhorizon-3", issuer_cn="rhorizon-ha-lab", days=5))
    assert _server_cert_needs_renew(path) is True


def test_absent_cert_does_not_renew(tmp_path):
    """No server cert yet is not the same as a bad one -- stay quiet."""
    assert _server_cert_needs_renew(str(tmp_path / "nope.crt")) is False


def test_unparseable_cert_forces_renew(tmp_path):
    path = _write(tmp_path, b"-----BEGIN CERTIFICATE-----\nnot a cert\n")
    assert _server_cert_needs_renew(path) is True


@pytest.mark.parametrize("days", [1, 90, 3650])
def test_self_signed_renews_at_any_validity(tmp_path, days):
    """Issuer decides, not the clock."""
    path = _write(tmp_path, _cert("rhorizon-4", days=days), name=f"s{days}.crt")
    assert _server_cert_needs_renew(path) is True
