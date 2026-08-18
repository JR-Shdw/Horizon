# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""mTLS auth dependency tests.

Coverage map :

Parser (cluster_mtls.parse_x_client_cert)
- URL-escaped PEM roundtrip
- empty header -> MtlsMalformedCertError
- no PEM marker -> MtlsMalformedCertError
- garbage bytes -> MtlsMalformedCertError

Trust proxy gate (cluster_mtls._is_trusted_proxy)
- empty identity-proxy trust fails closed
- external IP rejected when not in list
- empty list rejects everything

Full pipeline (cluster_mtls.authenticate)
- happy path returns identity matching cert CN + fingerprint
- missing header -> 401 MtlsMissingCertError
- revoked uuid -> 403 MtlsRevokedError
- expired cert -> 401 MtlsExpiredCertError
- wrong-CA signature -> 401 MtlsBadSignatureError
- serverAuth-only cert -> 401 MtlsUnusableCertError
- CA cert presented -> 401 MtlsUnusableCertError
- untrusted peer -> 403 MtlsUntrustedProxyError
- sealed vault -> VaultSealedError
"""

import urllib.parse
import uuid as _uuid
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from api.app import cluster_ca, cluster_membership, cluster_mtls
from api.app import node_uuid as nu
from api.app.config import settings
from api.app.database import async_session
from api.app.ha_password import clear as hp_clear
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID
from sqlalchemy import text

_CLUSTER_KEYS = (
    "cluster_id",
    "ha_password_encrypted",
    "cluster_ca_cert",
    "cluster_ca_key",
    "primary_uuid",
    "primary_since",
    "revoked_node_uuids",
)


# --- fixtures ---------------------------------------------------------------


@pytest_asyncio.fixture
async def _fresh_cluster(tmp_path, monkeypatch, admin_token, client):
    """Boot a fresh cluster via /cluster/init + isolated cert paths."""
    cert_p = tmp_path / "cluster-cert.pem"
    key_p = tmp_path / "cluster-cert.key"
    monkeypatch.setattr(settings, "cluster_cert_path", str(cert_p))
    monkeypatch.setattr(settings, "cluster_cert_key_path", str(key_p))
    monkeypatch.setattr(settings, "proxy_trusted_ips", "127.0.0.1/32")
    nu.init_node_uuid(settings.node_uuid_path)

    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_cluster_nodes"))
        await db.execute(
            text("DELETE FROM vault_cluster_config WHERE key = ANY(:ks)"),
            {"ks": list(_CLUSTER_KEYS)},
        )
        await db.commit()
    hp_clear()

    r = await client.post(
        "/api/v1/vault/cluster/init",
        json={"cluster_name": "mtls-dep-test"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 200, r.text
    yield
    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_cluster_nodes"))
        await db.execute(
            text("DELETE FROM vault_cluster_config WHERE key = ANY(:ks)"),
            {"ks": list(_CLUSTER_KEYS)},
        )
        await db.commit()
    hp_clear()


async def _sign_node_cert(node_uuid: str, source_ip: str = "127.0.0.1"):
    async with async_session() as db:
        pair = await cluster_ca.load_cluster_ca(db)
    assert pair is not None
    ca_cert_pem, ca_key_pem = pair
    return cluster_ca.sign_node_cert(ca_cert_pem, ca_key_pem, node_uuid, source_ip)


async def _insert_member(
    node_uuid: str,
    cert_pem: bytes,
    source_ip: str = "127.0.0.1",
    ha_state: str = "secondary",
) -> None:
    fpr = cluster_ca.compute_fingerprint(cert_pem)
    nbf = cluster_ca.parse_cert(cert_pem).not_valid_after_utc
    async with async_session() as db:
        await db.execute(
            text(
                "INSERT INTO vault_cluster_nodes (node_uuid, source_ip, "
                "ha_state, cluster_version, cert_fingerprint, cert_not_after) "
                "VALUES (:u, CAST(:ip AS INET), :st, :v, :f, :n)"
            ),
            {
                "u": node_uuid,
                "ip": source_ip,
                "st": ha_state,
                "v": "1.0.0-test",
                "f": fpr,
                "n": nbf,
            },
        )
        await db.commit()


def _x_client_cert_header(cert_pem: bytes) -> str:
    """nginx $ssl_client_escaped_cert format = URL-escaped PEM."""
    return urllib.parse.quote(cert_pem.decode("ascii"))


class _StubRequest:
    """Minimal Request stand-in for direct authenticate() calls in tests."""

    class _Client:
        def __init__(self, host: str) -> None:
            self.host = host

    def __init__(self, headers: dict[str, str], host: str = "127.0.0.1") -> None:
        self.headers = headers
        self.client = self._Client(host)


# --- parser -----------------------------------------------------------------


def test_parse_x_client_cert_url_escaped_pem_roundtrip():
    fake_pem = (
        b"-----BEGIN CERTIFICATE-----\n"
        b"MIIBdjCCASigAwIBAgIBATAKBggqhkjOPQQDAjAUMRIwEAYDVQQDDAlydG1pbi1jYTAe\n"
        b"-----END CERTIFICATE-----\n"
    )
    header = _x_client_cert_header(fake_pem)
    # parse_x_client_cert calls load_pem_x509_certificate which will reject
    # the fake bytes ; that's an MtlsMalformedCertError (cryptography parse
    # error). The point of this test is the unquote roundtrip.
    with pytest.raises(cluster_mtls.MtlsMalformedCertError) as exc:
        cluster_mtls.parse_x_client_cert(header)
    # Confirm we got past the marker check (the error mentions a parse
    # error, not "not a PEM-encoded certificate").
    assert (
        "parse error" in str(exc.value.detail).lower()
        or "asn1" in str(exc.value.detail).lower()
    )


def test_parse_x_client_cert_empty_header():
    with pytest.raises(cluster_mtls.MtlsMalformedCertError):
        cluster_mtls.parse_x_client_cert("")


def test_parse_x_client_cert_no_pem_marker():
    with pytest.raises(cluster_mtls.MtlsMalformedCertError) as exc:
        cluster_mtls.parse_x_client_cert("garbage%20bytes%20not%20PEM")
    assert "not a PEM" in str(exc.value.detail)


def test_parse_x_client_cert_garbage_bytes():
    with pytest.raises(cluster_mtls.MtlsMalformedCertError):
        cluster_mtls.parse_x_client_cert("%FF%FE%FD%FC")


# --- trusted proxy gate -----------------------------------------------------


def test_is_trusted_proxy_default_is_fail_closed():
    assert settings.proxy_trusted_ips == ""
    assert cluster_mtls._is_trusted_proxy("127.0.0.1") is False
    assert cluster_mtls._is_trusted_proxy("::1") is False


def test_is_trusted_proxy_external_ip(monkeypatch):
    monkeypatch.setattr(settings, "proxy_trusted_ips", "10.0.0.1/24")
    assert cluster_mtls._is_trusted_proxy("10.0.0.1") is True
    assert cluster_mtls._is_trusted_proxy("192.0.2.1") is False


def test_is_trusted_proxy_empty_list_rejects_everything(monkeypatch):
    monkeypatch.setattr(settings, "proxy_trusted_ips", "")
    assert cluster_mtls._is_trusted_proxy("127.0.0.1") is False
    assert cluster_mtls._is_trusted_proxy("10.0.0.1") is False


def test_is_trusted_proxy_invalid_ip_returns_false():
    assert cluster_mtls._is_trusted_proxy("not-an-ip") is False


# --- authenticate pipeline -------------------------------------------------


@pytest.mark.asyncio
async def test_authenticate_happy_path(_fresh_cluster):
    node_uuid = str(_uuid.uuid4())
    cert_pem, _key_pem = await _sign_node_cert(node_uuid)
    await _insert_member(node_uuid, cert_pem)

    req = _StubRequest({"X-Client-Cert": _x_client_cert_header(cert_pem)})
    async with async_session() as db:
        identity = await cluster_mtls.authenticate(req, db)
    assert identity.node_uuid == node_uuid
    assert identity.source_ip == "127.0.0.1"
    assert identity.cert_fingerprint == cluster_ca.compute_fingerprint(cert_pem)


@pytest.mark.asyncio
async def test_authenticate_missing_header(_fresh_cluster):
    req = _StubRequest({})  # no X-Client-Cert
    async with async_session() as db:
        with pytest.raises(cluster_mtls.MtlsMissingCertError):
            await cluster_mtls.authenticate(req, db)


@pytest.mark.asyncio
async def test_authenticate_revoked_uuid(_fresh_cluster):
    node_uuid = str(_uuid.uuid4())
    cert_pem, _ = await _sign_node_cert(node_uuid)
    await _insert_member(node_uuid, cert_pem)
    async with async_session() as db:
        await cluster_membership.add_revoked_uuid(
            db, node_uuid, actor="test", ip_address="127.0.0.1"
        )
        await db.commit()

    req = _StubRequest({"X-Client-Cert": _x_client_cert_header(cert_pem)})
    async with async_session() as db:
        with pytest.raises(cluster_mtls.MtlsRevokedError):
            await cluster_mtls.authenticate(req, db)


@pytest.mark.asyncio
async def test_authenticate_corrupt_revoked_list_fails_closed(_fresh_cluster):
    """A corrupt revoked_node_uuids row must deny (503), not admit the node
    by treating an unreadable revocation list as empty."""
    node_uuid = str(_uuid.uuid4())
    cert_pem, _ = await _sign_node_cert(node_uuid)
    await _insert_member(node_uuid, cert_pem)
    async with async_session() as db:
        await db.execute(
            text(
                "INSERT INTO vault_cluster_config (key, value) "
                "VALUES ('revoked_node_uuids', 'garbage{') "
                "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value"
            )
        )
        await db.commit()

    req = _StubRequest({"X-Client-Cert": _x_client_cert_header(cert_pem)})
    async with async_session() as db:
        with pytest.raises(cluster_mtls.MtlsRevocationUnavailableError):
            await cluster_mtls.authenticate(req, db)


@pytest.mark.asyncio
async def test_authenticate_expired_cert(_fresh_cluster, monkeypatch):
    # Sign a cert with negative validity by mutating the helper's clamp.
    # Easier path : build a cert that already expired (validity 1 day +
    # monkey-patch the cluster_mtls._now_utc-equivalent to NOW + 2 days).
    node_uuid = str(_uuid.uuid4())
    cert_pem, _ = await _sign_node_cert(node_uuid)
    await _insert_member(node_uuid, cert_pem)

    # Mock the clock used by _verify_validity_window to push past
    # the cert's NotAfter.
    real_now = datetime.now(timezone.utc)
    fake_now = real_now + timedelta(days=settings.cluster_node_cert_validity_days + 1)

    class _FakeDatetime:
        @staticmethod
        def now(tz=None):
            return fake_now

    monkeypatch.setattr(cluster_mtls, "datetime", _FakeDatetime)
    req = _StubRequest({"X-Client-Cert": _x_client_cert_header(cert_pem)})
    async with async_session() as db:
        with pytest.raises(cluster_mtls.MtlsExpiredCertError):
            await cluster_mtls.authenticate(req, db)


@pytest.mark.asyncio
async def test_authenticate_wrong_ca_signature(_fresh_cluster):
    # Forge a cert with a different CA -- it will fail signature
    # verification against the cluster CA.
    rogue_ca_key = Ed25519PrivateKey.generate()
    rogue_ca_pub = rogue_ca_key.public_key()
    rogue_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "rogue-ca")])
    now = datetime.now(timezone.utc)
    rogue_ca_cert = (
        x509.CertificateBuilder()
        .subject_name(rogue_subject)
        .issuer_name(rogue_subject)
        .public_key(rogue_ca_pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(rogue_ca_key, algorithm=None)
    )

    node_key = Ed25519PrivateKey.generate()
    node_pub = node_key.public_key()
    target_uuid = str(_uuid.uuid4())
    node_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, target_uuid)])
    rogue_node_cert = (
        x509.CertificateBuilder()
        .subject_name(node_subject)
        .issuer_name(rogue_ca_cert.subject)
        .public_key(node_pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=90))
        .sign(rogue_ca_key, algorithm=None)
    )
    rogue_pem = rogue_node_cert.public_bytes(serialization.Encoding.PEM)

    req = _StubRequest({"X-Client-Cert": _x_client_cert_header(rogue_pem)})
    async with async_session() as db:
        with pytest.raises(cluster_mtls.MtlsBadSignatureError):
            await cluster_mtls.authenticate(req, db)


@pytest.mark.asyncio
async def test_authenticate_rejects_server_cert(_fresh_cluster):
    # A serverAuth-only cert is signed by the cluster CA but is not a member
    # identity -- the verifier must reject it (clientAuth EKU required).
    async with async_session() as db:
        ca_cert_pem, ca_key_pem = await cluster_ca.load_cluster_ca(db)
    server_pem, _key = cluster_ca.sign_server_cert(
        ca_cert_pem, ca_key_pem, ["127.0.0.1"], []
    )
    req = _StubRequest({"X-Client-Cert": _x_client_cert_header(server_pem)})
    async with async_session() as db:
        with pytest.raises(cluster_mtls.MtlsUnusableCertError):
            await cluster_mtls.authenticate(req, db)


@pytest.mark.asyncio
async def test_authenticate_rejects_ca_cert(_fresh_cluster):
    # The public self-signed cluster CA cert verifies against its own key, but
    # BasicConstraints CA:TRUE must bar it from being used as a member identity.
    async with async_session() as db:
        ca_cert_pem, _ca_key_pem = await cluster_ca.load_cluster_ca(db)
    req = _StubRequest({"X-Client-Cert": _x_client_cert_header(ca_cert_pem)})
    async with async_session() as db:
        with pytest.raises(cluster_mtls.MtlsUnusableCertError):
            await cluster_mtls.authenticate(req, db)


@pytest.mark.asyncio
async def test_verify_signed_by_ca_accepts_and_rejects(_fresh_cluster):
    # Renewal chain check (cluster_cert_renewal): a node cert signed by the
    # cluster CA verifies; one signed by a foreign CA does not.
    node_uuid = str(_uuid.uuid4())
    node_pem, _ = await _sign_node_cert(node_uuid)
    async with async_session() as db:
        ca_cert_pem = await cluster_ca.load_cluster_ca_cert(db)
    assert cluster_ca.verify_signed_by_ca(node_pem, ca_cert_pem) is True
    foreign_cert, _key, _fpr = cluster_ca.mint_cluster_ca()
    assert cluster_ca.verify_signed_by_ca(node_pem, foreign_cert) is False


@pytest.mark.asyncio
async def test_authenticate_rejects_cert_without_eku(_fresh_cluster):
    # A cert signed by the cluster CA but with NO BasicConstraints + NO EKU is
    # not a usable member identity (covers the absent-extension branches).
    async with async_session() as db:
        ca_cert_pem, ca_key_pem = await cluster_ca.load_cluster_ca(db)
    ca_key = cluster_ca.parse_key(ca_key_pem)
    ca_cert = cluster_ca.parse_cert(ca_cert_pem)
    now = datetime.now(timezone.utc)
    bare = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, str(_uuid.uuid4()))])
        )
        .issuer_name(ca_cert.subject)
        .public_key(Ed25519PrivateKey.generate().public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=1))
        .sign(ca_key, algorithm=None)
    )
    pem = bare.public_bytes(serialization.Encoding.PEM)
    req = _StubRequest({"X-Client-Cert": _x_client_cert_header(pem)})
    async with async_session() as db:
        with pytest.raises(cluster_mtls.MtlsUnusableCertError):
            await cluster_mtls.authenticate(req, db)


@pytest.mark.asyncio
async def test_authenticate_untrusted_proxy(_fresh_cluster, monkeypatch):
    # Empty the trusted-proxy list -- the default 127.0.0.1 peer is now
    # untrusted, even with a perfectly valid cert.
    monkeypatch.setattr(settings, "proxy_trusted_ips", "")
    node_uuid = str(_uuid.uuid4())
    cert_pem, _ = await _sign_node_cert(node_uuid)
    await _insert_member(node_uuid, cert_pem)
    req = _StubRequest({"X-Client-Cert": _x_client_cert_header(cert_pem)})
    async with async_session() as db:
        with pytest.raises(cluster_mtls.MtlsUntrustedProxyError):
            await cluster_mtls.authenticate(req, db)


@pytest.mark.asyncio
async def test_authenticate_sealed_vault_raises(_fresh_cluster):
    from api.app.vault_state import VaultSealedError, vault

    node_uuid = str(_uuid.uuid4())
    cert_pem, _ = await _sign_node_cert(node_uuid)
    await _insert_member(node_uuid, cert_pem)
    req = _StubRequest({"X-Client-Cert": _x_client_cert_header(cert_pem)})
    vault.seal()
    try:
        async with async_session() as db:
            with pytest.raises(VaultSealedError):
                await cluster_mtls.authenticate(req, db)
    finally:
        # admin_token fixture is function-scoped and will re-unseal next
        # test ; here we leave sealed and let the fixture re-unseal.
        pass
