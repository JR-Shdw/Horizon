# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""/cluster/join carries the joiner's server cert.

Reuses the JOIN test harness pattern from test_ha_cluster_join.py
to assert that, on top of the existing node identity cert, the
response now includes :

- ``server_cert_pem`` : a fresh server cert signed by the cluster CA.
- ``server_cert_key_wrapped_hex`` : the matching private key wrapped
  under HKDF(ha_password, info="cluster-server-key-wrap:<uuid>").

Verifies that :
- the server cert verifies under the cluster CA,
- the server cert carries EKU=server_auth only (no client_auth),
- the SAN matches the source IP observed by the primary,
- the wrapped key decrypts and matches the cert's public key,
- the wrap domain is distinct from the node-key wrap (the same blob
  cannot be unwrapped under the node-key derivation).
"""

import base64
import hashlib
import hmac as _hmac

import pytest
import pytest_asyncio
from api.app import ha_password as hp
from api.app import node_uuid as nu
from api.app.config import settings
from api.app.database import async_session
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA512
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.x509.oid import ExtendedKeyUsageOID
from sqlalchemy import text

_CLUSTER_CFG_KEYS = (
    "cluster_id",
    "ha_password_encrypted",
    "cluster_ca_cert",
    "cluster_ca_key",
    "primary_uuid",
    "primary_since",
)


async def _wipe_state():
    async with async_session() as db:
        await db.execute(
            text("DELETE FROM vault_cluster_config WHERE key = ANY(:ks)"),
            {"ks": list(_CLUSTER_CFG_KEYS)},
        )
        await db.execute(text("DELETE FROM vault_cluster_nodes"))
        await db.execute(
            text("DELETE FROM vault_challenges WHERE purpose = 'cluster_join'")
        )
        await db.commit()
    hp.clear()


@pytest_asyncio.fixture
async def _wipe_cluster_state():
    nu.init_node_uuid(settings.node_uuid_path)
    await _wipe_state()
    yield
    await _wipe_state()


async def _init_cluster(admin_token, client) -> tuple[str, bytes, str]:
    r = await client.post(
        "/api/v1/vault/cluster/init",
        json={"cluster_name": "test-11d"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    return (
        body["cluster_id"],
        base64.b64decode(body["ha_password"]),
        body["primary_uuid"],
    )


def _proof(
    ha_password: bytes,
    cluster_id: str,
    node_uuid: str,
    source_ip: str,
    nonce: str,
    issued_at_epoch: int,
) -> str:
    msg = (
        cluster_id.encode()
        + node_uuid.encode()
        + source_ip.encode()
        + nonce.encode()
        + str(issued_at_epoch).encode()
    )
    return _hmac.new(ha_password, msg, hashlib.sha512).hexdigest()


def _unwrap_server_key(ha_password: bytes, node_uuid: str, wrapped_hex: str) -> bytes:
    info = b"cluster-server-key-wrap:" + node_uuid.encode()
    aad = b"vault-cluster:server-key:" + node_uuid.encode()
    derived = HKDF(algorithm=SHA512(), length=32, salt=None, info=info).derive(
        ha_password
    )
    blob = bytes.fromhex(wrapped_hex)
    nonce, ct = blob[:12], blob[12:]
    return AESGCM(derived).decrypt(nonce, ct, aad)


async def _challenge_and_proof(
    client, cluster_id: str, ha_password: bytes, node_uuid: str
) -> dict:
    cr = await client.post(
        "/api/v1/vault/cluster/challenge",
        json={"node_uuid": node_uuid, "rhorizon_version": "1.0.0"},
    )
    assert cr.status_code == 200, cr.text
    nonce = cr.json()["nonce"]
    async with async_session() as db:
        row = (
            await db.execute(
                text(
                    "SELECT source_ip, issued_at "
                    "FROM vault_challenges WHERE challenge = :c"
                ),
                {"c": nonce},
            )
        ).fetchone()
    source_ip = row.source_ip
    issued_at_epoch = int(row.issued_at.timestamp())
    return {
        "cluster_id": cluster_id,
        "node_uuid": node_uuid,
        "nonce": nonce,
        "ha_password_proof": _proof(
            ha_password, cluster_id, node_uuid, source_ip, nonce, issued_at_epoch
        ),
        "rhorizon_version": "1.0.0",
    }, source_ip


@pytest.mark.asyncio
async def test_join_response_carries_server_cert(
    admin_token, client, _wipe_cluster_state
):
    cluster_id, ha_pw, _ = await _init_cluster(admin_token, client)
    node_uuid = "join-server-cert-001"
    body, _src = await _challenge_and_proof(client, cluster_id, ha_pw, node_uuid)
    r = await client.post("/api/v1/vault/cluster/join", json=body)
    assert r.status_code == 200, r.text
    resp = r.json()
    assert "server_cert_pem" in resp
    assert "server_cert_key_wrapped_hex" in resp
    assert resp["server_cert_pem"].startswith("-----BEGIN CERTIFICATE-----")
    assert len(resp["server_cert_key_wrapped_hex"]) > 0


@pytest.mark.asyncio
async def test_server_cert_signed_by_cluster_ca(
    admin_token, client, _wipe_cluster_state
):
    cluster_id, ha_pw, _ = await _init_cluster(admin_token, client)
    node_uuid = "join-server-cert-002"
    body, _src = await _challenge_and_proof(client, cluster_id, ha_pw, node_uuid)
    r = await client.post("/api/v1/vault/cluster/join", json=body)
    assert r.status_code == 200
    resp = r.json()
    server_cert = x509.load_pem_x509_certificate(resp["server_cert_pem"].encode())
    ca_cert = x509.load_pem_x509_certificate(resp["ca_cert_pem"].encode())
    ca_cert.public_key().verify(
        server_cert.signature, server_cert.tbs_certificate_bytes
    )


@pytest.mark.asyncio
async def test_server_cert_eku_server_auth_only(
    admin_token, client, _wipe_cluster_state
):
    cluster_id, ha_pw, _ = await _init_cluster(admin_token, client)
    node_uuid = "join-server-cert-003"
    body, _src = await _challenge_and_proof(client, cluster_id, ha_pw, node_uuid)
    r = await client.post("/api/v1/vault/cluster/join", json=body)
    assert r.status_code == 200
    cert = x509.load_pem_x509_certificate(r.json()["server_cert_pem"].encode())
    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    eku_set = set(eku)
    assert ExtendedKeyUsageOID.SERVER_AUTH in eku_set
    assert ExtendedKeyUsageOID.CLIENT_AUTH not in eku_set


@pytest.mark.asyncio
async def test_server_cert_san_matches_source_ip(
    admin_token, client, _wipe_cluster_state
):
    cluster_id, ha_pw, _ = await _init_cluster(admin_token, client)
    node_uuid = "join-server-cert-004"
    body, source_ip = await _challenge_and_proof(client, cluster_id, ha_pw, node_uuid)
    r = await client.post("/api/v1/vault/cluster/join", json=body)
    assert r.status_code == 200
    cert = x509.load_pem_x509_certificate(r.json()["server_cert_pem"].encode())
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    import ipaddress

    ips = san.get_values_for_type(x509.IPAddress)
    assert ipaddress.ip_address(source_ip) in ips


@pytest.mark.asyncio
async def test_wrapped_server_key_decrypts_and_matches_cert(
    admin_token, client, _wipe_cluster_state
):
    cluster_id, ha_pw, _ = await _init_cluster(admin_token, client)
    node_uuid = "join-server-cert-005"
    body, _src = await _challenge_and_proof(client, cluster_id, ha_pw, node_uuid)
    r = await client.post("/api/v1/vault/cluster/join", json=body)
    assert r.status_code == 200
    resp = r.json()
    key_pem = _unwrap_server_key(ha_pw, node_uuid, resp["server_cert_key_wrapped_hex"])
    assert key_pem.startswith(b"-----BEGIN PRIVATE KEY-----")
    parsed_key = serialization.load_pem_private_key(key_pem, password=None)
    assert isinstance(parsed_key, Ed25519PrivateKey)
    cert = x509.load_pem_x509_certificate(resp["server_cert_pem"].encode())
    derived_pub = parsed_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    cert_pub = cert.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    assert derived_pub == cert_pub


@pytest.mark.asyncio
async def test_server_wrap_cannot_be_unwrapped_under_node_domain(
    admin_token, client, _wipe_cluster_state
):
    """Cross-domain isolation : a wrapped server key cannot be decrypted
    under the node-key HKDF domain, even with the right ha_password and
    node_uuid."""
    cluster_id, ha_pw, _ = await _init_cluster(admin_token, client)
    node_uuid = "join-server-cert-006"
    body, _ = await _challenge_and_proof(client, cluster_id, ha_pw, node_uuid)
    r = await client.post("/api/v1/vault/cluster/join", json=body)
    assert r.status_code == 200
    resp = r.json()
    info = b"cluster-node-key-wrap:" + node_uuid.encode()
    aad = b"vault-cluster:node-key:" + node_uuid.encode()
    derived = HKDF(algorithm=SHA512(), length=32, salt=None, info=info).derive(ha_pw)
    blob = bytes.fromhex(resp["server_cert_key_wrapped_hex"])
    nonce, ct = blob[:12], blob[12:]
    with pytest.raises(Exception):
        AESGCM(derived).decrypt(nonce, ct, aad)
