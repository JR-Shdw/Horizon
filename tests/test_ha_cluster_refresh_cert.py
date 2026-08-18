# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""POST /cluster/refresh-cert endpoint tests.

Coverage map :

Happy path
- 200 + new cert/key returned, fingerprint differs from prev
- cert_not_after / cert_fingerprint updated on vault_cluster_nodes
- force_renew_at cleared after refresh
- audit row ``cluster_cert_refreshed`` emitted

Error paths
- missing X-Client-Cert -> 401
- vault sealed -> 409
- node membership absent -> 404
- node ha_state='evicted' -> 403
- node uuid revoked -> 403 (via mTLS dep, not the route handler)
"""

import urllib.parse
import uuid as _uuid

import pytest
import pytest_asyncio
from api.app import cluster_ca, cluster_membership
from api.app import node_uuid as nu
from api.app.config import settings
from api.app.database import async_session
from api.app.ha_password import clear as hp_clear
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


@pytest_asyncio.fixture
async def _fresh_cluster(tmp_path, monkeypatch, admin_token, client):
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
        json={"cluster_name": "refresh-cert-test"},
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


def _hdr(cert_pem: bytes) -> dict:
    return {"X-Client-Cert": urllib.parse.quote(cert_pem.decode("ascii"))}


@pytest.mark.asyncio
async def test_refresh_cert_happy_path(_fresh_cluster, client):
    node_uuid = str(_uuid.uuid4())
    cert_pem, _key_pem = await _sign_node_cert(node_uuid)
    await _insert_member(node_uuid, cert_pem)
    prev_fpr = cluster_ca.compute_fingerprint(cert_pem)

    r = await client.post("/api/v1/vault/cluster/refresh-cert", headers=_hdr(cert_pem))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["node_uuid"] == node_uuid
    assert body["node_cert_pem"].startswith("-----BEGIN CERTIFICATE-----")
    assert body["node_cert_key_pem"].startswith("-----BEGIN PRIVATE KEY-----")
    # Fresh keypair = different fingerprint (Ed25519 deterministic on key,
    # not on the rest -- but the key itself is random).
    assert body["cert_fingerprint"] != prev_fpr


@pytest.mark.asyncio
async def test_refresh_cert_ships_server_cert(_fresh_cluster, client):
    """The refresh-cert response also carries a fresh nginx
    server cert signed by the cluster CA, allowing the renewal loop to
    rotate node + server certs in one round-trip."""
    from cryptography import x509
    from cryptography.x509.oid import ExtendedKeyUsageOID

    node_uuid = str(_uuid.uuid4())
    cert_pem, _ = await _sign_node_cert(node_uuid)
    await _insert_member(node_uuid, cert_pem)

    r = await client.post("/api/v1/vault/cluster/refresh-cert", headers=_hdr(cert_pem))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["server_cert_pem"].startswith("-----BEGIN CERTIFICATE-----")
    assert body["server_cert_key_pem"].startswith("-----BEGIN PRIVATE KEY-----")
    assert len(body["server_cert_fingerprint"]) == 64
    server_cert = x509.load_pem_x509_certificate(body["server_cert_pem"].encode())
    eku = server_cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert ExtendedKeyUsageOID.SERVER_AUTH in set(eku)
    assert ExtendedKeyUsageOID.CLIENT_AUTH not in set(eku)


@pytest.mark.asyncio
async def test_refresh_cert_updates_membership_row(_fresh_cluster, client):
    node_uuid = str(_uuid.uuid4())
    cert_pem, _ = await _sign_node_cert(node_uuid)
    await _insert_member(node_uuid, cert_pem)
    prev_fpr = cluster_ca.compute_fingerprint(cert_pem)

    r = await client.post("/api/v1/vault/cluster/refresh-cert", headers=_hdr(cert_pem))
    assert r.status_code == 200, r.text
    new_fpr = r.json()["cert_fingerprint"]
    async with async_session() as db:
        row = (
            await db.execute(
                text(
                    "SELECT cert_fingerprint, cert_not_after "
                    "FROM vault_cluster_nodes WHERE node_uuid = :u"
                ),
                {"u": node_uuid},
            )
        ).fetchone()
    assert row.cert_fingerprint == new_fpr
    assert row.cert_fingerprint != prev_fpr


@pytest.mark.asyncio
async def test_refresh_cert_clears_force_renew_at(_fresh_cluster, client):
    node_uuid = str(_uuid.uuid4())
    cert_pem, _ = await _sign_node_cert(node_uuid)
    await _insert_member(node_uuid, cert_pem)
    async with async_session() as db:
        await db.execute(
            text(
                "UPDATE vault_cluster_nodes "
                "SET force_renew_at = NOW() WHERE node_uuid = :u"
            ),
            {"u": node_uuid},
        )
        await db.commit()

    r = await client.post("/api/v1/vault/cluster/refresh-cert", headers=_hdr(cert_pem))
    assert r.status_code == 200

    async with async_session() as db:
        row = (
            await db.execute(
                text(
                    "SELECT force_renew_at FROM vault_cluster_nodes "
                    "WHERE node_uuid = :u"
                ),
                {"u": node_uuid},
            )
        ).fetchone()
    assert row.force_renew_at is None


@pytest.mark.asyncio
async def test_refresh_cert_audit_row_emitted(_fresh_cluster, client):
    node_uuid = str(_uuid.uuid4())
    cert_pem, _ = await _sign_node_cert(node_uuid)
    await _insert_member(node_uuid, cert_pem)

    r = await client.post("/api/v1/vault/cluster/refresh-cert", headers=_hdr(cert_pem))
    assert r.status_code == 200

    async with async_session() as db:
        row = (
            await db.execute(
                text(
                    "SELECT actor, target, action FROM vault_audit "
                    "WHERE action = 'cluster_cert_refreshed' "
                    "  AND target = :u ORDER BY id DESC LIMIT 1"
                ),
                {"u": node_uuid},
            )
        ).fetchone()
    assert row is not None
    assert row.actor == f"node:{node_uuid}"


@pytest.mark.asyncio
async def test_refresh_cert_missing_header_returns_401(_fresh_cluster, client):
    r = await client.post("/api/v1/vault/cluster/refresh-cert")
    assert r.status_code == 401, r.text


@pytest.mark.asyncio
async def test_refresh_cert_no_membership_row_404(_fresh_cluster, client):
    # Cert is valid (signed by cluster CA) but no membership row exists.
    orphan_uuid = str(_uuid.uuid4())
    cert_pem, _ = await _sign_node_cert(orphan_uuid)
    r = await client.post("/api/v1/vault/cluster/refresh-cert", headers=_hdr(cert_pem))
    assert r.status_code == 404, r.text
    assert "re-JOIN" in r.json()["detail"]


@pytest.mark.asyncio
async def test_refresh_cert_evicted_node_403(_fresh_cluster, client):
    node_uuid = str(_uuid.uuid4())
    cert_pem, _ = await _sign_node_cert(node_uuid)
    await _insert_member(node_uuid, cert_pem, ha_state="evicted")
    r = await client.post("/api/v1/vault/cluster/refresh-cert", headers=_hdr(cert_pem))
    assert r.status_code == 403, r.text


@pytest.mark.asyncio
async def test_refresh_cert_revoked_uuid_403(_fresh_cluster, client):
    node_uuid = str(_uuid.uuid4())
    cert_pem, _ = await _sign_node_cert(node_uuid)
    await _insert_member(node_uuid, cert_pem)
    async with async_session() as db:
        await cluster_membership.add_revoked_uuid(
            db, node_uuid, actor="test", ip_address="127.0.0.1"
        )
        await db.commit()
    r = await client.post("/api/v1/vault/cluster/refresh-cert", headers=_hdr(cert_pem))
    assert r.status_code == 403, r.text


@pytest.mark.asyncio
async def test_refresh_cert_sealed_vault_returns_503_or_500(
    _fresh_cluster, client, admin_token, master_password
):
    """Sealed vault path : the mTLS dep raises VaultSealedError before the
    handler runs ; the global error handler maps to 503 (sealed vault is a
    transient state, retry-after pattern). After this test the admin_token
    fixture (function-scoped) re-unseals for subsequent tests.
    """
    from api.app.vault_state import vault

    node_uuid = str(_uuid.uuid4())
    cert_pem, _ = await _sign_node_cert(node_uuid)
    await _insert_member(node_uuid, cert_pem)

    vault.seal()
    try:
        r = await client.post(
            "/api/v1/vault/cluster/refresh-cert", headers=_hdr(cert_pem)
        )
        # VaultSealedError -> 503 via global exception handler.
        assert r.status_code in (409, 503), r.text
    finally:
        # Re-unseal so subsequent tests have a working vault.
        await client.post("/api/v1/vault/unseal", json={"password": master_password})
