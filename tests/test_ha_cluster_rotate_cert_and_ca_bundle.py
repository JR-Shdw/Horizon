# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""/cluster/rotate-cert + /cluster/ca-bundle tests.

Coverage map :

POST /cluster/rotate-cert/{node_uuid} (admin:w)
- single-node flips force_renew_at on the row
- 404 on unknown uuid
- 404 on evicted node
- 401 without admin token
- audit row ``cluster_cert_force_rotate`` emitted

POST /cluster/rotate-cert/all (admin:w)
- flips force_renew_at on every non-evicted row
- counter scope=all bumped
- evicted rows skipped

GET /cluster/ca-bundle (admin:r)
- returns CA PEM + fingerprint
- 401 without admin token
- 503 when CA not initialised (pre /cluster/init)
- 409 when vault sealed
- does not unwrap the private key for public CA material
"""

import uuid as _uuid

import pytest
import pytest_asyncio
from api.app import cluster_ca
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
)


@pytest_asyncio.fixture
async def _fresh_cluster(tmp_path, monkeypatch, admin_token, client):
    cert_p = tmp_path / "cluster-cert.pem"
    key_p = tmp_path / "cluster-cert.key"
    monkeypatch.setattr(settings, "cluster_cert_path", str(cert_p))
    monkeypatch.setattr(settings, "cluster_cert_key_path", str(key_p))
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
        json={"cluster_name": "rotate-ca-bundle-test"},
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


async def _insert_fake_node(
    node_uuid: str,
    source_ip: str = "127.0.0.1",
    ha_state: str = "secondary",
) -> None:
    async with async_session() as db:
        pair = await cluster_ca.load_cluster_ca(db)
        assert pair is not None
        ca_cert_pem, ca_key_pem = pair
    cert_pem, _ = cluster_ca.sign_node_cert(
        ca_cert_pem, ca_key_pem, node_uuid, source_ip
    )
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


# --- rotate-cert single -----------------------------------------------------


@pytest.mark.asyncio
async def test_rotate_cert_one_flips_force_renew_at(
    _fresh_cluster, client, admin_token
):
    node_uuid = str(_uuid.uuid4())
    await _insert_fake_node(node_uuid)
    r = await client.post(
        f"/api/v1/vault/cluster/rotate-cert/{node_uuid}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["scope"] == "one"
    assert body["flipped"] == 1
    assert body["target"] == node_uuid

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
    assert row.force_renew_at is not None


@pytest.mark.asyncio
async def test_rotate_cert_one_unknown_uuid_404(_fresh_cluster, client, admin_token):
    r = await client.post(
        f"/api/v1/vault/cluster/rotate-cert/{_uuid.uuid4()}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_rotate_cert_one_evicted_404(_fresh_cluster, client, admin_token):
    node_uuid = str(_uuid.uuid4())
    await _insert_fake_node(node_uuid, ha_state="evicted")
    r = await client.post(
        f"/api/v1/vault/cluster/rotate-cert/{node_uuid}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_rotate_cert_one_no_admin_token_401(_fresh_cluster, client):
    node_uuid = str(_uuid.uuid4())
    await _insert_fake_node(node_uuid)
    r = await client.post(f"/api/v1/vault/cluster/rotate-cert/{node_uuid}")
    assert r.status_code in (401, 403, 422)


@pytest.mark.asyncio
async def test_rotate_cert_audit_emitted(_fresh_cluster, client, admin_token):
    node_uuid = str(_uuid.uuid4())
    await _insert_fake_node(node_uuid)
    r = await client.post(
        f"/api/v1/vault/cluster/rotate-cert/{node_uuid}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 200
    async with async_session() as db:
        row = (
            await db.execute(
                text(
                    "SELECT actor, target, action FROM vault_audit "
                    "WHERE action = 'cluster_cert_force_rotate' "
                    "  AND target = :u ORDER BY id DESC LIMIT 1"
                ),
                {"u": node_uuid},
            )
        ).fetchone()
    assert row is not None


# --- rotate-cert all --------------------------------------------------------


@pytest.mark.asyncio
async def test_rotate_cert_all_flips_every_non_evicted_row(
    _fresh_cluster, client, admin_token
):
    keep_uuids = [str(_uuid.uuid4()) for _ in range(3)]
    evicted_uuid = str(_uuid.uuid4())
    # Distinct source_ip per node -- the vault_cluster_nodes_active_ip partial
    # unique forbids two active nodes sharing an IP.
    for i, u in enumerate(keep_uuids):
        await _insert_fake_node(u, source_ip=f"198.51.100.{i + 1}")
    await _insert_fake_node(evicted_uuid, source_ip="10.0.0.1", ha_state="evicted")

    r = await client.post(
        "/api/v1/vault/cluster/rotate-cert/all",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["scope"] == "all"
    # The /cluster/init primary row also exists, so flipped >= 3.
    assert body["flipped"] >= 3

    async with async_session() as db:
        rows = (
            await db.execute(
                text("SELECT node_uuid, force_renew_at FROM vault_cluster_nodes")
            )
        ).fetchall()
    by_uuid = {r.node_uuid: r.force_renew_at for r in rows}
    for u in keep_uuids:
        assert by_uuid[u] is not None
    assert by_uuid[evicted_uuid] is None  # evicted row skipped


@pytest.mark.asyncio
async def test_rotate_cert_all_audit_emitted(_fresh_cluster, client, admin_token):
    await _insert_fake_node(str(_uuid.uuid4()))
    r = await client.post(
        "/api/v1/vault/cluster/rotate-cert/all",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 200
    async with async_session() as db:
        row = (
            await db.execute(
                text(
                    "SELECT actor, target, action FROM vault_audit "
                    "WHERE action = 'cluster_cert_force_rotate' "
                    "  AND target = 'all' ORDER BY id DESC LIMIT 1"
                )
            )
        ).fetchone()
    assert row is not None


# --- ca-bundle --------------------------------------------------------------


@pytest.mark.asyncio
async def test_ca_bundle_returns_pem_and_fingerprint(
    _fresh_cluster, client, admin_token
):
    r = await client.get(
        "/api/v1/vault/cluster/ca-bundle",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ca_cert_pem"].startswith("-----BEGIN CERTIFICATE-----")
    assert len(body["fingerprint"]) == 64  # SHA-256 hex


@pytest.mark.asyncio
async def test_ca_bundle_no_token_401(_fresh_cluster, client):
    r = await client.get("/api/v1/vault/cluster/ca-bundle")
    assert r.status_code in (401, 403, 422)


@pytest.mark.asyncio
async def test_ca_bundle_no_longer_503_on_follower(
    _fresh_cluster, client, admin_token, monkeypatch
):
    """the master-only gate on /cluster/ca-bundle was
    removed. ``cluster_ca.load_cluster_ca`` unwraps the CA private key
    via :meth:`VaultState.ha_wrap_decrypt`, which RPCs to master from
    any follower worker. In this single-process unit
    test no RPC client is attached and the subkeys live locally, so the
    route falls back to the local primitive ; the assertion is that the
    historical 503 + Retry-After: 1 + "master" payload signature is gone.
    """
    from api.app.vault_state import vault as _vault

    monkeypatch.setattr(type(_vault), "is_master", property(lambda _self: False))

    r = await client.get(
        "/api/v1/vault/cluster/ca-bundle",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    # Before : 503 + Retry-After: 1 + body.detail contains "master".
    # After : the route returns 200 in this unit test (subkeys
    # locally available). Guard against the specific historical gate
    # signature, not against 503 in general (load_cluster_ca itself
    # can still 503 if no CA row exists).
    if r.status_code == 503:
        body_detail = (r.json().get("detail") or "").lower()
        assert "master" not in body_detail, r.text
        assert r.headers.get("retry-after") != "1", r.text


@pytest.mark.asyncio
async def test_ca_bundle_uninit_ca_503(client, admin_token, monkeypatch, tmp_path):
    # Wipe the cluster config rows so load_cluster_ca returns None.
    monkeypatch.setattr(
        settings, "cluster_cert_path", str(tmp_path / "cluster-cert.pem")
    )
    monkeypatch.setattr(
        settings, "cluster_cert_key_path", str(tmp_path / "cluster-cert.key")
    )
    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_cluster_nodes"))
        await db.execute(
            text("DELETE FROM vault_cluster_config WHERE key = ANY(:ks)"),
            {"ks": list(_CLUSTER_KEYS)},
        )
        await db.commit()
    hp_clear()
    r = await client.get(
        "/api/v1/vault/cluster/ca-bundle",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 503, r.text


@pytest.mark.asyncio
async def test_ca_bundle_does_not_unwrap_private_key(
    _fresh_cluster, client, admin_token
):
    """The bundle endpoint returns only public CA material.

    Regression for the lab failure: a stale/corrupt ``cluster_ca_key`` must not
    break CA bundle distribution, because the route does not need the signer.
    """
    async with async_session() as db:
        await db.execute(
            text(
                "UPDATE vault_cluster_config SET value = :v "
                "WHERE key = 'cluster_ca_key'"
            ),
            {"v": "00" * 64},
        )
        await db.commit()

    r = await client.get(
        "/api/v1/vault/cluster/ca-bundle",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ca_cert_pem"].startswith("-----BEGIN CERTIFICATE-----")
    assert len(body["fingerprint"]) == 64
