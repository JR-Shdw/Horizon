"""Tests for api/app/routes/cluster.py -- `GET /api/v1/vault/cluster`
topology endpoint.
"""

import pytest
from api.app.database import async_session
from api.app.vault_state import vault as vs
from sqlalchemy import text

# ---------------------------------------------------------------------------
# Integration tests for GET /cluster
# ---------------------------------------------------------------------------


@pytest.fixture
async def clean_workers(client, master_password):
    """Clears vault_workers and ensures the unsealed state before each test.

    An earlier test in the suite can leave the vault sealed (the 2FA tests in
    particular). Without this re-unseal, the admin_token cannot be validated
    and every /cluster call returns 503.
    """
    if vs.sealed:
        await client.post("/api/v1/vault/unseal", json={"password": master_password})
    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_workers"))
        await db.commit()
    yield
    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_workers"))
        await db.commit()


@pytest.mark.asyncio
async def test_cluster_topology_empty(client, admin_token, clean_workers):
    """No live workers -> structured response but empty hosts."""
    r = await client.get(
        "/api/v1/vault/cluster",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["hosts"] == {}
    assert body["held_cluster_locks"] == []
    assert "this_host" in body
    assert "this_pid" in body


@pytest.mark.asyncio
async def test_cluster_topology_with_master_and_follower(
    client, admin_token, clean_workers
):
    """Insert 1 master + 1 follower on the same host, check the grouping."""
    async with async_session() as db:
        await db.execute(
            text("""
                INSERT INTO vault_workers
                    (hostname, pid, worker_state, crypto_socket_name, socket_name,
                     last_heartbeat)
                VALUES
                    ('testhost', 1001, 'master',
                     '/run/rhorizon/crypto-ops-testhost.sock', NULL, NOW()),
                    ('testhost', 1002, 'follower',
                     NULL, '/run/rhorizon/share-testhost-1002.sock', NOW())
            """)
        )
        await db.commit()

    r = await client.get(
        "/api/v1/vault/cluster",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 200
    hosts = r.json()["hosts"]
    assert "testhost" in hosts
    assert hosts["testhost"]["master"] == {
        "pid": 1001,
        "age_sec": pytest.approx(0, abs=2),
    }
    assert len(hosts["testhost"]["followers"]) == 1
    f = hosts["testhost"]["followers"][0]
    assert f["pid"] == 1002
    assert f["worker_state"] == "follower"


@pytest.mark.asyncio
async def test_cluster_topology_filters_stale_workers(
    client, admin_token, clean_workers
):
    """A worker with heartbeat > 30s is filtered out (not in the response)."""
    async with async_session() as db:
        await db.execute(
            text("""
                INSERT INTO vault_workers
                    (hostname, pid, worker_state, crypto_socket_name, last_heartbeat)
                VALUES
                    ('fresh', 2001, 'master',
                     '/run/rhorizon/crypto-ops-fresh.sock', NOW()),
                    ('stale', 2002, 'master',
                     '/run/rhorizon/crypto-ops-stale.sock',
                     NOW() - INTERVAL '60 seconds')
            """)
        )
        await db.commit()

    r = await client.get(
        "/api/v1/vault/cluster",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    hosts = r.json()["hosts"]
    assert "fresh" in hosts
    assert "stale" not in hosts


@pytest.mark.asyncio
async def test_cluster_topology_does_not_promote_advisory_master_without_crypto(
    client, admin_token, clean_workers
):
    """A boot-time master claim is not operational until its crypto socket exists."""
    async with async_session() as db:
        await db.execute(
            text("""
                INSERT INTO vault_workers
                    (hostname, pid, worker_state, crypto_socket_name, last_heartbeat)
                VALUES
                    ('phantom', 2501, 'master', NULL, NOW())
            """)
        )
        await db.commit()

    r = await client.get(
        "/api/v1/vault/cluster",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    hosts = r.json()["hosts"]
    assert hosts["phantom"]["master"] is None
    assert hosts["phantom"]["followers"][0]["pid"] == 2501
    assert hosts["phantom"]["followers"][0]["worker_state"] == "master"


@pytest.mark.asyncio
async def test_cluster_topology_unknown_host_bucket(client, admin_token, clean_workers):
    """Worker with empty hostname falls into the 'unknown' bucket."""
    async with async_session() as db:
        # hostname is NOT NULL by schema, but an empty string is still
        # possible if $HOSTNAME was unset at registration -- the endpoint
        # coerces it to the 'unknown' bucket via `w.hostname or "unknown"`.
        await db.execute(
            text("""
                INSERT INTO vault_workers
                    (hostname, pid, worker_state, last_heartbeat)
                VALUES
                    ('', 3001, 'follower', NOW())
            """)
        )
        await db.commit()

    r = await client.get(
        "/api/v1/vault/cluster",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    hosts = r.json()["hosts"]
    assert "unknown" in hosts
    assert hosts["unknown"]["master"] is None
    assert len(hosts["unknown"]["followers"]) == 1


@pytest.mark.asyncio
async def test_cluster_topology_max_age_tracks_oldest(
    client, admin_token, clean_workers
):
    """max_age_sec of a host = age of the oldest worker (always <30s)."""
    async with async_session() as db:
        await db.execute(
            text("""
                INSERT INTO vault_workers
                    (hostname, pid, worker_state, crypto_socket_name, last_heartbeat)
                VALUES
                    ('h1', 4001, 'master',
                     '/run/rhorizon/crypto-ops-h1.sock', NOW()),
                    ('h1', 4002, 'follower',
                     '/run/rhorizon/crypto-ops-h1.sock',
                     NOW() - INTERVAL '20 seconds')
            """)
        )
        await db.commit()

    r = await client.get(
        "/api/v1/vault/cluster",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    h1 = r.json()["hosts"]["h1"]
    assert h1["max_age_sec"] >= 19.0
