# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""post-close (2026-06-01) -- auto-promote signing gate.

Verifies that ``POST /cluster/issue-server-cert`` refuses to mint a
fresh server cert while ``PRIMARY_ELECTION_LOCK`` is held by another
session. Cf docs/HA-CLUSTER.md s15.3.

Scope note (2026-06-06) : the twin gate that bf3fe8d also wrapped
around ``POST /cluster/join`` was removed -- it serialised joins
behind the election lock and 503'd for the whole election/churn
window with no correctness benefit (the node cert is a pure identity
bundle that encodes no primary state ; the joining-row INSERT does
not race primary_uuid). Only the ``issue-server-cert`` gate remains,
which this test covers.
"""

import pytest
import pytest_asyncio
from api.app import cluster_membership
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
    "primary_lease_expires_at",
)


@pytest_asyncio.fixture
async def _fresh_cluster(tmp_path, monkeypatch, admin_token, client):
    """Init a cluster, isolated cert paths, wipe on teardown."""
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
        json={"cluster_name": "signing-gate-test"},
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


@pytest.mark.asyncio
async def test_issue_server_cert_503_when_lock_held(
    _fresh_cluster, client, admin_token
):
    """Election lock held in another session -> 503 + Retry-After: 5.

    The lock name reproduces the with_cluster_lock prefix
    (`rhorizon:cluster:` + PRIMARY_ELECTION_LOCK) so the gate
    composes with the manual /promote, /demote, /drain,
    /evict path.
    """
    lock_name = f"rhorizon:cluster:{cluster_membership.PRIMARY_ELECTION_LOCK}"

    # Acquire the lock in a separate session and HOLD it across the
    # route call. pg_advisory_xact_lock (the non-try variant) blocks
    # if held, but no one else holds it at this point so it succeeds.
    # The lock stays until we commit/rollback this session.
    async with async_session() as lock_holder:
        await lock_holder.execute(
            text("SELECT pg_advisory_xact_lock(hashtext(:n))"),
            {"n": lock_name},
        )

        r = await client.post(
            "/api/v1/vault/cluster/issue-server-cert",
            json={"san_ips": ["10.0.0.42"], "san_dns": []},
            headers={"Authorization": f"Bearer {admin_token}"},
        )

        await lock_holder.rollback()  # release the lock

    assert r.status_code == 503, r.text
    assert r.json() == {"detail": "election_in_progress"}
    assert r.headers.get("Retry-After") == "5"


@pytest.mark.asyncio
async def test_issue_server_cert_happy_path_no_lock(
    _fresh_cluster, client, admin_token
):
    """Sanity : without contention, the gate is transparent (200)."""
    r = await client.post(
        "/api/v1/vault/cluster/issue-server-cert",
        json={"san_ips": ["10.0.0.42"], "san_dns": []},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["server_cert_pem"].startswith("-----BEGIN CERTIFICATE-----")
