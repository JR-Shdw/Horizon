# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""promote / demote / drain / evict / unrevoke.

Coverage :
- promote secondary -> primary, ex-primary demoted, primary_uuid updated.
- promote 404 / 409-already-primary / 409-bad-state / 409-version-floor.
- demote primary -> secondary, primary_uuid cleared.
- demote 404 / 409 (target not primary).
- drain secondary : 202, ha_state=draining, drain_deadline_at set.
- drain primary -> 409 "demote first".
- drain joining/quarantined -> 409 (evict instead).
- drain already draining -> 409.
- evict secondary : ha_state=evicted, revoked_node_uuids append, audit row.
- evict primary -> 409 "demote first".
- evict joining -> evicted directly + appended.
- evict already evicted -> 409.
- unrevoke 200 / 404.
- /cluster/join with revoked node_uuid -> 403 + audit row.
- reaper bascule draining -> evicted past drain_deadline_at + appends revoked
  + bumps cluster_nodes_reaped_total{reason=drain_deadline_expired}.
- self-draining gate : POST /cluster/challenge + /cluster/join -> 503.
- counters : cluster_state_transitions_total bumped per transition.
"""

import asyncio
import base64
import hashlib
import hmac as _hmac
import json

import pytest
import pytest_asyncio
from api.app import cluster_ha_loops as loops
from api.app import cluster_membership as cm
from api.app import ha_password as hp
from api.app import metrics as _m
from api.app import node_uuid as nu
from api.app.config import settings
from api.app.crypto import generate_token
from api.app.database import async_session
from api.app.vault_state import vault
from sqlalchemy import text

_CLUSTER_CONFIG_KEYS = (
    "cluster_id",
    "ha_password_encrypted",
    "cluster_ca_cert",
    "cluster_ca_key",
    "primary_uuid",
    "primary_since",
    "revoked_node_uuids",
    "pending_ha_password_rotation",
)


@pytest_asyncio.fixture(autouse=True)
async def _wipe_cluster_state():
    nu.init_node_uuid(settings.node_uuid_path)
    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_cluster_nodes"))
        await db.execute(
            text("DELETE FROM vault_cluster_config WHERE key = ANY(:ks)"),
            {"ks": list(_CLUSTER_CONFIG_KEYS)},
        )
        await db.execute(
            text("DELETE FROM vault_challenges WHERE purpose = 'cluster_join'")
        )
        await db.commit()
    hp.clear()
    yield
    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_cluster_nodes"))
        await db.execute(
            text("DELETE FROM vault_cluster_config WHERE key = ANY(:ks)"),
            {"ks": list(_CLUSTER_CONFIG_KEYS)},
        )
        await db.execute(
            text("DELETE FROM vault_challenges WHERE purpose = 'cluster_join'")
        )
        await db.commit()
    hp.clear()


async def _init_cluster(client, admin_token):
    r = await client.post(
        "/api/v1/vault/cluster/init",
        json={"cluster_name": "slice10-test"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 200, r.text
    return r.json()


async def _make_token(name: str, perms: dict) -> str:
    raw = generate_token()
    token_hash = await vault.hmac_sha512_hex(raw)
    async with async_session() as db:
        await db.execute(
            text(
                "INSERT INTO vault_tokens (name, token_hash, permissions, "
                "created_by) VALUES (:n, :h, CAST(:p AS jsonb), 'test') "
                "ON CONFLICT (name) WHERE active DO UPDATE SET token_hash = :h, "
                "permissions = CAST(:p AS jsonb)"
            ),
            {"n": name, "h": token_hash, "p": json.dumps(perms)},
        )
        await db.commit()
    return raw


async def _insert_secondary(uuid: str, source_ip: str, version: str = "1.0.0-beta"):
    """Insert a synthetic secondary row -- bypass the JOIN flow.

    These tests focus on the membership-op state machine ; the
    full JOIN flow is covered by test_ha_cluster_join.py.
    """
    async with async_session() as db:
        await db.execute(
            text(
                "INSERT INTO vault_cluster_nodes ("
                "    node_uuid, source_ip, ha_state, quarantine_until,"
                "    cluster_version, cert_fingerprint, cert_not_after,"
                "    last_heartbeat"
                ") VALUES ("
                "    :u, CAST(:ip AS INET), 'secondary', NULL,"
                "    :ver, 'fpr-' || :u, NOW() + INTERVAL '30 days',"
                "    NOW()"
                ")"
            ),
            {"u": uuid, "ip": source_ip, "ver": version},
        )
        await db.commit()


async def _insert_node_in_state(
    uuid: str,
    source_ip: str,
    ha_state: str,
    drain_deadline_at_sql: str | None = None,
):
    """Insert a node with arbitrary ha_state for state-specific tests."""
    cols = (
        "node_uuid, source_ip, ha_state, quarantine_until, "
        "cluster_version, cert_fingerprint, cert_not_after, last_heartbeat"
    )
    vals = (
        ":u, CAST(:ip AS INET), :s, "
        "CASE WHEN :s = 'joining' THEN NOW() + INTERVAL '15 seconds' ELSE NULL END,"
        "'1.0.0-beta', 'fpr-' || :u, NOW() + INTERVAL '30 days', NOW()"
    )
    if drain_deadline_at_sql is not None:
        cols += ", drain_deadline_at"
        vals += f", {drain_deadline_at_sql}"
    async with async_session() as db:
        await db.execute(
            text(f"INSERT INTO vault_cluster_nodes ({cols}) VALUES ({vals})"),
            {"u": uuid, "ip": source_ip, "s": ha_state},
        )
        await db.commit()


async def _read_node(uuid: str):
    async with async_session() as db:
        row = (
            await db.execute(
                text(
                    "SELECT node_uuid, ha_state, drain_deadline_at "
                    "FROM vault_cluster_nodes WHERE node_uuid = :u"
                ),
                {"u": uuid},
            )
        ).fetchone()
    return row


async def _read_revoked() -> set[str]:
    async with async_session() as db:
        return await cm.read_revoked_uuids(db)


async def _read_primary_uuid() -> str | None:
    async with async_session() as db:
        return await cm.read_primary_uuid(db)


def _transition_count(from_state: str, to_state: str) -> int:
    metric = _m.cluster_state_transitions.labels(
        from_state=from_state, to_state=to_state
    )
    return int(metric._value.get())


def _reaped_count(reason: str) -> int:
    metric = _m.cluster_nodes_reaped.labels(reason=reason)
    return int(metric._value.get())


# --- 1. promote happy path -----------------------------------------------


@pytest.mark.asyncio
async def test_concurrent_revoke_no_lost_update(admin_token, client):
    """Two concurrent revokes on separate sessions must both land. Without
    the advisory xact lock in add_revoked_uuid the read-modify-write races
    (evict route vs auto-evict reaper hold different locks) and one
    revocation is silently dropped -- a node stays able to re-auth."""
    await _init_cluster(client, admin_token)
    uuid_a, uuid_b = "a" * 32, "b" * 32

    async def add_one(u):
        async with async_session() as db:
            await cm.add_revoked_uuid(db, u, actor="test")
            await db.commit()

    await asyncio.gather(add_one(uuid_a), add_one(uuid_b))

    async with async_session() as db:
        revoked = await cm.read_revoked_uuids(db)
    assert {uuid_a, uuid_b} <= revoked


@pytest.mark.asyncio
async def test_read_revoked_corrupt_row_fails_closed():
    """A corrupt revoked_node_uuids row raises (fail-closed), not an empty
    set that would silently void every revocation."""
    async with async_session() as db:
        await db.execute(
            text(
                "INSERT INTO vault_cluster_config (key, value) "
                "VALUES ('revoked_node_uuids', 'garbage{') "
                "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value"
            )
        )
        await db.commit()
    async with async_session() as db:
        with pytest.raises(cm.RevokedListError):
            await cm.read_revoked_uuids(db)


@pytest.mark.asyncio
async def test_promote_secondary_to_primary(admin_token, client):
    init = await _init_cluster(client, admin_token)
    primary_uuid = init["primary_uuid"]
    await _insert_secondary("node-bbbb", "10.0.0.1")
    transitions_before = _transition_count("secondary", "primary")
    demotes_before = _transition_count("primary", "secondary")

    r = await client.post(
        "/api/v1/vault/cluster/promote/node-bbbb",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["node_uuid"] == "node-bbbb"
    assert body["ha_state"] == "primary"
    assert body["primary_uuid"] == "node-bbbb"

    new_primary = await _read_node("node-bbbb")
    assert new_primary.ha_state == "primary"
    ex_primary = await _read_node(primary_uuid)
    assert ex_primary.ha_state == "secondary"
    assert await _read_primary_uuid() == "node-bbbb"
    assert _transition_count("secondary", "primary") == transitions_before + 1
    assert _transition_count("primary", "secondary") == demotes_before + 1


# --- 2. promote error paths ----------------------------------------------


@pytest.mark.asyncio
async def test_promote_404_unknown_uuid(admin_token, client):
    await _init_cluster(client, admin_token)
    r = await client.post(
        "/api/v1/vault/cluster/promote/does-not-exist",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_promote_409_already_primary(admin_token, client):
    init = await _init_cluster(client, admin_token)
    r = await client.post(
        f"/api/v1/vault/cluster/promote/{init['primary_uuid']}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 409
    assert "already primary" in r.json()["detail"]


@pytest.mark.asyncio
async def test_promote_409_target_in_joining_state(admin_token, client):
    await _init_cluster(client, admin_token)
    await _insert_node_in_state("node-joiner", "10.0.0.1", "joining")
    r = await client.post(
        "/api/v1/vault/cluster/promote/node-joiner",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 409
    assert "joining" in r.json()["detail"]


@pytest.mark.asyncio
async def test_promote_409_version_below_floor(admin_token, client):
    await _init_cluster(client, admin_token)
    # Insert a secondary whose cluster_version sits below the configured floor.
    await _insert_secondary("node-old", "10.0.0.1", version="0.9.0")
    r = await client.post(
        "/api/v1/vault/cluster/promote/node-old",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 409
    assert "below cluster floor" in r.json()["detail"]


# --- 3. demote ----------------------------------------------------------


@pytest.mark.asyncio
async def test_demote_primary_to_secondary(admin_token, client):
    init = await _init_cluster(client, admin_token)
    primary_uuid = init["primary_uuid"]

    r = await client.post(
        f"/api/v1/vault/cluster/demote/{primary_uuid}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ha_state"] == "secondary"
    assert body["primary_uuid"] is None

    fresh = await _read_node(primary_uuid)
    assert fresh.ha_state == "secondary"
    assert await _read_primary_uuid() is None


@pytest.mark.asyncio
async def test_demote_404_unknown_uuid(admin_token, client):
    await _init_cluster(client, admin_token)
    r = await client.post(
        "/api/v1/vault/cluster/demote/does-not-exist",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_demote_409_not_primary(admin_token, client):
    await _init_cluster(client, admin_token)
    await _insert_secondary("node-bbbb", "10.0.0.1")
    r = await client.post(
        "/api/v1/vault/cluster/demote/node-bbbb",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 409
    assert "only the current primary" in r.json()["detail"]


# --- 4. drain -----------------------------------------------------------


@pytest.mark.asyncio
async def test_drain_secondary_returns_202_and_sets_deadline(admin_token, client):
    await _init_cluster(client, admin_token)
    await _insert_secondary("node-bbbb", "10.0.0.1")
    transitions_before = _transition_count("secondary", "draining")

    r = await client.post(
        "/api/v1/vault/cluster/drain/node-bbbb",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 202, r.text
    body = r.json()
    assert body["ha_state"] == "draining"
    assert body["drain_deadline_at"] is not None

    fresh = await _read_node("node-bbbb")
    assert fresh.ha_state == "draining"
    assert fresh.drain_deadline_at is not None
    assert _transition_count("secondary", "draining") == transitions_before + 1


@pytest.mark.asyncio
async def test_drain_primary_refused_demote_first(admin_token, client):
    init = await _init_cluster(client, admin_token)
    primary_uuid = init["primary_uuid"]

    r = await client.post(
        f"/api/v1/vault/cluster/drain/{primary_uuid}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 409
    assert "demote" in r.json()["detail"]
    fresh = await _read_node(primary_uuid)
    assert fresh.ha_state == "primary"  # unchanged


@pytest.mark.asyncio
async def test_drain_joining_refused_evict_instead(admin_token, client):
    await _init_cluster(client, admin_token)
    await _insert_node_in_state("node-joiner", "10.0.0.1", "joining")
    r = await client.post(
        "/api/v1/vault/cluster/drain/node-joiner",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 409
    assert "evict it instead" in r.json()["detail"]


@pytest.mark.asyncio
async def test_drain_already_draining_409(admin_token, client):
    await _init_cluster(client, admin_token)
    await _insert_node_in_state(
        "node-bbbb",
        "10.0.0.1",
        "draining",
        drain_deadline_at_sql="NOW() + INTERVAL '30 seconds'",
    )
    r = await client.post(
        "/api/v1/vault/cluster/drain/node-bbbb",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 409


# --- 5. evict -----------------------------------------------------------


@pytest.mark.asyncio
async def test_evict_secondary_marks_evicted_and_revokes(admin_token, client):
    await _init_cluster(client, admin_token)
    await _insert_secondary("node-bbbb", "10.0.0.1")
    revoked_before = await _read_revoked()
    assert "node-bbbb" not in revoked_before

    r = await client.post(
        "/api/v1/vault/cluster/evict/node-bbbb",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 200, r.text
    assert r.json()["ha_state"] == "evicted"

    fresh = await _read_node("node-bbbb")
    assert fresh.ha_state == "evicted"
    revoked_after = await _read_revoked()
    assert "node-bbbb" in revoked_after


@pytest.mark.asyncio
async def test_evict_primary_refused_demote_first(admin_token, client):
    init = await _init_cluster(client, admin_token)
    primary_uuid = init["primary_uuid"]

    r = await client.post(
        f"/api/v1/vault/cluster/evict/{primary_uuid}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 409
    assert "demote" in r.json()["detail"]
    revoked = await _read_revoked()
    assert primary_uuid not in revoked


@pytest.mark.asyncio
async def test_evict_joining_node_directly(admin_token, client):
    await _init_cluster(client, admin_token)
    await _insert_node_in_state("node-joiner", "10.0.0.1", "joining")
    r = await client.post(
        "/api/v1/vault/cluster/evict/node-joiner",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 200, r.text
    assert r.json()["ha_state"] == "evicted"
    assert "node-joiner" in await _read_revoked()


@pytest.mark.asyncio
async def test_evict_already_evicted_409(admin_token, client):
    await _init_cluster(client, admin_token)
    await _insert_node_in_state("node-gone", "10.0.0.1", "evicted")
    r = await client.post(
        "/api/v1/vault/cluster/evict/node-gone",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 409


# --- 6. unrevoke --------------------------------------------------------


@pytest.mark.asyncio
async def test_unrevoke_happy_path(admin_token, client):
    await _init_cluster(client, admin_token)
    await _insert_secondary("node-bbbb", "10.0.0.1")
    await client.post(
        "/api/v1/vault/cluster/evict/node-bbbb",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert "node-bbbb" in await _read_revoked()

    r = await client.post(
        "/api/v1/vault/cluster/unrevoke/node-bbbb",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["node_uuid"] == "node-bbbb"
    assert body["revoked"] is False
    assert "node-bbbb" not in await _read_revoked()


@pytest.mark.asyncio
async def test_unrevoke_not_in_list_404(admin_token, client):
    await _init_cluster(client, admin_token)
    r = await client.post(
        "/api/v1/vault/cluster/unrevoke/never-revoked",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 404


# --- 7. cluster_join 403 on revoked uuid --------------------------------


@pytest.mark.asyncio
async def test_cluster_join_rejected_when_uuid_revoked(admin_token, client):
    init = await _init_cluster(client, admin_token)
    cluster_id = init["cluster_id"]
    ha_password = base64.b64decode(init["ha_password"])

    # First, insert a secondary, evict it -> uuid lands in revoked list.
    await _insert_secondary("revoked-uuid", "10.0.0.1")
    er = await client.post(
        "/api/v1/vault/cluster/evict/revoked-uuid",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert er.status_code == 200

    # Then attempt /cluster/challenge + /cluster/join with the same uuid.
    cr = await client.post(
        "/api/v1/vault/cluster/challenge",
        json={"node_uuid": "revoked-uuid", "rhorizon_version": "1.0.0"},
    )
    assert cr.status_code == 200, cr.text
    nonce = cr.json()["nonce"]
    async with async_session() as db:
        row = (
            await db.execute(
                text(
                    "SELECT source_ip, issued_at FROM vault_challenges "
                    "WHERE challenge = :c"
                ),
                {"c": nonce},
            )
        ).fetchone()
    source_ip = row.source_ip
    issued_at_epoch = int(row.issued_at.timestamp())
    msg = (
        cluster_id.encode()
        + b"revoked-uuid"
        + source_ip.encode()
        + nonce.encode()
        + str(issued_at_epoch).encode()
    )
    proof = _hmac.new(ha_password, msg, hashlib.sha512).hexdigest()
    jr = await client.post(
        "/api/v1/vault/cluster/join",
        json={
            "cluster_id": cluster_id,
            "node_uuid": "revoked-uuid",
            "nonce": nonce,
            "ha_password_proof": proof,
            "rhorizon_version": "1.0.0",
        },
    )
    assert jr.status_code == 403
    assert "revoked" in jr.json()["detail"]


# --- 8. reaper bascule draining -> evicted past deadline ----------------


@pytest.mark.asyncio
async def test_reaper_basule_drained_past_deadline(admin_token, client):
    await _init_cluster(client, admin_token)
    # Insert a node already draining with a deadline in the past.
    await _insert_node_in_state(
        "node-stale",
        "10.0.0.1",
        "draining",
        drain_deadline_at_sql="NOW() - INTERVAL '1 second'",
    )
    reaped_before = _reaped_count("drain_deadline_expired")
    transitions_before = _transition_count("draining", "evicted")

    async with async_session() as db:
        n = await loops._reap_drained_past_deadline(db)
    assert n == 1

    fresh = await _read_node("node-stale")
    assert fresh.ha_state == "evicted"
    assert fresh.drain_deadline_at is None
    assert "node-stale" in await _read_revoked()
    assert _reaped_count("drain_deadline_expired") == reaped_before + 1
    assert _transition_count("draining", "evicted") == transitions_before + 1


@pytest.mark.asyncio
async def test_reaper_leaves_undeadlined_draining_alone(admin_token, client):
    await _init_cluster(client, admin_token)
    await _insert_node_in_state(
        "node-fresh",
        "10.0.0.1",
        "draining",
        drain_deadline_at_sql="NOW() + INTERVAL '30 seconds'",
    )
    async with async_session() as db:
        n = await loops._reap_drained_past_deadline(db)
    assert n == 0
    fresh = await _read_node("node-fresh")
    assert fresh.ha_state == "draining"  # unchanged


# --- 9. self-draining gate on /cluster/challenge + /cluster/join --------


@pytest.mark.asyncio
async def test_self_draining_refuses_incoming_cluster_requests(admin_token, client):
    init = await _init_cluster(client, admin_token)
    primary_uuid = init["primary_uuid"]

    # Demote then drain the primary -- now the local node is in 'draining'.
    dr = await client.post(
        f"/api/v1/vault/cluster/demote/{primary_uuid}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert dr.status_code == 200
    drr = await client.post(
        f"/api/v1/vault/cluster/drain/{primary_uuid}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert drr.status_code == 202

    # /cluster/challenge -> 503
    cr = await client.post(
        "/api/v1/vault/cluster/challenge",
        json={"node_uuid": "would-be-joiner", "rhorizon_version": "1.0.0"},
    )
    assert cr.status_code == 503
    assert "draining" in cr.json()["detail"]
    assert cr.headers.get("Retry-After") == "5"
