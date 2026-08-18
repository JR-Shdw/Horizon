# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""/cluster/join idempotency cache (bug D structural fix).

Coverage :

- Same nonce replay returns the identical cached payload (200), not a
  freshly minted divergent cert nor a 401 nonce-already-consumed.
- Cache row is persisted in vault_join_idempotency with response_json
  and expires_at = created_at + cluster_join_idempotency_ttl_secs.
- Cache hit increments rhorizon_cluster_join_idempotency_hits_total.
- Replay with mismatched node_uuid surfaces 401 (anti-theft).
- Replay with mismatched source_ip surfaces 401 (anti-theft, exercised
  via direct DB mutation of the cache row since the ASGI test client
  always reports 127.0.0.1).
- Replay after the cache row has expired falls back to the normal flow
  and is rejected 401 because the challenge was consumed at the first
  call (DELETE+RETURNING).
- Replay does not write a second audit row (the cache short-circuits
  every state-mutating step).
- Replay succeeds even when the membership row has already advanced
  past 'joining' -- this is the case (c) PermanentError path
  that the idempotency cache eliminates.
- The reaper purges expired idempotency rows.
- cluster_join_idempotency_ttl_secs is clamped to [60, 3600].
"""

import base64
import hashlib
import hmac as _hmac

import pytest
import pytest_asyncio
from api.app import ha_password as hp
from api.app import metrics as _metrics
from api.app import node_uuid as nu
from api.app.config import Settings, settings
from api.app.database import async_session
from sqlalchemy import text

_CLUSTER_CFG_KEYS = (
    "cluster_id",
    "ha_password_encrypted",
    "cluster_ca_cert",
    "cluster_ca_key",
    "primary_uuid",
    "primary_since",
)


def _compute_proof(
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
        await db.execute(text("DELETE FROM vault_join_idempotency"))
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
        json={"cluster_name": "test-sliceO"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    return (
        body["cluster_id"],
        base64.b64decode(body["ha_password"]),
        body["primary_uuid"],
    )


async def _get_challenge_meta(nonce: str) -> tuple[str, int]:
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
    return row.source_ip, int(row.issued_at.timestamp())


async def _challenge_and_proof(
    client, cluster_id: str, ha_password: bytes, node_uuid: str
) -> dict:
    cr = await client.post(
        "/api/v1/vault/cluster/challenge",
        json={"node_uuid": node_uuid, "rhorizon_version": "1.0.0"},
    )
    assert cr.status_code == 200, cr.text
    nonce = cr.json()["nonce"]
    source_ip, issued_at_epoch = await _get_challenge_meta(nonce)
    proof = _compute_proof(
        ha_password, cluster_id, node_uuid, source_ip, nonce, issued_at_epoch
    )
    return {
        "cluster_id": cluster_id,
        "node_uuid": node_uuid,
        "nonce": nonce,
        "ha_password_proof": proof,
        "rhorizon_version": "1.0.0",
    }


# ---------------------------------------------------------------------------
# Cache replay -- happy paths
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_replay_same_nonce_returns_identical_payload(
    admin_token, client, _wipe_cluster_state
):
    """The structural fix for bug D : a joiner that lost the previous
    wire response replays the same nonce and recovers the identical
    cert + wrapped key, not a fresh divergent mint.
    """
    cluster_id, ha_pw, _ = await _init_cluster(admin_token, client)
    node_uuid = "sliceO-replay-001"
    body = await _challenge_and_proof(client, cluster_id, ha_pw, node_uuid)
    r1 = await client.post("/api/v1/vault/cluster/join", json=body)
    assert r1.status_code == 200, r1.text
    r2 = await client.post("/api/v1/vault/cluster/join", json=body)
    assert r2.status_code == 200, r2.text
    # Byte-identical payload : same node_cert_pem and same wrapped key.
    # If the second call had hit the old refresh_joining_row path,
    # the cert would be re-minted with a fresh keypair (different bytes).
    assert r1.json() == r2.json()


@pytest.mark.asyncio
async def test_cache_row_persisted_after_join(admin_token, client, _wipe_cluster_state):
    cluster_id, ha_pw, _ = await _init_cluster(admin_token, client)
    node_uuid = "sliceO-persist-001"
    body = await _challenge_and_proof(client, cluster_id, ha_pw, node_uuid)
    r = await client.post("/api/v1/vault/cluster/join", json=body)
    assert r.status_code == 200, r.text
    async with async_session() as db:
        row = (
            await db.execute(
                text(
                    "SELECT nonce, node_uuid, source_ip, response_json, "
                    "       expires_at, created_at "
                    "FROM vault_join_idempotency WHERE nonce = :n"
                ),
                {"n": body["nonce"]},
            )
        ).fetchone()
    assert row is not None
    assert row.node_uuid == node_uuid
    assert row.source_ip  # non-empty
    # response_json is a serialisable representation of the returned body.
    assert '"node_cert_pem"' in row.response_json
    # TTL window matches the setting (with second-grain slack).
    delta = (row.expires_at - row.created_at).total_seconds()
    assert abs(delta - settings.cluster_join_idempotency_ttl_secs) < 2, (
        f"TTL drift {delta} vs {settings.cluster_join_idempotency_ttl_secs}"
    )


@pytest.mark.asyncio
async def test_replay_increments_cache_hits_metric(
    admin_token, client, _wipe_cluster_state
):
    cluster_id, ha_pw, _ = await _init_cluster(admin_token, client)
    node_uuid = "sliceO-metric-001"
    body = await _challenge_and_proof(client, cluster_id, ha_pw, node_uuid)
    before = _metrics.cluster_join_idempotency_hits._value.get()
    r1 = await client.post("/api/v1/vault/cluster/join", json=body)
    assert r1.status_code == 200
    # First call mints fresh, no hit.
    assert _metrics.cluster_join_idempotency_hits._value.get() == before
    r2 = await client.post("/api/v1/vault/cluster/join", json=body)
    assert r2.status_code == 200
    assert _metrics.cluster_join_idempotency_hits._value.get() == before + 1


# ---------------------------------------------------------------------------
# Cache replay -- binding mismatch (anti-theft)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_replay_binding_mismatch_uuid_rejected_401(
    admin_token, client, _wipe_cluster_state
):
    """Stolen nonce with the cached row's uuid swapped for a different
    one : the cache row exists but the binding fails, so we surface 401
    rather than serve the original joiner's cert to a different identity.
    """
    cluster_id, ha_pw, _ = await _init_cluster(admin_token, client)
    node_uuid = "sliceO-binding-uuid-001"
    body = await _challenge_and_proof(client, cluster_id, ha_pw, node_uuid)
    r1 = await client.post("/api/v1/vault/cluster/join", json=body)
    assert r1.status_code == 200
    body["node_uuid"] = "sliceO-binding-uuid-thief-002"
    r2 = await client.post("/api/v1/vault/cluster/join", json=body)
    assert r2.status_code == 401
    assert "binding mismatch" in r2.json()["detail"].lower()


@pytest.mark.asyncio
async def test_replay_binding_mismatch_ip_rejected_401(
    admin_token, client, _wipe_cluster_state
):
    """The ASGI client always reports 127.0.0.1, so we mutate the cache
    row's source_ip directly to simulate a stolen nonce being replayed
    from a different IP. The route compares the row's source_ip with
    the freshly observed get_client_ip() value at request time, so the
    mismatch surfaces 401.
    """
    cluster_id, ha_pw, _ = await _init_cluster(admin_token, client)
    node_uuid = "sliceO-binding-ip-001"
    body = await _challenge_and_proof(client, cluster_id, ha_pw, node_uuid)
    r1 = await client.post("/api/v1/vault/cluster/join", json=body)
    assert r1.status_code == 200
    async with async_session() as db:
        await db.execute(
            text(
                "UPDATE vault_join_idempotency SET source_ip = '10.0.0.99' "
                "WHERE nonce = :n"
            ),
            {"n": body["nonce"]},
        )
        await db.commit()
    r2 = await client.post("/api/v1/vault/cluster/join", json=body)
    assert r2.status_code == 401
    assert "binding mismatch" in r2.json()["detail"].lower()


# ---------------------------------------------------------------------------
# Cache replay -- TTL expiry
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_replay_after_cache_expiry_falls_back_and_is_rejected(
    admin_token, client, _wipe_cluster_state
):
    """Once the cache row has expired (expires_at < NOW), the SELECT
    misses, the flow proceeds to step 1, and DELETE+RETURNING returns
    nothing because the challenge was already consumed at the first
    call. The retry surfaces as 401 -- expected behavior outside the
    cache window.
    """
    cluster_id, ha_pw, _ = await _init_cluster(admin_token, client)
    node_uuid = "sliceO-ttl-expired-001"
    body = await _challenge_and_proof(client, cluster_id, ha_pw, node_uuid)
    r1 = await client.post("/api/v1/vault/cluster/join", json=body)
    assert r1.status_code == 200
    async with async_session() as db:
        await db.execute(
            text(
                "UPDATE vault_join_idempotency "
                "SET expires_at = NOW() - INTERVAL '1 second' "
                "WHERE nonce = :n"
            ),
            {"n": body["nonce"]},
        )
        await db.commit()
    r2 = await client.post("/api/v1/vault/cluster/join", json=body)
    assert r2.status_code == 401


# ---------------------------------------------------------------------------
# Audit interaction
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_replay_does_not_write_second_audit_row(
    admin_token, client, _wipe_cluster_state
):
    """Replay short-circuits before reaching log_action, so a single
    JOIN attempt that the joiner retries N times still produces one
    audit row -- not N rows that would look like N distinct JOIN events
    in the chain.
    """
    cluster_id, ha_pw, _ = await _init_cluster(admin_token, client)
    node_uuid = "sliceO-audit-001"
    body = await _challenge_and_proof(client, cluster_id, ha_pw, node_uuid)
    r1 = await client.post("/api/v1/vault/cluster/join", json=body)
    assert r1.status_code == 200
    async with async_session() as db:
        count_before = (
            await db.execute(
                text(
                    "SELECT COUNT(*) AS n FROM vault_audit "
                    "WHERE action IN ('cluster_join','cluster_join_retry') "
                    "  AND detail->>'node_uuid' = :u"
                ),
                {"u": node_uuid},
            )
        ).fetchone()
    assert count_before.n == 1
    r2 = await client.post("/api/v1/vault/cluster/join", json=body)
    assert r2.status_code == 200
    async with async_session() as db:
        count_after = (
            await db.execute(
                text(
                    "SELECT COUNT(*) AS n FROM vault_audit "
                    "WHERE action IN ('cluster_join','cluster_join_retry') "
                    "  AND detail->>'node_uuid' = :u"
                ),
                {"u": node_uuid},
            )
        ).fetchone()
    assert count_after.n == 1


# ---------------------------------------------------------------------------
# Case (c) elimination
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_replay_works_even_after_membership_advanced_past_joining(
    admin_token, client, _wipe_cluster_state
):
    """Case (c) : the previous attempt landed the row in
    'joining', the state-machine advanced it to 'secondary' before the
    retry arrived, the old joiner-side handler classified this as
    AutoJoinPermanentError + operator R1 hint. The idempotency cache
    eliminates this path entirely : the cache hit returns the original
    payload regardless of the row's current ha_state.
    """
    cluster_id, ha_pw, _ = await _init_cluster(admin_token, client)
    node_uuid = "sliceO-case-c-001"
    body = await _challenge_and_proof(client, cluster_id, ha_pw, node_uuid)
    r1 = await client.post("/api/v1/vault/cluster/join", json=body)
    assert r1.status_code == 200
    # Simulate the state-machine flipping the row past 'joining' between
    # the first JOIN and the retry.
    async with async_session() as db:
        await db.execute(
            text(
                "UPDATE vault_cluster_nodes SET ha_state = 'secondary', "
                "    quarantine_until = NULL WHERE node_uuid = :u"
            ),
            {"u": node_uuid},
        )
        await db.commit()
    r2 = await client.post("/api/v1/vault/cluster/join", json=body)
    assert r2.status_code == 200, r2.text
    # Same cached payload -- the joiner gets to persist its cert and
    # exit the JOIN loop without an R1 recovery.
    assert r2.json() == r1.json()


# ---------------------------------------------------------------------------
# Reaper
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_reaper_purges_expired_idempotency_rows(
    admin_token, client, _wipe_cluster_state
):
    """The reaper loop runs the same DELETE we exercise here. We invoke
    the DELETE directly rather than spinning the 5-min reaper task --
    the SQL is the contract under test.
    """
    cluster_id, ha_pw, _ = await _init_cluster(admin_token, client)
    node_uuid = "sliceO-reaper-001"
    body = await _challenge_and_proof(client, cluster_id, ha_pw, node_uuid)
    r = await client.post("/api/v1/vault/cluster/join", json=body)
    assert r.status_code == 200
    # Backdate the row past expiry.
    async with async_session() as db:
        await db.execute(
            text(
                "UPDATE vault_join_idempotency "
                "SET expires_at = NOW() - INTERVAL '1 hour' "
                "WHERE nonce = :n"
            ),
            {"n": body["nonce"]},
        )
        await db.commit()
    # Replay the reaper's purge SQL.
    async with async_session() as db:
        await db.execute(
            text("DELETE FROM vault_join_idempotency WHERE expires_at < NOW()")
        )
        await db.commit()
        remaining = (
            await db.execute(
                text(
                    "SELECT COUNT(*) AS n FROM vault_join_idempotency WHERE nonce = :n"
                ),
                {"n": body["nonce"]},
            )
        ).fetchone()
    assert remaining.n == 0


# ---------------------------------------------------------------------------
# Settings validator
# ---------------------------------------------------------------------------


def test_idempotency_ttl_setting_clamped_to_range():
    """60s floor / 3600s ceiling -- avoids accidental zero (no cache at
    all) and 24h+ (stale rows accumulating)."""

    def _ttl(v: int) -> int:
        return Settings(
            cluster_join_idempotency_ttl_secs=v
        ).cluster_join_idempotency_ttl_secs

    assert _ttl(0) == 60
    assert _ttl(10) == 60
    assert _ttl(300) == 300
    assert _ttl(99999) == 3600
