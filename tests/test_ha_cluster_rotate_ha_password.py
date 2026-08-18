# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""POST /cluster/rotate-ha-password (two-phase).

Coverage :
- stage records a meta row (no plaintext at rest) ; old HMAC still verifies.
- confirm rotates the password, returns plaintext once, swaps RAM cache.
- cancel drops the pending row without minting a new password.
- replay guards : stage twice -> 409, confirm without stage -> 409,
  cancel without stage -> 404.
- GET status reflects the pending row presence.
- cert independence : vault_cluster_nodes.cert_fingerprint untouched.
- /cluster/join Q2 enforcement : pre-rotation HMAC -> 401, post-rotation
  HMAC -> accepted.
- expired/corrupt pending rows: route returns 410; reaper helper purges safely.
- auth gates : admin:w for stage/confirm/cancel, admin:r for GET.
- seal/unseal cycle preserves the pending row (TEXT column survives).
- metric outcomes bumped on each exit path.
"""

import base64
import hashlib
import hmac as _hmac
import json

import pytest
import pytest_asyncio
from api.app import ha_password as hp
from api.app import metrics as _m
from api.app import node_uuid as nu
from api.app.config import settings
from api.app.crypto import generate_token
from api.app.database import async_session
from api.app.vault_state import vault
from sqlalchemy import text

_CLUSTER_CFG_KEYS = (
    "cluster_id",
    "ha_password_encrypted",
    "cluster_ca_cert",
    "cluster_ca_key",
    "primary_uuid",
    "primary_since",
    "pending_ha_password_rotation",
)


async def _wipe_state():
    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_cluster_nodes"))
        await db.execute(
            text("DELETE FROM vault_cluster_config WHERE key = ANY(:ks)"),
            {"ks": list(_CLUSTER_CFG_KEYS)},
        )
        await db.execute(
            text("DELETE FROM vault_challenges WHERE purpose = 'cluster_join'")
        )
        await db.commit()
    hp.clear()


@pytest_asyncio.fixture(autouse=True)
async def _wipe_cluster_state():
    nu.init_node_uuid(settings.node_uuid_path)
    await _wipe_state()
    yield
    await _wipe_state()


async def _init_cluster(admin_token, client) -> tuple[str, bytes, str]:
    r = await client.post(
        "/api/v1/vault/cluster/init",
        json={"cluster_name": "slice9-test"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    return (
        body["cluster_id"],
        base64.b64decode(body["ha_password"]),
        body["primary_uuid"],
    )


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


def _compute_proof(
    ha_password: bytes,
    cluster_id: str,
    node_uuid: str,
    source_ip: str,
    nonce: str,
    issued_at_epoch: int,
) -> str:
    """Replay the canonical HMAC message the /cluster/join layer recomputes."""
    msg = (
        cluster_id.encode()
        + node_uuid.encode()
        + source_ip.encode()
        + nonce.encode()
        + str(issued_at_epoch).encode()
    )
    return _hmac.new(ha_password, msg, hashlib.sha512).hexdigest()


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


async def _read_pending() -> dict | None:
    async with async_session() as db:
        row = (
            await db.execute(
                text(
                    "SELECT value FROM vault_cluster_config "
                    "WHERE key = 'pending_ha_password_rotation'"
                )
            )
        ).fetchone()
    return json.loads(row.value) if row else None


def _counter_value(outcome: str) -> int:
    metric = _m.cluster_ha_password_rotations.labels(outcome=outcome)
    return int(metric._value.get())


# --- 1. stage records meta row, no at-rest plaintext, old HMAC still works


@pytest.mark.asyncio
async def test_stage_records_meta_row(admin_token, client):
    cluster_id, ha_pw, _ = await _init_cluster(admin_token, client)
    before = _counter_value("staged")

    r = await client.post(
        "/api/v1/vault/cluster/rotate-ha-password/stage",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["staged_by"] == "test-admin"
    assert body["staged_at"]
    assert body["expires_at"]
    assert body["expires_at"] > body["staged_at"]

    pending = await _read_pending()
    assert pending is not None
    assert pending["staged_by"] == "test-admin"
    # The pending row carries metadata only -- no encrypted plaintext.
    assert set(pending.keys()) == {"staged_by", "staged_at", "expires_at"}

    # Pre-rotation HMAC primitive still verifies against the live password.
    hex_digest = await vault.ha_password_hmac(b"slice9-probe")
    expected = _hmac.new(ha_pw, b"slice9-probe", hashlib.sha512).hexdigest()
    assert hex_digest == expected

    assert _counter_value("staged") == before + 1


# --- 2. confirm rotates, returns plaintext once, swaps RAM cache


@pytest.mark.asyncio
async def test_confirm_rotates_and_returns_plaintext_once(admin_token, client):
    cluster_id, old_ha_pw, _ = await _init_cluster(admin_token, client)
    s = await client.post(
        "/api/v1/vault/cluster/rotate-ha-password/stage",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert s.status_code == 201

    before_confirm = _counter_value("confirmed")
    c = await client.post(
        "/api/v1/vault/cluster/rotate-ha-password/confirm",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert c.status_code == 200, c.text
    body = c.json()
    assert "ha_password" in body
    assert body["rotated_at"]
    assert "shown only this once" in body["warning"]
    new_ha_pw = base64.b64decode(body["ha_password"])
    assert len(new_ha_pw) == 32
    assert new_ha_pw != old_ha_pw

    # Pending row dropped.
    assert await _read_pending() is None

    # RAM cache reflects the new password. NEW HMAC verifies, OLD does not.
    probe = b"slice9-confirm-probe"
    server_hmac = await vault.ha_password_hmac(probe)
    new_expected = _hmac.new(new_ha_pw, probe, hashlib.sha512).hexdigest()
    old_expected = _hmac.new(old_ha_pw, probe, hashlib.sha512).hexdigest()
    assert server_hmac == new_expected
    assert server_hmac != old_expected

    assert _counter_value("confirmed") == before_confirm + 1


# --- 3. stage twice -> 409


@pytest.mark.asyncio
async def test_stage_twice_returns_409(admin_token, client):
    await _init_cluster(admin_token, client)
    r1 = await client.post(
        "/api/v1/vault/cluster/rotate-ha-password/stage",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r1.status_code == 201
    r2 = await client.post(
        "/api/v1/vault/cluster/rotate-ha-password/stage",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r2.status_code == 409
    detail = r2.json()["detail"]
    assert detail["error"] == "rotation already pending"
    assert detail["pending"]["staged_by"] == "test-admin"


# --- 4. confirm without stage -> 409


@pytest.mark.asyncio
async def test_confirm_without_stage_returns_409(admin_token, client):
    await _init_cluster(admin_token, client)
    r = await client.post(
        "/api/v1/vault/cluster/rotate-ha-password/confirm",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 409
    assert "no pending rotation" in r.json()["detail"]


# --- 5. cancel after stage -> 204, then stage works again


@pytest.mark.asyncio
async def test_cancel_then_restage(admin_token, client):
    await _init_cluster(admin_token, client)
    s1 = await client.post(
        "/api/v1/vault/cluster/rotate-ha-password/stage",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert s1.status_code == 201

    before = _counter_value("cancelled")
    c = await client.post(
        "/api/v1/vault/cluster/rotate-ha-password/cancel",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert c.status_code == 204
    assert _counter_value("cancelled") == before + 1
    assert await _read_pending() is None

    s2 = await client.post(
        "/api/v1/vault/cluster/rotate-ha-password/stage",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert s2.status_code == 201


# --- 6. cancel without stage -> 404


@pytest.mark.asyncio
async def test_cancel_without_stage_returns_404(admin_token, client):
    await _init_cluster(admin_token, client)
    r = await client.post(
        "/api/v1/vault/cluster/rotate-ha-password/cancel",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 404


# --- 7. get with pending row


@pytest.mark.asyncio
async def test_get_with_pending(admin_token, client):
    await _init_cluster(admin_token, client)
    await client.post(
        "/api/v1/vault/cluster/rotate-ha-password/stage",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    r = await client.get(
        "/api/v1/vault/cluster/rotate-ha-password",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["pending"] is not None
    assert body["pending"]["staged_by"] == "test-admin"
    assert body["pending"]["expires_at"] > body["pending"]["staged_at"]


# --- 8. get without pending row


@pytest.mark.asyncio
async def test_get_without_pending(admin_token, client):
    await _init_cluster(admin_token, client)
    r = await client.get(
        "/api/v1/vault/cluster/rotate-ha-password",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 200
    assert r.json() == {"pending": None}


# --- 9. cert independence


@pytest.mark.asyncio
async def test_confirm_preserves_node_cert_fingerprint(admin_token, client):
    _, _, primary_uuid = await _init_cluster(admin_token, client)
    async with async_session() as db:
        fpr_before = (
            await db.execute(
                text(
                    "SELECT cert_fingerprint FROM vault_cluster_nodes "
                    "WHERE node_uuid = :u"
                ),
                {"u": primary_uuid},
            )
        ).scalar_one()

    await client.post(
        "/api/v1/vault/cluster/rotate-ha-password/stage",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    c = await client.post(
        "/api/v1/vault/cluster/rotate-ha-password/confirm",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert c.status_code == 200

    async with async_session() as db:
        fpr_after = (
            await db.execute(
                text(
                    "SELECT cert_fingerprint FROM vault_cluster_nodes "
                    "WHERE node_uuid = :u"
                ),
                {"u": primary_uuid},
            )
        ).scalar_one()
    assert fpr_after == fpr_before


# --- 10. JOIN with HMAC computed pre-rotation -> 401 after confirm


@pytest.mark.asyncio
async def test_join_with_pre_rotation_proof_rejected(admin_token, client):
    cluster_id, old_ha_pw, _ = await _init_cluster(admin_token, client)
    node_uuid = "slice9-stale-joiner"
    # Compute the proof now, against the OLD password.
    body = await _challenge_and_proof(client, cluster_id, old_ha_pw, node_uuid)

    # Rotate the password between challenge and the JOIN attempt.
    await client.post(
        "/api/v1/vault/cluster/rotate-ha-password/stage",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    await client.post(
        "/api/v1/vault/cluster/rotate-ha-password/confirm",
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    r = await client.post("/api/v1/vault/cluster/join", json=body)
    # Q2 enforcement : no grace window. Stale proof is rejected.
    assert r.status_code == 401
    assert "proof" in r.json()["detail"].lower()


# --- 11. JOIN with HMAC computed post-rotation -> accepted


@pytest.mark.asyncio
async def test_join_with_post_rotation_proof_accepted(admin_token, client):
    cluster_id, _old_ha_pw, _ = await _init_cluster(admin_token, client)

    await client.post(
        "/api/v1/vault/cluster/rotate-ha-password/stage",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    c = await client.post(
        "/api/v1/vault/cluster/rotate-ha-password/confirm",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert c.status_code == 200
    new_ha_pw = base64.b64decode(c.json()["ha_password"])

    body = await _challenge_and_proof(
        client, cluster_id, new_ha_pw, "slice9-fresh-joiner"
    )
    r = await client.post("/api/v1/vault/cluster/join", json=body)
    assert r.status_code == 200, r.text
    assert r.json()["accepted"] is True


# --- 12. expired pending row : route returns 410 + reaper SQL purges


@pytest.mark.asyncio
async def test_expired_pending_route_returns_410_and_reaper_purges(admin_token, client):
    await _init_cluster(admin_token, client)
    await client.post(
        "/api/v1/vault/cluster/rotate-ha-password/stage",
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    # Backdate expires_at to the past. Mirrors the reaper-then-confirm
    # race window where a row passes its TTL between two confirm
    # attempts (or before the reaper picks it up).
    async with async_session() as db:
        await db.execute(
            text(
                "UPDATE vault_cluster_config "
                "SET value = jsonb_set("
                "    jsonb_set("
                "        value::jsonb, '{staged_at}',"
                "        to_jsonb((NOW() - INTERVAL '1 hour')::text)"
                "    ),"
                "    '{expires_at}',"
                "    to_jsonb((NOW() - INTERVAL '5 seconds')::text)"
                ")::text "
                "WHERE key = 'pending_ha_password_rotation'"
            )
        )
        await db.commit()

    # Route layer surfaces the expired state as 410 Gone.
    r = await client.post(
        "/api/v1/vault/cluster/rotate-ha-password/confirm",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 410
    assert "expired" in r.json()["detail"]

    # Run the real reaper helper -- the row must be eligible for purge.
    from api.app.main import _purge_pending_ha_password_rotation

    async with async_session() as db:
        outcome = await _purge_pending_ha_password_rotation(db)
        await db.commit()
    assert outcome == "expired"
    assert await _read_pending() is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("value", "error_type"),
    [
        ("not-json", "JSONDecodeError"),
        (
            json.dumps({"expires_at": "2099-01-01T00:00:00+00:00"}),
            "KeyError",
        ),
        (
            json.dumps(
                {
                    "staged_by": "operator",
                    "staged_at": "2099-01-02T00:00:00+00:00",
                    "expires_at": "2099-01-01T00:00:00+00:00",
                }
            ),
            "ValueError",
        ),
    ],
)
async def test_reaper_cancels_corrupt_pending_rotation(
    admin_token, client, value, error_type
):
    """Malformed metadata is audited and removed instead of wedging reaper."""
    await _init_cluster(admin_token, client)
    async with async_session() as db:
        await db.execute(
            text(
                """
                INSERT INTO vault_cluster_config (key, value)
                VALUES ('pending_ha_password_rotation', :value)
                ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value
                """
            ),
            {"value": value},
        )
        await db.commit()

    from api.app.main import _purge_pending_ha_password_rotation

    async with async_session() as db:
        outcome = await _purge_pending_ha_password_rotation(db)
        await db.commit()

    assert outcome == "corrupt"
    assert await _read_pending() is None
    async with async_session() as db:
        audit = (
            await db.execute(
                text(
                    "SELECT action, detail FROM vault_audit "
                    "WHERE action = 'ha_password_rotate_corrupt' "
                    "ORDER BY timestamp DESC LIMIT 1"
                )
            )
        ).fetchone()
    assert audit is not None
    assert audit.detail["error_type"] == error_type


@pytest.mark.asyncio
async def test_reaper_keeps_valid_future_pending_rotation(admin_token, client):
    await _init_cluster(admin_token, client)
    staged = await client.post(
        "/api/v1/vault/cluster/rotate-ha-password/stage",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert staged.status_code == 201

    from api.app.main import _purge_pending_ha_password_rotation

    async with async_session() as db:
        outcome = await _purge_pending_ha_password_rotation(db)
        await db.commit()
    assert outcome is None
    assert await _read_pending() is not None


# --- 13. auth gates


@pytest.mark.asyncio
async def test_stage_requires_admin_scope(admin_token, client):
    # Existing auth semantics : `admin` key in perms grants everything (r
    # and w both bypass the scope check). A token without `admin` at all
    # is what gets rejected -- match that policy so the test stays
    # aligned with require_permission's actual contract.
    await _init_cluster(admin_token, client)
    secrets_only = await _make_token("slice9-secrets-rw", {"secrets": "rw"})
    r = await client.post(
        "/api/v1/vault/cluster/rotate-ha-password/stage",
        headers={"Authorization": f"Bearer {secrets_only}"},
    )
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_get_requires_admin_r(admin_token, client):
    await _init_cluster(admin_token, client)
    no_admin = await _make_token("slice9-secrets-r", {"secrets": "r"})
    r = await client.get(
        "/api/v1/vault/cluster/rotate-ha-password",
        headers={"Authorization": f"Bearer {no_admin}"},
    )
    assert r.status_code == 403


# --- 14. seal/unseal cycle preserves the pending row


@pytest.mark.asyncio
async def test_pending_survives_seal_unseal_cycle(admin_token, client, master_password):
    await _init_cluster(admin_token, client)
    await client.post(
        "/api/v1/vault/cluster/rotate-ha-password/stage",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    pending_before = await _read_pending()
    assert pending_before is not None

    # Seal + unseal. The pending row lives in vault_cluster_config as
    # plain TEXT (no master-key-wrapped material) so it must survive
    # the cycle untouched.
    await client.post(
        "/api/v1/vault/seal",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    await client.post("/api/v1/vault/unseal", json={"password": master_password})

    pending_after = await _read_pending()
    assert pending_after == pending_before

    # Status endpoint still surfaces it post-unseal. A fresh admin
    # token is required (seal/unseal invalidated the old hmac context
    # only when prev_hmac is unset ; admin_token is function-scoped
    # so the conftest re-mints it on next request -- here we re-mint
    # one inline since this test already burned admin_token).
    fresh_admin = await _make_token("slice9-fresh-admin", {"admin": "rw"})
    r = await client.get(
        "/api/v1/vault/cluster/rotate-ha-password",
        headers={"Authorization": f"Bearer {fresh_admin}"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["pending"]["staged_by"] == pending_before["staged_by"]
