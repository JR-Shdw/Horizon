"""S1 (rotation-safe) -- unified key_epoch marker + stale-keys fence.

A key rotation on one host bumps a unified
``vault_config['key_epoch']``; every other host's in-RAM keys then lag, and
the per-node fence quarantines them out of ``/readiness`` instead of letting
them silently serve 500s. See api/app/key_epoch.py + cluster_ha_loops.py.

Isolation note: ``vault_config['key_epoch']`` is GLOBAL shared state and the
audit chain tags each row with it. A test that leaves a bogus epoch behind
would mis-tag later audit rows and break /audit/verify session-wide. So the
fence tests drive the "stale" condition through the in-RAM epoch (relative to
the real current epoch) and never write a fake DB epoch while emitting audit;
the autouse fixture restores the counter + cleans test node rows regardless.
"""

import os

import pytest
import pytest_asyncio
from api.app import cluster_ca
from api.app import key_epoch as ke
from api.app.cluster_ha_loops import _key_epoch_fence_body
from api.app.database import async_session
from api.app.node_uuid import init_node_uuid
from api.app.vault_state import vault
from sqlalchemy import text

pytestmark = pytest.mark.asyncio

_TEST_NODE_IP = "10.0.0.9"


@pytest_asyncio.fixture(autouse=True)
async def _clean_test_nodes():
    """Purge this file's synthetic cluster node rows after each test.

    A stray ``quarantined`` row would otherwise 503 an unrelated readiness
    probe later in the session. NOTE: this deliberately does NOT touch
    ``key_epoch`` -- tests that do REAL rotations advance the global epoch
    (and the audit-chain tags + archive) consistently and must keep that
    advancement. Only the synthetic-counter tests below restore it, via
    ``preserve_epoch``.
    """
    yield
    async with async_session() as db:
        await db.execute(
            text("DELETE FROM vault_cluster_nodes WHERE source_ip = :ip"),
            {"ip": _TEST_NODE_IP},
        )
        await db.commit()


@pytest_asyncio.fixture
async def preserve_epoch():
    """Snapshot + restore ``vault_config['key_epoch']`` for tests that poke it
    directly (without a real rotation). Leaving a bogus counter behind would
    mis-tag later audit rows and break /audit/verify session-wide."""
    async with async_session() as db:
        row = (
            await db.execute(
                text("SELECT value FROM vault_config WHERE key = 'key_epoch'")
            )
        ).fetchone()
        orig = row.value if row else None
    yield
    async with async_session() as db:
        if orig is None:
            await db.execute(text("DELETE FROM vault_config WHERE key = 'key_epoch'"))
        else:
            await db.execute(
                text(
                    "INSERT INTO vault_config (key, value) VALUES ('key_epoch', :v) "
                    "ON CONFLICT (key) DO UPDATE SET value = :v"
                ),
                {"v": orig},
            )
        await db.commit()


async def _set_db_epoch(value: int) -> None:
    async with async_session() as db:
        await db.execute(
            text(
                "INSERT INTO vault_config (key, value) VALUES ('key_epoch', :v) "
                "ON CONFLICT (key) DO UPDATE SET value = :v"
            ),
            {"v": str(value)},
        )
        await db.commit()


async def _ensure_node_row(node_uuid: str, ha_state: str) -> None:
    async with async_session() as db:
        await db.execute(
            text("DELETE FROM vault_cluster_nodes WHERE node_uuid = :u"),
            {"u": node_uuid},
        )
        await db.execute(
            text(
                "INSERT INTO vault_cluster_nodes "
                "(node_uuid, source_ip, ha_state, cluster_version, "
                " cert_fingerprint, cert_not_after) "
                "VALUES (:u, :ip, :s, 'v1', 'fp', NOW() + INTERVAL '1 day')"
            ),
            {"u": node_uuid, "ip": _TEST_NODE_IP, "s": ha_state},
        )
        await db.commit()


async def _node_state(node_uuid: str) -> str | None:
    async with async_session() as db:
        r = await db.execute(
            text("SELECT ha_state FROM vault_cluster_nodes WHERE node_uuid = :u"),
            {"u": node_uuid},
        )
        row = r.fetchone()
        return row.ha_state if row else None


async def _current_epoch() -> int:
    async with async_session() as db:
        return await ke.get_key_epoch(db)


# -- key_epoch helpers -----------------------------------------------------


async def test_get_key_epoch_defaults_zero(admin_token, preserve_epoch):
    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_config WHERE key = 'key_epoch'"))
        await db.commit()
        assert await ke.get_key_epoch(db) == 0


async def test_bump_key_epoch_monotonic(admin_token, preserve_epoch):
    await _set_db_epoch(0)
    async with async_session() as db:
        assert await ke.bump_key_epoch(db) == 1
        assert await ke.bump_key_epoch(db) == 2
        await db.commit()
        assert await ke.get_key_epoch(db) == 2


@pytest.mark.parametrize("bad_epoch", ["nope", "-1", "2147483648"])
async def test_get_key_epoch_corrupt_value_is_zero(
    admin_token, preserve_epoch, bad_epoch
):
    async with async_session() as db:
        await db.execute(
            text(
                "INSERT INTO vault_config (key, value) VALUES ('key_epoch', :v) "
                "ON CONFLICT (key) DO UPDATE SET value = :v"
            ),
            {"v": bad_epoch},
        )
        await db.commit()
        assert await ke.get_key_epoch(db) == 0


@pytest.mark.parametrize("bad_epoch", ["nope", "-1", "2147483648"])
async def test_corrupt_epoch_fences_writes_fail_closed(
    admin_token, preserve_epoch, bad_epoch
):
    """A3: a present-but-unparseable key_epoch fences key-material writes.

    get_key_epoch coerces corrupt -> 0 to keep the audit hot path alive, but the
    WRITE fence must NOT be fooled into "fresh install -> allow". The fence reads
    the raw epoch and fails CLOSED: is_generation_current returns False and
    require_generation_current raises a retryable 503 rather than waving a write
    through under possibly-stale keys.
    """
    from fastapi import HTTPException

    async with async_session() as db:
        await db.execute(
            text(
                "INSERT INTO vault_config (key, value) VALUES ('key_epoch', :v) "
                "ON CONFLICT (key) DO UPDATE SET value = :v"
            ),
            {"v": bad_epoch},
        )
        await db.commit()
        assert await ke.is_generation_current(db, vault) is False
        with pytest.raises(HTTPException) as ei:
            await ke.require_generation_current(db, vault)
        assert ei.value.status_code == 503


# -- rotation bumps the epoch + records it on the rotating worker ----------


async def test_rotate_password_bumps_epoch(client, master_password, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}
    before = await _current_epoch()

    new_pw = "rotated-master-pw-s1-A"
    r = await client.post(
        "/api/v1/vault/rotate-password",
        headers=headers,
        json={"current_password": master_password, "new_password": new_pw},
    )
    assert r.status_code == 200, r.text

    after = await _current_epoch()
    assert after == before + 1
    # The worker that rotated is now on the new generation.
    assert vault.key_epoch == after

    # Restore the canonical password so later tests / the admin_token fixture
    # keep working against master_password.
    r = await client.post(
        "/api/v1/vault/rotate-password",
        headers=headers,
        json={
            "current_password": new_pw,
            "new_password": master_password,
            "force": True,
        },
    )
    assert r.status_code == 200, r.text


async def test_rotate_password_rewraps_cluster_ca_key(
    client, master_password, admin_token, tmp_path, monkeypatch
):
    """A master password rotation must keep the HA signer recoverable.

    The isolated ``cluster_ca.rewrap_for_master_rotation`` helper already had
    coverage; this verifies the actual /rotate-password route calls it.
    """
    from api.app.config import settings
    from api.app.ha_password import clear as hp_clear

    monkeypatch.setattr(
        settings, "cluster_cert_path", str(tmp_path / "cluster-cert.pem")
    )
    monkeypatch.setattr(
        settings, "cluster_cert_key_path", str(tmp_path / "cluster-cert.key")
    )
    init_node_uuid(settings.node_uuid_path)
    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_cluster_nodes"))
        await db.execute(
            text(
                "DELETE FROM vault_cluster_config WHERE key IN "
                "('cluster_id','ha_password_encrypted','cluster_ca_cert',"
                "'cluster_ca_key','primary_uuid','primary_since')"
            )
        )
        await db.commit()
    hp_clear()

    headers = {"Authorization": f"Bearer {admin_token}"}
    r = await client.post(
        "/api/v1/vault/cluster/init",
        headers=headers,
        json={"cluster_name": "rotation-route-ca-regression"},
    )
    assert r.status_code == 200, r.text

    async with async_session() as db:
        before = (
            await db.execute(
                text(
                    "SELECT value FROM vault_cluster_config "
                    "WHERE key = 'cluster_ca_key'"
                )
            )
        ).fetchone()
    assert before is not None

    new_pw = "rotated-master-pw-ca-route"
    r = await client.post(
        "/api/v1/vault/rotate-password",
        headers=headers,
        json={"current_password": master_password, "new_password": new_pw},
    )
    assert r.status_code == 200, r.text

    async with async_session() as db:
        after = (
            await db.execute(
                text(
                    "SELECT value FROM vault_cluster_config "
                    "WHERE key = 'cluster_ca_key'"
                )
            )
        ).fetchone()
        loaded = await cluster_ca.load_cluster_ca(db)
    assert after is not None
    assert after.value != before.value
    assert loaded is not None
    cert_pem, key_pem = loaded
    assert cert_pem.startswith(b"-----BEGIN CERTIFICATE-----")
    assert b"PRIVATE KEY-----" in key_pem

    # Restore the canonical password so later tests / the admin_token fixture
    # keep working against master_password.
    r = await client.post(
        "/api/v1/vault/rotate-password",
        headers=headers,
        json={
            "current_password": new_pw,
            "new_password": master_password,
            "force": True,
        },
    )
    assert r.status_code == 200, r.text
    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_cluster_nodes"))
        await db.execute(
            text(
                "DELETE FROM vault_cluster_config WHERE key IN "
                "('cluster_id','ha_password_encrypted','cluster_ca_cert',"
                "'cluster_ca_key','primary_uuid','primary_since')"
            )
        )
        await db.commit()
    hp_clear()


async def test_rotate_dek_key_bumps_epoch(client, master_password, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}
    before = await _current_epoch()
    r = await client.post(
        "/api/v1/vault/admin/rotate-dek-key",
        headers=headers,
        json={"current_password": master_password},
    )
    assert r.status_code == 200, r.text
    after = await _current_epoch()
    assert after == before + 1
    assert vault.key_epoch == after


async def test_unseal_records_epoch(client, master_password, admin_token):
    # admin_token fixture seals + unseals; the unsealed worker should carry
    # the DB epoch.
    assert vault.key_epoch == await _current_epoch()


# -- fence -----------------------------------------------------------------
#
# These never write a fake DB epoch: the DB stays at the real current epoch
# (so the quarantine/recover audit rows are tagged correctly), and the "stale"
# condition is simulated purely via the in-RAM epoch.


async def test_fence_quarantines_stale_master(admin_token, monkeypatch):
    node_uuid = init_node_uuid(os.environ["RHORIZON_NODE_UUID_PATH"])
    cur = await _current_epoch()
    await _ensure_node_row(node_uuid, "secondary")

    async def _advanced_epoch(_db):
        return cur + 1

    monkeypatch.setattr("api.app.cluster_ha_loops.get_key_epoch", _advanced_epoch)
    # Master (no RPC client in tests) holding the real current keys while the
    # fence observes a simulated one-generation DB advance.
    vault.set_key_epoch(cur)
    async with async_session() as db:
        action = await _key_epoch_fence_body(db, node_uuid)
    assert action == "quarantined"
    assert await _node_state(node_uuid) == "quarantined"


async def test_fence_recovers_on_epoch_match(admin_token):
    node_uuid = init_node_uuid(os.environ["RHORIZON_NODE_UUID_PATH"])
    cur = await _current_epoch()
    await _ensure_node_row(node_uuid, "quarantined")
    vault.set_key_epoch(cur)  # operator re-unsealed to current generation
    async with async_session() as db:
        action = await _key_epoch_fence_body(db, node_uuid)
    assert action == "recovered"
    assert await _node_state(node_uuid) == "secondary"


async def test_fence_noop_when_current(admin_token):
    node_uuid = init_node_uuid(os.environ["RHORIZON_NODE_UUID_PATH"])
    cur = await _current_epoch()
    await _ensure_node_row(node_uuid, "secondary")
    vault.set_key_epoch(cur)
    async with async_session() as db:
        action = await _key_epoch_fence_body(db, node_uuid)
    assert action is None
    assert await _node_state(node_uuid) == "secondary"


async def test_fence_skips_follower(admin_token, monkeypatch):
    node_uuid = init_node_uuid(os.environ["RHORIZON_NODE_UUID_PATH"])
    cur = await _current_epoch()
    await _ensure_node_row(node_uuid, "secondary")

    async def _advanced_epoch(_db):
        return cur + 1

    monkeypatch.setattr("api.app.cluster_ha_loops.get_key_epoch", _advanced_epoch)
    vault.set_key_epoch(cur)  # would be stale if this process held keys...
    # ...but a follower delegates crypto and must not self-judge.
    vault.attach_rpc_client(object())
    try:
        async with async_session() as db:
            action = await _key_epoch_fence_body(db, node_uuid)
    finally:
        vault.detach_rpc_client()
    assert action is None
    assert await _node_state(node_uuid) == "secondary"


async def test_fence_quarantines_unknown_epoch_when_probe_fails(
    admin_token, monkeypatch
):
    async def _epoch(_db):
        return 2

    async def _probe(_db, _aesgcm, **_kwargs):
        return False

    monkeypatch.setattr("api.app.cluster_ha_loops.get_key_epoch", _epoch)
    monkeypatch.setattr("api.app.cluster_ha_loops.keys_match_current_data", _probe)
    node_uuid = init_node_uuid(os.environ["RHORIZON_NODE_UUID_PATH"])
    await _ensure_node_row(node_uuid, "secondary")
    vault.set_key_epoch(None)  # legacy unseal, must prove current DEK key
    async with async_session() as db:
        action = await _key_epoch_fence_body(db, node_uuid)
    assert action == "quarantined"
    assert await _node_state(node_uuid) == "quarantined"


async def test_fence_adopts_unknown_epoch_when_probe_passes(admin_token, monkeypatch):
    async def _epoch(_db):
        return 2

    async def _probe(_db, _aesgcm, **_kwargs):
        return True

    monkeypatch.setattr("api.app.cluster_ha_loops.get_key_epoch", _epoch)
    monkeypatch.setattr("api.app.cluster_ha_loops.keys_match_current_data", _probe)
    node_uuid = init_node_uuid(os.environ["RHORIZON_NODE_UUID_PATH"])
    await _ensure_node_row(node_uuid, "secondary")
    vault.set_key_epoch(None)
    async with async_session() as db:
        action = await _key_epoch_fence_body(db, node_uuid)
    assert action is None
    assert await _node_state(node_uuid) == "secondary"
    assert vault.key_epoch == 2


# -- readiness -------------------------------------------------------------


async def test_readiness_503_when_quarantined(client, admin_token, monkeypatch):
    from api.app import main as main_mod

    node_uuid = init_node_uuid(os.environ["RHORIZON_NODE_UUID_PATH"])
    monkeypatch.setattr(main_mod.settings, "cluster_ha_enabled", True)

    await _ensure_node_row(node_uuid, "quarantined")
    r = await client.get("/readiness")
    assert r.status_code == 503
    assert r.json() == {
        "status": "quarantined",
        "component": "cluster_membership",
    }

    await _ensure_node_row(node_uuid, "secondary")
    r = await client.get("/readiness")
    assert r.status_code == 200


async def test_readiness_ignores_quarantine_when_ha_disabled(
    client, admin_token, monkeypatch
):
    from api.app import main as main_mod

    node_uuid = init_node_uuid(os.environ["RHORIZON_NODE_UUID_PATH"])
    monkeypatch.setattr(main_mod.settings, "cluster_ha_enabled", False)
    await _ensure_node_row(node_uuid, "quarantined")
    r = await client.get("/readiness")
    assert r.status_code == 200


async def test_readiness_checks_database_when_ha_is_disabled(
    client, admin_token, monkeypatch
):
    from api.app import database
    from api.app import main as main_mod

    monkeypatch.setattr(main_mod.settings, "cluster_ha_enabled", False)

    def _database_unavailable():
        raise RuntimeError("test database unavailable")

    monkeypatch.setattr(database, "async_session", _database_unavailable)
    r = await client.get("/readiness")
    assert r.status_code == 503
    assert r.json() == {
        "status": "database_unreachable",
        "component": "postgresql",
    }


async def test_database_readiness_probe_has_a_strict_timeout(monkeypatch):
    import asyncio

    from api.app import database
    from api.app import main as main_mod

    class _SlowSession:
        async def __aenter__(self):
            await asyncio.sleep(1)
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

    monkeypatch.setattr(database, "async_session", _SlowSession)
    monkeypatch.setattr(main_mod, "_DATABASE_READINESS_TIMEOUT_SECS", 0.01)
    assert await main_mod._database_ready() is False


async def test_readiness_fails_closed_when_quarantine_state_is_unknown(
    client, admin_token, monkeypatch
):
    from unittest.mock import AsyncMock

    from api.app import database
    from api.app import main as main_mod

    monkeypatch.setattr(main_mod.settings, "cluster_ha_enabled", True)
    monkeypatch.setattr(main_mod, "_database_ready", AsyncMock(return_value=True))

    def _database_unavailable():
        raise RuntimeError("test database unavailable")

    monkeypatch.setattr(database, "async_session", _database_unavailable)
    r = await client.get("/readiness")
    assert r.status_code == 503
    assert r.json() == {
        "status": "unknown",
        "component": "cluster_membership",
    }


async def test_readiness_fences_and_recovers_broken_follower_rpc(
    client, admin_token, monkeypatch
):
    from unittest.mock import AsyncMock

    from api.app import main as main_mod
    from api.app.cluster_rpc import MasterUnreachable

    monkeypatch.setattr(main_mod.settings, "cluster_ha_enabled", True)
    rpc_client = AsyncMock()
    rpc_client.call.side_effect = MasterUnreachable("master unavailable")
    vault.attach_rpc_client(rpc_client)
    vault._mark_rpc_unreachable()
    try:
        r = await client.get("/readiness")
        assert r.status_code == 503
        assert r.json() == {"status": "rpc_unreachable"}
        assert vault.rpc_fenced is True

        rpc_client.call.side_effect = None
        rpc_client.call.return_value = "ab" * 64
        r = await client.get("/readiness")
        assert r.status_code == 200
        assert vault.rpc_fenced is False
    finally:
        vault.detach_rpc_client()


async def test_readiness_blocks_expected_auto_joiner_until_active(
    client, admin_token, monkeypatch
):
    from api.app import main as main_mod

    node_uuid = init_node_uuid(os.environ["RHORIZON_NODE_UUID_PATH"])
    monkeypatch.setattr(main_mod.settings, "cluster_ha_enabled", True)
    monkeypatch.setattr(main_mod.settings, "ha_auto_join", True)
    monkeypatch.setattr(main_mod.settings, "ha_primary_url", "https://primary:8443")

    async with async_session() as db:
        await db.execute(
            text("DELETE FROM vault_cluster_nodes WHERE node_uuid = :u"),
            {"u": node_uuid},
        )
        await db.commit()

    r = await client.get("/readiness")
    assert r.status_code == 503
    assert r.json() == {
        "status": "auto_join_pending",
        "ha_state": "unjoined",
    }

    await _ensure_node_row(node_uuid, "joining")
    r = await client.get("/readiness")
    assert r.status_code == 503
    assert r.json()["ha_state"] == "joining"

    await _ensure_node_row(node_uuid, "secondary")
    r = await client.get("/readiness")
    assert r.status_code == 200


# -- reconstruct epoch resolver -------------------------------------------


async def test_resolve_reconstruct_epoch_current_keys(admin_token):
    cur = await _current_epoch()
    async with async_session() as db:
        has_dek = (await db.execute(text("SELECT 1 FROM vault_dek LIMIT 1"))).fetchone()
        # vault.aesgcm is the live, current dek_key -> unwraps current DEKs.
        epoch = await ke.resolve_reconstruct_epoch(db, vault.aesgcm)
    if has_dek or cur == 0:
        assert epoch == cur
    else:
        assert epoch == cur - 1


async def test_resolve_reconstruct_epoch_stale_keys(admin_token):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    cur = await _current_epoch()
    bogus = AESGCM(os.urandom(32))  # a key that cannot unwrap the real DEKs
    async with async_session() as db:
        epoch = await ke.resolve_reconstruct_epoch(db, bogus)
    if cur > 0:
        assert epoch == cur - 1  # below db epoch -> fence fires
    else:
        assert epoch == 0  # no rotation yet, so nothing can be stale
