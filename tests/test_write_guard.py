"""write-path generation guard (key_epoch.is_generation_current).

A rotation on any host bumps ``vault_config.key_epoch`` and re-wraps every DEK
under the new ``dek_key``. Until this host's master adopts that generation, a
fresh DEK wrapped here would land under the OLD ``dek_key`` and be unreadable
once the cluster converges. The guard turns that <=1-heartbeat window into a
retryable 503 instead of silent corruption.

These exercise the decision core directly with a stub vault (is_master +
key_epoch are the only attributes read) :

- no rotation ever (db_epoch == 0)            -> allow
- master : in-RAM key_epoch vs db_epoch       -> ground truth
- follower : per-node ``active_key_epoch``     -> the master's published epoch,
  NOT the follower's own inert key_epoch
- require_generation_current raises 503 + Retry-After exactly when the core
  returns False.
"""

import os
from types import SimpleNamespace

import pytest
import pytest_asyncio
from api.app import key_epoch as key_epoch_mod
from api.app.database import async_session
from api.app.key_epoch import is_generation_current, require_generation_current
from api.app.node_uuid import get_node_uuid, init_node_uuid
from fastapi import HTTPException
from sqlalchemy import text

_NODE_IP = "203.0.113.77"


async def _set_epoch(db, value):
    if value is None:
        await db.execute(text("DELETE FROM vault_config WHERE key = 'key_epoch'"))
        return
    await db.execute(
        text(
            "INSERT INTO vault_config (key, value) VALUES ('key_epoch', :v) "
            "ON CONFLICT (key) DO UPDATE SET value = :v"
        ),
        {"v": str(value)},
    )


async def _upsert_self_node(db, node_uuid, active_epoch):
    """Insert/refresh this host's vault_cluster_nodes row with active_key_epoch."""
    await db.execute(
        text("DELETE FROM vault_cluster_nodes WHERE node_uuid = :u"),
        {"u": node_uuid},
    )
    await db.execute(
        text(
            "INSERT INTO vault_cluster_nodes "
            "(node_uuid, source_ip, ha_state, cluster_version, cert_fingerprint, "
            " cert_not_after, active_key_epoch) "
            "VALUES (:u, :ip, 'secondary', '1', 'fp', "
            "        NOW() + INTERVAL '90 days', :e)"
        ),
        {"u": node_uuid, "ip": _NODE_IP, "e": active_epoch},
    )


@pytest_asyncio.fixture
async def restore_epoch(setup_db):
    """Snapshot + restore the GLOBAL key_epoch counter and drop the test node row
    so this file does not leak a synthetic generation into the shared session.

    Depends on ``setup_db`` (session-scoped, applies schema.sql) -- these tests
    hit ``async_session()`` directly instead of going through the
    ``client``/``admin_token`` chain, so without this dependency they could be
    ordered before the schema exists (UndefinedTableError on a fresh DB)."""
    async with async_session() as db:
        row = (
            await db.execute(
                text("SELECT value FROM vault_config WHERE key = 'key_epoch'")
            )
        ).fetchone()
        orig = row.value if row else None
    yield
    async with async_session() as db:
        await _set_epoch(db, orig)
        await db.execute(
            text("DELETE FROM vault_cluster_nodes WHERE source_ip = :ip"),
            {"ip": _NODE_IP},
        )
        await db.commit()


@pytest.mark.asyncio
async def test_allows_when_no_rotation_ever(restore_epoch):
    async with async_session() as db:
        await _set_epoch(db, None)  # db_epoch -> 0
        await db.commit()
        # Even a master whose in-RAM epoch is None / a follower with no marker
        # is allowed : there is nothing to be stale against.
        assert await is_generation_current(
            db, SimpleNamespace(is_master=True, key_epoch=None)
        )
        assert await is_generation_current(
            db, SimpleNamespace(is_master=False, key_epoch=None)
        )


@pytest.mark.asyncio
async def test_master_uses_in_ram_epoch(restore_epoch):
    async with async_session() as db:
        await _set_epoch(db, 4)
        await db.commit()
        assert await is_generation_current(
            db, SimpleNamespace(is_master=True, key_epoch=4)
        )  # current
        assert not await is_generation_current(
            db, SimpleNamespace(is_master=True, key_epoch=3)
        )  # lags -> fence
        # Legacy unseal predating the marker (None) must fail closed unless the
        # live DEK key proves it can decrypt current rows.
        assert not await is_generation_current(
            db, SimpleNamespace(is_master=True, key_epoch=None)
        )


@pytest.mark.asyncio
async def test_master_unknown_epoch_can_pass_dek_probe(restore_epoch, monkeypatch):
    async def _probe(_db, _aesgcm, **_kwargs):
        return True

    monkeypatch.setattr(key_epoch_mod, "keys_match_current_data", _probe)
    async with async_session() as db:
        await _set_epoch(db, 4)
        await db.commit()
        assert await is_generation_current(
            db,
            SimpleNamespace(is_master=True, key_epoch=None, aesgcm=object()),
        )


@pytest.mark.asyncio
async def test_follower_uses_node_marker_not_own_epoch(restore_epoch):
    """The decisive case : a follower's own key_epoch is inert (it delegates the
    wrap to the host master). It must judge currency by the master's published
    active_key_epoch, so key_epoch=999 does NOT make a stale host look current."""
    node_uuid = init_node_uuid(os.environ["RHORIZON_NODE_UUID_PATH"])
    assert node_uuid == get_node_uuid()
    follower = SimpleNamespace(is_master=False, key_epoch=999)
    async with async_session() as db:
        await _set_epoch(db, 7)
        # marker current -> allow
        await _upsert_self_node(db, node_uuid, 7)
        await db.commit()
        assert await is_generation_current(db, follower)
        # marker stale (host master mid-convergence) -> fence, despite key_epoch=999
        await _upsert_self_node(db, node_uuid, 6)
        await db.commit()
        assert not await is_generation_current(db, follower)
        # marker NULL (non-HA / master not stamped yet) -> allow
        await _upsert_self_node(db, node_uuid, None)
        await db.commit()
        assert await is_generation_current(db, follower)


@pytest.mark.asyncio
async def test_require_raises_503_with_retry_after(restore_epoch):
    async with async_session() as db:
        await _set_epoch(db, 4)
        await db.commit()
        with pytest.raises(HTTPException) as ei:
            await require_generation_current(
                db, SimpleNamespace(is_master=True, key_epoch=3)
            )
        assert ei.value.status_code == 503
        assert ei.value.headers.get("Retry-After") == "1"
        # current generation -> no raise
        await require_generation_current(
            db, SimpleNamespace(is_master=True, key_epoch=4)
        )
