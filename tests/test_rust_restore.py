# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Backup restore through the standalone Rust custody boundary.

A logical restore never changes the runtime key bundle -- argon2_salt,
master_check and dek_key_version all stay current, so the custodians keep the
generation they already hold. What the restore DOES own is the post-restore
seal: under Rust custody that is a durable decision, committed in the same
transaction as the restored rows, not an in-process state flip. The daemon
seal that follows is therefore replayable, and an interrupted restore converges
through the ordinary maintenance path.

The other half is negative: the backup payload carries the vault_config of the
vault it was taken from, including that vault's custody generation counter.
Importing it would point the durable recovery decision at a generation no local
slot has.
"""

import pytest
import pytest_asyncio
from api.app import custody, rust_custody_backend
from api.app import custody_generation as cg
from api.app.database import async_session
from api.app.routes import backup as backup_routes
from api.app.vault_state import vault
from sqlalchemy import text

AGE_PASSPHRASE = "restore-age-passphrase-2026"


class FakePool:
    """Records the daemon transitions the restore drives."""

    def __init__(self):
        self.events = []

    async def seal_all(self):
        self.events.append("seal")


def _enable_rust_canary(monkeypatch, pool) -> None:
    monkeypatch.setattr(custody.settings, "custody_mode", "separated")
    monkeypatch.setattr(custody.settings, "custody_backend", "rust")
    monkeypatch.setattr(custody.settings, "process_role", "api")
    monkeypatch.setattr(rust_custody_backend, "_configured_pool", pool)


@pytest_asyncio.fixture
async def custody_state_sandbox():
    """Isolate the durable custody rows, then restore them."""
    keys = (
        cg.custody_state_key(),
        cg.CUSTODY_STATE_CONFIG_KEY,
        cg.CUSTODY_ACTIVATION_CONFIG_KEY,
    )
    originals = {}
    async with async_session() as db:
        for key in keys:
            row = (
                await db.execute(
                    text("SELECT value FROM vault_config WHERE key = :key"),
                    {"key": key},
                )
            ).fetchone()
            originals[key] = row.value if row else None
            await db.execute(
                text("DELETE FROM vault_config WHERE key = :key"), {"key": key}
            )
        await db.commit()
    yield
    async with async_session() as db:
        for key, original in originals.items():
            if original is None:
                await db.execute(
                    text("DELETE FROM vault_config WHERE key = :key"), {"key": key}
                )
            else:
                await db.execute(
                    text(
                        "INSERT INTO vault_config (key, value) VALUES (:key, :value) "
                        "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value"
                    ),
                    {"key": key, "value": original},
                )
        await db.commit()


async def _seed_active_generation(*, threshold=2, slots=3) -> int:
    async with async_session() as db:
        started = await cg.begin_custody_generation(
            db, threshold=threshold, slots=slots
        )
        await cg.choose_custody_generation(db, started.target_generation)
        await cg.finish_custody_generation(db, started.target_generation)
        await cg.set_rust_custody_activation(db, unsealed=True)
        await db.commit()
    return started.target_generation


async def _custody_state():
    async with async_session() as db:
        return await cg.get_custody_generation_state(db)


async def _activation() -> str | None:
    async with async_session() as db:
        return (
            await db.execute(
                text("SELECT value FROM vault_config WHERE key = :key"),
                {"key": cg.CUSTODY_ACTIVATION_CONFIG_KEY},
            )
        ).scalar_one_or_none()


async def _create_backup(client, headers) -> str:
    created = await client.post(
        "/api/v1/vault/backup/create",
        headers=headers,
        json={"passphrase": AGE_PASSPHRASE},
    )
    assert created.status_code == 200, created.text
    return created.json()["payload"]


def _restore_body(payload_b64: str, master_password: str) -> dict:
    return {
        "passphrase": AGE_PASSPHRASE,
        "master_password_backup": master_password,
        "confirm_phrase": "RESTORE",
        "payload": payload_b64,
    }


@pytest.mark.asyncio
async def test_restore_never_imports_the_backup_custody_generation_state(
    client, master_password, admin_token, custody_state_sandbox
):
    """The backup carries its own vault's generation counter. Adopting it would
    point recovery at a generation no local slot holds.

    Backend-independent: the exclusion is a property of the config key set, so
    it must hold on the Python default too.
    """
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    backup_generation = await _seed_active_generation()
    payload = await _create_backup(client, headers)

    # The live pool moves on after the backup was taken.
    live_generation = await _seed_active_generation()
    assert live_generation > backup_generation, "test premise: generations differ"

    restored = await client.post(
        "/api/v1/vault/backup/restore",
        headers=headers,
        json=_restore_body(payload, master_password),
    )
    assert restored.status_code == 200, restored.text

    state = await _custody_state()
    assert state.active_generation == live_generation, (
        "restore adopted the backup's custody generation; the durable recovery "
        "decision now names a generation the daemons never prepared"
    )
    assert state.phase == "stable"


@pytest.mark.asyncio
async def test_rust_restore_commits_the_seal_decision_and_seals_the_pool(
    client, master_password, admin_token, monkeypatch, custody_state_sandbox
):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    generation = await _seed_active_generation()
    payload = await _create_backup(client, headers)
    assert await _activation() == "unsealed"

    pool = FakePool()
    _enable_rust_canary(monkeypatch, pool)

    restored = await client.post(
        "/api/v1/vault/backup/restore",
        headers=headers,
        json=_restore_body(payload, master_password),
    )
    assert restored.status_code == 200, restored.text
    assert restored.json()["sealed"] is True

    # The operator intent is durable: the maintenance leader re-attaches any
    # pool whose recorded activation still says unsealed, so a bare
    # vault.seal() would be undone within one maintenance interval.
    assert await _activation() == "sealed"
    assert pool.events == ["seal"]
    assert vault.sealed is True
    # The generation itself is untouched -- a logical restore does not replace
    # the runtime bundle, so the custodians keep the shares they hold.
    assert (await _custody_state()).active_generation == generation


@pytest.mark.asyncio
async def test_rust_restore_rejects_a_concurrent_custody_operation(
    client, master_password, admin_token, monkeypatch, custody_state_sandbox
):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    await _seed_active_generation()
    payload = await _create_backup(client, headers)

    pool = FakePool()
    _enable_rust_canary(monkeypatch, pool)

    async with async_session() as holder:
        async with holder.begin():
            held = await holder.execute(
                text("SELECT pg_try_advisory_xact_lock(hashtext(:lock_name))"),
                {"lock_name": cg.CUSTODY_ORCHESTRATION_LOCK},
            )
            assert held.scalar() is True

            blocked = await client.post(
                "/api/v1/vault/backup/restore",
                headers=headers,
                json=_restore_body(payload, master_password),
            )

    assert blocked.status_code == 409, blocked.text
    assert "Rust custody operation" in blocked.text
    # Refused before any daemon transition and before the seal decision.
    assert pool.events == []
    assert await _activation() == "unsealed"
    assert vault.sealed is False


@pytest.mark.asyncio
async def test_interrupted_rust_restore_leaves_a_decision_maintenance_completes(
    client, master_password, admin_token, monkeypatch, custody_state_sandbox
):
    """Crash boundary: the restore committed, the daemon seal did not.

    The decision is already durable, so the ordinary maintenance path finishes
    the seal. The route must not report a failure for work that committed.
    """
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    await _seed_active_generation()
    payload = await _create_backup(client, headers)

    pool = FakePool()
    _enable_rust_canary(monkeypatch, pool)

    async def interrupted(*_args, **_kwargs):
        raise RuntimeError("custodian socket vanished after the restore commit")

    monkeypatch.setattr(rust_custody_backend, "deactivate_rust_custody", interrupted)

    restored = await client.post(
        "/api/v1/vault/backup/restore",
        headers=headers,
        json=_restore_body(payload, master_password),
    )
    assert restored.status_code == 200, restored.text
    assert restored.json()["sealed"] is True

    assert await _activation() == "sealed"
    assert pool.events == [], "premise: the daemon seal never ran"
    assert vault.sealed is True, "the local API view seals even when the pool cannot"

    # Recovery: the maintenance leader reads the committed decision and seals
    # the daemons it could not reach during the restore.
    attached = await rust_custody_backend.refresh_rust_custody(pool, vault)
    assert attached is False
    assert pool.events == ["seal"]
    assert vault.sealed is True


@pytest.mark.asyncio
async def test_failed_rust_restore_rolls_back_the_seal_decision(
    client, master_password, admin_token, monkeypatch, custody_state_sandbox
):
    """Pre-commit failure: the rows and the seal decision roll back together."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    kept = await client.post(
        "/api/v1/vault/secrets/",
        headers=headers,
        json={"name": "rust-restore-survivor", "value": "untouched"},
    )
    assert kept.status_code in (200, 201), kept.text

    generation = await _seed_active_generation()
    payload = await _create_backup(client, headers)

    pool = FakePool()
    _enable_rust_canary(monkeypatch, pool)

    async def fail_decision(_db, *, unsealed):
        raise RuntimeError("forced custody activation failure")

    monkeypatch.setattr(backup_routes, "set_rust_custody_activation", fail_decision)

    with pytest.raises(RuntimeError, match="forced custody activation failure"):
        await client.post(
            "/api/v1/vault/backup/restore",
            headers=headers,
            json=_restore_body(payload, master_password),
        )

    assert pool.events == []
    assert await _activation() == "unsealed"
    assert (await _custody_state()).active_generation == generation
    assert vault.sealed is False

    # The wipe-and-reimport transaction rolled back whole.
    survivor = await client.get(
        "/api/v1/vault/secrets/rust-restore-survivor", headers=headers
    )
    assert survivor.status_code == 200, survivor.text
    assert survivor.json()["value"] == "untouched"
