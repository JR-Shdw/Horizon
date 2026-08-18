"""Master-password rotation through the standalone Rust custody boundary."""

import json

import pytest
from api.app import custody, custody_generation, custody_reshare, rust_custody_backend
from api.app.crypto import derive_keys, derive_master_key_async
from api.app.database import async_session
from api.app.key_epoch import get_key_epoch
from api.app.routes import vault as vault_routes
from api.app.vault_state import vault
from rhorizon_crypto import secure_zero
from sqlalchemy import text


@pytest.mark.asyncio
async def test_rust_password_rotation_stages_before_commit_and_restores_password(
    client, master_password, admin_token, monkeypatch
):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    monkeypatch.setattr(custody.settings, "custody_mode", "separated")
    monkeypatch.setattr(custody.settings, "custody_backend", "rust")
    monkeypatch.setattr(custody.settings, "process_role", "api")
    monkeypatch.setattr(custody.settings, "rust_custodian_slots", 3)
    monkeypatch.setattr(custody.settings, "rust_custodian_threshold", 2)
    pool = object()
    monkeypatch.setattr(rust_custody_backend, "_configured_pool", pool)

    events = []
    generations = iter(((22, 21), (23, 22)))
    passwords = iter(("rust-rotation-test-password", master_password))

    async def stage(bundle, candidate_pool, **kwargs):
        assert candidate_pool is pool
        assert kwargs == {"threshold": 2, "slots": 3}
        assert len(bundle) == 160
        target, previous = next(generations)
        events.append(("stage", target, previous))
        secure_zero(bundle)
        return target, previous

    async def choose(_db, target):
        events.append(("choose", target))

    async def finish(candidate_pool, candidate_vault, *, target, key_epoch):
        assert candidate_pool is pool
        assert candidate_vault is vault
        password = next(passwords)
        async with async_session() as db:
            salt = bytes.fromhex(
                (
                    await db.execute(
                        text("SELECT value FROM vault_config WHERE key='argon2_salt'")
                    )
                ).scalar_one()
            )
            version_row = (
                await db.execute(
                    text("SELECT value FROM vault_config WHERE key='dek_key_version'")
                )
            ).scalar_one_or_none()
            version = int(version_row or "1")
        master = bytearray(await derive_master_key_async(password.encode(), salt))
        try:
            keys = derive_keys(master, dek_key_version=version)
        finally:
            secure_zero(master)
        vault.unseal(keys)
        vault.set_key_epoch(key_epoch)
        if target == 22:
            from api.app.auth import load_prev_hmac_into_ram

            async with async_session() as db:
                await load_prev_hmac_into_ram(db)
        events.append(("finish", target, key_epoch))

    monkeypatch.setattr(custody_reshare, "stage_local_bundle_for_rust_rotation", stage)
    monkeypatch.setattr(custody_generation, "choose_custody_generation", choose)
    monkeypatch.setattr(
        rust_custody_backend, "finish_rust_custody_key_rotation", finish
    )

    headers = {"Authorization": f"Bearer {admin_token}"}
    rotated = await client.post(
        "/api/v1/vault/rotate-password",
        headers=headers,
        json={
            "current_password": master_password,
            "new_password": "rust-rotation-test-password",
            "force": True,
        },
    )
    assert rotated.status_code == 200, rotated.text

    restored = await client.post(
        "/api/v1/vault/rotate-password",
        headers=headers,
        json={
            "current_password": "rust-rotation-test-password",
            "new_password": master_password,
            "force": True,
        },
    )
    assert restored.status_code == 200, restored.text
    assert [event[:2] for event in events] == [
        ("stage", 22),
        ("choose", 22),
        ("finish", 22),
        ("stage", 23),
        ("choose", 23),
        ("finish", 23),
    ]

    # The forced second rotation only retains generation 22 as previous HMAC.
    # Restore the shared fixture's original admin token under the current key.
    async with async_session() as db:
        token_hash = await vault.hmac_sha512_hex(admin_token)
        await db.execute(
            text("""
                INSERT INTO vault_tokens (name, token_hash, permissions, created_by)
                VALUES ('test-admin', :hash, CAST(:perms AS jsonb), 'bootstrap')
                ON CONFLICT (name) WHERE active DO UPDATE SET token_hash = :hash
            """),
            {"hash": token_hash, "perms": json.dumps({"admin": "rw"})},
        )
        assert await get_key_epoch(db) == vault.key_epoch
        await db.commit()


@pytest.mark.asyncio
async def test_rust_password_rotation_db_failure_aborts_staged_generation(
    client, master_password, admin_token, monkeypatch
):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    monkeypatch.setattr(custody.settings, "custody_mode", "separated")
    monkeypatch.setattr(custody.settings, "custody_backend", "rust")
    monkeypatch.setattr(custody.settings, "process_role", "api")
    monkeypatch.setattr(custody.settings, "rust_custodian_slots", 3)
    monkeypatch.setattr(custody.settings, "rust_custodian_threshold", 2)
    pool = object()
    monkeypatch.setattr(rust_custody_backend, "_configured_pool", pool)
    events = []

    async with async_session() as db:
        original = {
            row.key: row.value
            for row in (
                await db.execute(
                    text(
                        "SELECT key, value FROM vault_config "
                        "WHERE key IN ('argon2_salt', 'master_check')"
                    )
                )
            ).fetchall()
        }
        old_epoch = await get_key_epoch(db)

    async def stage(bundle, candidate_pool, **_kwargs):
        assert candidate_pool is pool
        secure_zero(bundle)
        events.append("stage")
        return 32, 31

    async def choose(_db, target):
        events.append(("choose", target))

    async def fail_bump(_db):
        raise RuntimeError("forced key-epoch failure")

    async def abort(
        candidate_pool,
        candidate_vault,
        *,
        target,
        previous,
        key_epoch,
    ):
        assert candidate_pool is pool
        assert candidate_vault is vault
        events.append(("abort", target, previous, key_epoch))

    monkeypatch.setattr(custody_reshare, "stage_local_bundle_for_rust_rotation", stage)
    monkeypatch.setattr(custody_generation, "choose_custody_generation", choose)
    monkeypatch.setattr(vault_routes, "bump_key_epoch", fail_bump)
    monkeypatch.setattr(rust_custody_backend, "abort_rust_custody_key_rotation", abort)

    with pytest.raises(RuntimeError, match="forced key-epoch failure"):
        await client.post(
            "/api/v1/vault/rotate-password",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={
                "current_password": master_password,
                "new_password": "must-not-commit",
                "force": True,
            },
        )

    assert events == [
        "stage",
        ("choose", 32),
        ("abort", 32, 31, old_epoch),
    ]
    async with async_session() as db:
        current = {
            row.key: row.value
            for row in (
                await db.execute(
                    text(
                        "SELECT key, value FROM vault_config "
                        "WHERE key IN ('argon2_salt', 'master_check')"
                    )
                )
            ).fetchall()
        }
    assert current == original
