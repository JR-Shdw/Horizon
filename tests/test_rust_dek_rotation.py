"""dek_key rotation through the standalone Rust custody boundary.

The route stages a replacement generation that differs from the live bundle
only by `dek_key`, commits the custody roll-forward decision in the same
transaction as the re-wrapped rows and the key-epoch bump, and rolls forward
only after that commit. Every pre-decision failure restores the previous
generation.
"""

import os
from contextlib import asynccontextmanager

import pytest
import pytest_asyncio
from api.app import custody, custody_generation, custody_reshare, rust_custody_backend
from api.app import custody_generation as cg
from api.app.crypto import derive_keys, derive_master_key_async
from api.app.database import async_session
from api.app.key_epoch import get_key_epoch
from api.app.routes import vault as vault_routes
from api.app.routes.vault import _encrypt_2fa
from api.app.vault_state import vault
from rhorizon_crypto import secure_zero
from sqlalchemy import text


async def _dek_key_version() -> int:
    async with async_session() as db:
        row = (
            await db.execute(
                text("SELECT value FROM vault_config WHERE key = 'dek_key_version'")
            )
        ).scalar_one_or_none()
    return int(row or "1")


async def _subkeys(master_password: str, version: int) -> dict[str, bytes]:
    async with async_session() as db:
        salt = bytes.fromhex(
            (
                await db.execute(
                    text("SELECT value FROM vault_config WHERE key = 'argon2_salt'")
                )
            ).scalar_one()
        )
    master = bytearray(await derive_master_key_async(master_password.encode(), salt))
    try:
        keys = derive_keys(master, dek_key_version=version)
    finally:
        secure_zero(master)
    return {
        name: bytes(keys[name])
        for name in ("hmac_key", "dek_key", "audit_key", "ha_wrap_key", "pki_wrap_key")
    }


class FakePool:
    """Records the daemon transitions the coordinator drives."""

    def __init__(self):
        self.events = []
        self.client = object()
        self.fail_commit = False
        self.share_state = None

    async def seal_all(self):
        self.events.append(("seal",))

    async def prepare_shares(self, shares, generation):
        self.events.append(("prepare", sorted(shares), generation))

    async def rollback_generation_all(self, generation):
        self.events.append(("rollback", generation))

    async def commit_generation_all(self, generation):
        self.events.append(("commit", generation))
        if self.fail_commit:
            raise RuntimeError("daemon commit interrupted")

    async def finalize_generation_all(self, generation):
        self.events.append(("finalize", generation))

    async def share_statuses(self):
        self.events.append(("share-statuses",))
        return self.share_state

    async def unseal(self, *, generation):
        self.events.append(("unseal", generation))
        return self.client


class FakeVault:
    """Stands in for the process-global vault a restarted worker rebuilds."""

    def __init__(self):
        self._rpc_client = None
        self._sealed = True
        self.events = []

    @asynccontextmanager
    async def master_transition_lock(self):
        self.events.append("lock")
        yield

    def attach_rpc_client(self, client):
        self.events.append(("attach", client))
        self._rpc_client = client

    def detach_rpc_client(self):
        self.events.append("detach")
        self._rpc_client = None

    def seal(self):
        self.events.append("seal")
        self._sealed = True


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


def _enable_rust_canary(monkeypatch, pool) -> None:
    monkeypatch.setattr(custody.settings, "custody_mode", "separated")
    monkeypatch.setattr(custody.settings, "custody_backend", "rust")
    monkeypatch.setattr(custody.settings, "process_role", "api")
    monkeypatch.setattr(custody.settings, "rust_custodian_slots", 3)
    monkeypatch.setattr(custody.settings, "rust_custodian_threshold", 2)
    monkeypatch.setattr(rust_custody_backend, "_configured_pool", pool)


@pytest.mark.asyncio
async def test_rust_dek_rotation_stages_only_a_new_dek_and_rewraps_prev_hmac(
    client, master_password, admin_token, monkeypatch
):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}
    pool = object()
    _enable_rust_canary(monkeypatch, pool)

    old_version = await _dek_key_version()
    old_keys = await _subkeys(master_password, old_version)
    new_keys = await _subkeys(master_password, old_version + 1)

    # A previous HMAC key rides dek_key: the route re-wraps its envelope, so
    # the custodian's envelope fingerprint has to be refreshed after commit.
    prev_key = os.urandom(32)
    async with async_session() as db:
        await db.execute(
            text("""
                INSERT INTO vault_config (key, value) VALUES ('prev_hmac_key', :v)
                ON CONFLICT (key) DO UPDATE SET value = :v
            """),
            {"v": _encrypt_2fa(prev_key, vault.aesgcm)},
        )
        await db.commit()
        old_epoch = await get_key_epoch(db)

    events = []
    staged = {}

    async def stage(bundle, candidate_pool, **kwargs):
        assert candidate_pool is pool
        assert kwargs == {"threshold": 2, "slots": 3}
        staged["bundle"] = bytes(bundle)
        secure_zero(bundle)
        events.append("stage")
        return 51, 50

    async def choose(_db, target):
        # Still inside the route's uncommitted application transaction.
        assert await _dek_key_version() == old_version
        events.append(("choose", target))

    async def finish(candidate_pool, candidate_vault, *, target, key_epoch):
        assert candidate_pool is pool
        assert candidate_vault is vault
        vault.unseal(
            {
                "hmac_key": old_keys["hmac_key"],
                "dek_key": new_keys["dek_key"],
                "audit_key": old_keys["audit_key"],
                "ha_wrap_key": old_keys["ha_wrap_key"],
                "pki_wrap_key": old_keys["pki_wrap_key"],
            }
        )
        vault.set_key_epoch(key_epoch)
        # The committed envelope must be readable under the generation the
        # custodians just adopted -- this is what re-installs it in Rust.
        from api.app.auth import load_prev_hmac_into_ram

        async with async_session() as db:
            assert await load_prev_hmac_into_ram(db) is True
        events.append(("finish", target, key_epoch))

    monkeypatch.setattr(custody_reshare, "stage_local_bundle_for_rust_rotation", stage)
    monkeypatch.setattr(custody_generation, "choose_custody_generation", choose)
    monkeypatch.setattr(
        rust_custody_backend, "finish_rust_custody_key_rotation", finish
    )

    try:
        rotated = await client.post(
            "/api/v1/vault/admin/rotate-dek-key",
            headers=headers,
            json={"current_password": master_password},
        )
        assert rotated.status_code == 200, rotated.text
        assert rotated.json()["new_version"] == old_version + 1

        assert events == [
            "stage",
            ("choose", 51),
            ("finish", 51, old_epoch + 1),
        ]
        # hmac(old) || dek(new) || audit(old) || ha_wrap(old) || pki_wrap(old)
        assert staged["bundle"] == (
            old_keys["hmac_key"]
            + new_keys["dek_key"]
            + old_keys["audit_key"]
            + old_keys["ha_wrap_key"]
            + old_keys["pki_wrap_key"]
        )
        assert await _dek_key_version() == old_version + 1
    finally:
        async with async_session() as db:
            await db.execute(
                text(
                    "DELETE FROM vault_config "
                    "WHERE key IN ('prev_hmac_key', 'prev_hmac_rotated_at')"
                )
            )
            await db.commit()
        vault.clear_prev_hmac()


@pytest.mark.asyncio
async def test_rust_dek_rotation_db_failure_aborts_to_the_previous_generation(
    client, master_password, admin_token, monkeypatch
):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}
    pool = object()
    _enable_rust_canary(monkeypatch, pool)

    secret = await client.post(
        "/api/v1/vault/secrets/",
        headers=headers,
        json={"name": "rust-dek-abort", "value": "still-readable"},
    )
    assert secret.status_code in (200, 201), secret.text

    old_version = await _dek_key_version()
    async with async_session() as db:
        old_epoch = await get_key_epoch(db)
    events = []

    async def stage(bundle, candidate_pool, **_kwargs):
        assert candidate_pool is pool
        secure_zero(bundle)
        events.append("stage")
        return 61, 60

    async def choose(_db, target):
        events.append(("choose", target))

    async def fail_bump(_db):
        raise RuntimeError("forced key-epoch failure")

    async def abort(candidate_pool, candidate_vault, *, target, previous, key_epoch):
        assert candidate_pool is pool
        assert candidate_vault is vault
        events.append(("abort", target, previous, key_epoch))

    monkeypatch.setattr(custody_reshare, "stage_local_bundle_for_rust_rotation", stage)
    monkeypatch.setattr(custody_generation, "choose_custody_generation", choose)
    monkeypatch.setattr(vault_routes, "bump_key_epoch", fail_bump)
    monkeypatch.setattr(rust_custody_backend, "abort_rust_custody_key_rotation", abort)

    try:
        with pytest.raises(RuntimeError, match="forced key-epoch failure"):
            await client.post(
                "/api/v1/vault/admin/rotate-dek-key",
                headers=headers,
                json={"current_password": master_password},
            )

        assert events == [
            "stage",
            ("choose", 61),
            ("abort", 61, 60, old_epoch),
        ]
        assert await _dek_key_version() == old_version
        # The DEK re-wraps rolled back with the decision: the live dek_key
        # still unwraps every stored DEK.
        read = await client.get("/api/v1/vault/secrets/rust-dek-abort", headers=headers)
        assert read.status_code == 200, read.text
        assert read.json()["value"] == "still-readable"
    finally:
        await client.delete("/api/v1/vault/secrets/rust-dek-abort", headers=headers)


@pytest.mark.asyncio
async def test_rust_dek_rotation_staging_failure_reattaches_before_failing(
    client, master_password, admin_token, monkeypatch
):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}
    pool = object()
    _enable_rust_canary(monkeypatch, pool)

    old_version = await _dek_key_version()
    async with async_session() as db:
        old_epoch = await get_key_epoch(db)
    events = []

    async def stage(bundle, candidate_pool, **_kwargs):
        secure_zero(bundle)
        events.append("stage")
        raise RuntimeError("forced staging failure")

    async def resync(candidate_pool, candidate_vault, *, key_epoch):
        assert candidate_pool is pool
        assert candidate_vault is vault
        events.append(("resync", key_epoch))

    async def choose(_db, target):
        raise AssertionError("no generation may be chosen after a staging failure")

    monkeypatch.setattr(custody_reshare, "stage_local_bundle_for_rust_rotation", stage)
    monkeypatch.setattr(custody_generation, "choose_custody_generation", choose)
    monkeypatch.setattr(rust_custody_backend, "resync_rust_custody_attachment", resync)

    with pytest.raises(RuntimeError, match="forced staging failure"):
        await client.post(
            "/api/v1/vault/admin/rotate-dek-key",
            headers=headers,
            json={"current_password": master_password},
        )

    assert events == ["stage", ("resync", old_epoch)]
    assert await _dek_key_version() == old_version
    async with async_session() as db:
        assert await get_key_epoch(db) == old_epoch


@pytest.mark.asyncio
async def test_rust_dek_rotation_daemon_failure_after_the_decision_never_rolls_back(
    client, master_password, admin_token, monkeypatch, custody_state_sandbox
):
    """Post-decision boundary: the rewrapped rows own the new dek_key.

    Once the application transaction commits, only the staged generation can
    read the re-wrapped DEKs. Rolling the daemons back to the previous
    generation would strand every secret, so a daemon failure here must leave
    the durable phase at `committing` for recovery to finish forward.

    This drives the real staging and state machine; only the daemons are fake.
    """
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}
    pool = FakePool()
    _enable_rust_canary(monkeypatch, pool)
    active = await _seed_active_generation()
    old_version = await _dek_key_version()

    async def failing_finish(*_args, **_kwargs):
        raise RuntimeError("custodian unreachable after the decision")

    monkeypatch.setattr(
        rust_custody_backend, "finish_rust_custody_key_rotation", failing_finish
    )

    try:
        with pytest.raises(RuntimeError, match="custodian unreachable"):
            await client.post(
                "/api/v1/vault/admin/rotate-dek-key",
                headers=headers,
                json={"current_password": master_password},
            )

        target = active + 1
        assert pool.events == [("seal",), ("prepare", [1, 2, 3], target)]
        state = await _custody_state()
        assert state.phase == "committing"
        assert (state.active_generation, state.target_generation) == (target, target)
        assert state.previous_generation == active
        # The rotation itself committed: the rows now need the staged bundle.
        assert await _dek_key_version() == old_version + 1

        # Recovery may only finish forward.
        pool.events.clear()
        recovered = await custody_reshare.reconcile_rust_custody_generation(pool)
        assert recovered is pool.client
        assert pool.events == [
            ("seal",),
            ("commit", target),
            ("finalize", target),
            ("unseal", target),
        ]
        assert (await _custody_state()).phase == "stable"
    finally:
        # The worker still holds the retired dek_key: re-derive at the
        # committed version, as a restart would. Leave the canary first, or
        # the unseal tries to migrate into the generation this test created.
        monkeypatch.undo()
        await client.post("/api/v1/vault/seal", headers=headers)
        await client.post("/api/v1/vault/unseal", json={"password": master_password})


@pytest.mark.asyncio
async def test_rust_dek_rotation_restart_while_committing_adopts_the_new_generation(
    client, master_password, monkeypatch, custody_state_sandbox
):
    """Restart boundary: startup must roll a `committing` decision forward."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    active = await _seed_active_generation()
    target = active + 1
    async with async_session() as db:
        started = await cg.begin_custody_generation(db, threshold=2, slots=3)
        assert started.target_generation == target
        await cg.choose_custody_generation(db, target)
        await db.commit()

    pool = FakePool()
    pool.share_state = {
        slot: {
            "slot": slot,
            "threshold": 2,
            "slots": 3,
            "generation": target,
            "prepared_generation": None,
            "previous_generation": None,
            "reshare_generation": None,
        }
        for slot in (1, 2, 3)
    }
    restarted = FakeVault()

    attached = await rust_custody_backend.attach_reconciled_rust_custody(
        pool, restarted
    )

    assert attached is True
    assert restarted._rpc_client is pool.client
    assert not restarted._sealed
    assert ("rollback", target) not in pool.events
    assert pool.events[:4] == [
        ("seal",),
        ("commit", target),
        ("finalize", target),
        ("unseal", target),
    ]
    state = await _custody_state()
    assert state.phase == "stable"
    assert state.active_generation == target
