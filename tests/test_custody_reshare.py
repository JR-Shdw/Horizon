"""Crash boundaries for the unwired Rust custodian migration coordinator."""

import weakref

import pytest
import pytest_asyncio
import rhorizon_crypto
from api.app import cluster_rpc, custody_reshare, rust_custody_backend
from api.app import custody_generation as cg
from api.app.database import async_session
from sqlalchemy import text


@pytest_asyncio.fixture
async def empty_custody_generation_state(setup_db):
    keys = (
        cg.custody_state_key(),
        cg.CUSTODY_STATE_CONFIG_KEY,
        cg.CUSTODY_ACTIVATION_CONFIG_KEY,
        # Production never resets the high-water mark -- that is the whole
        # point of it -- so a fixture that forgets it leaks a raised floor
        # into every later test and generations come out as 31 instead of 1.
        cg.custody_high_water_key(),
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
                text("DELETE FROM vault_config WHERE key = :key"),
                {"key": key},
            )
        await db.commit()
    yield
    async with async_session() as db:
        for key, original in originals.items():
            if original is None:
                await db.execute(
                    text("DELETE FROM vault_config WHERE key = :key"),
                    {"key": key},
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


class OpaqueShare:
    def __init__(self, slot):
        self.x = slot


class LocalVault:
    def __init__(self):
        self.bundle = bytearray(range(160))

    def export_subkeys_for_shamir(self):
        return self.bundle


class Pool:
    def __init__(self, vault=None):
        self.vault = vault
        self.events = []
        self.fail_prepare = False
        self.fail_native_prepare = False
        self.fail_commit = False
        self.client = object()
        self.active_slot = 1
        self.share_state = None
        self.fail_unseal = False

    async def seal_all(self):
        self.events.append(("seal",))

    async def prepare_shares(self, shares, generation):
        if self.vault is not None:
            assert self.vault.bundle == bytearray(160)
        self.events.append(("prepare", sorted(shares), generation))
        if self.fail_prepare:
            raise RuntimeError("prepare interrupted")

    async def prepare_native_reshare(self, generation):
        self.events.append(("native-prepare", generation))
        if self.fail_native_prepare:
            raise RuntimeError("native prepare interrupted")

    async def share_statuses(self):
        self.events.append(("share-statuses",))
        return self.share_state

    async def rollback_generation_all(self, generation):
        self.events.append(("rollback", generation))

    async def commit_generation_all(self, generation):
        self.events.append(("commit", generation))
        if self.fail_commit:
            raise RuntimeError("commit interrupted")

    async def finalize_generation_all(self, generation):
        self.events.append(("finalize", generation))

    async def unseal(self, *, generation):
        self.events.append(("unseal", generation))
        if self.fail_unseal:
            raise RuntimeError("quorum unavailable")
        return self.client


async def _state():
    async with async_session() as db:
        return await cg.get_custody_generation_state(db)


async def test_migration_commits_decision_and_drops_local_share_references(
    empty_custody_generation_state,
):
    vault = LocalVault()
    pool = Pool(vault)
    shares = [OpaqueShare(1), OpaqueShare(2), OpaqueShare(3)]
    references = [weakref.ref(share) for share in shares]

    client = await custody_reshare.migrate_local_keys_to_rust_custodians(
        vault,
        pool,
        threshold=2,
        slots=3,
        split_opaque=lambda *_: shares,
    )

    assert client is pool.client
    assert vault.bundle == bytearray(160)
    assert shares == []
    assert all(reference() is None for reference in references)
    assert pool.events == [
        ("seal",),
        ("prepare", [1, 2, 3], 1),
        ("commit", 1),
        ("finalize", 1),
        ("unseal", 1),
    ]
    state = await _state()
    assert state.phase == "stable"
    assert state.active_generation == 1
    async with async_session() as db:
        assert await cg.get_rust_custody_activation(db)


async def test_prepare_failure_rolls_back_before_aborting_database_decision(
    empty_custody_generation_state,
):
    vault = LocalVault()
    pool = Pool(vault)
    pool.fail_prepare = True
    shares = [OpaqueShare(1), OpaqueShare(2), OpaqueShare(3)]
    references = [weakref.ref(share) for share in shares]

    with pytest.raises(RuntimeError, match="prepare interrupted"):
        await custody_reshare.migrate_local_keys_to_rust_custodians(
            vault,
            pool,
            threshold=2,
            slots=3,
            split_opaque=lambda *_: shares,
        )

    assert pool.events == [
        ("seal",),
        ("prepare", [1, 2, 3], 1),
        ("rollback", 1),
    ]
    assert shares == []
    assert all(reference() is None for reference in references)
    assert await _state() == cg.CustodyGenerationState(
        version=1,
        phase="stable",
        active_generation=None,
        target_generation=None,
        previous_generation=None,
        threshold=2,
        slots=3,
    )


async def test_post_decision_failure_never_rolls_back_and_recovery_rolls_forward(
    empty_custody_generation_state,
):
    vault = LocalVault()
    pool = Pool(vault)
    pool.fail_commit = True
    shares = [OpaqueShare(1), OpaqueShare(2), OpaqueShare(3)]

    with pytest.raises(RuntimeError, match="commit interrupted"):
        await custody_reshare.migrate_local_keys_to_rust_custodians(
            vault,
            pool,
            threshold=2,
            slots=3,
            split_opaque=lambda *_: shares,
        )
    state = await _state()
    assert state.phase == "committing"
    assert state.active_generation == 1
    assert ("rollback", 1) not in pool.events

    pool.fail_commit = False
    pool.events.clear()
    assert await custody_reshare.reconcile_rust_custody_generation(pool) is pool.client
    assert pool.events == [
        ("seal",),
        ("commit", 1),
        ("finalize", 1),
        ("unseal", 1),
    ]
    assert (await _state()).phase == "stable"


async def test_recovery_rolls_back_preparing_state_before_returning_to_stable(
    empty_custody_generation_state,
):
    async with async_session() as db:
        await cg.begin_custody_generation(db, threshold=2, slots=3)
        await db.commit()
    pool = Pool()

    assert await custody_reshare.reconcile_rust_custody_generation(pool) is None
    assert pool.events == [("seal",), ("rollback", 1)]
    assert (await _state()).phase == "stable"


async def test_migration_uses_native_default_splitter(
    empty_custody_generation_state, monkeypatch
):
    vault = LocalVault()
    pool = Pool(vault)
    shares = [OpaqueShare(1), OpaqueShare(2), OpaqueShare(3)]
    monkeypatch.setattr(
        rhorizon_crypto,
        "shamir_split_opaque_bytearray",
        lambda bundle, threshold, slots: shares,
        raising=False,
    )

    assert (
        await custody_reshare.migrate_local_keys_to_rust_custodians(
            vault, pool, threshold=2, slots=3
        )
        is pool.client
    )
    assert shares == []


async def test_duplicate_split_coordinates_roll_back_before_database_abort(
    empty_custody_generation_state,
):
    vault = LocalVault()
    pool = Pool(vault)
    shares = [OpaqueShare(1), OpaqueShare(1), OpaqueShare(2)]

    with pytest.raises(RuntimeError, match="duplicate or missing"):
        await custody_reshare.migrate_local_keys_to_rust_custodians(
            vault,
            pool,
            threshold=2,
            slots=3,
            split_opaque=lambda *_: shares,
        )
    assert pool.events == [("seal",), ("rollback", 1)]
    assert (await _state()).phase == "stable"


async def test_zeroization_interruption_retries_wipe_before_returning(
    empty_custody_generation_state, monkeypatch
):
    vault = LocalVault()
    pool = Pool(vault)
    calls = 0

    def interrupted_zero(buffer):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("wipe interrupted")
        buffer[:] = bytearray(len(buffer))

    monkeypatch.setattr(rhorizon_crypto, "secure_zero", interrupted_zero)

    with pytest.raises(RuntimeError, match="wipe interrupted"):
        await custody_reshare.migrate_local_keys_to_rust_custodians(
            vault,
            pool,
            threshold=2,
            slots=3,
            split_opaque=lambda *_: pytest.fail("split must not complete"),
        )
    assert calls == 2
    assert vault.bundle == bytearray(160)
    assert pool.events == [("seal",), ("rollback", 1)]


async def test_native_reshare_commits_without_python_key_material(
    empty_custody_generation_state,
):
    async with async_session() as db:
        started = await cg.begin_custody_generation(db, threshold=2, slots=3)
        await cg.choose_custody_generation(db, started.target_generation)
        await cg.finish_custody_generation(db, started.target_generation)
        await db.commit()
    pool = Pool()

    assert (
        await custody_reshare.reshare_rust_custodians(pool, threshold=2, slots=3)
        is pool.client
    )
    assert pool.events == [
        ("unseal", 1),
        ("native-prepare", 2),
        ("seal",),
        ("commit", 2),
        ("finalize", 2),
        ("unseal", 2),
    ]
    state = await _state()
    assert state.phase == "stable"
    assert state.active_generation == 2


async def test_external_key_rotation_stages_opaque_generation_then_rolls_forward(
    empty_custody_generation_state,
):
    async with async_session() as db:
        started = await cg.begin_custody_generation(db, threshold=2, slots=3)
        await cg.choose_custody_generation(db, started.target_generation)
        await cg.finish_custody_generation(db, started.target_generation)
        await db.commit()
    pool = Pool()
    bundle = bytearray(range(160))
    shares = [OpaqueShare(1), OpaqueShare(2), OpaqueShare(3)]

    target, previous = await custody_reshare.stage_local_bundle_for_rust_rotation(
        bundle,
        pool,
        threshold=2,
        slots=3,
        split_opaque=lambda *_: shares,
    )

    assert (target, previous) == (2, 1)
    assert bundle == bytearray(160)
    assert shares == []
    assert pool.events == [("seal",), ("prepare", [1, 2, 3], 2)]
    assert (await _state()).phase == "preparing"

    async with async_session() as db:
        await cg.choose_custody_generation(db, target)
        await db.commit()
    assert (
        await custody_reshare.finish_staged_rust_rotation(pool, target=target)
        is pool.client
    )
    assert pool.events[-4:] == [
        ("seal",),
        ("commit", 2),
        ("finalize", 2),
        ("unseal", 2),
    ]
    state = await _state()
    assert state.phase == "stable"
    assert state.active_generation == 2


async def test_external_key_rotation_prepare_failure_restores_old_generation(
    empty_custody_generation_state,
):
    async with async_session() as db:
        started = await cg.begin_custody_generation(db, threshold=2, slots=3)
        await cg.choose_custody_generation(db, started.target_generation)
        await cg.finish_custody_generation(db, started.target_generation)
        await db.commit()
    pool = Pool()
    pool.fail_prepare = True
    bundle = bytearray(range(160))

    with pytest.raises(RuntimeError, match="prepare interrupted"):
        await custody_reshare.stage_local_bundle_for_rust_rotation(
            bundle,
            pool,
            threshold=2,
            slots=3,
            split_opaque=lambda *_: [
                OpaqueShare(1),
                OpaqueShare(2),
                OpaqueShare(3),
            ],
        )

    assert bundle == bytearray(160)
    assert pool.events == [
        ("seal",),
        ("prepare", [1, 2, 3], 2),
        ("seal",),
        ("rollback", 2),
        ("unseal", 1),
    ]
    state = await _state()
    assert state.phase == "stable"
    assert state.active_generation == 1


async def test_external_key_rotation_refuses_topology_drift_and_unstable_state(
    empty_custody_generation_state,
):
    async with async_session() as db:
        started = await cg.begin_custody_generation(db, threshold=2, slots=3)
        await cg.choose_custody_generation(db, started.target_generation)
        await cg.finish_custody_generation(db, started.target_generation)
        await db.commit()
    pool = Pool()

    topology_bundle = bytearray(range(160))
    with pytest.raises(cg.CustodyGenerationConflict, match="topology"):
        await custody_reshare.stage_local_bundle_for_rust_rotation(
            topology_bundle, pool, threshold=3, slots=3
        )
    assert topology_bundle == bytearray(160)

    async with async_session() as db:
        await cg.begin_custody_generation(db, threshold=2, slots=3)
        await db.commit()
    unstable_bundle = bytearray(range(160))
    with pytest.raises(cg.CustodyGenerationConflict, match="stable active"):
        await custody_reshare.stage_local_bundle_for_rust_rotation(
            unstable_bundle, pool, threshold=2, slots=3
        )
    assert unstable_bundle == bytearray(160)


async def test_local_migration_refuses_an_existing_rust_generation(
    empty_custody_generation_state,
):
    async with async_session() as db:
        started = await cg.begin_custody_generation(db, threshold=2, slots=3)
        await cg.choose_custody_generation(db, started.target_generation)
        await cg.finish_custody_generation(db, started.target_generation)
        await db.commit()
    vault = LocalVault()
    pool = Pool(vault)

    with pytest.raises(cg.CustodyGenerationConflict, match="empty stable"):
        await custody_reshare.migrate_local_keys_to_rust_custodians(
            vault,
            pool,
            threshold=2,
            slots=3,
            split_opaque=lambda *_: pytest.fail("must not split an active pool"),
        )
    assert pool.events == []


async def test_native_reshare_requires_an_active_stable_generation(
    empty_custody_generation_state,
):
    pool = Pool()

    with pytest.raises(cg.CustodyGenerationConflict, match="stable active"):
        await custody_reshare.reshare_rust_custodians(pool, threshold=2, slots=3)
    assert pool.events == []


async def test_custody_operation_rejects_a_concurrent_orchestrator(
    empty_custody_generation_state,
):
    pool = Pool()
    async with async_session() as lock_db:
        async with lock_db.begin():
            await lock_db.execute(
                text("SELECT pg_advisory_xact_lock(hashtext(:lock_name))"),
                {"lock_name": cg.CUSTODY_ORCHESTRATION_LOCK},
            )
            with pytest.raises(cg.CustodyGenerationConflict, match="in progress"):
                await custody_reshare.reconcile_rust_custody_generation(pool)
    assert pool.events == []


async def test_native_reshare_prepare_failure_restores_previous_generation(
    empty_custody_generation_state,
):
    async with async_session() as db:
        started = await cg.begin_custody_generation(db, threshold=2, slots=3)
        await cg.choose_custody_generation(db, started.target_generation)
        await cg.finish_custody_generation(db, started.target_generation)
        await db.commit()
    pool = Pool()
    pool.fail_native_prepare = True

    with pytest.raises(RuntimeError, match="native prepare interrupted"):
        await custody_reshare.reshare_rust_custodians(pool, threshold=2, slots=3)
    assert pool.events == [
        ("unseal", 1),
        ("native-prepare", 2),
        ("seal",),
        ("rollback", 2),
        ("unseal", 1),
    ]
    state = await _state()
    assert state.phase == "stable"
    assert state.active_generation == 1


@pytest_asyncio.fixture
async def unsealed_custody_intent(empty_custody_generation_state):
    """Record the operator decision the maintenance path checks first."""
    async with async_session() as db:
        await cg.set_rust_custody_activation(db, unsealed=True)
        await db.commit()


def _stable_share_status(slot, generation):
    return {
        "slot": slot,
        "generation": generation,
        "threshold": 2,
        "slots": 3,
        "prepared_generation": None,
        "previous_generation": None,
        "reshare_generation": None,
    }


async def test_repair_without_an_active_generation_stays_sealed(
    unsealed_custody_intent,
):
    pool = Pool()

    assert await custody_reshare.refresh_rust_custody_generation(pool) is None
    assert pool.events == []


async def test_repair_keeps_a_complete_stable_generation(
    unsealed_custody_intent,
):
    async with async_session() as db:
        started = await cg.begin_custody_generation(db, threshold=2, slots=3)
        await cg.choose_custody_generation(db, started.target_generation)
        await cg.finish_custody_generation(db, started.target_generation)
        await db.commit()
    pool = Pool()
    pool.share_state = {slot: _stable_share_status(slot, 1) for slot in range(1, 4)}

    assert await custody_reshare.refresh_rust_custody_generation(pool) is pool.client
    assert pool.events == [("unseal", 1), ("share-statuses",)]
    assert (await _state()).active_generation == 1


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("prepared_generation", 2, "inconsistent stable"),
        ("generation", 7, "unexpected share generation"),
    ],
)
async def test_repair_rejects_mixed_or_residual_generation_state(
    unsealed_custody_intent, field, value, message
):
    async with async_session() as db:
        started = await cg.begin_custody_generation(db, threshold=2, slots=3)
        await cg.choose_custody_generation(db, started.target_generation)
        await cg.finish_custody_generation(db, started.target_generation)
        await db.commit()
    pool = Pool()
    pool.share_state = {slot: _stable_share_status(slot, 1) for slot in range(1, 4)}
    pool.share_state[3][field] = value

    with pytest.raises(cluster_rpc.CustodianPoolUnavailable, match=message):
        await custody_reshare.refresh_rust_custody_generation(pool)
    assert (await _state()).active_generation == 1


async def test_repair_reshare_restores_an_empty_fixed_slot(
    unsealed_custody_intent,
):
    async with async_session() as db:
        started = await cg.begin_custody_generation(db, threshold=2, slots=3)
        await cg.choose_custody_generation(db, started.target_generation)
        await cg.finish_custody_generation(db, started.target_generation)
        await db.commit()
    pool = Pool()
    pool.share_state = {
        1: _stable_share_status(1, 1),
        2: _stable_share_status(2, 1),
        3: _stable_share_status(3, None),
    }

    assert await custody_reshare.refresh_rust_custody_generation(pool) is pool.client
    assert pool.events == [
        ("unseal", 1),
        ("share-statuses",),
        ("unseal", 1),
        ("native-prepare", 2),
        ("seal",),
        ("commit", 2),
        ("finalize", 2),
        ("unseal", 2),
    ]
    assert (await _state()).active_generation == 2


async def test_repair_refuses_loss_beyond_the_configured_quorum(
    unsealed_custody_intent,
):
    async with async_session() as db:
        started = await cg.begin_custody_generation(db, threshold=2, slots=3)
        await cg.choose_custody_generation(db, started.target_generation)
        await cg.finish_custody_generation(db, started.target_generation)
        await db.commit()
    pool = Pool()
    pool.share_state = {
        1: _stable_share_status(1, 1),
        2: _stable_share_status(2, None),
        3: _stable_share_status(3, None),
    }

    with pytest.raises(
        cluster_rpc.CustodianPoolUnavailable, match="surviving current quorum"
    ):
        await custody_reshare.refresh_rust_custody_generation(pool)
    assert (await _state()).active_generation == 1


async def _install_stable_generation(pool, *, threshold=2, slots=3):
    async with async_session() as db:
        started = await cg.begin_custody_generation(
            db, threshold=threshold, slots=slots
        )
        await cg.choose_custody_generation(db, started.target_generation)
        await cg.finish_custody_generation(db, started.target_generation)
        await db.commit()
    pool.share_state = {
        slot: _stable_share_status(slot, 1) for slot in range(1, slots + 1)
    }


async def _activation():
    async with async_session() as db:
        return await cg.get_rust_custody_activation(db)


async def test_local_unseal_reopens_the_generation_the_custodians_already_hold(
    empty_custody_generation_state,
):
    """A sealed pool that already owns a generation must be reopenable.

    Migration is only correct for an empty pool: it splits a fresh polynomial.
    Every later unseal -- after a manual seal, after a restore -- has to come
    back through the shares the custodians kept.
    """
    vault = LocalVault()
    pool = Pool(vault)
    await _install_stable_generation(pool)

    client = await custody_reshare.open_rust_custody_for_local_unseal(
        vault,
        pool,
        threshold=2,
        slots=3,
        split_opaque=lambda *_: pytest.fail("a held generation must not be resplit"),
    )

    assert client is pool.client
    # share_statuses() runs FIRST now: open_rust_custody_for_local_unseal
    # must prove the pool holds nothing before it may abandon a durable
    # generation. A pool that still holds one falls straight through to the
    # ordinary reopen, which is what this asserts.
    assert pool.events == [("share-statuses",), ("unseal", 1), ("share-statuses",)]
    assert vault.bundle == bytearray(range(160))
    assert (await _state()).active_generation == 1
    assert await _activation()


async def test_local_unseal_records_the_intent_only_after_the_daemons_unsealed(
    empty_custody_generation_state,
):
    """A failed reopen must not leave an unsealed decision behind.

    The maintenance leader acts on that decision: persisting it first would
    keep re-attaching a pool that could not assemble a quorum.
    """
    vault = LocalVault()
    pool = Pool(vault)
    await _install_stable_generation(pool)
    pool.fail_unseal = True

    with pytest.raises(RuntimeError, match="quorum unavailable"):
        await custody_reshare.open_rust_custody_for_local_unseal(
            vault, pool, threshold=2, slots=3
        )

    assert not await _activation()
    assert (await _state()).active_generation == 1


async def test_local_unseal_still_migrates_into_an_empty_pool(
    empty_custody_generation_state,
):
    vault = LocalVault()
    pool = Pool(vault)
    shares = [OpaqueShare(1), OpaqueShare(2), OpaqueShare(3)]

    client = await custody_reshare.open_rust_custody_for_local_unseal(
        vault,
        pool,
        threshold=2,
        slots=3,
        split_opaque=lambda *_: shares,
    )

    assert client is pool.client
    assert vault.bundle == bytearray(160)
    assert pool.events == [
        ("seal",),
        ("prepare", [1, 2, 3], 1),
        ("commit", 1),
        ("finalize", 1),
        ("unseal", 1),
    ]
    assert (await _state()).active_generation == 1
    assert await _activation()


async def test_local_unseal_refuses_a_reconfigured_topology(
    empty_custody_generation_state,
):
    """Growing the pool in the settings is a reshare, not an unseal."""
    vault = LocalVault()
    pool = Pool(vault)
    await _install_stable_generation(pool)

    with pytest.raises(cg.CustodyGenerationConflict, match="topology"):
        await custody_reshare.open_rust_custody_for_local_unseal(
            vault, pool, threshold=3, slots=5
        )

    assert pool.events == []
    assert not await _activation()


async def test_refresh_seals_the_pool_when_the_durable_decision_is_sealed(
    empty_custody_generation_state,
):
    pool = Pool()
    await _install_stable_generation(pool)

    assert await custody_reshare.refresh_rust_custody_generation(pool) is None
    assert pool.events == [("seal",)]

    async with async_session() as db:
        await cg.set_rust_custody_activation(db, unsealed=True)
        await db.commit()

    assert await custody_reshare.refresh_rust_custody_generation(pool) is pool.client
    assert pool.events[1:] == [("unseal", 1), ("share-statuses",)]


async def test_refresh_reads_the_decision_inside_the_orchestration_lock(
    empty_custody_generation_state,
):
    """Maintenance must not act on an activation it read before the lock.

    An operator reopening the pool commits its unsealed decision while holding
    this lock. A tick that decided "sealed" outside it would seal the pool the
    operator just brought back, and the API would flap until the next tick.
    """
    pool = Pool()
    await _install_stable_generation(pool)

    async with async_session() as blocker:
        async with blocker.begin():
            await blocker.execute(
                text("SELECT pg_advisory_xact_lock(hashtext(:lock_name))"),
                {"lock_name": cg.CUSTODY_ORCHESTRATION_LOCK},
            )
            with pytest.raises(cg.CustodyGenerationConflict, match="in progress"):
                await custody_reshare.refresh_rust_custody_generation(pool)

    assert pool.events == []


class ApiVault(LocalVault):
    """Enough of ``VaultState`` for the activation adapter to drive."""

    def __init__(self, master_check):
        super().__init__()
        self.master_check = master_check
        self.rpc_client = None
        self.sealed = True
        self.key_epoch = None

    def detach_rpc_client(self):
        self.rpc_client = None

    def seal(self):
        self.sealed = True

    def attach_rpc_client(self, client):
        self.rpc_client = client
        self.sealed = False

    def set_key_epoch(self, epoch):
        self.key_epoch = epoch

    async def hmac_sha512_hex(self, _message):
        if self.rpc_client is None:
            raise AssertionError("master check must be computed through Rust")
        return self.master_check


@pytest_asyncio.fixture
async def stored_master_check():
    value = "0" * 128
    async with async_session() as db:
        row = (
            await db.execute(
                text("SELECT value FROM vault_config WHERE key = 'master_check'")
            )
        ).fetchone()
        original = row.value if row else None
        await db.execute(
            text(
                "INSERT INTO vault_config (key, value) VALUES ('master_check', :value) "
                "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value"
            ),
            {"value": value},
        )
        await db.commit()
    yield value
    async with async_session() as db:
        if original is None:
            await db.execute(
                text("DELETE FROM vault_config WHERE key = 'master_check'")
            )
        else:
            await db.execute(
                text(
                    "UPDATE vault_config SET value = :value WHERE key = 'master_check'"
                ),
                {"value": original},
            )
        await db.commit()


async def test_password_unseal_reopens_a_sealed_pool_that_holds_a_generation(
    empty_custody_generation_state, stored_master_check, monkeypatch
):
    """End-to-end regression for the blocker: manual seal was one-way.

    ``/unseal`` had a single Rust branch, and it migrated. Against a pool that
    already held a generation that branch raised ``CustodyGenerationConflict``,
    so a sealed canary vault -- including every post-restore vault -- could
    never be reopened.
    """
    vault = ApiVault(stored_master_check)
    pool = Pool(vault)
    await _install_stable_generation(pool)

    async def no_envelopes(_session_factory):
        return None

    monkeypatch.setattr(
        rust_custody_backend, "_reload_external_ancillary_state", no_envelopes
    )

    await rust_custody_backend.activate_rust_custody_from_local(
        pool,
        vault,
        key_epoch=4,
        threshold=2,
        slots=3,
    )

    assert vault.rpc_client is pool.client
    assert not vault.sealed
    assert vault.key_epoch == 4
    assert vault.bundle == bytearray(range(160))
    # share_statuses() runs FIRST now: open_rust_custody_for_local_unseal
    # must prove the pool holds nothing before it may abandon a durable
    # generation. A pool that still holds one falls straight through to the
    # ordinary reopen, which is what this asserts.
    assert pool.events == [("share-statuses",), ("unseal", 1), ("share-statuses",)]
    assert await _activation()
