"""The half of a topology change that survives the operator's restart.

The interesting cases are not the happy path: they are what a process that
wakes up mid-ceremony decides, because the process that started it is gone.
"""

import pytest
import pytest_asyncio
from api.app import custody_generation as cg
from api.app import custody_reshare
from api.app.cluster_rpc import CustodianPoolUnavailable
from api.app.database import async_session
from sqlalchemy import text

ENVELOPE = "ab" * (cg.CUSTODY_TOPOLOGY_ENVELOPE_HEX // 2)
KEY = "cd" * 32


def _envelopes(slots):
    # Distinct per slot so a misrouted delivery is visible in an assertion.
    return {slot: f"{slot:02x}" + ENVELOPE[2:] for slot in range(1, slots + 1)}


@pytest_asyncio.fixture
async def clean_custody_state(setup_db):
    async def _wipe():
        async with async_session() as db:
            await db.execute(
                text("DELETE FROM vault_config WHERE key LIKE :key"),
                {"key": f"{cg.CUSTODY_STATE_CONFIG_KEY}%"},
            )
            await db.execute(text("DELETE FROM vault_custody_topology_reshare"))
            await db.commit()

    await _wipe()
    yield
    await _wipe()


class Pool:
    def __init__(self, *, threshold=2, slots=3, keys=None):
        self.threshold = threshold
        self.slots = slots
        self.keys = keys or {slot: KEY for slot in range(1, slots + 1)}
        self.events = []
        self.client = object()
        # None until a test says the daemons hold a generation; the
        # superseded-state sweep refuses a pool that cannot prove it.
        self.generation = None
        self.active_slot = 1
        self.generated = None
        self.fail_generate = False

    async def share_statuses(self):
        return {
            slot: {
                "slot": slot,
                "threshold": self.threshold,
                "slots": self.slots,
                "generation": self.generation,
                "transport_public_key": self.keys[slot],
            }
            for slot in range(1, self.slots + 1)
        }

    async def seal_all(self):
        self.events.append(("seal",))

    async def unseal(self, *, generation):
        self.events.append(("unseal", generation))
        return self.client

    async def generate_topology_reshare(
        self, generation, *, threshold, slots, peer_keys
    ):
        self.events.append(("generate", generation, threshold, slots, peer_keys))
        if self.fail_generate:
            raise CustodianPoolUnavailable("coordinator unavailable")
        self.generated = _envelopes(slots)
        return self.generated

    async def deliver_topology_reshare(self, generation, deliveries):
        self.events.append(("deliver", generation, sorted(deliveries)))
        return {slot: "installed" for slot in deliveries}

    async def rollback_generation_all(self, generation):
        self.events.append(("rollback", generation))

    async def commit_generation_all(self, generation):
        self.events.append(("commit", generation))

    async def finalize_generation_all(self, generation):
        self.events.append(("finalize", generation))


async def _state():
    async with async_session() as db:
        return await cg.get_custody_generation_state(db)


async def _deliveries():
    async with async_session() as db:
        return await cg.get_custody_topology_deliveries(db)


async def _set_stable(generation, threshold, slots):
    async with async_session() as db:
        await cg._write(
            db,
            cg.CustodyGenerationState(
                version=cg.CUSTODY_STATE_VERSION,
                phase="stable",
                active_generation=generation,
                target_generation=None,
                previous_generation=None,
                threshold=threshold,
                slots=slots,
            ),
        )
        await db.commit()


async def test_begin_records_envelopes_and_leaves_the_pool_alone(clean_custody_state):
    await _set_stable(7, 2, 3)
    pool = Pool()

    target = await custody_reshare.begin_rust_custodian_topology_change(
        pool, threshold=3, slots=5, new_peer_keys={4: KEY, 5: KEY}
    )

    assert target == 8
    state = await _state()
    assert state.phase == "resharding"
    assert (state.active_generation, state.target_generation) == (7, 8)
    # The durable shape is still the one the daemons run: that is what an
    # abort returns to, and nothing has left the old generation yet.
    assert (state.threshold, state.slots) == (2, 3)
    assert await _deliveries() == (8, 3, 5, _envelopes(5))
    # No share transition was asked of the running pool.
    assert not [event for event in pool.events if event[0] in {"commit", "rollback"}]


async def test_begin_reads_surviving_keys_from_the_daemons(clean_custody_state):
    """A caller may key the slots the target adds, and nothing else."""
    await _set_stable(7, 2, 3)
    pool = Pool(keys={1: "11" * 32, 2: "22" * 32, 3: "33" * 32})

    await custody_reshare.begin_rust_custodian_topology_change(
        pool, threshold=3, slots=5, new_peer_keys={4: "44" * 32, 5: "55" * 32}
    )

    (generate,) = [event for event in pool.events if event[0] == "generate"]
    assert generate[4] == {
        1: "11" * 32,
        2: "22" * 32,
        3: "33" * 32,
        4: "44" * 32,
        5: "55" * 32,
    }


@pytest.mark.parametrize(
    "new_peer_keys",
    [
        {},
        {4: KEY},
        {4: KEY, 5: KEY, 6: KEY},
        {1: KEY, 4: KEY, 5: KEY},
    ],
)
async def test_begin_needs_a_key_for_exactly_the_added_slots(
    clean_custody_state, new_peer_keys
):
    await _set_stable(7, 2, 3)
    pool = Pool()
    with pytest.raises(ValueError):
        await custody_reshare.begin_rust_custodian_topology_change(
            pool, threshold=3, slots=5, new_peer_keys=new_peer_keys
        )
    assert (await _state()).phase == "stable"
    assert await _deliveries() is None


async def test_begin_refuses_a_same_shape_target(clean_custody_state):
    """That is the transactional native reshare, which does not need this."""
    await _set_stable(7, 2, 3)
    with pytest.raises(cg.CustodyGenerationConflict):
        await custody_reshare.begin_rust_custodian_topology_change(
            Pool(), threshold=2, slots=3
        )
    assert (await _state()).phase == "stable"


async def test_a_failed_generate_drops_the_target(clean_custody_state):
    await _set_stable(7, 2, 3)
    pool = Pool()
    pool.fail_generate = True

    with pytest.raises(CustodianPoolUnavailable):
        await custody_reshare.begin_rust_custodian_topology_change(
            pool, threshold=3, slots=5, new_peer_keys={4: KEY, 5: KEY}
        )

    state = await _state()
    assert state.phase == "stable"
    assert (state.active_generation, state.threshold, state.slots) == (7, 2, 3)
    assert await _deliveries() is None


async def test_relaunch_under_the_target_rolls_the_transition_forward(
    clean_custody_state,
):
    await _set_stable(7, 2, 3)
    await custody_reshare.begin_rust_custodian_topology_change(
        Pool(), threshold=3, slots=5, new_peer_keys={4: KEY, 5: KEY}
    )

    # The operator restarted the pool with the target environment.
    relaunched = Pool(threshold=3, slots=5)
    client = await custody_reshare.reconcile_rust_custody_generation(relaunched)

    assert client is relaunched.client
    state = await _state()
    assert state.phase == "stable"
    assert (state.active_generation, state.threshold, state.slots) == (8, 3, 5)
    assert ("deliver", 8, [1, 2, 3, 4, 5]) in relaunched.events
    # The only copy of the new generation is now in the daemons.
    assert await _deliveries() is None


async def test_relaunch_under_the_old_shape_reverts_the_transition(
    clean_custody_state,
):
    await _set_stable(7, 2, 3)
    await custody_reshare.begin_rust_custodian_topology_change(
        Pool(), threshold=3, slots=5, new_peer_keys={4: KEY, 5: KEY}
    )

    # The operator put the environment back instead.
    reverted = Pool(threshold=2, slots=3)
    client = await custody_reshare.reconcile_rust_custody_generation(reverted)

    assert client is reverted.client
    state = await _state()
    assert state.phase == "stable"
    assert (state.active_generation, state.threshold, state.slots) == (7, 2, 3)
    assert not [event for event in reverted.events if event[0] == "deliver"]
    assert await _deliveries() is None
    # The generation the transition would have replaced is served again, which
    # is the whole point of never touching it.
    assert ("unseal", 7) in reverted.events


async def test_reconcile_does_not_roll_a_topology_change_back_as_a_prepare(
    clean_custody_state,
):
    """Why the transition has a phase of its own.

    Under `preparing`, reconcile rolls back unconditionally. Relaunched
    daemons hold nothing to roll back, so `rollback_share` would answer
    `already-rolled-back` and the rollback would look like it worked, leaving
    the durable decision on a generation no slot has -- unrecoverable short of
    hand-editing vault_config. So: the ceremony must never leave the state in
    `preparing`, and a relaunched pool must never be asked to roll back.
    """
    await _set_stable(7, 2, 3)
    await custody_reshare.begin_rust_custodian_topology_change(
        Pool(), threshold=3, slots=5, new_peer_keys={4: KEY, 5: KEY}
    )
    assert (await _state()).phase == "resharding"

    relaunched = Pool(threshold=3, slots=5)
    await custody_reshare.reconcile_rust_custody_generation(relaunched)

    assert not [event for event in relaunched.events if event[0] == "rollback"]
    assert (await _state()).active_generation == 8
    # And the same for the abort side, which is the case that most resembles
    # a prepare rollback.
    await _set_stable(7, 2, 3)
    await custody_reshare.begin_rust_custodian_topology_change(
        Pool(), threshold=3, slots=5, new_peer_keys={4: KEY, 5: KEY}
    )
    reverted = Pool(threshold=2, slots=3)
    await custody_reshare.reconcile_rust_custody_generation(reverted)
    assert not [event for event in reverted.events if event[0] == "rollback"]


async def test_reconcile_refuses_a_third_topology(clean_custody_state):
    """Neither the shape it left nor the one it was going to."""
    await _set_stable(7, 2, 3)
    await custody_reshare.begin_rust_custodian_topology_change(
        Pool(), threshold=3, slots=5, new_peer_keys={4: KEY, 5: KEY}
    )

    with pytest.raises(CustodianPoolUnavailable):
        await custody_reshare.reconcile_rust_custody_generation(
            Pool(threshold=4, slots=7)
        )
    assert (await _state()).phase == "resharding"
    assert await _deliveries() is not None


async def test_a_crash_before_the_envelopes_land_reverts(clean_custody_state):
    """`resharding` with nothing recorded can only mean the target is lost."""
    await _set_stable(7, 2, 3)
    async with async_session() as db:
        await cg.begin_custody_topology_change(db, threshold=3, slots=5)
        await db.commit()
    assert (await _state()).phase == "resharding"

    reverted = Pool(threshold=2, slots=3)
    await custody_reshare.reconcile_rust_custody_generation(reverted)

    state = await _state()
    assert (state.phase, state.active_generation) == ("stable", 7)


async def test_delivery_is_recorded_once(clean_custody_state):
    """A second coordinator would split a different polynomial."""
    await _set_stable(7, 2, 3)
    async with async_session() as db:
        await cg.begin_custody_topology_change(db, threshold=3, slots=5)
        await cg.record_custody_topology_deliveries(
            db, generation=8, threshold=3, slots=5, deliveries=_envelopes(5)
        )
        await db.commit()

    async with async_session() as db:
        # The identical set is a retry of the same transfer.
        await cg.record_custody_topology_deliveries(
            db, generation=8, threshold=3, slots=5, deliveries=_envelopes(5)
        )
        other = _envelopes(5)
        other[3] = "ff" + other[3][2:]
        with pytest.raises(cg.CustodyGenerationConflict):
            await cg.record_custody_topology_deliveries(
                db, generation=8, threshold=3, slots=5, deliveries=other
            )


async def test_deliveries_must_cover_every_target_slot(clean_custody_state):
    await _set_stable(7, 2, 3)
    async with async_session() as db:
        await cg.begin_custody_topology_change(db, threshold=3, slots=5)
        partial = _envelopes(5)
        del partial[5]
        with pytest.raises(ValueError):
            await cg.record_custody_topology_deliveries(
                db, generation=8, threshold=3, slots=5, deliveries=partial
            )
        malformed = _envelopes(5)
        malformed[2] = "zz" + malformed[2][2:]
        with pytest.raises(ValueError):
            await cg.record_custody_topology_deliveries(
                db, generation=8, threshold=3, slots=5, deliveries=malformed
            )


async def test_a_mixed_delivery_set_fails_closed(clean_custody_state):
    await _set_stable(7, 2, 3)
    async with async_session() as db:
        await cg.begin_custody_topology_change(db, threshold=3, slots=5)
        await cg.record_custody_topology_deliveries(
            db, generation=8, threshold=3, slots=5, deliveries=_envelopes(5)
        )
        await db.execute(
            text(
                "UPDATE vault_custody_topology_reshare SET generation = 9 "
                "WHERE slot = 4"
            )
        )
        await db.commit()
    with pytest.raises(cg.CustodyGenerationCorrupt):
        await _deliveries()


async def test_a_resolved_change_sweeps_what_it_superseded(
    clean_custody_state, tmp_path, monkeypatch
):
    """The operator is not asked to remember the dead shape's share state.

    Closing the transition is the one moment the sweep is certainly right: it
    has just happened, and the pool is the target shape.
    """
    from api.app.config import settings

    monkeypatch.setattr(settings, "rust_custodian_key_dir", str(tmp_path))
    for slot in (1, 2, 3):
        (tmp_path / f"slot-{slot}.2-of-3.share-state").write_bytes(b"old")
    for slot in range(1, 6):
        (tmp_path / f"slot-{slot}.3-of-5.share-state").write_bytes(b"new")
        (tmp_path / f"slot-{slot}.transport-key").write_bytes(b"k" * 32)

    await _set_stable(7, 2, 3)
    await custody_reshare.begin_rust_custodian_topology_change(
        Pool(), threshold=3, slots=5, new_peer_keys={4: KEY, 5: KEY}
    )

    relaunched = Pool(threshold=3, slots=5)
    relaunched.generation = 8
    await custody_reshare.reconcile_rust_custody_generation(relaunched)

    # 2-of-3 needs two shares; one may stay, the rest are gone.
    survivors = list(tmp_path.glob("*.2-of-3.share-state"))
    assert len(survivors) == 1
    # Nothing the live shape needs was touched.
    assert len(list(tmp_path.glob("*.3-of-5.share-state"))) == 5
    assert len(list(tmp_path.glob("*.transport-key"))) == 5


async def test_a_refused_sweep_does_not_undo_a_closed_transition(
    clean_custody_state, tmp_path, monkeypatch
):
    """Hygiene must never cost correctness: the change is already durable."""
    from api.app.config import settings

    monkeypatch.setattr(settings, "rust_custodian_key_dir", str(tmp_path / "missing"))

    await _set_stable(7, 2, 3)
    await custody_reshare.begin_rust_custodian_topology_change(
        Pool(), threshold=3, slots=5, new_peer_keys={4: KEY, 5: KEY}
    )

    relaunched = Pool(threshold=3, slots=5)
    relaunched.generation = 8
    client = await custody_reshare.reconcile_rust_custody_generation(relaunched)

    assert client is relaunched.client
    state = await _state()
    assert (state.phase, state.active_generation, state.slots) == ("stable", 8, 5)
