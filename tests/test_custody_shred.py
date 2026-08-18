"""Putting a superseded custody shape below its own threshold.

Two things are asserted throughout: that what survives cannot reconstruct the
bundle, and that nothing beyond that is touched. Deleting custody state has no
soft landing -- below quorum the API does not start and no master password
recovers it -- so every file left alone is a file a bug here cannot destroy.
"""

import pytest
import pytest_asyncio
from api.app import custody_generation as cg
from api.app import custody_shred
from api.app.cluster_rpc import CustodianPoolUnavailable
from api.app.custody_shred import CustodyShredRefused, shred_superseded_custody_state
from api.app.database import async_session
from sqlalchemy import text


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
    def __init__(self, *, threshold=2, slots=3, generation=7, overrides=None):
        self.threshold = threshold
        self.slots = slots
        self.generation = generation
        self.overrides = overrides or {}
        self.status_calls = 0
        self.unavailable = False

    async def share_statuses(self):
        self.status_calls += 1
        if self.unavailable:
            raise CustodianPoolUnavailable("no quorum")
        statuses = {}
        for slot in range(1, self.slots + 1):
            status = {
                "slot": slot,
                "threshold": self.threshold,
                "slots": self.slots,
                "generation": self.generation,
                "prepared_generation": None,
                "previous_generation": None,
                "reshare_generation": None,
            }
            status.update(self.overrides.get(slot, {}))
            statuses[slot] = status
        return statuses


async def _set_state(phase, generation, threshold, slots):
    async with async_session() as db:
        await cg._write(
            db,
            cg.CustodyGenerationState(
                version=cg.CUSTODY_STATE_VERSION,
                phase=phase,
                active_generation=generation,
                target_generation=None if phase == "stable" else generation + 1,
                previous_generation=None,
                threshold=threshold,
                slots=slots,
            ),
        )
        await db.commit()


def _populate(key_dir, shapes, keys):
    """shapes: {(threshold, slots): [slot, ...]}; keys: [slot, ...]."""
    for (threshold, slots), members in shapes.items():
        for slot in members:
            (key_dir / f"slot-{slot}.{threshold}-of-{slots}.share-state").write_bytes(
                bytes([slot]) * 32
            )
    for slot in keys:
        (key_dir / f"slot-{slot}.transport-key").write_bytes(b"k" * 32)


def _names(key_dir):
    return sorted(entry.name for entry in key_dir.iterdir())


def _decryptable(key_dir, threshold, slots):
    """Shares of a shape whose slot still owns a transport key."""
    return [
        slot
        for slot in range(1, slots + 1)
        if (key_dir / f"slot-{slot}.{threshold}-of-{slots}.share-state").is_file()
        and (key_dir / f"slot-{slot}.transport-key").is_file()
    ]


@pytest.mark.asyncio
async def test_a_grow_shreds_only_what_crosses_the_old_threshold(
    clean_custody_state, tmp_path
):
    # 3 -> 5. Every slot of the dead 2-of-3 shape is still live, so its shares
    # all still decrypt: three of them, and two is already enough. Exactly one
    # may stay.
    _populate(
        tmp_path, {(2, 3): [1, 2, 3], (3, 5): [1, 2, 3, 4, 5]}, keys=[1, 2, 3, 4, 5]
    )
    await _set_state("stable", 9, 3, 5)

    report = await shred_superseded_custody_state(
        Pool(threshold=3, slots=5, generation=9), key_dir=tmp_path
    )

    assert report["superseded_share_state"] == [
        "slot-2.2-of-3.share-state",
        "slot-3.2-of-3.share-state",
    ]
    assert report["orphan_transport_keys"] == []
    assert len(_decryptable(tmp_path, 2, 3)) == 1 < 2
    # The live shape is untouched, and a grow orphans no slot at all.
    assert len(_decryptable(tmp_path, 3, 5)) == 5
    assert all(
        (tmp_path / f"slot-{slot}.transport-key").is_file() for slot in range(1, 6)
    )


@pytest.mark.asyncio
async def test_a_deep_shrink_takes_orphaned_slots_whole(clean_custody_state, tmp_path):
    # 9 -> 3, the case that strands a whole reconstructible quorum. Slots 4-9
    # have no daemon left, so key AND state go: leaving the state would leave
    # a file no custodian could open, and one of those refuses to start a slot.
    # What survives of 5-of-9 is then three shares, below its five.
    _populate(
        tmp_path,
        {(5, 9): list(range(1, 10)), (2, 3): [1, 2, 3]},
        keys=list(range(1, 10)),
    )
    await _set_state("stable", 4, 2, 3)

    report = await shred_superseded_custody_state(
        Pool(threshold=2, slots=3, generation=4), key_dir=tmp_path
    )

    assert report["orphan_transport_keys"] == [
        f"slot-{slot}.transport-key" for slot in range(4, 10)
    ]
    assert report["superseded_share_state"] == [
        f"slot-{slot}.5-of-9.share-state" for slot in range(4, 10)
    ]
    assert report["residual"] == ["5-of-9: 3 decryptable of 5 needed"]
    assert len(_decryptable(tmp_path, 5, 9)) == 3 < 5
    # The three surviving slots keep everything they need.
    assert len(_decryptable(tmp_path, 2, 3)) == 3
    # And no unreadable file is left for a future relaunch to trip over.
    assert not [name for name in _names(tmp_path) if name.startswith("slot-4")]


@pytest.mark.asyncio
async def test_a_shallow_shrink_shreds_keys_and_the_one_share_that_remains_over(
    clean_custody_state, tmp_path
):
    # 5 -> 3. Orphaning slots 4-5 leaves three decryptable shares of a 3-of-5
    # shape, which is still exactly a quorum, so one share has to go too.
    _populate(
        tmp_path, {(3, 5): [1, 2, 3, 4, 5], (2, 3): [1, 2, 3]}, keys=[1, 2, 3, 4, 5]
    )
    await _set_state("stable", 3, 2, 3)

    report = await shred_superseded_custody_state(
        Pool(threshold=2, slots=3, generation=3), key_dir=tmp_path
    )

    assert report["orphan_transport_keys"] == [
        "slot-4.transport-key",
        "slot-5.transport-key",
    ]
    # Slots 4-5 go whole; slot 3 then crosses 3-of-5 below its threshold.
    assert report["superseded_share_state"] == [
        "slot-3.3-of-5.share-state",
        "slot-4.3-of-5.share-state",
        "slot-5.3-of-5.share-state",
    ]
    assert len(_decryptable(tmp_path, 3, 5)) == 2 < 3
    assert len(_decryptable(tmp_path, 2, 3)) == 3


@pytest.mark.asyncio
async def test_dry_run_touches_nothing(clean_custody_state, tmp_path):
    _populate(
        tmp_path, {(3, 5): [1, 2, 3, 4, 5], (2, 3): [1, 2, 3]}, keys=[1, 2, 3, 4, 5]
    )
    await _set_state("stable", 3, 2, 3)
    before = _names(tmp_path)

    report = await shred_superseded_custody_state(
        Pool(threshold=2, slots=3, generation=3), key_dir=tmp_path, dry_run=True
    )

    assert report["superseded_share_state"] or report["orphan_transport_keys"]
    assert _names(tmp_path) == before


@pytest.mark.asyncio
async def test_a_pending_transition_supersedes_nothing(clean_custody_state, tmp_path):
    # Mid-ceremony the older shape IS the revert path. Deleting it here would
    # take away the only thing that makes a change reversible.
    _populate(
        tmp_path, {(2, 3): [1, 2, 3], (3, 5): [1, 2, 3, 4, 5]}, keys=[1, 2, 3, 4, 5]
    )
    await _set_state("resharding", 7, 2, 3)
    before = _names(tmp_path)

    with pytest.raises(CustodyShredRefused, match="not stable"):
        await shred_superseded_custody_state(
            Pool(threshold=2, slots=3, generation=7), key_dir=tmp_path
        )
    assert _names(tmp_path) == before


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "overrides, expected",
    [
        ({2: {"generation": 6}}, "does not hold the active generation"),
        ({3: {"threshold": 3, "slots": 5}}, "does not run the durable topology"),
        ({1: {"prepared_generation": 8}}, "custody transaction in flight"),
        ({2: {"previous_generation": 6}}, "custody transaction in flight"),
        ({3: {"reshare_generation": 8}}, "custody transaction in flight"),
    ],
)
async def test_an_unhealthy_pool_deletes_nothing(
    clean_custody_state, tmp_path, overrides, expected
):
    _populate(
        tmp_path, {(2, 3): [1, 2, 3], (3, 5): [1, 2, 3, 4, 5]}, keys=[1, 2, 3, 4, 5]
    )
    await _set_state("stable", 7, 2, 3)
    before = _names(tmp_path)

    with pytest.raises(CustodyShredRefused, match=expected):
        await shred_superseded_custody_state(
            Pool(threshold=2, slots=3, generation=7, overrides=overrides),
            key_dir=tmp_path,
        )
    assert _names(tmp_path) == before


@pytest.mark.asyncio
async def test_an_unreachable_pool_deletes_nothing(clean_custody_state, tmp_path):
    _populate(
        tmp_path, {(2, 3): [1, 2, 3], (3, 5): [1, 2, 3, 4, 5]}, keys=[1, 2, 3, 4, 5]
    )
    await _set_state("stable", 7, 2, 3)
    pool = Pool(threshold=2, slots=3, generation=7)
    pool.unavailable = True
    before = _names(tmp_path)

    with pytest.raises(CustodyShredRefused, match="not reachable"):
        await shred_superseded_custody_state(pool, key_dir=tmp_path)
    assert _names(tmp_path) == before


@pytest.mark.asyncio
async def test_incomplete_live_state_on_disk_deletes_nothing(
    clean_custody_state, tmp_path
):
    # The daemons hold their shares in memory and answer happily; the disk is
    # what has to survive the next restart, so it is checked separately.
    _populate(tmp_path, {(2, 3): [1, 2], (3, 5): [1, 2, 3, 4, 5]}, keys=[1, 2, 3, 4, 5])
    await _set_state("stable", 7, 2, 3)
    before = _names(tmp_path)

    with pytest.raises(CustodyShredRefused, match="slot-3.2-of-3.share-state"):
        await shred_superseded_custody_state(
            Pool(threshold=2, slots=3, generation=7), key_dir=tmp_path
        )
    assert _names(tmp_path) == before


@pytest.mark.asyncio
async def test_shredded_bytes_are_overwritten_before_the_unlink(
    clean_custody_state, tmp_path, monkeypatch
):
    _populate(
        tmp_path, {(2, 3): [1, 2, 3], (3, 5): [1, 2, 3, 4, 5]}, keys=[1, 2, 3, 4, 5]
    )
    await _set_state("stable", 9, 3, 5)
    seen: list[bytes] = []
    real_unlink = custody_shred.Path.unlink

    def capture(self, *args, **kwargs):
        seen.append(self.read_bytes())
        return real_unlink(self, *args, **kwargs)

    monkeypatch.setattr(custody_shred.Path, "unlink", capture)

    await shred_superseded_custody_state(
        Pool(threshold=3, slots=5, generation=9), key_dir=tmp_path
    )

    assert seen
    assert all(set(content) == {0} for content in seen)
