"""Durable Rust custodian generation decisions and crash recovery states."""

import json

import pytest
import pytest_asyncio
from api.app import custody_generation as cg
from api.app.database import async_session
from sqlalchemy import text


@pytest_asyncio.fixture
async def preserve_custody_generation_state(setup_db):
    async with async_session() as db:
        row = (
            await db.execute(
                text("SELECT value FROM vault_config WHERE key = :key"),
                {"key": cg.CUSTODY_STATE_CONFIG_KEY},
            )
        ).fetchone()
        original = row.value if row else None
        await db.execute(
            text("DELETE FROM vault_config WHERE key LIKE :key"),
            {"key": f"{cg.CUSTODY_STATE_CONFIG_KEY}%"},
        )
        # The high-water mark is deliberately never reset by production code,
        # so the fixture has to clear it or a raised mark leaks into every
        # later test that expects the counter to start at 1.
        await db.execute(
            text("DELETE FROM vault_config WHERE key LIKE :key"),
            {"key": f"{cg.CUSTODY_HIGH_WATER_CONFIG_KEY}%"},
        )
        await db.commit()
    yield
    async with async_session() as db:
        if original is None:
            await db.execute(
                text("DELETE FROM vault_config WHERE key LIKE :key"),
                {"key": f"{cg.CUSTODY_STATE_CONFIG_KEY}%"},
            )
        else:
            await db.execute(
                text(
                    "INSERT INTO vault_config (key, value) VALUES (:key, :value) "
                    "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value"
                ),
                {"key": cg.custody_state_key(), "value": original},
            )
        await db.execute(
            text("DELETE FROM vault_config WHERE key LIKE :key"),
            {"key": f"{cg.CUSTODY_HIGH_WATER_CONFIG_KEY}%"},
        )
        await db.commit()


@pytest_asyncio.fixture
async def preserve_custody_activation_state(setup_db):
    async with async_session() as db:
        row = (
            await db.execute(
                text("SELECT value FROM vault_config WHERE key = :key"),
                {"key": cg.CUSTODY_ACTIVATION_CONFIG_KEY},
            )
        ).fetchone()
        original = row.value if row else None
        await db.execute(
            text("DELETE FROM vault_config WHERE key = :key"),
            {"key": cg.CUSTODY_ACTIVATION_CONFIG_KEY},
        )
        await db.commit()
    yield
    async with async_session() as db:
        if original is None:
            await db.execute(
                text("DELETE FROM vault_config WHERE key = :key"),
                {"key": cg.CUSTODY_ACTIVATION_CONFIG_KEY},
            )
        else:
            await db.execute(
                text(
                    "INSERT INTO vault_config (key, value) VALUES (:key, :value) "
                    "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value"
                ),
                {"key": cg.CUSTODY_ACTIVATION_CONFIG_KEY, "value": original},
            )
        await db.commit()


def test_generation_state_roundtrip_is_canonical_and_strict():
    state = cg.CustodyGenerationState(
        version=1,
        phase="committing",
        active_generation=9,
        target_generation=9,
        previous_generation=8,
        threshold=2,
        slots=3,
    )
    encoded = cg.encode_custody_generation_state(state)
    assert cg.parse_custody_generation_state(encoded) == state
    assert encoded == json.dumps(
        {
            "active_generation": 9,
            "phase": "committing",
            "previous_generation": 8,
            "slots": 3,
            "target_generation": 9,
            "threshold": 2,
            "version": 1,
        },
        separators=(",", ":"),
        sort_keys=True,
    )


def _state_json(**changes):
    value = {
        "version": 1,
        "phase": "stable",
        "active_generation": 1,
        "target_generation": None,
        "previous_generation": None,
        "threshold": 2,
        "slots": 3,
    }
    value.update(changes)
    return json.dumps(value)


def test_empty_state_encoding_and_parsing_uses_zero_topology():
    empty = cg.CustodyGenerationState.empty()
    assert (
        cg.parse_custody_generation_state(cg.encode_custody_generation_state(empty))
        == empty
    )


@pytest.mark.parametrize(
    "changes",
    [
        {"active_generation": True},
        {"active_generation": 0},
        {"threshold": True},
        {"slots": True},
        {"slots": 2},
        {"version": 2},
        {"phase": "unknown"},
        {
            "phase": "preparing",
            "target_generation": 2,
            "previous_generation": 1,
        },
    ],
)
def test_generation_state_rejects_invalid_scalar_fields(changes):
    with pytest.raises(cg.CustodyGenerationCorrupt):
        cg.parse_custody_generation_state(_state_json(**changes))


@pytest.mark.parametrize(
    "value",
    [
        "not-json",
        "{}",
        json.dumps(
            {
                "version": 1,
                "phase": "stable",
                "active_generation": 1,
                "target_generation": 2,
                "previous_generation": None,
                "threshold": 2,
                "slots": 3,
            }
        ),
        json.dumps(
            {
                "version": 1,
                "phase": "preparing",
                "active_generation": 2,
                "target_generation": 2,
                "previous_generation": None,
                "threshold": 2,
                "slots": 3,
            }
        ),
        json.dumps(
            {
                "version": 1,
                "phase": "committing",
                "active_generation": 3,
                "target_generation": 4,
                "previous_generation": 2,
                "threshold": 2,
                "slots": 3,
            }
        ),
        # previous >= active: a rollback target that is not older is the
        # corruption that matters. (active=3 with previous=None is NOT corrupt
        # any more -- it is the first commit after an abandon, where the
        # counter skipped ahead and there is genuinely nothing to roll back
        # to. Contiguity was incidental; strict ordering is the invariant.)
        json.dumps(
            {
                "version": 1,
                "phase": "committing",
                "active_generation": 3,
                "target_generation": 3,
                "previous_generation": 3,
                "threshold": 2,
                "slots": 3,
            }
        ),
        json.dumps(
            {
                "version": 1,
                "phase": "committing",
                "active_generation": 3,
                "target_generation": 3,
                "previous_generation": 4,
                "threshold": 2,
                "slots": 3,
            }
        ),
    ],
)
def test_generation_state_corruption_fails_closed(value):
    with pytest.raises(cg.CustodyGenerationCorrupt):
        cg.parse_custody_generation_state(value)


async def test_rust_custody_activation_defaults_sealed_and_roundtrips(
    preserve_custody_activation_state,
):
    async with async_session() as db:
        assert not await cg.get_rust_custody_activation(db)
        await cg.set_rust_custody_activation(db, unsealed=True)
        await db.commit()
    async with async_session() as db:
        assert await cg.get_rust_custody_activation(db)
        await cg.set_rust_custody_activation(db, unsealed=False)
        await db.commit()
    async with async_session() as db:
        assert not await cg.get_rust_custody_activation(db)


async def test_rust_custody_activation_rejects_corrupt_or_non_boolean_state(
    preserve_custody_activation_state,
):
    async with async_session() as db:
        await db.execute(
            text(
                "INSERT INTO vault_config (key, value) VALUES (:key, :value) "
                "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value"
            ),
            {"key": cg.CUSTODY_ACTIVATION_CONFIG_KEY, "value": "maybe"},
        )
        await db.commit()
    async with async_session() as db:
        with pytest.raises(cg.CustodyGenerationCorrupt, match="activation"):
            await cg.get_rust_custody_activation(db)
        with pytest.raises(ValueError, match="boolean"):
            await cg.set_rust_custody_activation(db, unsealed=1)


async def test_durable_state_selects_rollback_then_roll_forward(
    preserve_custody_generation_state,
):
    async with async_session() as db:
        preparing = await cg.begin_custody_generation(db, threshold=2, slots=3)
        assert preparing.phase == "preparing"
        assert preparing.active_generation is None
        assert preparing.target_generation == 1
        await db.commit()

    async with async_session() as db:
        observed = await cg.get_custody_generation_state(db)
        assert observed == preparing
        committing = await cg.choose_custody_generation(db, 1)
        assert committing.phase == "committing"
        assert committing.active_generation == 1
        assert committing.previous_generation is None
        await db.commit()

    async with async_session() as db:
        assert await cg.choose_custody_generation(db, 1) == committing
        await db.commit()

    async with async_session() as db:
        stable = await cg.finish_custody_generation(db, 1)
        assert stable.phase == "stable"
        assert stable.active_generation == 1
        await db.commit()

    async with async_session() as db:
        assert await cg.finish_custody_generation(db, 1) == stable
        await db.commit()

    async with async_session() as db:
        second = await cg.begin_custody_generation(db, threshold=2, slots=3)
        assert second.target_generation == 2
        await db.commit()
    async with async_session() as db:
        rolled_back = await cg.abort_custody_generation(db, 2)
        assert rolled_back.phase == "stable"
        assert rolled_back.active_generation == 1
        await db.commit()
    async with async_session() as db:
        assert await cg.abort_custody_generation(db, 2) == rolled_back
        await db.commit()


async def test_generation_transition_and_topology_conflicts_fail_closed(
    preserve_custody_generation_state,
):
    async with async_session() as db:
        with pytest.raises(ValueError, match="topology"):
            await cg.begin_custody_generation(db, threshold=1, slots=3)
        await db.rollback()
    async with async_session() as db:
        await cg.begin_custody_generation(db, threshold=2, slots=3)
        await db.commit()
    async with async_session() as db:
        with pytest.raises(cg.CustodyGenerationConflict, match="already preparing"):
            await cg.begin_custody_generation(db, threshold=2, slots=3)
        await db.rollback()
    async with async_session() as db:
        with pytest.raises(cg.CustodyGenerationConflict, match="not awaiting"):
            await cg.choose_custody_generation(db, 2)
        await db.rollback()
    async with async_session() as db:
        with pytest.raises(cg.CustodyGenerationConflict, match="rollback-eligible"):
            await cg.abort_custody_generation(db, 2)
        await db.rollback()
    async with async_session() as db:
        with pytest.raises(cg.CustodyGenerationConflict, match="ready to finalize"):
            await cg.finish_custody_generation(db, 1)
        await db.rollback()
    async with async_session() as db:
        await cg.choose_custody_generation(db, 1)
        await cg.finish_custody_generation(db, 1)
        await db.commit()
    async with async_session() as db:
        with pytest.raises(cg.CustodyGenerationConflict, match="topology change"):
            await cg.begin_custody_generation(db, threshold=3, slots=5)
        await db.rollback()


async def test_generation_counter_exhaustion_fails_closed(
    preserve_custody_generation_state,
):
    exhausted = cg.CustodyGenerationState(
        version=1,
        phase="stable",
        active_generation=cg.CUSTODY_GENERATION_MAX,
        target_generation=None,
        previous_generation=None,
        threshold=2,
        slots=3,
    )
    async with async_session() as db:
        await db.execute(
            text(
                "INSERT INTO vault_config (key, value) VALUES (:key, :value) "
                "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value"
            ),
            {
                "key": cg.custody_state_key(),
                "value": cg.encode_custody_generation_state(exhausted),
            },
        )
        await db.commit()
    async with async_session() as db:
        with pytest.raises(cg.CustodyGenerationConflict, match="exhausted"):
            await cg.begin_custody_generation(db, threshold=2, slots=3)
        await db.rollback()


async def test_uncommitted_generation_reservation_is_not_durable(
    preserve_custody_generation_state,
):
    async with async_session() as db:
        state = await cg.begin_custody_generation(db, threshold=2, slots=3)
        assert state.target_generation == 1
        await db.rollback()
    async with async_session() as db:
        assert (
            await cg.get_custody_generation_state(db)
            == cg.CustodyGenerationState.empty()
        )


async def test_persisted_corruption_is_never_coerced_to_empty(
    preserve_custody_generation_state,
):
    async with async_session() as db:
        await db.execute(
            text(
                "INSERT INTO vault_config (key, value) VALUES (:key, :value) "
                "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value"
            ),
            {"key": cg.custody_state_key(), "value": "{}"},
        )
        await db.commit()
    async with async_session() as db:
        with pytest.raises(cg.CustodyGenerationCorrupt):
            await cg.get_custody_generation_state(db)


@pytest.mark.asyncio
async def test_generation_never_restarts_after_an_abandon(
    preserve_custody_generation_state,
):
    """Transport envelopes bind the generation INSIDE the AEAD (transport.rs).

    abandon clears active_generation and the mint is `(active or 0) + 1`, so
    without a high-water mark the counter restarts at 1 -- which, with share
    persistence off, is every host reboot. A reused number lets an envelope
    captured from a previous incarnation authenticate against the new one. It
    fails closed via master_check, but that is the last line, not the binding.
    """
    async with async_session() as db:
        await cg.begin_custody_generation(db, threshold=2, slots=3)
        await db.commit()
    async with async_session() as db:
        await cg.choose_custody_generation(db, 1)
        await db.commit()
    async with async_session() as db:
        state = await cg.finish_custody_generation(db, 1)
        await db.commit()
    assert state.active_generation == 1

    async with async_session() as db:
        abandoned = await cg.abandon_custody_generation(db, 1)
        await db.commit()
    assert abandoned.active_generation is None

    # The pool is empty, so the state says nothing -- but the number 1 must
    # never be minted again.
    async with async_session() as db:
        reborn = await cg.begin_custody_generation(db, threshold=2, slots=3)
        await db.commit()
    assert reborn.target_generation == 2, "generation restarted after abandon"

    # And it keeps climbing across repeated abandons.
    async with async_session() as db:
        await cg.choose_custody_generation(db, 2)
        await db.commit()
    async with async_session() as db:
        await cg.finish_custody_generation(db, 2)
        await db.commit()
    async with async_session() as db:
        await cg.abandon_custody_generation(db, 2)
        await db.commit()
    async with async_session() as db:
        third = await cg.begin_custody_generation(db, threshold=2, slots=3)
        await db.commit()
    assert third.target_generation == 3


@pytest.mark.asyncio
async def test_a_malformed_high_water_mark_never_lowers_the_counter(
    preserve_custody_generation_state,
):
    """Corruption must not mint a number already in use, nor wedge the vault."""
    async with async_session() as db:
        await db.execute(
            text(
                "INSERT INTO vault_config (key, value) VALUES (:key, 'not-a-number') "
                "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value"
            ),
            {"key": cg.custody_high_water_key()},
        )
        await db.commit()

    async with async_session() as db:
        await cg.begin_custody_generation(db, threshold=2, slots=3)
        await db.commit()
    async with async_session() as db:
        await cg.choose_custody_generation(db, 1)
        await db.commit()
    async with async_session() as db:
        await cg.finish_custody_generation(db, 1)
        await db.commit()

    # Garbage floor is ignored, but the LIVE generation still bounds the mint,
    # so the next number is above the one in use rather than a repeat.
    async with async_session() as db:
        following = await cg.begin_custody_generation(db, threshold=2, slots=3)
        await db.commit()
    assert following.target_generation == 2


def test_a_gap_in_generation_numbers_is_not_corruption():
    """After an abandon the counter skips ahead and supersedes nothing.

    The high-water mark makes numbering monotonic but no longer contiguous, so
    a first commit in a new incarnation legitimately has active > 1 with no
    previous generation at all.
    """
    parsed = cg.parse_custody_generation_state(
        json.dumps(
            {
                "version": 1,
                "phase": "committing",
                "active_generation": 7,
                "target_generation": 7,
                "previous_generation": None,
                "threshold": 2,
                "slots": 3,
            }
        )
    )
    assert parsed.active_generation == 7
    assert parsed.previous_generation is None

    # A gap between previous and active is fine too, as long as it is older.
    gapped = cg.parse_custody_generation_state(
        json.dumps(
            {
                "version": 1,
                "phase": "committing",
                "active_generation": 9,
                "target_generation": 9,
                "previous_generation": 4,
                "threshold": 2,
                "slots": 3,
            }
        )
    )
    assert (gapped.active_generation, gapped.previous_generation) == (9, 4)
