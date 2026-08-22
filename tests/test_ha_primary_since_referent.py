# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""`primary_since` as the referent a peer-aware classifier can compare.

THE QUESTION LOCAL RULES CANNOT ANSWER. A frozen node knows it cannot reach
PostgreSQL. It does not know WHY, and the two causes want opposite reactions:
a SHARED outage means hold and keep the keys (the cluster is not moving on
without it), while its OWN isolation means seal fast (the cluster already
replaced it, and it is sitting on key material it will never use again). Today
both take the same path -- frozen at the TTL, fence at frozen_max -- so the
isolation case holds keys for 300s on a node the cluster has already written
off, and an attacker chooses when that window starts.

WHY THIS FIELD. `primary_since` is stamped with the PostgreSQL clock under the
election lock on every promote, so it MOVES AT EVERY FAILOVER. A peer reporting
a value strictly newer than a frozen node's is positive evidence that an
election completed without it.

`key_epoch` cannot do this -- it tracks key rotations, not elections, and does
not move at failover. `observed_generation` does not exist anywhere in the
codebase; it has no referent at all, which is why `generation` was rejected.

SCOPE. This is step 1: publish the referent, do not act on it. No
classification changes here. The tests pin the properties a later classifier
will depend on.
"""

from datetime import datetime, timezone

import pytest_asyncio
from api.app import cluster_membership
from api.app.database import async_session
from api.app.vault_state import VaultState
from sqlalchemy import text


@pytest_asyncio.fixture
async def clean_primary_since(setup_db):
    """Only the row these tests touch.

    Deliberately narrower than the auto-promote suite's `fresh`, which wipes
    the whole cluster state and neutralises election jitter. Nothing here
    elects anything; borrowing that fixture would couple these tests to setup
    they do not need and would hide which row actually matters.
    """
    await _delete_since()
    yield
    await _delete_since()


async def _delete_since() -> None:
    async with async_session() as db:
        await db.execute(
            text("DELETE FROM vault_cluster_config WHERE key = :k"),
            {"k": "primary_since"},
        )
        await db.commit()


async def _set_config(db, key: str, value: str) -> None:
    await db.execute(
        text(
            "INSERT INTO vault_cluster_config (key, value) VALUES (:k, :v) "
            "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value"
        ),
        {"k": key, "v": value},
    )
    await db.commit()


async def test_primary_since_is_read_back(clean_primary_since):
    """It was written six times and read zero times before this change.

    The referent existed and was inert. A classifier cannot compare a value
    nobody fetches.
    """
    stamped = datetime(2026, 8, 22, 3, 14, 15, tzinfo=timezone.utc)
    async with async_session() as db:
        await _set_config(db, "primary_since", stamped.isoformat())
        _, _, _, since = await cluster_membership.read_canonical_primary(db)

    assert since == stamped


async def test_primary_since_rides_the_same_round_trip_as_the_clock(
    clean_primary_since,
):
    """One trip, so the term start and the clock cannot disagree.

    Fetching it separately would let a caller compare two readings taken at
    different instants and conclude an election had happened when none had.
    Asserted by shape: the same call returns both.
    """
    stamped = datetime(2026, 8, 22, 3, 14, 15, tzinfo=timezone.utc)
    async with async_session() as db:
        await _set_config(db, "primary_since", stamped.isoformat())
        _, _, db_now, since = await cluster_membership.read_canonical_primary(db)

    assert since == stamped
    assert db_now.tzinfo is not None, "the clock must be tz-aware to be comparable"
    assert since.tzinfo is not None


async def test_absent_primary_since_is_no_signal(clean_primary_since):
    """Pre-init clusters have no term start. None means 'nothing to compare'.

    A classifier must never read None as 'older than anything' -- that would
    turn a fresh cluster into evidence of isolation and seal it.
    """
    async with async_session() as db:
        _, _, _, since = await cluster_membership.read_canonical_primary(db)

    assert since is None


async def test_unparseable_primary_since_is_no_signal(clean_primary_since):
    """Garbage is not a timestamp and must not be treated as one.

    Same defence the lease already had. A value that cannot be parsed is
    absence of evidence, and the alternative -- raising -- would take down the
    heartbeat over a corrupt config row.
    """
    async with async_session() as db:
        await _set_config(db, "primary_since", "not-a-timestamp")
        _, _, _, since = await cluster_membership.read_canonical_primary(db)

    assert since is None


def test_cached_referent_cannot_outlive_its_confirmation():
    """The published value must age with the confirmation that produced it.

    It is cached on the same round-trip as renew_db_confirmation, so a reader
    judging it by `confirmation_age_seconds` is judging the right thing. If it
    could be refreshed independently, a frozen node could advertise a term
    start fresher than anything it had actually confirmed -- and a peer would
    compare against a value that was never true at that moment.
    """
    v = VaultState()
    v.note_primary_since("2026-08-22T03:14:15+00:00")
    v.renew_db_confirmation(ttl_secs=20.0, seal_grace_secs=300.0)

    assert v.last_primary_since == "2026-08-22T03:14:15+00:00"
    assert v.db_confirmation_age() is not None

    # Losing the confirmation must not silently leave a fresh-looking referent
    # behind claiming authority this node no longer has.
    v.release_db_confirmation()
    assert v.db_confirmation_age() is None


# NOT TESTED HERE, deliberately: "a peer value strictly newer than mine means
# isolation". Writing that as a test today would assert that datetime
# comparison works -- a tautology wearing the costume of coverage, since no
# code performs the comparison yet. The rule is specified in
# sextant rhorizon/user/plan_peer_aware_classification.md and gets a real test
# when step 2 gives it something to exercise. Strictly newer, not merely
# different: equal means the same term, which is the shared-outage case where
# holding is correct.
