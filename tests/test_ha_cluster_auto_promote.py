# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""post-close (2026-06-01) -- auto-promote v1.

Targets the two body functions extended this round :

- ``cluster_ha_loops._heartbeat_body`` -- the primary's heartbeat also
  UPSERTs ``primary_lease_expires_at`` in vault_cluster_config.
  Secondaries touch only their own row (no lease write).
- ``cluster_ha_loops._maybe_auto_promote`` -- a secondary observing a
  stale lease (NOW > lease + skew) claims primary under
  PRIMARY_ELECTION_LOCK, sets primary_uuid, resets the lease, and
  emits a ``cluster_primary_auto_elected`` audit row.

Indirection : the bodies are sync helpers ; we drive them directly
under an explicit DB state instead of running the daemon loops.
Jitter is neutralised via a ``secrets.randbelow``-returning-0 stub
so tests do not pay the [0, ttl/6] sleep.

Cf docs/HA-CLUSTER.md s15 "Auto-promote v1".
"""

import types
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from api.app import cluster_ha_loops as loops
from api.app import node_uuid as nu
from api.app.config import settings
from api.app.database import async_session
from sqlalchemy import text

_OTHER_NODE_UUID = "ffffeeeeddddccccbbbbaaaa99998888"


async def _insert_node(
    *,
    node_uuid: str,
    source_ip: str = "10.0.0.1",
    ha_state: str = "secondary",
    quarantine_secs: int = -60,  # already elapsed by default
    joined_offset_secs: int = 0,
    heartbeat_offset_secs: int | None = 1,
    role_changed_offset_secs: int | None = None,
):
    async with async_session() as db:
        await db.execute(
            text(
                "INSERT INTO vault_cluster_nodes ("
                "    node_uuid, source_ip, ha_state, quarantine_until, "
                "    joined_at, cluster_version, cert_fingerprint, "
                "    cert_not_after, last_heartbeat"
                ") VALUES ("
                "    :u, CAST(:ip AS INET), :s, "
                "    NOW() + make_interval(secs => :qs), "
                "    NOW() - make_interval(secs => :jo), "
                "    '1.0.0-beta', 'fpr', NOW() + INTERVAL '30 days', "
                "    CASE WHEN CAST(:hb AS INT) IS NULL THEN NULL ELSE "
                "         NOW() - make_interval(secs => CAST(:hb AS INT)) END"
                ")"
            ),
            {
                "u": node_uuid,
                "ip": source_ip,
                "s": ha_state,
                "qs": quarantine_secs,
                "jo": joined_offset_secs,
                "hb": heartbeat_offset_secs,
            },
        )
        # role_changed_at : left NULL by default (= no cooldown). When an
        # offset is given, stamp NOW(), offset so the dwell-time gate in
        # _maybe_auto_promote can be exercised (recent change -> blocked,
        # old change -> eligible).
        if role_changed_offset_secs is not None:
            await db.execute(
                text(
                    "UPDATE vault_cluster_nodes "
                    "SET role_changed_at = NOW() - make_interval(secs => :rc) "
                    "WHERE node_uuid = :u"
                ),
                {"rc": role_changed_offset_secs, "u": node_uuid},
            )
        await db.commit()


async def _set_config(key: str, value: str):
    async with async_session() as db:
        await db.execute(
            text(
                "INSERT INTO vault_cluster_config (key, value) VALUES (:k, :v) "
                "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value"
            ),
            {"k": key, "v": value},
        )
        await db.commit()


async def _read_config(key: str) -> str | None:
    async with async_session() as db:
        r = await db.execute(
            text("SELECT value FROM vault_cluster_config WHERE key = :k"),
            {"k": key},
        )
        row = r.fetchone()
        return row.value if row else None


async def _get_state(node_uuid: str) -> str | None:
    async with async_session() as db:
        r = await db.execute(
            text("SELECT ha_state FROM vault_cluster_nodes WHERE node_uuid = :u"),
            {"u": node_uuid},
        )
        row = r.fetchone()
        return row.ha_state if row else None


async def _wipe():
    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_cluster_nodes"))
        await db.execute(
            text(
                "DELETE FROM vault_cluster_config WHERE key IN ("
                "    'primary_uuid', 'primary_since', "
                "    'primary_lease_expires_at'"
                ")"
            )
        )
        await db.commit()


@pytest_asyncio.fixture
async def fresh(setup_db, monkeypatch):
    """Clean cluster state + zero-jitter election + ensure node_uuid file exists."""
    # Ensure the test node has a node_uuid file (idempotent).
    nu.init_node_uuid(settings.node_uuid_path)
    # Neutralise the jitter sleep so tests don't pay [0, ttl/6] seconds.
    monkeypatch.setattr(loops, "secrets", types.SimpleNamespace(randbelow=lambda _n: 0))
    await _wipe()
    yield
    await _wipe()


# ---------------------------------------------------------------------------
# _heartbeat_body : lease writer
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_heartbeat_primary_writes_lease(fresh):
    """If self is primary, heartbeat ALSO UPSERTs primary_lease_expires_at."""
    self_uuid = nu.get_node_uuid()
    await _insert_node(node_uuid=self_uuid, ha_state="primary")
    await _set_config("primary_uuid", self_uuid)

    before_lease = await _read_config("primary_lease_expires_at")
    assert before_lease is None

    async with async_session() as db:
        ok = await loops._heartbeat_body(db, self_uuid)
    assert ok is True

    lease_iso = await _read_config("primary_lease_expires_at")
    assert lease_iso is not None
    lease_dt = datetime.fromisoformat(lease_iso)
    now = datetime.now(timezone.utc)
    ttl = settings.cluster_primary_lease_ttl_secs
    # The lease should be in the future, within (ttl, 2s, ttl + 2s).
    delta = (lease_dt - now).total_seconds()
    assert ttl - 2 <= delta <= ttl + 2


@pytest.mark.asyncio
async def test_heartbeat_secondary_does_not_write_lease(fresh):
    """A secondary's heartbeat touches its own row only, never the lease."""
    self_uuid = nu.get_node_uuid()
    await _insert_node(node_uuid=self_uuid, ha_state="secondary")
    # Primary is some other node.
    await _set_config("primary_uuid", _OTHER_NODE_UUID)

    async with async_session() as db:
        ok = await loops._heartbeat_body(db, self_uuid)
    assert ok is True

    # Lease row was NOT created by this secondary.
    assert await _read_config("primary_lease_expires_at") is None


@pytest.mark.asyncio
async def test_heartbeat_no_primary_uuid_set_does_not_write_lease(fresh):
    """Pre-cluster-init state : no primary_uuid -> no lease write."""
    self_uuid = nu.get_node_uuid()
    await _insert_node(node_uuid=self_uuid, ha_state="primary")
    # NOTE : no primary_uuid in vault_cluster_config.

    async with async_session() as db:
        ok = await loops._heartbeat_body(db, self_uuid)
    assert ok is True

    assert await _read_config("primary_lease_expires_at") is None


@pytest.mark.asyncio
async def test_heartbeat_no_row_returns_false_and_no_lease(fresh):
    """No vault_cluster_nodes row for self -> early return False, no lease."""
    self_uuid = nu.get_node_uuid()
    # Even if primary_uuid points at us, an absent membership row means we
    # have not yet JOINed -- nothing to UPDATE, nothing to extend.
    await _set_config("primary_uuid", self_uuid)

    async with async_session() as db:
        ok = await loops._heartbeat_body(db, self_uuid)
    assert ok is False

    assert await _read_config("primary_lease_expires_at") is None


# ---------------------------------------------------------------------------
# _maybe_auto_promote : election trigger
# ---------------------------------------------------------------------------


async def _seed_stale_lease(secs_in_past: int = 60):
    """Write a primary_lease_expires_at that is firmly in the past."""
    expired = datetime.now(timezone.utc) - timedelta(seconds=secs_in_past)
    await _set_config("primary_lease_expires_at", expired.isoformat())


async def _seed_fresh_lease(secs_in_future: int = 60):
    fresh_dt = datetime.now(timezone.utc) + timedelta(seconds=secs_in_future)
    await _set_config("primary_lease_expires_at", fresh_dt.isoformat())


@pytest.mark.asyncio
async def test_auto_promote_no_lease_returns_zero(fresh):
    """No lease row established yet -> no election trigger."""
    self_uuid = nu.get_node_uuid()
    await _insert_node(node_uuid=self_uuid, ha_state="secondary")
    await _set_config("primary_uuid", _OTHER_NODE_UUID)

    async with async_session() as db:
        n = await loops._maybe_auto_promote(db)
    assert n == 0
    assert await _get_state(self_uuid) == "secondary"


@pytest.mark.asyncio
async def test_auto_promote_lease_fresh_returns_zero(fresh):
    """Lease still within the skew window -> no election."""
    self_uuid = nu.get_node_uuid()
    await _insert_node(node_uuid=self_uuid, ha_state="secondary")
    await _set_config("primary_uuid", _OTHER_NODE_UUID)
    await _seed_fresh_lease(secs_in_future=60)

    async with async_session() as db:
        n = await loops._maybe_auto_promote(db)
    assert n == 0
    assert await _get_state(self_uuid) == "secondary"
    # primary_uuid not flipped.
    assert await _read_config("primary_uuid") == _OTHER_NODE_UUID


@pytest.mark.asyncio
async def test_auto_promote_self_already_primary_returns_zero(fresh):
    """If self is already primary_uuid, no election triggers."""
    self_uuid = nu.get_node_uuid()
    await _insert_node(node_uuid=self_uuid, ha_state="primary")
    await _set_config("primary_uuid", self_uuid)
    await _seed_stale_lease()

    async with async_session() as db:
        n = await loops._maybe_auto_promote(db)
    assert n == 0


@pytest.mark.asyncio
async def test_auto_promote_self_not_secondary_returns_zero(fresh):
    """Self in 'joining' (not secondary) -> not eligible."""
    self_uuid = nu.get_node_uuid()
    await _insert_node(node_uuid=self_uuid, ha_state="joining")
    await _set_config("primary_uuid", _OTHER_NODE_UUID)
    await _seed_stale_lease()

    async with async_session() as db:
        n = await loops._maybe_auto_promote(db)
    assert n == 0
    assert await _get_state(self_uuid) == "joining"


@pytest.mark.asyncio
async def test_auto_promote_self_stale_heartbeat_returns_zero(fresh):
    """Self's own heartbeat is stale -> not eligible (we're sick too)."""
    self_uuid = nu.get_node_uuid()
    stale = settings.cluster_heartbeat_interval_secs * 10
    await _insert_node(
        node_uuid=self_uuid, ha_state="secondary", heartbeat_offset_secs=stale
    )
    await _set_config("primary_uuid", _OTHER_NODE_UUID)
    await _seed_stale_lease()

    async with async_session() as db:
        n = await loops._maybe_auto_promote(db)
    assert n == 0
    assert await _get_state(self_uuid) == "secondary"


@pytest.mark.asyncio
async def test_auto_promote_invalid_lease_value_returns_zero(fresh):
    """Corrupt ISO-8601 in the lease row -> log warn, no election."""
    self_uuid = nu.get_node_uuid()
    await _insert_node(node_uuid=self_uuid, ha_state="secondary")
    await _set_config("primary_uuid", _OTHER_NODE_UUID)
    await _set_config("primary_lease_expires_at", "not-a-timestamp")

    async with async_session() as db:
        n = await loops._maybe_auto_promote(db)
    assert n == 0
    assert await _get_state(self_uuid) == "secondary"


@pytest.mark.asyncio
async def test_auto_promote_lease_expired_self_eligible_promotes(fresh):
    """Stale lease + self eligible secondary -> promote, update primary_uuid + lease."""
    self_uuid = nu.get_node_uuid()
    await _insert_node(node_uuid=self_uuid, ha_state="secondary")
    await _set_config("primary_uuid", _OTHER_NODE_UUID)
    await _seed_stale_lease()

    async with async_session() as db:
        n = await loops._maybe_auto_promote(db)
    assert n == 1
    assert await _get_state(self_uuid) == "primary"
    # primary_uuid flipped to self.
    assert await _read_config("primary_uuid") == self_uuid
    # primary_since stamped.
    since_iso = await _read_config("primary_since")
    assert since_iso is not None
    # Lease reset to NOW + ttl (fresh future deadline).
    new_lease = await _read_config("primary_lease_expires_at")
    new_lease_dt = datetime.fromisoformat(new_lease)
    now = datetime.now(timezone.utc)
    delta = (new_lease_dt - now).total_seconds()
    ttl = settings.cluster_primary_lease_ttl_secs
    assert ttl - 2 <= delta <= ttl + 2


@pytest.mark.asyncio
async def test_auto_promote_demotes_previous_primary_in_same_transaction(fresh):
    """The old primary row cannot overlap the newly elected primary."""
    self_uuid = nu.get_node_uuid()
    await _insert_node(node_uuid=self_uuid, ha_state="secondary")
    await _insert_node(
        node_uuid=_OTHER_NODE_UUID,
        source_ip="10.0.0.1",
        ha_state="primary",
    )
    await _set_config("primary_uuid", _OTHER_NODE_UUID)
    await _seed_stale_lease()

    async with async_session() as db:
        n = await loops._maybe_auto_promote(db)

    assert n == 1
    assert await _get_state(self_uuid) == "primary"
    assert await _get_state(_OTHER_NODE_UUID) == "secondary"
    async with async_session() as db:
        primary_count = (
            await db.execute(
                text(
                    "SELECT count(*) FROM vault_cluster_nodes "
                    "WHERE ha_state = 'primary'"
                )
            )
        ).scalar()
    assert primary_count == 1


# ---------------------------------------------------------------------------
# _maybe_auto_promote : demotion cooldown (anti-thrash, sprint 1.x)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_auto_promote_blocked_during_cooldown(fresh, monkeypatch):
    """A node that changed role within the cooldown window is NOT eligible.

    Models the partition-heal thrash case : the returning ex-primary lands
    in 'secondary' (role_changed_at = NOW()) ; even with a stale lease it
    must dwell before it can re-claim primary.
    """
    monkeypatch.setattr(settings, "cluster_auto_promote_cooldown_secs", 15)
    self_uuid = nu.get_node_uuid()
    # role changed 1s ago -- well inside the 15s cooldown.
    await _insert_node(
        node_uuid=self_uuid, ha_state="secondary", role_changed_offset_secs=1
    )
    await _set_config("primary_uuid", _OTHER_NODE_UUID)
    await _seed_stale_lease()

    async with async_session() as db:
        n = await loops._maybe_auto_promote(db)
    assert n == 0
    assert await _get_state(self_uuid) == "secondary"
    # Lease untouched : no election happened.
    assert await _read_config("primary_uuid") == _OTHER_NODE_UUID


@pytest.mark.asyncio
async def test_auto_promote_allowed_after_cooldown_elapsed(fresh, monkeypatch):
    """Once the dwell window has elapsed, the node is eligible again."""
    monkeypatch.setattr(settings, "cluster_auto_promote_cooldown_secs", 15)
    self_uuid = nu.get_node_uuid()
    # role changed 20s ago -- past the 15s cooldown.
    await _insert_node(
        node_uuid=self_uuid, ha_state="secondary", role_changed_offset_secs=20
    )
    await _set_config("primary_uuid", _OTHER_NODE_UUID)
    await _seed_stale_lease()

    async with async_session() as db:
        n = await loops._maybe_auto_promote(db)
    assert n == 1
    assert await _get_state(self_uuid) == "primary"


@pytest.mark.asyncio
async def test_auto_promote_cooldown_disabled_ignores_recent_change(fresh, monkeypatch):
    """cooldown_secs = 0 disables the gate : a just-demoted node promotes."""
    monkeypatch.setattr(settings, "cluster_auto_promote_cooldown_secs", 0)
    self_uuid = nu.get_node_uuid()
    await _insert_node(
        node_uuid=self_uuid, ha_state="secondary", role_changed_offset_secs=0
    )
    await _set_config("primary_uuid", _OTHER_NODE_UUID)
    await _seed_stale_lease()

    async with async_session() as db:
        n = await loops._maybe_auto_promote(db)
    assert n == 1
    assert await _get_state(self_uuid) == "primary"


@pytest.mark.asyncio
async def test_auto_promote_null_role_changed_at_is_eligible(fresh, monkeypatch):
    """NULL role_changed_at (pre-migration row, init primary) = no cooldown."""
    monkeypatch.setattr(settings, "cluster_auto_promote_cooldown_secs", 15)
    self_uuid = nu.get_node_uuid()
    # role_changed_offset_secs left None -> column stays NULL.
    await _insert_node(node_uuid=self_uuid, ha_state="secondary")
    await _set_config("primary_uuid", _OTHER_NODE_UUID)
    await _seed_stale_lease()

    async with async_session() as db:
        n = await loops._maybe_auto_promote(db)
    assert n == 1
    assert await _get_state(self_uuid) == "primary"


@pytest.mark.asyncio
async def test_auto_promote_emits_audit_row(fresh):
    """The auto-elected promote emits a cluster_primary_auto_elected audit row."""
    self_uuid = nu.get_node_uuid()
    await _insert_node(node_uuid=self_uuid, ha_state="secondary")
    await _set_config("primary_uuid", _OTHER_NODE_UUID)
    await _seed_stale_lease()

    async with async_session() as db:
        await loops._maybe_auto_promote(db)

    async with async_session() as db:
        r = await db.execute(
            text(
                "SELECT actor, action, target FROM vault_audit "
                "WHERE action = 'cluster_primary_auto_elected' "
                "ORDER BY timestamp DESC LIMIT 1"
            )
        )
        row = r.fetchone()
    assert row is not None
    assert row.actor == "auto-promote"
    assert row.target == self_uuid


@pytest.mark.asyncio
async def test_auto_promote_self_row_missing_returns_zero(fresh):
    """No membership row for self at all -> not eligible (pre-JOIN)."""
    # No _insert_node call for self_uuid : the vault_cluster_nodes row is absent.
    await _set_config("primary_uuid", _OTHER_NODE_UUID)
    await _seed_stale_lease()

    async with async_session() as db:
        n = await loops._maybe_auto_promote(db)
    assert n == 0
    # Nothing was written.
    assert await _read_config("primary_uuid") == _OTHER_NODE_UUID


# ---------------------------------------------------------------------------
# _state_machine_body integration : joining-flip + auto-promote in one tick
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_state_machine_combines_join_flip_and_auto_promote(fresh):
    """One tick : flips a joining row AND auto-promotes self. Return count = 2."""
    self_uuid = nu.get_node_uuid()
    await _insert_node(node_uuid=self_uuid, ha_state="secondary")
    # Another node ready to flip joining -> secondary.
    await _insert_node(
        node_uuid=_OTHER_NODE_UUID,
        ha_state="joining",
        quarantine_secs=-10,
        heartbeat_offset_secs=1,
        source_ip="10.0.0.1",
    )
    await _set_config("primary_uuid", "0" * 32)  # phantom primary, no row
    await _seed_stale_lease()

    async with async_session() as db:
        n = await loops._state_machine_body(db)

    # Expect : the joining-flip (other node -> secondary) AND self auto-promote.
    assert n == 2
    assert await _get_state(_OTHER_NODE_UUID) == "secondary"
    assert await _get_state(self_uuid) == "primary"
    assert await _read_config("primary_uuid") == self_uuid


# ---------------------------------------------------------------------------
# Clock authority : the lease is evaluated and stamped by PostgreSQL only
#
# The lease is a distributed deadline -- one node stamps it, the others judge
# it. While both sides read their own wall clock, the margin absorbing NTP
# disagreement was ttl/3, and that same margin is what orders the primary's
# monotonic self-fence BEFORE any secondary may promote. A node running more
# than ttl/3 ahead could therefore promote while the old primary was still
# serving. These tests pin the clock authority to the database.
#
# Each stubs loops.datetime with a clock skewed far into the future. Post-fix
# the promote/heartbeat paths never consult it, so the stub must have no
# effect ; before the fix each of these promoted or stamped on the fake clock.
# ---------------------------------------------------------------------------


def _skewed_clock(seconds_ahead: int):
    """Stand-in for loops.datetime whose .now() runs seconds_ahead fast."""
    return types.SimpleNamespace(
        now=lambda tz=None: (
            datetime.now(tz or timezone.utc) + timedelta(seconds=seconds_ahead)
        )
    )


@pytest.mark.asyncio
async def test_auto_promote_ignores_fast_local_clock(fresh, monkeypatch):
    """A node inside the exploitable skew window must not promote early.

    The window is narrow and has to be hit deliberately -- a wildly fast clock
    does NOT reach the lease gate, because gate 4 judges the node's own
    last_heartbeat (stamped by PG) against the same fast clock and finds it
    stale, so the node disqualifies itself. With ttl=20 / heartbeat=3 :

        gate 3 calls a fresh lease stale once  skew > ttl/3          = 6.67s
        gate 4 self-blocks once                skew + hb_age > 3*hb  = 9s

    so only skew in (6.67, 9] with a fresh heartbeat both passes gate 4 and
    fires gate 3 early. skew=8 with a 0s-old heartbeat sits in it.

    The lease here is 3s in the past : still fresh to PostgreSQL (3 < 6.67
    skew margin) but stale to a clock 8s fast. Before the fix this promoted
    while the real primary was still serving -- the primary's monotonic
    self-fence does not fire until ttl, so the ordering that keeps the two
    apart was inverted.
    """
    self_uuid = nu.get_node_uuid()
    await _insert_node(
        node_uuid=self_uuid, ha_state="secondary", heartbeat_offset_secs=0
    )
    await _set_config("primary_uuid", _OTHER_NODE_UUID)
    await _seed_stale_lease(secs_in_past=3)  # "stale" only to the skewed clock

    monkeypatch.setattr(loops, "datetime", _skewed_clock(8))

    async with async_session() as db:
        n = await loops._maybe_auto_promote(db)

    assert n == 0, "promoted on a skewed local clock instead of PostgreSQL's"
    assert await _get_state(self_uuid) == "secondary"
    assert await _read_config("primary_uuid") == _OTHER_NODE_UUID


@pytest.mark.asyncio
async def test_auto_promote_still_fires_when_pg_says_stale(fresh, monkeypatch):
    """The guard is PG's clock, not "never promote" : a truly stale lease elects.

    Companion to the test above -- together they prove the gate moved to
    PostgreSQL rather than simply becoming harder to satisfy. Here the local
    clock is skewed BACKWARD, so a wall-clock reader would refuse.
    """
    self_uuid = nu.get_node_uuid()
    await _insert_node(node_uuid=self_uuid, ha_state="secondary")
    await _set_config("primary_uuid", _OTHER_NODE_UUID)
    await _seed_stale_lease(secs_in_past=60)

    monkeypatch.setattr(loops, "datetime", _skewed_clock(-3600))

    async with async_session() as db:
        n = await loops._maybe_auto_promote(db)
        await db.commit()

    assert n == 1
    assert await _get_state(self_uuid) == "primary"
    assert await _read_config("primary_uuid") == self_uuid


@pytest.mark.asyncio
async def test_heartbeat_stamps_lease_from_pg_clock(fresh, monkeypatch):
    """The primary's lease write is stamped by PG, not by a fast local clock.

    A lease stamped an hour ahead would be read as fresh by every secondary
    for that hour, disabling failover entirely.
    """
    self_uuid = nu.get_node_uuid()
    await _insert_node(node_uuid=self_uuid, ha_state="primary")
    await _set_config("primary_uuid", self_uuid)

    monkeypatch.setattr(loops, "datetime", _skewed_clock(3600))

    async with async_session() as db:
        await loops._heartbeat_body(db, self_uuid)
        await db.commit()

    lease = datetime.fromisoformat(await _read_config("primary_lease_expires_at"))
    ttl = settings.cluster_primary_lease_ttl_secs
    ahead = (lease - datetime.now(timezone.utc)).total_seconds()
    # Expect ~ttl ahead of real time. On the skewed clock it would be ttl+3600.
    assert ttl - 10 < ahead < ttl + 10, f"lease is {ahead}s ahead, expected ~{ttl}s"


@pytest.mark.asyncio
async def test_read_canonical_primary_clock_advances_within_transaction(fresh):
    """db_now must be clock_timestamp(), not NOW().

    NOW() is transaction_timestamp() and is frozen for the life of the
    transaction. _maybe_auto_promote sleeps on its election jitter INSIDE the
    transaction holding the advisory lock, so a frozen reading would make the
    under-lock re-check judge a stale moment and stamp a lease short by the
    jitter. Guards against a future "simplification" back to NOW().
    """
    import asyncio

    from api.app import cluster_membership

    async with async_session() as db:
        _, _, first, _ = await cluster_membership.read_canonical_primary(db)
        await asyncio.sleep(1.1)
        _, _, second, _ = await cluster_membership.read_canonical_primary(db)

    advanced = (second - first).total_seconds()
    assert advanced > 1.0, (
        f"db_now advanced only {advanced}s across a 1.1s in-transaction sleep -- "
        "this is NOW()/transaction_timestamp(), not clock_timestamp()"
    )
