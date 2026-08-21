# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Standalone: a dead local database must freeze the node, then seal it.

Before this existed, standalone had NEITHER behaviour. The HA loops are gated
on cluster_ha_enabled, so nothing ever set an authority deadline and nothing
sealed: PostgreSQL could die and the process would sit there failing every
request with the master key live in RAM, indefinitely.

The evidence bar differs from HA, which is why the thresholds do. In HA
"cannot reach the database" is ambiguous -- a reconvergence, a VIP settling,
this node's own NIC -- and a peer may be covering, so the node freezes and
waits rather than destroying keys over a transient event. Standalone has no
partition to blame and no peer that could be serving: the database is on this
machine, so sustained unreachability is evidence, and data protection wins.

Cf api/app/main.py::_standalone_db_watchdog.
"""

import asyncio
import contextlib

import pytest
from api.app import main
from api.app.config import Settings, settings
from api.app.vault_state import VaultState


class _Row:
    def __init__(self, in_recovery: bool, read_only: str):
        self.in_recovery = in_recovery
        self.read_only = read_only


class _Result:
    def __init__(self, row):
        self._row = row

    def fetchone(self):
        return self._row


class _FakeDB:
    """Models the three states the probe must tell apart.

    down       -- unreachable at all
    standby    -- reachable, pg_is_in_recovery() true (a replica)
    read_only  -- reachable primary, transaction_read_only on (full disk,
                  or configured read-only)
    """

    def __init__(self, state: dict):
        self._state = state

    async def execute(self, *a, **k):
        if self._state["down"]:
            raise ConnectionError("postgres is gone")
        return _Result(
            _Row(
                self._state.get("standby", False),
                "on" if self._state.get("read_only", False) else "off",
            )
        )


class _FakeSession:
    """async_session() stand-in whose reachability the test flips."""

    def __init__(self, state: dict):
        self._state = state

    def __call__(self):
        return self

    async def __aenter__(self):
        return _FakeDB(self._state)

    async def __aexit__(self, *a):
        return False


@contextlib.asynccontextmanager
async def _watchdog(monkeypatch, *, freeze=3, seal=6, down=False):
    """Run the real watchdog against a fake database and a fresh VaultState."""
    state = {"down": down, "sealed": []}
    vs = VaultState()
    vs._sealed = False

    monkeypatch.setattr(settings, "standalone_db_freeze_secs", freeze)
    monkeypatch.setattr(settings, "standalone_db_seal_secs", seal)
    monkeypatch.setattr(main, "vs", vs)
    monkeypatch.setattr("api.app.database.async_session", _FakeSession(state))

    async def fake_fence_seal(vault):
        state["sealed"].append(1)
        vault._sealed = True

    monkeypatch.setattr("api.app.cluster_ha_loops._lease_fence_seal", fake_fence_seal)

    task = asyncio.create_task(main._standalone_db_watchdog())
    try:
        yield vs, state
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task


@pytest.mark.asyncio
async def test_reachable_database_keeps_the_node_serving(monkeypatch):
    async with _watchdog(monkeypatch, freeze=3, seal=6) as (vs, _):
        await asyncio.sleep(2.5)
        assert vs.frozen is False
        vs.require_unsealed()  # must not raise


@pytest.mark.asyncio
async def test_dead_database_freezes_but_keeps_the_keys(monkeypatch):
    """Freeze is not seal: a database that comes back needs no unseal."""
    async with _watchdog(monkeypatch, freeze=3, seal=600) as (vs, state):
        await asyncio.sleep(1.2)  # one good probe arms the deadline
        assert vs.frozen is False
        state["down"] = True
        await asyncio.sleep(4.0)  # deadline lapses
        assert vs.frozen is True, "a dead local database must stop the node serving"
        assert vs.sealed is False, "freezing must NOT drop key material"
        assert state["sealed"] == []


@pytest.mark.asyncio
async def test_database_returning_before_the_seal_restores_service(monkeypatch):
    """The whole point: recover without a manual unseal."""
    async with _watchdog(monkeypatch, freeze=3, seal=600) as (vs, state):
        await asyncio.sleep(1.2)
        state["down"] = True
        await asyncio.sleep(4.0)
        assert vs.frozen is True
        state["down"] = False
        await asyncio.sleep(2.0)
        assert vs.frozen is False, "reachable database must restore service"
        assert vs.sealed is False, "and it must not have sealed on the way"


@pytest.mark.asyncio
async def test_sustained_outage_seals_to_protect_the_data(monkeypatch):
    """Past the seal window the evidence is conclusive: drop the keys."""
    async with _watchdog(monkeypatch, freeze=3, seal=3) as (vs, state):
        await asyncio.sleep(1.2)
        state["down"] = True
        await asyncio.sleep(8.0)
        assert state["sealed"], "a sustained dead local database must seal"
        assert vs.sealed is True


@pytest.mark.asyncio
async def test_past_the_seal_point_a_node_cannot_serve_even_with_no_loop(monkeypatch):
    """Invariant 6, made structural: not-serving needs no code to run.

    The seal point is a deadline on VaultState, not an action a loop performs,
    so a node past it refuses requests even when every background task is dead.
    Here nothing is running at all -- the deadline alone must do it.
    """
    from api.app.vault_state import VaultSealedError

    vs = VaultState()
    vs._sealed = False
    vs.renew_db_confirmation(0.05, 0.05)
    await asyncio.sleep(0.25)

    assert vs.must_seal is True
    # Reports SEALED, not FROZEN: frozen advertises self-recovery, which is
    # no longer true past this point.
    with pytest.raises(VaultSealedError):
        vs.require_unsealed()


def test_ha_and_standalone_thresholds_are_tuned_opposite_ways():
    """HA biases availability, standalone biases data protection.

    Not cosmetic: they encode different evidence. If standalone ever seals
    later than HA does, the reasoning has been inverted somewhere.
    """
    s = Settings()
    assert s.standalone_db_freeze_secs < s.cluster_primary_lease_ttl_secs
    assert s.standalone_db_seal_secs < s.cluster_frozen_max_secs


@pytest.mark.asyncio
async def test_a_read_only_standby_is_not_authority(monkeypatch):
    """Invariant 4: only a WRITABLE PostgreSQL can validate authority.

    The first version of this probe was SELECT 1, which succeeds against a
    replica -- so a node pointed at a standby renewed its lease forever while
    unable to write a single audit row. Losing write authority is losing
    authority.
    """
    async with _watchdog(monkeypatch, freeze=3, seal=600) as (vs, state):
        await asyncio.sleep(1.2)
        assert vs.frozen is False
        state["standby"] = True  # reachable, but pg_is_in_recovery()
        await asyncio.sleep(4.0)
        assert vs.frozen is True, "a read-only standby must not sustain the lease"


@pytest.mark.asyncio
async def test_a_read_only_primary_is_not_authority(monkeypatch):
    """Same invariant via transaction_read_only: a full disk, or configured."""
    async with _watchdog(monkeypatch, freeze=3, seal=600) as (vs, state):
        await asyncio.sleep(1.2)
        assert vs.frozen is False
        state["read_only"] = True
        await asyncio.sleep(4.0)
        assert vs.frozen is True, "a read-only primary must not sustain the lease"
