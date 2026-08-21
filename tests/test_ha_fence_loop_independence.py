# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""The hard fence must not be reachable only when the database answers.

THE FIELD DEFECT. A 340s PostgreSQL blackout on rhorizon-4 left ONE worker in
five having dropped its key material. The other four sat past a terminal
deadline -- refusing requests, keys resident -- for the life of the process.
The journal carried no ``hard fence error`` on any of them, which rules out
the fence raising: it was never REACHED.

WHY. ``cluster_ha_heartbeat_loop`` evaluates its fence at the end of a tick
that opens with ``async with async_session() as db``, in the SAME iteration.
Nothing bounded that await -- asyncpg's ``command_timeout`` defaults to None,
``pool_timeout`` bounds only the wait for a connection FROM the pool, and
``pool_pre_ping`` adds a round-trip to the acquisition itself. The K7 fault is
a blackhole route: packets dropped, no RST, no FIN. A worker mid-query parks
there indefinitely, and the fence below it is never evaluated. The one worker
that fenced is the one whose await happened to RAISE instead of hang.

``must_seal``'s docstring carries the safety argument -- the loops,
"supervised, and restarted if they die -- are what make 'keys gone' follow".
The gap: ``_supervised`` restarts a loop that DIES, and a coroutine parked in
an unbounded await is neither dead nor progressing. A hang is not a death.

So these tests fix the property structurally rather than by timing: sealing
follows from a lapsed deadline ALONE, with no database in the picture at all.
"""

import asyncio

import pytest
from api.app import cluster_ha_loops as loops
from api.app.config import settings


class _FakeVault:
    """Minimal VaultState surface the fence loop reads."""

    def __init__(self, *, sealed=False, must_seal=False):
        self.sealed = sealed
        self.must_seal = must_seal
        self.seal_calls = 0

    def seal(self):
        self.seal_calls += 1
        self.sealed = True


class _HangingSession:
    """A session acquisition that never returns -- the blackhole route.

    Not an exception: an exception would be CAUGHT and the loop would iterate,
    which is the case that already worked. The defect is the await that never
    completes, so the test has to reproduce exactly that.
    """

    def __init__(self, entered: asyncio.Event):
        self._entered = entered

    async def __aenter__(self):
        self._entered.set()
        await asyncio.Event().wait()  # never set, by design

    async def __aexit__(self, *exc):
        return False


async def _run_until(event: asyncio.Event, *coros, timeout=6.0):
    """Run daemon loops until `event` fires, then cancel them."""
    tasks = [asyncio.create_task(c) for c in coros]
    try:
        await asyncio.wait_for(event.wait(), timeout=timeout)
    finally:
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


@pytest.fixture
def fence_env(monkeypatch):
    """Fence loop wired to a fake vault, with any database use fatal."""
    vs = _FakeVault(must_seal=True)
    monkeypatch.setattr(loops, "vs", vs)
    sealed = asyncio.Event()

    async def _seal(vault):
        vault.seal()
        sealed.set()

    monkeypatch.setattr(loops, "_lease_fence_seal", _seal)
    return vs, sealed


async def test_seals_from_a_lapsed_deadline_with_no_database(fence_env, monkeypatch):
    """The invariant: a passed deadline produces a seal, full stop.

    ``async_session`` is replaced with a landmine. If the fence loop touches
    the database at all -- to check anything, to log anything -- this fails,
    because the outage that fires the fence is precisely when the database is
    unavailable.
    """
    vs, sealed = fence_env

    def _explode(*a, **kw):
        raise AssertionError("the fence must not touch the database")

    monkeypatch.setattr(loops, "async_session", _explode)

    await _run_until(sealed, loops.cluster_ha_fence_loop())
    assert vs.seal_calls == 1


async def test_not_starved_by_a_heartbeat_hung_on_the_database(fence_env, monkeypatch):
    """THE REGRESSION, reproduced end to end.

    The real ``cluster_ha_heartbeat_loop`` runs against a session acquisition
    that never returns -- the exact shape of the blackhole route. Before the
    fence was split out, that loop WAS the only thing that could seal, so this
    is the four-workers-in-five case. The fence must still fire.
    """
    vs, sealed = fence_env
    monkeypatch.setattr(settings, "cluster_heartbeat_interval_secs", 0.1)
    monkeypatch.setattr(
        loops, "get_node_uuid", lambda: "11111111-2222-3333-4444-555555555555"
    )

    entered = asyncio.Event()
    monkeypatch.setattr(loops, "async_session", lambda: _HangingSession(entered))

    await _run_until(
        sealed,
        loops.cluster_ha_heartbeat_loop(),
        loops.cluster_ha_fence_loop(),
    )

    assert entered.is_set(), "the heartbeat never reached the hanging await"
    assert vs.seal_calls == 1, "the fence did not fire while the heartbeat hung"


async def test_control_the_heartbeat_alone_is_not_a_prompt_fence(
    fence_env, monkeypatch
):
    """CONTROL for the test above -- without it that one proves little.

    The new test necessarily calls a function that did not exist before the
    fix, so on the old tree it fails with AttributeError: it shows new code
    runs, not that a regression is caught. This runs the heartbeat ALONE in the
    same harness, against the same hanging session, and pins the defect: the
    deadline has passed, the node must seal, and while the await is parked it
    does not, because the loop sits upstream of its own fence.

    Scope, stated precisely. The heartbeat's DB block is now wrapped in
    ``asyncio.timeout(cluster_primary_lease_ttl_secs)``, so this path is no
    longer stuck forever -- it recovers after the TTL and then reaches its
    fence. What it is not is PROMPT: the assertion window here is well inside
    the TTL, so it measures the interval during which the heartbeat alone
    leaves key material resident. The fence loop closes that interval to one
    second, and does so without depending on the timeout being right.

    So this is a bound on the custody window, not a "never". If it ever seals
    inside the window, either the hang is no longer reproduced or the fence
    has been folded back into the heartbeat.
    """
    vs, sealed = fence_env
    monkeypatch.setattr(settings, "cluster_heartbeat_interval_secs", 0.1)
    monkeypatch.setattr(settings, "cluster_primary_lease_ttl_secs", 20)
    monkeypatch.setattr(
        loops, "get_node_uuid", lambda: "11111111-2222-3333-4444-555555555555"
    )

    entered = asyncio.Event()
    monkeypatch.setattr(loops, "async_session", lambda: _HangingSession(entered))

    with pytest.raises(asyncio.TimeoutError):
        await _run_until(sealed, loops.cluster_ha_heartbeat_loop(), timeout=3.0)

    assert entered.is_set(), "the heartbeat never reached the hanging await"
    assert vs.must_seal, "precondition: the deadline has passed"
    assert vs.seal_calls == 0, "the old path sealed -- the hang is not reproduced"


async def test_the_heartbeat_db_block_is_bounded(fence_env, monkeypatch):
    """The recovery half: a hung tick must end, not park for the TCP timeout.

    Custody is the fence loop's job. This is the other defect: a worker whose
    heartbeat never returns also never RE-RENEWS, so a blackout that ended
    long ago still walks it to a permanent seal. Nothing bounded that await --
    asyncpg's command_timeout is None by default -- and TCP retransmission
    would not raise for ~15 minutes, far past the 320s fence.

    A short TTL here keeps the test quick; the production budget is the real
    TTL, on the reasoning that a confirmation arriving after the deadline it
    would renew is not a confirmation.
    """
    vs, sealed = fence_env
    vs.must_seal = False  # keep the fence out of it; this is about the tick
    monkeypatch.setattr(settings, "cluster_heartbeat_interval_secs", 0.1)
    monkeypatch.setattr(settings, "cluster_primary_lease_ttl_secs", 1)
    monkeypatch.setattr(
        loops, "get_node_uuid", lambda: "11111111-2222-3333-4444-555555555555"
    )

    entries = []

    def _session():
        ev = asyncio.Event()
        entries.append(ev)
        return _HangingSession(ev)

    monkeypatch.setattr(loops, "async_session", _session)

    task = asyncio.create_task(loops.cluster_ha_heartbeat_loop())
    await asyncio.sleep(3.0)
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)

    # Unbounded, this enters exactly once and stays there forever. Bounded, it
    # times out each tick and comes back for another.
    assert len(entries) > 1, (
        f"the heartbeat entered the DB block {len(entries)} time(s) in 3s -- "
        "it is still parked in an unbounded await"
    )


def test_unseal_clears_the_deadline_from_the_previous_life():
    """An unseal must not be undone a second later by a stale deadline.

    CAUGHT ON THE LAB, by this change. `POST /unseal 200 OK` and "past the
    terminal seal deadline -- sealing" landed in the same second: the fence had
    sealed on a lapsed _seal_deadline, seal() does not clear it, so after the
    operator unsealed, `must_seal` was still true -- comparing against a
    timestamp from before the outage -- and the fence dropped the keys again.

    It only became reachable when the fence moved into its own loop. The
    heartbeat's fence was accidentally immune: it runs AFTER a round-trip that
    calls renew_db_confirmation() first, so the deadline it read had always
    just been refreshed. Removing that incidental ordering is what exposed the
    missing invariant, so the invariant is now stated in unseal() and pinned
    here.

    Uses the real VaultState, not the fake: the fake reimplements `must_seal`
    as a plain attribute, which is exactly the coupling this test must not
    have.
    """
    from api.app.vault_state import VaultState

    v = VaultState()
    # A deadline that lapsed long ago, i.e. the state a fence seals on.
    v.renew_db_confirmation(ttl_secs=-100.0, seal_grace_secs=0.0)
    assert v.must_seal, "precondition: the vault is past its terminal deadline"

    v.unseal(
        {
            "hmac_key": b"\x01" * 32,
            "dek_key": b"\x02" * 32,
            "audit_key": b"\x03" * 32,
            "ha_wrap_key": b"\x04" * 32,
            "pki_wrap_key": b"\x05" * 32,
        }
    )

    assert not v.sealed
    assert not v.must_seal, (
        "unseal left a lapsed deadline behind -- the fence will re-seal this "
        "vault within a second"
    )
    assert not v.frozen, "a freshly unsealed vault must not report frozen"


async def test_does_not_seal_before_the_deadline(fence_env, monkeypatch):
    """Freezing is not sealing. Inside the grace window the keys stay."""
    vs, sealed = fence_env
    vs.must_seal = False
    monkeypatch.setattr(loops, "async_session", lambda: None)

    with pytest.raises(asyncio.TimeoutError):
        await _run_until(sealed, loops.cluster_ha_fence_loop(), timeout=2.5)
    assert vs.seal_calls == 0


async def test_already_sealed_is_not_resealed(fence_env, monkeypatch):
    """A sealed node holds nothing to drop; re-running the teardown is noise."""
    vs, sealed = fence_env
    vs.sealed = True
    monkeypatch.setattr(loops, "async_session", lambda: None)

    with pytest.raises(asyncio.TimeoutError):
        await _run_until(sealed, loops.cluster_ha_fence_loop(), timeout=2.5)
    assert vs.seal_calls == 0


async def test_a_failing_seal_does_not_kill_the_loop(monkeypatch):
    """The loop retries rather than dying.

    A raise here would cost the 1s cadence a supervisor restart and its
    backoff, during which nothing seals -- and the next tick can simply try
    again. Two failures then a success proves it kept ticking.
    """
    vs = _FakeVault(must_seal=True)
    monkeypatch.setattr(loops, "vs", vs)
    monkeypatch.setattr(loops, "async_session", lambda: None)
    done = asyncio.Event()
    calls = {"n": 0}

    async def _flaky(vault):
        calls["n"] += 1
        if calls["n"] < 3:
            raise RuntimeError("custodian socket refused")
        vault.seal()
        done.set()

    monkeypatch.setattr(loops, "_lease_fence_seal", _flaky)

    await _run_until(done, loops.cluster_ha_fence_loop(), timeout=8.0)
    assert calls["n"] == 3
    assert vs.seal_calls == 1


async def test_concurrent_triggers_do_not_overlap_the_teardown(monkeypatch):
    """Both triggers can fire in the same second; the teardown must serialize.

    ``seal()`` is idempotent, but ``stop_master_services`` tears down a
    listener and a socket, and two concurrent teardowns are how a socket ends
    up half removed. The lock lives inside ``_lease_fence_seal`` so every
    caller is covered by construction, not by each one remembering to check.
    """
    from api.app import cluster_setup
    from api.app import rust_custody_backend as rcb

    # BOTH awaited steps are instrumented, on the same counter. Instrumenting
    # only stop_master_services passes against a lock that covers just that
    # call while the custodian seal still overlaps -- which is exactly the bug
    # this test was written against, and it reported green.
    overlap = {"depth": 0, "max": 0}

    async def _tracked(delay):
        overlap["depth"] += 1
        overlap["max"] = max(overlap["max"], overlap["depth"])
        await asyncio.sleep(delay)
        overlap["depth"] -= 1

    async def _stop(vault, db=None):
        await _tracked(0.05)

    monkeypatch.setattr(cluster_setup, "stop_master_services", _stop)

    async def _seal_custodians():
        await _tracked(0.05)
        return False

    monkeypatch.setattr(rcb, "seal_custodians_offline", _seal_custodians)

    vaults = [_FakeVault(must_seal=True) for _ in range(4)]
    await asyncio.gather(*(loops._lease_fence_seal(v) for v in vaults))

    assert overlap["max"] == 1, "fence teardowns ran concurrently"
    assert all(v.seal_calls == 1 for v in vaults)
