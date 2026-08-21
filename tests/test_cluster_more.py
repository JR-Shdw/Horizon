"""Extra tests for api/app/cluster.py.

Targets the uncovered areas: with_cluster_lock, resolve_lock_name,
heartbeat_loop, master_watch_loop (75% -> 90%+).
"""

import asyncio

import pytest
from api.app.cluster import (
    KNOWN_CLUSTER_LOCKS,
    heartbeat_loop,
    master_watch_loop,
    resolve_lock_name,
    with_cluster_lock,
)
from api.app.database import async_session
from sqlalchemy import text


@pytest.mark.asyncio
async def test_resolve_lock_name_known():
    """resolve_lock_name returns the symbolic name for a known objid."""
    async with async_session() as db:
        # KNOWN_CLUSTER_LOCKS holds canonical names. Pick the 1st, compute its
        # hashtext, then check that resolve_lock_name finds it again.
        name = next(iter(KNOWN_CLUSTER_LOCKS))
        full_name = (
            f"rhorizon:cluster:{name}" if not name.startswith("rhorizon:") else name
        )
        # Note: _populate_lock_registry maps the KNOWN_CLUSTER_LOCKS names
        # directly, not with the rhorizon:cluster: prefix. We test the name
        # directly (full_name is kept only to document the call convention).
        _ = full_name
        r2 = await db.execute(text("SELECT hashtext(:n)::int"), {"n": name})
        objid2 = int(r2.scalar())
        resolved = await resolve_lock_name(db, objid2)
        assert resolved == name


@pytest.mark.asyncio
async def test_resolve_lock_name_unknown():
    """objid that matches no known lock -> None."""
    async with async_session() as db:
        result = await resolve_lock_name(db, 999_999_999)
        assert result is None


@pytest.mark.asyncio
async def test_with_cluster_lock_executes_fn_when_acquired():
    """with_cluster_lock acquires then runs fn, returns True."""
    called = []

    async def fn():
        called.append("ran")

    async with async_session() as db:
        ok = await with_cluster_lock(db, "test_lock_unique_" + str(id(fn)), fn)
        await db.commit()

    assert ok is True
    assert called == ["ran"]


@pytest.mark.asyncio
async def test_with_cluster_lock_returns_false_when_held():
    """If the lock is held, with_cluster_lock returns False without running fn."""
    lock_name = "test_busy_lock_" + str(
        id(test_with_cluster_lock_returns_false_when_held)
    )
    called = []

    async def fn():
        called.append("ran")

    # First session: take and hold the lock
    async with async_session() as db1:
        # Acquire without releasing (xact lock, we keep the transaction open)
        held = await db1.execute(
            text("SELECT pg_try_advisory_xact_lock(hashtext(:n))"),
            {"n": f"rhorizon:cluster:{lock_name}"},
        )
        assert held.scalar() is True

        # Second session: tries to acquire the same lock -> must fail
        async with async_session() as db2:
            ok = await with_cluster_lock(db2, lock_name, fn)
            await db2.commit()

        assert ok is False
        assert called == []
        await db1.commit()  # release


# ---------------------------------------------------------------------------
# Background loops with stop_event
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_heartbeat_loop_stops_on_event(monkeypatch):
    """heartbeat_loop stops cleanly when stop_event is set."""
    # Patch heartbeat_once so we don't depend on a registered worker
    from api.app import cluster as cluster_mod

    called = []

    async def fake_hb_once(db):
        called.append(1)

    monkeypatch.setattr(cluster_mod, "heartbeat_once", fake_hb_once)
    # Shorten the interval to keep the test fast
    monkeypatch.setattr(cluster_mod, "HEARTBEAT_INTERVAL_SECS", 0.05)

    stop = asyncio.Event()
    task = asyncio.create_task(heartbeat_loop(async_session, stop_event=stop))
    await asyncio.sleep(0.15)  # allow 2-3 iterations
    stop.set()
    await asyncio.wait_for(task, timeout=1.0)

    assert len(called) >= 1


@pytest.mark.asyncio
async def test_heartbeat_loop_swallows_db_errors(monkeypatch, caplog):
    """A DB error in heartbeat_once does not break the loop - warn + continue."""
    from api.app import cluster as cluster_mod

    call_count = [0]

    async def boom(db):
        call_count[0] += 1
        raise RuntimeError("simulated DB error")

    monkeypatch.setattr(cluster_mod, "heartbeat_once", boom)
    monkeypatch.setattr(cluster_mod, "HEARTBEAT_INTERVAL_SECS", 0.03)

    stop = asyncio.Event()
    task = asyncio.create_task(heartbeat_loop(async_session, stop_event=stop))
    await asyncio.sleep(0.10)
    stop.set()
    await asyncio.wait_for(task, timeout=1.0)

    assert call_count[0] >= 1


@pytest.mark.asyncio
async def test_heartbeat_loop_retries_a_reregistration_it_could_not_do(monkeypatch):
    """A reaped row that cannot be restored is retried, not fail-closed.

    Asserted the opposite until 2026-08-20, on the reasoning that replacement
    was a prudent last resort. It was not: _reregister_after_reap returns False
    on ANY exception from one un-retried INSERT, and the reaper only deletes
    rows after a run of missed heartbeats -- so the trigger was a transient
    write failure during database recovery, and the penalty was seal + SIGTERM,
    destroying the Shamir share the process held.

    Sealing to protect the data is right on EVIDENCE; one ambiguous write is
    not evidence. A worker that truly cannot reach the database freezes on its
    own and seals from there.
    """
    from api.app import cluster as cluster_mod

    async def lost(db):
        raise cluster_mod.WorkerRegistrationLost("reaped")

    async def cannot_reregister(session_factory):
        attempts.append(1)
        if len(attempts) >= 3:
            stop.set()
        return False

    attempts: list[int] = []
    stop = asyncio.Event()
    terminated = []
    monkeypatch.setattr(cluster_mod, "heartbeat_once", lost)
    monkeypatch.setattr(cluster_mod, "_reregister_after_reap", cannot_reregister)
    monkeypatch.setattr(cluster_mod, "HEARTBEAT_INTERVAL_SECS", 0.01)
    monkeypatch.setattr(
        cluster_mod, "_terminate_lost_worker", lambda: terminated.append(True)
    )

    await asyncio.wait_for(heartbeat_loop(async_session, stop_event=stop), timeout=2)

    assert terminated == [], "a transient failure must not seal the worker"
    assert len(attempts) >= 3, "it must keep retrying on later ticks"


@pytest.mark.asyncio
async def test_heartbeat_loop_keeps_a_worker_it_could_reregister(monkeypatch):
    """A restored row keeps the process, and its share, alive."""
    from api.app import cluster as cluster_mod

    async def lost(db):
        raise cluster_mod.WorkerRegistrationLost("reaped")

    stop = asyncio.Event()
    terminated = []

    async def reregistered(session_factory):
        # Let the loop take its normal sleep path once, then leave.
        stop.set()
        return True

    monkeypatch.setattr(cluster_mod, "heartbeat_once", lost)
    monkeypatch.setattr(cluster_mod, "_reregister_after_reap", reregistered)
    monkeypatch.setattr(
        cluster_mod, "_terminate_lost_worker", lambda: terminated.append(True)
    )

    await heartbeat_loop(async_session, stop_event=stop)

    assert terminated == []


def test_terminate_lost_worker_seals_local_state_then_sigterms(monkeypatch):
    """Replacement erases only this process's keys before supervisor handoff."""
    from api.app import cluster as cluster_mod
    from api.app.vault_state import vault

    events = []
    monkeypatch.setattr(vault, "seal", lambda: events.append("sealed"))
    monkeypatch.setattr(cluster_mod.os, "getpid", lambda: 4242)
    monkeypatch.setattr(
        cluster_mod.os,
        "kill",
        lambda pid, sig: events.append(("signal", pid, sig)),
    )

    cluster_mod._terminate_lost_worker()

    assert events == ["sealed", ("signal", 4242, cluster_mod.signal.SIGTERM)]


@pytest.mark.asyncio
async def test_master_watch_loop_calls_handler_when_no_master(monkeypatch):
    """master_watch_loop calls on_master_lost when find_master returns None."""
    from api.app import cluster as cluster_mod

    handler_called = []

    async def fake_find_master(db):
        return None

    async def on_lost():
        handler_called.append(1)

    monkeypatch.setattr(cluster_mod, "find_master", fake_find_master)
    monkeypatch.setattr(cluster_mod, "MASTER_WATCH_INTERVAL_SECS", 0.05)

    stop = asyncio.Event()
    task = asyncio.create_task(
        master_watch_loop(async_session, on_lost, stop_event=stop)
    )
    await asyncio.sleep(0.12)
    stop.set()
    await asyncio.wait_for(task, timeout=1.0)

    assert len(handler_called) >= 1


@pytest.mark.asyncio
async def test_master_watch_loop_swallows_handler_errors(monkeypatch):
    """If on_master_lost raises, the loop logs but continues."""
    from api.app import cluster as cluster_mod

    handler_calls = []

    async def fake_find_master(db):
        return None

    async def on_lost_boom():
        handler_calls.append(1)
        raise RuntimeError("boom")

    monkeypatch.setattr(cluster_mod, "find_master", fake_find_master)
    monkeypatch.setattr(cluster_mod, "MASTER_WATCH_INTERVAL_SECS", 0.03)

    stop = asyncio.Event()
    task = asyncio.create_task(
        master_watch_loop(async_session, on_lost_boom, stop_event=stop)
    )
    await asyncio.sleep(0.10)
    stop.set()
    await asyncio.wait_for(task, timeout=1.0)

    assert len(handler_calls) >= 1


@pytest.mark.asyncio
async def test_master_watch_loop_swallows_outer_errors(monkeypatch):
    """An exception in the outer loop (find_master) is swallowed."""
    from api.app import cluster as cluster_mod

    async def find_master_boom(db):
        raise RuntimeError("DB error")

    async def on_lost():
        pass

    monkeypatch.setattr(cluster_mod, "find_master", find_master_boom)
    monkeypatch.setattr(cluster_mod, "MASTER_WATCH_INTERVAL_SECS", 0.03)

    stop = asyncio.Event()
    task = asyncio.create_task(
        master_watch_loop(async_session, on_lost, stop_event=stop)
    )
    await asyncio.sleep(0.10)
    stop.set()
    await asyncio.wait_for(task, timeout=1.0)
    # No assertion, the test passes simply if the task finishes without
    # propagating the exception
