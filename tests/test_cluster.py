"""Tests for cluster coordination - heartbeat + election."""

import asyncio

import pytest
from api.app.cluster import (
    ELECTION_RANDOM_DELAY_MAX_SECS,
    MASTER_TIMEOUT_SECS,
    WorkerRegistrationLost,
    WorkerState,
    _reregister_after_reap,
    acquire_master_or_follower,
    claim_master_role,
    deregister_worker,
    find_master,
    heartbeat_once,
    master_watch_loop,
    register_worker,
    run_election,
    update_worker_state,
)
from api.app.database import async_session
from sqlalchemy import text


@pytest.fixture(autouse=True)
async def _wipe_workers(setup_db):
    """Each test starts with a clean vault_workers table.

    Depends on setup_db (session-scoped, applies schema.sql) so the
    vault_workers table exists. Tests in this module don't use the HTTP
    client fixture so they wouldn't transitively pull setup_db otherwise.
    """
    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_workers"))
        await db.commit()
    yield
    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_workers"))
        await db.commit()


# -- Registration / worker_state / heartbeat --


@pytest.mark.asyncio
async def test_register_worker_creates_row():
    async with async_session() as db:
        await register_worker(db, socket_name=None, pid=11111)
        r = await db.execute(
            text("SELECT pid, worker_state FROM vault_workers WHERE pid = 11111")
        )
        row = r.fetchone()
    assert row is not None
    assert row.pid == 11111
    assert row.worker_state == "sealed"


@pytest.mark.asyncio
async def test_register_worker_pid_reuse_resets_process_state():
    """A recycled PID must never inherit master state or socket ownership."""
    async with async_session() as db:
        await register_worker(db, pid=22222)
        await update_worker_state(db, WorkerState.MASTER, pid=22222)
        await db.execute(
            text(
                "UPDATE vault_workers "
                "SET crypto_socket_name = '/run/rhorizon/stale-master.sock', "
                "    started_at = NOW() - INTERVAL '1 day' "
                "WHERE pid = 22222"
            )
        )
        await db.commit()
        await register_worker(db, pid=22222)
        r = await db.execute(
            text(
                "SELECT worker_state, crypto_socket_name, "
                "EXTRACT(EPOCH FROM (NOW() - started_at)) AS age "
                "FROM vault_workers WHERE pid = 22222"
            )
        )
        row = r.fetchone()
    assert row.worker_state == "sealed"
    assert row.crypto_socket_name is None
    assert row.age < 1.0


@pytest.mark.asyncio
@pytest.mark.parametrize("role", ["master", "follower"])
async def test_reregister_after_reap_restores_identity_and_live_sockets(
    monkeypatch, role
):
    """A surviving worker must remain discoverable after its row is reaped."""
    from api.app import cluster as cluster_mod
    from api.app import cluster_rpc, cluster_setup, node_uuid
    from api.app.vault_state import vault

    pid = 23232
    host = "reaped-host"
    expected_node_uuid = "a" * 32
    master_crypto = "/run/rhorizon/crypto-reaped.sock"
    master_shares = "/run/rhorizon/keys-reaped.sock"
    follower_shares = "/run/rhorizon/share-reaped.sock"

    monkeypatch.setattr(cluster_mod.os, "getpid", lambda: pid)
    monkeypatch.setattr(cluster_mod, "get_hostname", lambda: host)
    monkeypatch.setattr(node_uuid, "get_node_uuid", lambda: expected_node_uuid)
    monkeypatch.setattr(cluster_rpc, "crypto_socket_name", lambda: master_crypto)
    monkeypatch.setattr(cluster_setup, "master_keys_socket_name", lambda: master_shares)
    monkeypatch.setattr(
        cluster_setup,
        "follower_share_back_socket_name",
        lambda *, pid: follower_shares,
    )
    monkeypatch.setattr(vault, "_sealed", False)
    monkeypatch.setattr(vault, "_cluster_share_server", object())
    if role == "master":
        monkeypatch.setattr(vault, "_rpc_client", None)
        monkeypatch.setattr(vault, "_master_rpc_server", object())
        expected_crypto = master_crypto
        expected_share = master_shares
    else:
        monkeypatch.setattr(vault, "_rpc_client", object())
        monkeypatch.setattr(vault, "_master_rpc_server", None)
        expected_crypto = None
        expected_share = follower_shares

    assert await _reregister_after_reap(async_session)

    async with async_session() as db:
        result = await db.execute(
            text(
                "SELECT worker_state, socket_name, crypto_socket_name, node_uuid "
                "FROM vault_workers WHERE hostname = :host AND pid = :pid"
            ),
            {"host": host, "pid": pid},
        )
        row = result.fetchone()

    assert row is not None
    assert row.worker_state == role
    assert row.socket_name == expected_share
    assert row.crypto_socket_name == expected_crypto
    assert row.node_uuid == expected_node_uuid


@pytest.mark.asyncio
async def test_update_worker_state_transitions():
    async with async_session() as db:
        await register_worker(db, pid=33333)
        await update_worker_state(db, WorkerState.FOLLOWER, pid=33333)
        r = await db.execute(
            text("SELECT worker_state FROM vault_workers WHERE pid = 33333")
        )
        row = r.fetchone()
    assert row.worker_state == "follower"


@pytest.mark.asyncio
async def test_heartbeat_updates_timestamp():
    async with async_session() as db:
        await register_worker(db, pid=44444)
        # Force an old heartbeat
        await db.execute(
            text(
                "UPDATE vault_workers "
                "SET last_heartbeat = NOW() - INTERVAL '10 seconds' "
                "WHERE pid = 44444"
            )
        )
        await db.commit()

        await heartbeat_once(db, pid=44444)
        r = await db.execute(
            text(
                "SELECT EXTRACT(EPOCH FROM (NOW() - last_heartbeat)) AS age "
                "FROM vault_workers WHERE pid = 44444"
            )
        )
        row = r.fetchone()
    assert row.age < 1.0  # heartbeat just refreshed


@pytest.mark.asyncio
async def test_heartbeat_rejects_reaped_worker():
    async with async_session() as db:
        with pytest.raises(WorkerRegistrationLost):
            await heartbeat_once(db, pid=45454)


@pytest.mark.asyncio
async def test_deregister_worker_removes_row():
    async with async_session() as db:
        await register_worker(db, pid=55555)
        await deregister_worker(db, pid=55555)
        r = await db.execute(text("SELECT 1 FROM vault_workers WHERE pid = 55555"))
    assert r.fetchone() is None


# -- Master discovery --


@pytest.mark.asyncio
async def test_find_master_returns_none_when_no_master():
    async with async_session() as db:
        await register_worker(db, pid=66666)
        master = await find_master(db)
    assert master is None


async def _set_crypto_socket(db, pid: int, hostname: str = "default"):
    """Helper: stamp a vault_workers row to look like it belongs to a
    given host. Updates both the `hostname` column (which find_master
    now filters on) and the legacy `crypto_socket_name` (kept for the
    `/cluster` topology fallback). Mimics what start_master_services
    does at runtime."""
    await db.execute(
        text("""
            UPDATE vault_workers
            SET hostname = :host,
                crypto_socket_name = '/run/rhorizon/crypto-ops-' || :host || '.sock'
            WHERE pid = :pid
        """),
        {"host": hostname, "pid": pid},
    )
    await db.commit()


@pytest.mark.asyncio
async def test_find_master_returns_alive_master(monkeypatch):
    monkeypatch.setenv("HOSTNAME", "default")
    async with async_session() as db:
        await register_worker(db, pid=77777)
        await update_worker_state(db, WorkerState.MASTER, pid=77777)
        await _set_crypto_socket(db, 77777, "default")
        master = await find_master(db)
    assert master is not None
    assert master["pid"] == 77777
    assert master["worker_state"] == "master"


@pytest.mark.asyncio
async def test_find_master_ignores_advisory_master_without_crypto_socket(monkeypatch):
    monkeypatch.setenv("HOSTNAME", "default")
    async with async_session() as db:
        await register_worker(db, pid=77778)
        await update_worker_state(db, WorkerState.MASTER, pid=77778)
        master = await find_master(db)
    assert master is None


@pytest.mark.asyncio
async def test_find_master_ignores_stale_master(monkeypatch):
    monkeypatch.setenv("HOSTNAME", "default")
    async with async_session() as db:
        await register_worker(db, pid=88888)
        await update_worker_state(db, WorkerState.MASTER, pid=88888)
        await _set_crypto_socket(db, 88888, "default")
        # Staler than the master deadline. Derived from MASTER_TIMEOUT_SECS
        # rather than hardcoded: the default moved 5s -> 120s when failover
        # timing became operator-tunable, and a literal here silently stops
        # testing staleness at all.
        await db.execute(
            text(
                "UPDATE vault_workers "
                "SET last_heartbeat = NOW() - make_interval(secs => :stale) "
                "WHERE pid = 88888"
            ),
            {"stale": MASTER_TIMEOUT_SECS * 2},
        )
        await db.commit()
        master = await find_master(db)
    assert master is None


@pytest.mark.asyncio
async def test_find_master_ignores_other_hostname(monkeypatch):
    """a master row from a different host (multi-VM scenario)
    must NOT be returned to local find_master. Each host has its own
    cluster on the shared PG."""
    monkeypatch.setenv("HOSTNAME", "host-a")
    async with async_session() as db:
        # Register a master on a different host
        await register_worker(db, pid=99001)
        await update_worker_state(db, WorkerState.MASTER, pid=99001)
        await _set_crypto_socket(db, 99001, "host-b")
        master = await find_master(db)
    # find_master from host-a's perspective must not see host-b's master
    assert master is None


@pytest.mark.asyncio
async def test_register_worker_multi_host_no_collision(monkeypatch):
    """completion: two workers with the same pid on different
    hosts must produce two distinct rows. Before the (hostname, pid)
    composite PK, the second INSERT UPSERT-erased the first - the root
    cause of the Swarm split-brain reported on 2026-05-22."""
    same_pid = 12345

    monkeypatch.setenv("HOSTNAME", "host-a")
    async with async_session() as db:
        await register_worker(db, pid=same_pid)

    monkeypatch.setenv("HOSTNAME", "host-b")
    async with async_session() as db:
        await register_worker(db, pid=same_pid)

    async with async_session() as db:
        rows = (
            await db.execute(
                text(
                    "SELECT hostname, pid FROM vault_workers "
                    "WHERE pid = :pid ORDER BY hostname"
                ),
                {"pid": same_pid},
            )
        ).fetchall()
    assert len(rows) == 2
    assert {r.hostname for r in rows} == {"host-a", "host-b"}


# -- claim_master_role atomicity --


@pytest.mark.asyncio
async def test_claim_master_role_succeeds_when_no_master():
    async with async_session() as db:
        await register_worker(db, pid=99999)
        won = await claim_master_role(db, pid=99999)
    assert won is True

    async with async_session() as db:
        r = await db.execute(
            text("SELECT worker_state FROM vault_workers WHERE pid = 99999")
        )
    assert r.fetchone().worker_state == "master"


@pytest.mark.asyncio
async def test_claim_master_role_fails_if_master_alive():
    async with async_session() as db:
        # Existing master with fresh heartbeat
        await register_worker(db, pid=10001)
        await update_worker_state(db, WorkerState.MASTER, pid=10001)
        # Another worker tries to claim
        await register_worker(db, pid=10002)
        won = await claim_master_role(db, pid=10002)
    assert won is False


@pytest.mark.asyncio
async def test_claim_master_role_succeeds_after_master_timeout():
    async with async_session() as db:
        await register_worker(db, pid=10003)
        await update_worker_state(db, WorkerState.MASTER, pid=10003)
        # Staler than the master deadline (see the note in
        # test_find_master_ignores_stale_master).
        await db.execute(
            text(
                "UPDATE vault_workers "
                "SET last_heartbeat = NOW() - make_interval(secs => :stale) "
                "WHERE pid = 10003"
            ),
            {"stale": MASTER_TIMEOUT_SECS * 2},
        )
        await db.commit()

        await register_worker(db, pid=10004)
        won = await claim_master_role(db, pid=10004)
    assert won is True


@pytest.mark.asyncio
async def test_claim_master_role_concurrent_only_one_wins():
    """Two workers race to claim master - exactly one should win."""
    pids = [20001, 20002]
    async with async_session() as db:
        for pid in pids:
            await register_worker(db, pid=pid)

    # Both call claim_master_role concurrently
    async def attempt(pid):
        async with async_session() as db:
            return await claim_master_role(db, pid=pid)

    results = await asyncio.gather(*(attempt(pid) for pid in pids))
    assert sum(results) == 1, f"Expected exactly 1 winner, got {sum(results)}"


# -- acquire_master_or_follower --


@pytest.mark.asyncio
async def test_acquire_master_or_follower_first_wins_master():
    """First worker on a clean host wins MASTER."""
    async with async_session() as db:
        await register_worker(db, pid=80004)
        state = await acquire_master_or_follower(db, pid=80004)
    assert state == WorkerState.MASTER


@pytest.mark.asyncio
async def test_acquire_master_or_follower_loser_stays_sealed():
    """Master already held - next worker stays SEALED. The follower-boot
    loop in main.py transitions it to FOLLOWER once it attaches to the
    master's RPC socket (covered by test_main_loops)."""
    async with async_session() as db:
        await register_worker(db, pid=80005)
        first = await acquire_master_or_follower(db, pid=80005)
        await register_worker(db, pid=80006)
        second = await acquire_master_or_follower(db, pid=80006)
    assert first == WorkerState.MASTER
    assert second == WorkerState.SEALED


@pytest.mark.asyncio
async def test_acquire_master_or_follower_concurrent_only_one_wins():
    """Two workers race in acquire_master_or_follower - exactly one
    gets MASTER, the other stays SEALED."""
    pids = [80030, 80031]
    async with async_session() as db:
        for pid in pids:
            await register_worker(db, pid=pid)

    async def attempt(pid):
        async with async_session() as db:
            return await acquire_master_or_follower(db, pid=pid)

    results = await asyncio.gather(*(attempt(pid) for pid in pids))
    masters = [r for r in results if r == WorkerState.MASTER]
    sealed = [r for r in results if r == WorkerState.SEALED]
    assert len(masters) == 1
    assert len(sealed) == 1


# -- run_election --


@pytest.mark.asyncio
async def test_run_election_wins_when_no_master(monkeypatch):
    monkeypatch.setenv("HOSTNAME", "default")
    async with async_session() as db:
        await register_worker(db, pid=40001)
    won = await run_election(async_session, pid=40001)
    assert won is True

    # claim_master_role only flips worker_state='master'; a
    # fully operational master also publishes its crypto_socket_name
    # (done by start_master_services in production). Simulate that here
    # so find_master sees the row.
    async with async_session() as db:
        await _set_crypto_socket(db, 40001, "default")
        master = await find_master(db)
    assert master["pid"] == 40001


@pytest.mark.asyncio
async def test_run_election_random_delay_within_bounds():
    """Election should never wait longer than the configured max."""
    import time

    async with async_session() as db:
        await register_worker(db, pid=50001)
    start = time.monotonic()
    await run_election(async_session, pid=50001)
    elapsed = time.monotonic() - start
    # Allow some scheduler slack but ensure within bounded delay + DB latency
    assert elapsed < ELECTION_RANDOM_DELAY_MAX_SECS + 2.0


# -- heartbeat_loop / master_watch_loop --


@pytest.mark.asyncio
async def test_heartbeat_loop_refreshes_until_stop():
    async with async_session() as db:
        await register_worker(db, pid=60001)
        # Backdate heartbeat
        await db.execute(
            text(
                "UPDATE vault_workers "
                "SET last_heartbeat = NOW() - INTERVAL '10 seconds' "
                "WHERE pid = 60001"
            )
        )
        await db.commit()

    stop = asyncio.Event()

    async def run():
        # We can't override pid in heartbeat_loop without monkey-patching getpid,
        # so we directly call heartbeat_once in a custom loop for the test.
        while not stop.is_set():
            try:
                async with async_session() as db:
                    await heartbeat_once(db, pid=60001)
            except Exception:
                pass
            try:
                await asyncio.wait_for(stop.wait(), timeout=0.2)
                return
            except asyncio.TimeoutError:
                continue

    task = asyncio.create_task(run())
    await asyncio.sleep(0.5)
    stop.set()
    await task

    async with async_session() as db:
        r = await db.execute(
            text(
                "SELECT EXTRACT(EPOCH FROM (NOW() - last_heartbeat)) AS age "
                "FROM vault_workers WHERE pid = 60001"
            )
        )
        row = r.fetchone()
    assert row.age < 2.0  # was 10s stale, now refreshed within last <2s


@pytest.mark.asyncio
async def test_master_watch_triggers_callback_when_no_master():
    triggered = asyncio.Event()

    async def on_master_lost():
        triggered.set()

    stop = asyncio.Event()
    task = asyncio.create_task(
        master_watch_loop(async_session, on_master_lost, stop_event=stop)
    )

    # No master exists -> callback should fire on first iteration
    await asyncio.wait_for(triggered.wait(), timeout=5.0)
    stop.set()
    await task


@pytest.mark.asyncio
async def test_master_watch_does_not_trigger_when_master_alive(monkeypatch):
    monkeypatch.setenv("HOSTNAME", "default")
    async with async_session() as db:
        await register_worker(db, pid=70001)
        await update_worker_state(db, WorkerState.MASTER, pid=70001)
        # master row needs crypto_socket_name to be visible
        # to find_master (host-scoped filter).
        await _set_crypto_socket(db, 70001, "default")

    triggered = asyncio.Event()

    async def on_master_lost():
        triggered.set()

    stop = asyncio.Event()
    task = asyncio.create_task(
        master_watch_loop(async_session, on_master_lost, stop_event=stop)
    )
    # Refresh heartbeat periodically while we wait
    for _ in range(3):
        async with async_session() as db:
            await heartbeat_once(db, pid=70001)
        await asyncio.sleep(0.5)

    stop.set()
    await task
    assert not triggered.is_set()
