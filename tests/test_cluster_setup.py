"""Tests for cluster_setup - RPC auto-wire + follower attach.

Every test in this module exercises the real cluster_setup functions
(filesystem Unix sockets, KeyServer, RPC). The `cluster_real` marker disables
conftest's autouse IPC bypass for this module - see conftest.py.
"""

import asyncio
import os

import pytest
from api.app import cluster_setup
from api.app.cluster import (
    WorkerState,
    register_worker,
    update_worker_state,
)
from api.app.cluster_setup import (
    attach_to_master,
    detach_from_master,
    start_master_services,
    stop_master_services,
)
from api.app.database import async_session
from api.app.vault_state import VaultState
from sqlalchemy import text

pytestmark = pytest.mark.cluster_real


def _gen_keys():
    return {
        "hmac_key": os.urandom(32),
        "dek_key": os.urandom(32),
        "audit_key": os.urandom(32),
        "ha_wrap_key": os.urandom(32),
        "pki_wrap_key": os.urandom(32),
    }


@pytest.fixture(autouse=True)
async def _wipe_workers(setup_db):
    """Clean vault_workers + reset HOSTNAME for predictable socket names."""
    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_workers"))
        await db.commit()
    yield
    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_workers"))
        await db.commit()


# -- start_master_services --------------------------------------------------


@pytest.mark.asyncio
async def test_start_master_services_persists_socket_name(monkeypatch):
    monkeypatch.setenv("HOSTNAME", "master-host-A")
    pid = os.getpid()
    master = VaultState()
    master.unseal(_gen_keys())

    async with async_session() as db:
        await register_worker(db, pid=pid)
        await update_worker_state(db, WorkerState.MASTER, pid=pid)
        server = await start_master_services(db, master)
    try:
        assert master._master_rpc_server is server
        async with async_session() as db:
            r = await db.execute(
                text("SELECT crypto_socket_name FROM vault_workers WHERE pid = :pid"),
                {"pid": pid},
            )
            row = r.fetchone()
        assert row is not None
        assert row.crypto_socket_name is not None
        assert "master-host-A" in row.crypto_socket_name
        # Stored without leading \0 (PG TEXT can't hold null bytes); the
        # abstract-namespace prefix is re-added on read by cluster_setup.
        # Filesystem path; basename starts with crypto-ops-
        import os.path as _op

        assert _op.basename(row.crypto_socket_name).startswith("crypto-ops-")
        assert row.crypto_socket_name.endswith(".sock")
        assert "\0" not in row.crypto_socket_name
    finally:
        await stop_master_services(master)


@pytest.mark.asyncio
async def test_start_master_services_idempotent(monkeypatch):
    monkeypatch.setenv("HOSTNAME", "master-host-B")
    master = VaultState()
    master.unseal(_gen_keys())
    pid = os.getpid()

    async with async_session() as db:
        await register_worker(db, pid=pid)
        await update_worker_state(db, WorkerState.MASTER, pid=pid)
        s1 = await start_master_services(db, master)
        s2 = await start_master_services(db, master)
    try:
        assert s1 is s2  # second call returns the existing instance
    finally:
        await stop_master_services(master)


@pytest.mark.asyncio
async def test_start_master_services_single_worker_skips_rpc_and_shamir(monkeypatch):
    """Home preset (RH_WORKERS=1): the lone worker holds keys in-process,
    so start_master_services binds no crypto-ops RPC socket and skips the Shamir
    split. is_master stays True (crypto runs locally), socket columns stay NULL."""
    monkeypatch.setenv("HOSTNAME", "master-host-solo")
    monkeypatch.setattr(cluster_setup.settings, "workers", 1)
    master = VaultState()
    master.unseal(_gen_keys())
    pid = os.getpid()

    async with async_session() as db:
        await register_worker(db, pid=pid)
        await update_worker_state(db, WorkerState.MASTER, pid=pid)
        server = await start_master_services(db, master)

    assert server is None
    assert master._master_rpc_server is None
    assert master._cluster_share is None
    assert master._cluster_share_server is None
    assert master.is_master is True

    async with async_session() as db:
        r = await db.execute(
            text(
                "SELECT crypto_socket_name, socket_name "
                "FROM vault_workers WHERE pid = :pid"
            ),
            {"pid": pid},
        )
        row = r.fetchone()
    assert row.crypto_socket_name is None
    assert row.socket_name is None


@pytest.mark.asyncio
async def test_stop_master_services_clears_socket_name(monkeypatch):
    monkeypatch.setenv("HOSTNAME", "master-host-C")
    master = VaultState()
    master.unseal(_gen_keys())
    pid = os.getpid()

    async with async_session() as db:
        await register_worker(db, pid=pid)
        await update_worker_state(db, WorkerState.MASTER, pid=pid)
        await start_master_services(db, master)

    async with async_session() as db:
        await stop_master_services(master, db=db)

    async with async_session() as db:
        r = await db.execute(
            text("SELECT crypto_socket_name FROM vault_workers WHERE pid = :pid"),
            {"pid": pid},
        )
        row = r.fetchone()
    assert row.crypto_socket_name is None
    assert master._master_rpc_server is None


@pytest.mark.asyncio
async def test_stop_master_services_safe_when_not_started():
    """No-op when there's no server attached."""
    master = VaultState()
    await stop_master_services(master)  # must not raise
    assert master._master_rpc_server is None


# -- attach_to_master / detach_from_master ----------------------------------


@pytest.mark.asyncio
async def test_attach_to_master_succeeds_when_master_present(monkeypatch):
    """End-to-end: start a master, then verify a follower attaches, fetches
    a Shamir share, and crypto-ops route through the RPC."""
    monkeypatch.setenv("HOSTNAME", "e2e-host")
    master = VaultState()
    master.unseal(_gen_keys())
    master_pid = os.getpid()
    follower_pid = 91001  # fake PID for follower's row

    async with async_session() as db:
        await register_worker(db, pid=master_pid)
        await update_worker_state(db, WorkerState.MASTER, pid=master_pid)
        await start_master_services(db, master, pid=master_pid)
        await register_worker(db, pid=follower_pid)

    follower = VaultState()
    try:
        ok = await attach_to_master(async_session, follower, pid=follower_pid)
        assert ok is True
        assert follower._rpc_client is not None
        assert follower.sealed is False  # logically unsealed
        # Follower received a Shamir share (best-effort but expected to succeed)
        assert follower._cluster_share is not None
        # Roundtrip a real op to prove the RPC works
        sig_via_rpc = await follower.hmac_sha512_hex("ping")
        sig_local = master._hmac_sha512_hex_local("ping")
        assert sig_via_rpc == sig_local
    finally:
        await stop_master_services(master)
        await detach_from_master(follower)
        master.seal()


@pytest.mark.asyncio
async def test_attach_to_master_times_out_when_no_master(monkeypatch):
    """If no master ever appears, attach returns False quickly (test path
    overrides FOLLOWER_MASTER_WAIT_SECS to avoid waiting 120s)."""
    from api.app import cluster_setup

    monkeypatch.setattr(cluster_setup, "FOLLOWER_MASTER_WAIT_SECS", 1.5)
    monkeypatch.setattr(cluster_setup, "FOLLOWER_POLL_INTERVAL_SECS", 0.2)

    follower = VaultState()
    ok = await attach_to_master(async_session, follower)
    assert ok is False
    assert follower._rpc_client is None
    assert follower.sealed is True


@pytest.mark.asyncio
async def test_attach_to_master_idempotent(monkeypatch):
    """If already attached, returns True without re-polling."""
    from api.app.cluster_rpc import MasterRpcClient

    follower = VaultState()
    follower.attach_rpc_client(MasterRpcClient("\0rhorizon-fake"))
    follower._sealed = False
    ok = await attach_to_master(async_session, follower)
    assert ok is True


@pytest.mark.asyncio
async def test_attach_to_master_ignores_stale_master(monkeypatch):
    """A master row with a stale heartbeat should NOT be attached to."""
    from api.app import cluster_setup

    monkeypatch.setenv("HOSTNAME", "stale-host")
    monkeypatch.setattr(cluster_setup, "FOLLOWER_MASTER_WAIT_SECS", 1.5)
    monkeypatch.setattr(cluster_setup, "FOLLOWER_POLL_INTERVAL_SECS", 0.2)

    fake_pid = 99877
    async with async_session() as db:
        await register_worker(db, pid=fake_pid)
        await update_worker_state(db, WorkerState.MASTER, pid=fake_pid)
        await db.execute(
            text(
                "UPDATE vault_workers "
                "SET crypto_socket_name = '/run/rhorizon/crypto-ops-fake.sock', "
                "    last_heartbeat = NOW() - INTERVAL '60 seconds' "
                "WHERE pid = :pid"
            ),
            {"pid": fake_pid},
        )
        await db.commit()

    follower = VaultState()
    ok = await attach_to_master(async_session, follower)
    assert ok is False  # stale master ignored


@pytest.mark.asyncio
async def test_attach_to_master_rejects_unusable_advertised_socket(
    monkeypatch, tmp_path
):
    """A fresh master row with a dead crypto socket must not unseal followers."""
    monkeypatch.setenv("HOSTNAME", "dead-socket-host")

    master_pid = 99878
    follower_pid = 99879
    dead_socket = tmp_path / "crypto-ops-dead.sock"
    async with async_session() as db:
        await register_worker(db, pid=master_pid)
        await update_worker_state(db, WorkerState.MASTER, pid=master_pid)
        await db.execute(
            text(
                "UPDATE vault_workers "
                "SET crypto_socket_name = :sock, last_heartbeat = NOW() "
                "WHERE pid = :pid"
            ),
            {"sock": str(dead_socket), "pid": master_pid},
        )
        await register_worker(db, pid=follower_pid)
        await db.commit()

    follower = VaultState()
    ok = await attach_to_master(async_session, follower, pid=follower_pid)
    assert ok is False
    assert follower._rpc_client is None
    assert follower.sealed is True


@pytest.mark.asyncio
async def test_detach_from_master_seals_vault(monkeypatch):
    """After detach, vault must be sealed (no RPC client, no keys)."""
    from api.app.cluster_rpc import MasterRpcClient

    follower = VaultState()
    follower.attach_rpc_client(MasterRpcClient("\0rhorizon-fake"))
    follower._sealed = False  # mimic logical-unsealed state

    await detach_from_master(follower)
    assert follower._rpc_client is None
    assert follower.sealed is True


@pytest.mark.asyncio
async def test_failover_5_workers_iso_prod(monkeypatch):
    """End-to-end failover at the production worker count
    (cluster_shamir_total=5, threshold=3, 1 master + 4 followers).

    Complements the smaller-cluster `test_failover_reconstruct_with_quorum`
    by exercising the exact share-distribution + reconstruction shape that
    runs in production.

    1. Master unseals, splits keys into 5 Shamir shares (threshold=3),
       binds keys-distribution + crypto-ops sockets, keeps the x=1 share.
    2. Each follower runs attach_to_master: fetches a unique share from the
       master's keys-socket and binds its own per-pid share-back socket
       so a future new-master can collect that share.
    3. Master "crashes" - we stop_master_services and DELETE its row.
    4. A follower runs run_election (it wins because it's the only candidate
       in the test) and reconstruct_and_become_master, which:
         - has its own share locally (from step 2)
         - queries DB for live peers with share-back sockets
         - connects to the share-back of two surviving followers, fetches
           their shares (threshold=3 total: own + 2 peers)
         - reconstructs the original 96-byte sub-key blob via Shamir
         - calls vault.unseal(reconstructed_keys), becomes new master
    5. Assertions: the new master is unsealed, its sub-keys produce the
       same HMAC as the original master's sub-keys (proves reconstruction
       was lossless), DB has it as status=master with crypto_socket_name.

    This exercises the operational invariant: with cluster_shamir_threshold
    surviving followers (each with a share), a master crash is recoverable
    without operator intervention.
    """
    from api.app import cluster_setup
    from api.app.cluster import claim_master_role
    from api.app.cluster_setup import reconstruct_and_become_master
    from api.app.config import settings

    # Distinct HOSTNAME from `failover-host` (used by the 3-worker test) so
    # the abstract-namespace keys socket `\0rhorizon-keys-<HOSTNAME>` does
    # not collide if test ordering ever changes.
    monkeypatch.setenv("HOSTNAME", "failover-iso5-host")
    monkeypatch.setattr(cluster_setup, "FOLLOWER_MASTER_WAIT_SECS", 5.0)
    monkeypatch.setattr(cluster_setup, "FOLLOWER_POLL_INTERVAL_SECS", 0.2)
    monkeypatch.setattr(settings, "cluster_shamir_total", 5)
    monkeypatch.setattr(settings, "cluster_shamir_threshold", 3)

    # -- 1. Master setup --
    master_keys = _gen_keys()
    master = VaultState()
    master.unseal(master_keys)
    master_pid = 92001
    follower_pids = [92002, 92003, 92004, 92005]

    async with async_session() as db:
        await register_worker(db, pid=master_pid)
        await update_worker_state(db, WorkerState.MASTER, pid=master_pid)
        await start_master_services(db, master, pid=master_pid)
        for fpid in follower_pids:
            await register_worker(db, pid=fpid)

    # Capture an HMAC signature from the original master, for equality check
    # post-failover. If reconstruction is lossless, the new master will
    # produce the exact same signature.
    sig_before = master._hmac_sha512_hex_local("failover-payload")

    # -- 2. Each follower attaches: fetches its unique share + binds back --
    followers: list[VaultState] = []
    try:
        for fpid in follower_pids:
            f = VaultState()
            ok = await attach_to_master(async_session, f, pid=fpid)
            assert ok is True, f"follower pid={fpid} failed to attach"
            assert f._cluster_share is not None, (
                f"follower pid={fpid} did not receive a Shamir share"
            )
            followers.append(f)

        # Sanity: every follower has a share-back socket published in DB
        async with async_session() as db:
            r = await db.execute(
                text("""
                    SELECT pid, socket_name FROM vault_workers
                    WHERE pid = ANY(:pids) AND socket_name IS NOT NULL
                """),
                {"pids": follower_pids},
            )
            published = {row.pid: row.socket_name for row in r.fetchall()}
        assert set(published.keys()) == set(follower_pids), (
            "not every follower published its share-back socket"
        )

        # -- 3. Master crashes --
        await stop_master_services(master)
        master.seal()
        async with async_session() as db:
            await db.execute(
                text("DELETE FROM vault_workers WHERE pid = :pid"),
                {"pid": master_pid},
            )
            await db.commit()

        # -- 4. First follower runs election + failover --
        candidate_pid = follower_pids[0]
        candidate = followers[0]

        # run_election uses os.getpid(), we bypass it and call claim directly
        # with our fake pid so the test does not depend on the test process pid.
        async with async_session() as db:
            won = await claim_master_role(db, pid=candidate_pid)
        assert won is True

        ok = await reconstruct_and_become_master(
            async_session, candidate, pid=candidate_pid
        )
        assert ok is True, (
            "reconstruct_and_become_master returned False - likely quorum "
            "not met (peers may have already served their share to someone "
            "else, or share-back socket timed out)"
        )

        # -- 5. Verify the new master --
        assert candidate.sealed is False, (
            "new master should be unsealed after reconstruction"
        )
        assert candidate._rpc_client is None, "new master must not be RPC-client"
        assert candidate._master_rpc_server is not None, (
            "new master should have started master services"
        )

        # Lossless reconstruction: same input -> same HMAC
        sig_after = candidate._hmac_sha512_hex_local("failover-payload")
        assert sig_after == sig_before, (
            "HMAC differs post-failover - Shamir reconstruction LOST data"
        )

        # DB reflects the new master
        async with async_session() as db:
            r = await db.execute(
                text("""
                    SELECT pid, worker_state, crypto_socket_name
                    FROM vault_workers
                    WHERE worker_state = 'master'
                      AND last_heartbeat > NOW() - INTERVAL '5s'
                """)
            )
            masters = r.fetchall()
        assert len(masters) == 1, (
            f"expected exactly one live master, got {len(masters)}"
        )
        assert masters[0].pid == candidate_pid
        assert masters[0].crypto_socket_name is not None
    finally:
        # Cleanup: stop the new master's services + detach all followers
        for f in followers:
            try:
                await detach_from_master(f)
            except Exception:
                pass
        await stop_master_services(master)
        try:
            await stop_master_services(followers[0])
        except Exception:
            pass


@pytest.mark.asyncio
async def test_failover_rolls_back_when_start_master_services_fails(monkeypatch):
    """If start_master_services fails AFTER the keys are reconstructed and the
    worker_state='master' row is committed, reconstruct_and_become_master must
    fully roll back -- seal the reconstructed keys and reset the row -- instead
    of leaving a phantom master (is_master True, no RPC server, DB says master,
    sub-keys live in RAM). Mirrors start_master_services_or_rollback."""
    from api.app import cluster_setup
    from api.app.cluster import claim_master_role
    from api.app.cluster_setup import reconstruct_and_become_master
    from api.app.config import settings

    monkeypatch.setenv("HOSTNAME", "failover-rollback-host")
    monkeypatch.setattr(cluster_setup, "FOLLOWER_MASTER_WAIT_SECS", 5.0)
    monkeypatch.setattr(cluster_setup, "FOLLOWER_POLL_INTERVAL_SECS", 0.2)
    monkeypatch.setattr(settings, "cluster_shamir_total", 5)
    monkeypatch.setattr(settings, "cluster_shamir_threshold", 3)

    master = VaultState()
    master.unseal(_gen_keys())
    master_pid = 93001
    follower_pids = [93002, 93003, 93004, 93005]

    async with async_session() as db:
        await register_worker(db, pid=master_pid)
        await update_worker_state(db, WorkerState.MASTER, pid=master_pid)
        await start_master_services(db, master, pid=master_pid)
        for fpid in follower_pids:
            await register_worker(db, pid=fpid)

    followers: list[VaultState] = []
    try:
        for fpid in follower_pids:
            f = VaultState()
            assert await attach_to_master(async_session, f, pid=fpid) is True
            followers.append(f)

        await stop_master_services(master)
        master.seal()
        async with async_session() as db:
            await db.execute(
                text("DELETE FROM vault_workers WHERE pid = :pid"),
                {"pid": master_pid},
            )
            await db.commit()

        candidate_pid = follower_pids[0]
        candidate = followers[0]
        async with async_session() as db:
            assert await claim_master_role(db, pid=candidate_pid) is True

        # Force the promotion's start_master_services to fail AFTER reconstruct +
        # unseal + the worker_state='master' commit.
        async def _boom(*a, **k):
            raise RuntimeError("simulated start_master_services failure")

        monkeypatch.setattr(cluster_setup, "start_master_services", _boom)

        ok = await reconstruct_and_become_master(
            async_session, candidate, pid=candidate_pid
        )
        assert ok is False
        # Full rollback: keys sealed, no phantom master server, row not 'master'.
        assert candidate.sealed is True
        assert candidate.is_master is False
        assert candidate._master_rpc_server is None
        async with async_session() as db:
            r = await db.execute(
                text("SELECT worker_state FROM vault_workers WHERE pid = :pid"),
                {"pid": candidate_pid},
            )
            row = r.fetchone()
        assert row is not None and row.worker_state == "sealed"
    finally:
        for f in followers:
            try:
                await detach_from_master(f)
            except Exception:
                pass
        try:
            await stop_master_services(master)
        except Exception:
            pass


@pytest.mark.asyncio
async def test_attach_to_master_excludes_self_pid(monkeypatch):
    """A worker must not RPC-attach to its own crypto socket.

    Regression: when /unseal lands on a worker that acquired role=master at
    boot, that worker becomes status=master in DB. Its own follower-boot
    loop must NOT see itself as a candidate master and try to attach. Without
    the self-pid filter, the worker would loop-back to its own RPC server
    instead of recognizing it IS the master locally.
    """
    from api.app import cluster_setup

    monkeypatch.setenv("HOSTNAME", "self-loop-host")
    monkeypatch.setattr(cluster_setup, "FOLLOWER_MASTER_WAIT_SECS", 1.0)
    monkeypatch.setattr(cluster_setup, "FOLLOWER_POLL_INTERVAL_SECS", 0.2)

    # Set up a master row whose pid matches the self_pid we'll pass to
    # attach_to_master. Without the filter, attach would find this row and
    # try to connect to its own socket.
    self_pid = 91005
    async with async_session() as db:
        await register_worker(db, pid=self_pid)
        await update_worker_state(db, WorkerState.MASTER, pid=self_pid)
        await db.execute(
            text(
                "UPDATE vault_workers "
                "SET crypto_socket_name = "
                "    '/run/rhorizon/crypto-ops-self-loop-host.sock', "
                "    last_heartbeat = NOW() "
                "WHERE pid = :pid"
            ),
            {"pid": self_pid},
        )
        await db.commit()

    follower = VaultState()
    ok = await attach_to_master(async_session, follower, pid=self_pid)
    assert ok is False  # self-row excluded -> no candidate master -> timeout
    assert follower._rpc_client is None
    assert follower.sealed is True  # never attached, stays sealed locally


# -- Shamir distribution ----------------------------------------------------


@pytest.mark.asyncio
async def test_master_keeps_own_share_after_split(monkeypatch):
    """After start_master_services, master holds its own Shamir share."""
    monkeypatch.setenv("HOSTNAME", "split-host-A")
    master = VaultState()
    master.unseal(_gen_keys())
    pid = os.getpid()

    async with async_session() as db:
        await register_worker(db, pid=pid)
        await update_worker_state(db, WorkerState.MASTER, pid=pid)
        await start_master_services(db, master, pid=pid)
    try:
        assert master._cluster_share is not None
        assert master._cluster_share_server is not None
        # Share is x-coord 1 (first split)
        assert master._cluster_share.x == 1
    finally:
        await stop_master_services(master)
        master.seal()


@pytest.mark.asyncio
async def test_two_followers_get_distinct_shares(monkeypatch):
    """Two followers connecting to the same master receive shares with
    different x-coordinates (so they can be combined for reconstruction)."""
    monkeypatch.setenv("HOSTNAME", "split-host-B")
    master = VaultState()
    master.unseal(_gen_keys())
    master_pid = os.getpid()
    f1_pid = 92001
    f2_pid = 92002

    async with async_session() as db:
        await register_worker(db, pid=master_pid)
        await update_worker_state(db, WorkerState.MASTER, pid=master_pid)
        await start_master_services(db, master, pid=master_pid)
        await register_worker(db, pid=f1_pid)
        await register_worker(db, pid=f2_pid)

    f1 = VaultState()
    f2 = VaultState()
    try:
        ok1 = await attach_to_master(async_session, f1, pid=f1_pid)
        ok2 = await attach_to_master(async_session, f2, pid=f2_pid)
        assert ok1 and ok2
        assert f1._cluster_share is not None
        assert f2._cluster_share is not None
        # x-coordinates must differ, that's what makes Shamir reconstruct
        assert f1._cluster_share.x != f2._cluster_share.x
        # And neither equals the master's x=1 share.
        assert f1._cluster_share.x != master._cluster_share.x
        assert f2._cluster_share.x != master._cluster_share.x
    finally:
        await stop_master_services(master)
        await detach_from_master(f1)
        await detach_from_master(f2)
        master.seal()


@pytest.mark.asyncio
async def test_follower_share_back_socket_published(monkeypatch):
    """After attach, the follower's own share-back socket name is in DB."""
    monkeypatch.setenv("HOSTNAME", "split-host-C")
    master = VaultState()
    master.unseal(_gen_keys())
    master_pid = os.getpid()
    follower_pid = 92010

    async with async_session() as db:
        await register_worker(db, pid=master_pid)
        await update_worker_state(db, WorkerState.MASTER, pid=master_pid)
        await start_master_services(db, master, pid=master_pid)
        await register_worker(db, pid=follower_pid)

    follower = VaultState()
    try:
        ok = await attach_to_master(async_session, follower, pid=follower_pid)
        assert ok is True
        async with async_session() as db:
            r = await db.execute(
                text("SELECT socket_name FROM vault_workers WHERE pid = :pid"),
                {"pid": follower_pid},
            )
            row = r.fetchone()
        assert row is not None
        assert row.socket_name is not None
        # Filesystem path; basename starts with share-
        import os.path as _op

        assert _op.basename(row.socket_name).startswith("share-")
        assert row.socket_name.endswith(".sock")
        assert str(follower_pid) in row.socket_name
    finally:
        await stop_master_services(master)
        await detach_from_master(follower)
        master.seal()


# -- Concurrency: master appears AFTER follower starts polling --------------


# -- Failover ------------------------------------------


@pytest.mark.asyncio
async def test_failover_reconstruct_with_quorum(monkeypatch):
    """End-to-end failover: master + 2 followers, then "kill" master and
    have a follower reconstruct sub-keys from its own share + 1 peer share.

    cluster_shamir_threshold default is 3, so we'd need master+2 followers
    or 3 followers to reach quorum. We use threshold=2 here for simplicity
    (any 2 shares can reconstruct).
    """
    from api.app import config as _cfg
    from api.app.cluster_setup import reconstruct_and_become_master

    monkeypatch.setattr(_cfg.settings, "cluster_shamir_threshold", 2)
    monkeypatch.setattr(_cfg.settings, "cluster_shamir_total", 3)
    monkeypatch.setenv("HOSTNAME", "failover-host")

    master_keys = _gen_keys()
    master = VaultState()
    master.unseal(master_keys)
    master_pid = os.getpid()
    f1_pid = 93001
    f2_pid = 93002

    async with async_session() as db:
        await register_worker(db, pid=master_pid)
        await update_worker_state(db, WorkerState.MASTER, pid=master_pid)
        await start_master_services(db, master, pid=master_pid)
        await register_worker(db, pid=f1_pid)
        await register_worker(db, pid=f2_pid)

    f1 = VaultState()
    f2 = VaultState()
    try:
        await attach_to_master(async_session, f1, pid=f1_pid)
        await attach_to_master(async_session, f2, pid=f2_pid)
        assert f1._cluster_share is not None
        assert f2._cluster_share is not None

        # Simulate master death: stop master services + delete its row
        await stop_master_services(master)
        master.seal()
        async with async_session() as db:
            await db.execute(
                text("DELETE FROM vault_workers WHERE pid = :pid"),
                {"pid": master_pid},
            )
            await db.commit()

        # Now f1 wins the election (simulated) and reconstructs.
        # f1 has its own share (1) + can fetch from f2 (1 more) = 2 shares.
        # threshold=2 so quorum is met.
        # Use a different PID for the new master so it doesn't collide with
        # the old master row (which we just deleted, but for clarity).
        async with async_session() as db:
            # f1 needs to be marked master to use start_master_services
            await db.execute(
                text("UPDATE vault_workers SET worker_state='master' WHERE pid = :pid"),
                {"pid": f1_pid},
            )
            await db.commit()

        # keep HOSTNAME stable across failover. In production, the
        # surviving follower runs in the same container as the dead master,
        # so HOSTNAME is unchanged. The peer-share collection filters by
        # The collection query is scoped by HOSTNAME, so f2's share-back
        # socket is reachable only while the survivor stays on that hostname.
        ok = await reconstruct_and_become_master(async_session, f1, pid=f1_pid)
        assert ok is True

        # f1 should now be master: rpc_client detached, _hmac_enc set
        assert f1._rpc_client is None
        assert f1.sealed is False
        # And it should have the SAME sub-keys as the original master.
        # Compare HMACs against a fresh VaultState seeded with master_keys.
        oracle = VaultState()
        oracle.unseal(master_keys)
        sig_new = f1._hmac_sha512_hex_local("test-payload")
        sig_orig = oracle._hmac_sha512_hex_local("test-payload")
        oracle.seal()
        assert sig_new == sig_orig
    finally:
        await stop_master_services(f1)
        f1.seal()
        await detach_from_master(f2)
        master.seal()


@pytest.mark.asyncio
async def test_failover_fails_without_quorum(monkeypatch):
    """If only 1 share is available (master gone, no peers responsive),
    reconstruction fails with quorum-not-met."""
    from api.app import config as _cfg
    from api.app.cluster_setup import reconstruct_and_become_master

    monkeypatch.setattr(_cfg.settings, "cluster_shamir_threshold", 3)
    monkeypatch.setattr(_cfg.settings, "cluster_shamir_total", 5)
    monkeypatch.setenv("HOSTNAME", "no-quorum-host")

    master = VaultState()
    master.unseal(_gen_keys())
    master_pid = os.getpid()
    f1_pid = 94001

    async with async_session() as db:
        await register_worker(db, pid=master_pid)
        await update_worker_state(db, WorkerState.MASTER, pid=master_pid)
        await start_master_services(db, master, pid=master_pid)
        await register_worker(db, pid=f1_pid)

    f1 = VaultState()
    try:
        await attach_to_master(async_session, f1, pid=f1_pid)
        assert f1._cluster_share is not None

        # f1 has 1 share. Threshold is 3. No live peers (we removed master).
        async with async_session() as db:
            await db.execute(
                text("DELETE FROM vault_workers WHERE pid = :pid"),
                {"pid": master_pid},
            )
            await db.commit()
        await stop_master_services(master)
        master.seal()

        ok = await reconstruct_and_become_master(async_session, f1, pid=f1_pid)
        assert ok is False  # quorum not met
    finally:
        await detach_from_master(f1)


@pytest.mark.asyncio
async def test_failover_fails_when_no_share(monkeypatch):
    """A worker that never participated in distribution can't reconstruct."""
    from api.app.cluster_setup import reconstruct_and_become_master

    follower = VaultState()
    # No cluster_share set
    ok = await reconstruct_and_become_master(async_session, follower, pid=95001)
    assert ok is False


@pytest.mark.asyncio
async def test_failover_reloads_ha_password_after_promotion(monkeypatch):
    """After successful Shamir reconstruction + master promotion, the new
     master MUST call ha_password.load_ha_password_into_ram so that
     /cluster/challenge and /cluster/join can serve HMAC for new JOINs.
     Without this reload, the new master boots with ha_loaded=false even
     though the cluster is initialised and ha_password is wrapped in DB
    . The fix lives inside reconstruct_and_become_master
     in cluster_setup.py.
    """
    from api.app import config as _cfg
    from api.app import ha_password as _ha_password
    from api.app.cluster_setup import reconstruct_and_become_master

    monkeypatch.setattr(_cfg.settings, "cluster_shamir_threshold", 2)
    monkeypatch.setattr(_cfg.settings, "cluster_shamir_total", 3)
    monkeypatch.setenv("HOSTNAME", "reload-ha-host")

    master_keys = _gen_keys()
    master = VaultState()
    master.unseal(master_keys)
    master_pid = os.getpid()
    f1_pid = 95101
    f2_pid = 95102

    async with async_session() as db:
        await register_worker(db, pid=master_pid)
        await update_worker_state(db, WorkerState.MASTER, pid=master_pid)
        await start_master_services(db, master, pid=master_pid)
        await register_worker(db, pid=f1_pid)
        await register_worker(db, pid=f2_pid)

    f1 = VaultState()
    f2 = VaultState()
    # Record every call so the assertion does not depend on ha_password
    # singleton semantics (the param vault differs from the global vault
    # singleton in tests with multiple VaultState instances).
    calls: list[str] = []

    async def _spy(session):
        calls.append("called")
        return False

    monkeypatch.setattr(_ha_password, "load_ha_password_into_ram", _spy)

    try:
        await attach_to_master(async_session, f1, pid=f1_pid)
        await attach_to_master(async_session, f2, pid=f2_pid)

        # Simulate master death + delete master row from vault_workers
        await stop_master_services(master)
        master.seal()
        async with async_session() as db:
            await db.execute(
                text("DELETE FROM vault_workers WHERE pid = :pid"),
                {"pid": master_pid},
            )
            await db.commit()
        async with async_session() as db:
            await db.execute(
                text("UPDATE vault_workers SET worker_state='master' WHERE pid = :pid"),
                {"pid": f1_pid},
            )
            await db.commit()

        ok = await reconstruct_and_become_master(async_session, f1, pid=f1_pid)
        assert ok is True
        # The fix : reconstruct_and_become_master must call
        # load_ha_password_into_ram exactly once post-promotion.
        assert calls == ["called"], (
            f"expected load_ha_password_into_ram to be called once, got {calls!r}"
        )
    finally:
        await stop_master_services(f1)
        f1.seal()
        await detach_from_master(f2)
        master.seal()


# -- Concurrency: master appears AFTER follower starts polling --------------


@pytest.mark.asyncio
async def test_attach_to_master_succeeds_when_master_appears_late(monkeypatch):
    """Follower starts polling first, master appears 1s later - follower
    should still attach successfully."""
    from api.app import cluster_setup

    monkeypatch.setenv("HOSTNAME", "late-host")
    monkeypatch.setattr(cluster_setup, "FOLLOWER_MASTER_WAIT_SECS", 5.0)
    monkeypatch.setattr(cluster_setup, "FOLLOWER_POLL_INTERVAL_SECS", 0.2)

    master = VaultState()
    master.unseal(_gen_keys())
    master_pid = os.getpid()
    follower_pid = 91002

    async with async_session() as db:
        await register_worker(db, pid=follower_pid)

    async def _start_master_after_delay():
        await asyncio.sleep(1.0)
        async with async_session() as db:
            await register_worker(db, pid=master_pid)
            await update_worker_state(db, WorkerState.MASTER, pid=master_pid)
            await start_master_services(db, master, pid=master_pid)

    follower = VaultState()
    try:
        master_task = asyncio.create_task(_start_master_after_delay())
        ok = await attach_to_master(async_session, follower, pid=follower_pid)
        await master_task
        assert ok is True
        assert follower._rpc_client is not None
    finally:
        await stop_master_services(master)
        await detach_from_master(follower)
        master.seal()
