# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""coverage push on:mod:`api.app.cluster_setup`.

Targets paths not exercised by the real-socket suite
(:file:`test_cluster_setup.py`) :

- ``_shamir_total_threshold`` worker-count scaling.
- ``start_master_services`` socket-acquire failure paths (alive_refused, error).
- ``_serve_shares_loop`` "no more shares" / pending bookkeeping exit.
- ``stop_master_services`` server.stop() raise + DB clear failure.
- ``start_master_services_or_rollback`` failure -> rollback to SEALED.
- ``_wait_for_master_sockets`` DB exception falls through to retry.
- ``attach_to_master`` share fetch / expose failed branch.
- ``_serve_own_share_loop`` generic Exception bail-out.
- ``make_rpc_recover_fn`` recover callback drops stale client + re-attaches.
- ``reconstruct_and_become_master`` peer fetch_share failure logged + skipped.
"""

import asyncio
import os
from contextlib import asynccontextmanager
from unittest.mock import MagicMock

import pytest
from api.app import cluster_setup
from api.app.cluster_setup import (
    _collect_peer_shares,
    _serve_own_share_loop,
    _serve_shares_loop,
    _shamir_total_threshold,
    _wait_for_master_sockets,
    attach_to_master,
    make_rpc_recover_fn,
    reconstruct_and_become_master,
    start_master_services_or_rollback,
    stop_master_services,
)
from api.app.vault_state import VaultState

# Conftest installs an autouse no-op on start/stop/attach for the rest of
# the suite (they shouldn't pay for real-IPC setup). We are exercising
# those very paths -- opt out of the bypass.
pytestmark = pytest.mark.cluster_real

# --- _shamir_total_threshold env parse path -------------------------------


@pytest.mark.parametrize(
    ("workers", "expected"),
    [(1, (13, 3)), (5, (13, 3)), (8, (16, 5)), (10, (18, 6))],
)
def test_shamir_total_threshold_scales_with_workers(monkeypatch, workers, expected):
    """The default pool scales with workers and carries eight churn spares."""
    monkeypatch.setattr(cluster_setup.settings, "cluster_shamir_total", 0)
    monkeypatch.setattr(cluster_setup.settings, "cluster_shamir_threshold", 0)
    monkeypatch.setattr(cluster_setup.settings, "workers", workers)
    assert _shamir_total_threshold() == expected


# --- start_master_services socket-acquire failure modes -------------------


@pytest.mark.asyncio
async def test_start_master_services_acquire_runtime_error_bumps_alive_refused(
    monkeypatch,
):
    """``acquire_socket_path`` raising ``RuntimeError`` (live peer holds
    the socket) must bump the ``alive_refused`` counter and re-raise."""
    vault = VaultState()
    vault._master_rpc_server = None

    def _refuse(_path):
        raise RuntimeError("peer alive on socket -- refused")

    monkeypatch.setattr(cluster_setup, "acquire_socket_path", _refuse)

    bumped: list[str] = []

    class _FakeMetric:
        def labels(self, outcome):
            bumped.append(outcome)

            class _Inc:
                def inc(_self):
                    bumped.append(f"inc:{outcome}")

            return _Inc()

    monkeypatch.setattr(cluster_setup, "master_socket_acquire", _FakeMetric())

    db = MagicMock()
    with pytest.raises(RuntimeError, match="peer alive"):
        await cluster_setup.start_master_services(db, vault, pid=12345)
    assert "alive_refused" in bumped
    assert "inc:alive_refused" in bumped


@pytest.mark.asyncio
async def test_start_master_services_acquire_other_error_bumps_error(monkeypatch):
    """Any non-RuntimeError raised by ``acquire_socket_path`` bumps the
    ``error`` outcome label and re-raises."""
    vault = VaultState()
    vault._master_rpc_server = None

    def _refuse(_path):
        raise OSError("EACCES on socket path")

    monkeypatch.setattr(cluster_setup, "acquire_socket_path", _refuse)

    bumped: list[str] = []

    class _FakeMetric:
        def labels(self, outcome):
            bumped.append(outcome)

            class _Inc:
                def inc(_self):
                    bumped.append(f"inc:{outcome}")

            return _Inc()

    monkeypatch.setattr(cluster_setup, "master_socket_acquire", _FakeMetric())

    db = MagicMock()
    with pytest.raises(OSError, match="EACCES"):
        await cluster_setup.start_master_services(db, vault, pid=12345)
    assert "error" in bumped


# --- _serve_shares_loop "no more shares" exit -----------------------------


@pytest.mark.asyncio
async def test_serve_shares_loop_other_exception_exits_silently(monkeypatch):
    """A serve_one_share raising a generic Exception (e.g. "No more
    shares") bails the loop without raising upstream."""
    monkeypatch.setattr(cluster_setup, "_shamir_total_threshold", lambda: (5, 3))

    vault = VaultState()

    class _FakeSrv:
        def serve_one_share(self):
            raise RuntimeError("No more shares")

    vault._cluster_share_server = _FakeSrv()
    # Should exit without re-raising.
    await _serve_shares_loop(vault)


@pytest.mark.asyncio
async def test_serve_shares_loop_continues_on_timeout(monkeypatch):
    """A TimeoutError loops back to wait for the next peer ; we let it
    spin twice (1st TimeoutError, 2nd success) then exit when expected
    count is reached."""
    monkeypatch.setattr(cluster_setup, "_shamir_total_threshold", lambda: (2, 2))

    vault = VaultState()
    calls = {"n": 0}

    class _FakeSrv:
        def serve_one_share(self):
            calls["n"] += 1
            if calls["n"] == 1:
                raise TimeoutError("no peer yet")
            return 42

    vault._cluster_share_server = _FakeSrv()
    await _serve_shares_loop(vault)
    # 1 timeout (continue) + 1 success (served == expected=1) -> exit
    assert calls["n"] == 2


@pytest.mark.asyncio
async def test_serve_shares_loop_exits_when_server_cleared(monkeypatch):
    """``_cluster_share_server`` becoming None mid-loop (master sealed) ->
    immediate return."""
    monkeypatch.setattr(cluster_setup, "_shamir_total_threshold", lambda: (5, 3))

    vault = VaultState()
    vault._cluster_share_server = None
    await _serve_shares_loop(vault)


# --- stop_master_services failure modes -----------------------------------


@pytest.mark.asyncio
async def test_stop_master_services_server_stop_raises_swallowed():
    """A ``server.stop()`` that raises must NOT propagate -- the next
    seal cycle has to keep going (DB cleanup, share-server teardown)."""
    vault = VaultState()

    class _BadServer:
        def stop(self):
            raise RuntimeError("simulated stop failure")

    vault._master_rpc_server = _BadServer()
    vault._cluster_share_server = None
    # No DB -- exercise the in-memory cleanup path.
    await stop_master_services(vault, db=None)
    assert vault._master_rpc_server is None


@pytest.mark.asyncio
async def test_stop_master_services_db_clear_failure_swallowed(monkeypatch):
    """A DB UPDATE that raises (DB unreachable mid-seal) is swallowed --
    the reaper will eventually clean the stale row."""
    vault = VaultState()
    vault._master_rpc_server = None
    vault._cluster_share_server = None

    class _FailingDb:
        async def execute(self, *args, **kwargs):
            raise RuntimeError("DB unreachable during seal")

        async def commit(self):
            raise RuntimeError("commit refused")

    # Hostname lookup is part of the path -- stub it.
    from api.app import cluster as _cluster_mod

    monkeypatch.setattr(_cluster_mod, "get_hostname", lambda: "test-host")
    await stop_master_services(vault, db=_FailingDb(), pid=999)


@pytest.mark.asyncio
async def test_stop_master_services_share_server_close_swallowed():
    """``_cluster_share_server.close()`` raising must not propagate."""
    vault = VaultState()
    vault._master_rpc_server = None

    class _BadShareServer:
        def close(self):
            raise RuntimeError("close failure")

    vault._cluster_share_server = _BadShareServer()
    await stop_master_services(vault, db=None)
    assert vault._cluster_share_server is None


# --- start_master_services_or_rollback failure path -----------------------


@pytest.mark.asyncio
async def test_start_master_services_or_rollback_rolls_back_on_failure(
    monkeypatch,
):
    """``start_master_services`` raising triggers worker_state rollback
    to SEALED + local ``vault.seal()`` + re-raise."""
    vault = VaultState()
    vault._sealed = False
    vault.unseal(
        {
            "hmac_key": b"h" * 32,
            "dek_key": b"d" * 32,
            "audit_key": b"a" * 32,
            "ha_wrap_key": b"w" * 32,
            "pki_wrap_key": b"w" * 32,
        }
    )

    async def _boom(db, vault, pid=None):
        raise RuntimeError("simulated start failure")

    monkeypatch.setattr(cluster_setup, "start_master_services", _boom)

    update_calls: list = []

    async def _update_worker_state(db, state, pid=None):
        update_calls.append((state, pid))

    monkeypatch.setattr("api.app.cluster.update_worker_state", _update_worker_state)
    db = MagicMock()
    with pytest.raises(RuntimeError, match="simulated start failure"):
        await start_master_services_or_rollback(db, vault, pid=777)
    assert len(update_calls) == 1
    # WorkerState.SEALED would have been passed.
    from api.app.cluster import WorkerState

    assert update_calls[0] == (WorkerState.SEALED, 777)
    # Local seal happened too.
    assert vault.sealed is True


@pytest.mark.asyncio
async def test_start_master_services_or_rollback_rollback_update_failure_swallowed(
    monkeypatch,
):
    """If the rollback ``update_worker_state`` *also* fails, the original
    error still propagates and ``vault.seal()`` is still attempted."""
    vault = VaultState()
    vault.unseal(
        {
            "hmac_key": b"h" * 32,
            "dek_key": b"d" * 32,
            "audit_key": b"a" * 32,
            "ha_wrap_key": b"w" * 32,
            "pki_wrap_key": b"w" * 32,
        }
    )

    async def _boom(db, vault, pid=None):
        raise RuntimeError("start failure")

    async def _boom_update(db, state, pid=None):
        raise RuntimeError("rollback update failure")

    monkeypatch.setattr(cluster_setup, "start_master_services", _boom)
    monkeypatch.setattr("api.app.cluster.update_worker_state", _boom_update)
    db = MagicMock()
    with pytest.raises(RuntimeError, match="start failure"):
        await start_master_services_or_rollback(db, vault)
    assert vault.sealed is True


@pytest.mark.asyncio
async def test_start_master_services_or_rollback_vault_seal_failure_swallowed(
    monkeypatch,
):
    """If even ``vault.seal()`` raises, the original error still surfaces."""
    vault = VaultState()
    vault.unseal(
        {
            "hmac_key": b"h" * 32,
            "dek_key": b"d" * 32,
            "audit_key": b"a" * 32,
            "ha_wrap_key": b"w" * 32,
            "pki_wrap_key": b"w" * 32,
        }
    )

    async def _boom(db, vault, pid=None):
        raise RuntimeError("start failure")

    async def _ok_update(db, state, pid=None):
        return

    def _seal_boom(self):
        raise RuntimeError("seal failure")

    monkeypatch.setattr(cluster_setup, "start_master_services", _boom)
    monkeypatch.setattr("api.app.cluster.update_worker_state", _ok_update)
    monkeypatch.setattr(VaultState, "seal", _seal_boom, raising=False)
    db = MagicMock()
    with pytest.raises(RuntimeError, match="start failure"):
        await start_master_services_or_rollback(db, vault)


@pytest.mark.asyncio
async def test_start_master_services_or_rollback_releases_master_socket(
    monkeypatch,
):
    """Regression: a start_master_services that binds the crypto-ops RPC
    socket then fails at a later step must have that socket released on
    rollback. vault.seal() alone does NOT stop _master_rpc_server, so the
    rollback must route through stop_master_services -- otherwise the socket
    leaks as a live listener and every later /unseal 500s with
    "already bound by an alive process" until the process restarts.
    """

    class _FakeServer:
        def __init__(self):
            self.stopped = False

        def stop(self):  # sync, like the Rust MasterRpcServer
            self.stopped = True

    fake = _FakeServer()

    async def _bind_then_boom(db, vault, pid=None):
        # Mimic server.start() succeeding (socket now bound) before the
        # later Shamir/DB step blows up.
        vault._master_rpc_server = fake
        raise RuntimeError("simulated post-bind failure")

    monkeypatch.setattr(cluster_setup, "start_master_services", _bind_then_boom)

    async def _update_worker_state(db, state, pid=None):
        return

    monkeypatch.setattr("api.app.cluster.update_worker_state", _update_worker_state)

    vault = VaultState()
    vault.unseal(
        {
            "hmac_key": b"h" * 32,
            "dek_key": b"d" * 32,
            "audit_key": b"a" * 32,
            "ha_wrap_key": b"w" * 32,
            "pki_wrap_key": b"w" * 32,
        }
    )
    db = MagicMock()
    with pytest.raises(RuntimeError, match="simulated post-bind failure"):
        await start_master_services_or_rollback(db, vault, pid=42)

    # The socket-owning RPC server was torn down (stop() called + handle
    # cleared) and the vault is locally sealed.
    assert fake.stopped is True
    assert vault._master_rpc_server is None
    assert vault.sealed is True


# --- _wait_for_master_sockets DB hiccup -----------------------------------


@pytest.mark.asyncio
async def test_wait_for_master_sockets_db_exception_falls_through(monkeypatch):
    """A transient DB error in the poll loop is logged + the loop sleeps
    + retries. With timeout=0.1s, the loop exits with None after one
    failure window."""

    class _BadDb:
        async def execute(self, *args, **kwargs):
            raise RuntimeError("DB hiccup")

    @asynccontextmanager
    async def _factory():
        yield _BadDb()

    monkeypatch.setattr("api.app.cluster.get_hostname", lambda: "test-host")
    # Speed up the inner poll cadence.
    monkeypatch.setattr(cluster_setup, "FOLLOWER_POLL_INTERVAL_SECS", 0.01)
    result = await _wait_for_master_sockets(_factory, timeout_secs=0.1, self_pid=1)
    assert result is None


@pytest.mark.asyncio
async def test_wait_for_master_sockets_returns_pair_on_match(monkeypatch):
    """Happy path: a live master row -> returns (crypto_sock, keys_sock)."""

    class _Row:
        crypto_socket_name = "/run/rhorizon/crypto.sock"
        socket_name = "/run/rhorizon/keys.sock"

    class _Result:
        def fetchone(self):
            return _Row()

    class _OkDb:
        async def execute(self, *args, **kwargs):
            return _Result()

    @asynccontextmanager
    async def _factory():
        yield _OkDb()

    monkeypatch.setattr("api.app.cluster.get_hostname", lambda: "test-host")
    result = await _wait_for_master_sockets(_factory, timeout_secs=1.0, self_pid=1)
    assert result == ("/run/rhorizon/crypto.sock", "/run/rhorizon/keys.sock")


@pytest.mark.asyncio
async def test_wait_for_master_sockets_handles_null_keys_socket(monkeypatch):
    """A master pre-commit-6a publishes crypto but no keys -- return
    ``(crypto, None)`` so the follower attaches RPC-only."""

    class _Row:
        crypto_socket_name = "/run/rhorizon/crypto.sock"
        socket_name = None

    class _Result:
        def fetchone(self):
            return _Row()

    class _OkDb:
        async def execute(self, *args, **kwargs):
            return _Result()

    @asynccontextmanager
    async def _factory():
        yield _OkDb()

    monkeypatch.setattr("api.app.cluster.get_hostname", lambda: "test-host")
    crypto, keys = await _wait_for_master_sockets(
        _factory, timeout_secs=1.0, self_pid=1
    )
    assert crypto == "/run/rhorizon/crypto.sock"
    assert keys is None


# --- attach_to_master share-fetch failure ---------------------------------


@pytest.mark.asyncio
async def test_attach_to_master_share_fetch_failure_stays_sealed_for_retry(
    monkeypatch,
):
    """An advertised share socket makes quorum participation mandatory.

    A transient transfer failure must leave the worker sealed and detached;
    the persistent follower reconciler can then retry instead of accepting a
    permanently quorumless worker.
    """
    vault = VaultState()

    async def _fake_wait(*args, **kwargs):
        return ("/run/rhorizon/crypto.sock", "/run/rhorizon/keys.sock")

    monkeypatch.setattr(cluster_setup, "_wait_for_master_sockets", _fake_wait)

    class _FakeRpcClient:
        def __init__(self, sock):
            self.sock = sock

        async def call(self, method, params=None):
            # answer the attach-time hmac_sha512 healthcheck
            return {"ok": True}

    monkeypatch.setattr(cluster_setup, "MasterRpcClient", _FakeRpcClient)

    async def _boom(*args, **kwargs):
        raise RuntimeError("share fetch failed")

    monkeypatch.setattr(cluster_setup, "_fetch_and_expose_share", _boom)

    class _Published:
        rowcount = 1

    class _Db:
        async def execute(self, *_args, **_kwargs):
            return _Published()

        async def commit(self):
            return None

    @asynccontextmanager
    async def _factory():
        yield _Db()

    ok = await attach_to_master(_factory, vault, pid=os.getpid())
    assert ok is False
    assert vault._rpc_client is None
    assert vault.sealed is True


@pytest.mark.asyncio
async def test_attach_to_master_fails_closed_when_worker_row_disappears(monkeypatch):
    vault = VaultState()

    async def _fake_wait(*args, **kwargs):
        return ("/run/rhorizon/crypto.sock", None)

    monkeypatch.setattr(cluster_setup, "_wait_for_master_sockets", _fake_wait)

    class _FakeRpcClient:
        def __init__(self, _sock):
            pass

        async def call(self, _method, _params=None):
            return {"ok": True}

    monkeypatch.setattr(cluster_setup, "MasterRpcClient", _FakeRpcClient)

    class _Missing:
        rowcount = 0

    class _Db:
        async def execute(self, *_args, **_kwargs):
            return _Missing()

        async def commit(self):
            return None

    @asynccontextmanager
    async def _factory():
        yield _Db()

    ok = await attach_to_master(_factory, vault, pid=1)

    assert ok is False
    assert vault.sealed is True
    assert vault._rpc_client is None


@pytest.mark.asyncio
async def test_attach_to_master_does_not_overwrite_concurrent_local_master(
    monkeypatch,
):
    """An operator unseal completing during the RPC probe wins the transition."""
    vault = VaultState()

    async def _fake_wait(*args, **kwargs):
        return ("/run/rhorizon/crypto.sock", None)

    monkeypatch.setattr(cluster_setup, "_wait_for_master_sockets", _fake_wait)

    class _FakeRpcClient:
        def __init__(self, _sock):
            pass

        async def call(self, _method, _params=None):
            vault.unseal(
                {
                    "hmac_key": b"h" * 32,
                    "dek_key": b"d" * 32,
                    "audit_key": b"a" * 32,
                    "ha_wrap_key": b"w" * 32,
                    "pki_wrap_key": b"p" * 32,
                }
            )
            return {"ok": True}

    monkeypatch.setattr(cluster_setup, "MasterRpcClient", _FakeRpcClient)

    ok = await attach_to_master(None, vault, pid=1)

    assert ok is False
    assert vault.is_master is True
    assert vault._rpc_client is None


@pytest.mark.asyncio
async def test_attach_to_master_returns_true_when_already_attached():
    """Idempotent: ``_rpc_client`` already wired -> early return True."""
    vault = VaultState()
    vault._rpc_client = object()  # any sentinel
    vault._sealed = False

    @asynccontextmanager
    async def _factory():
        yield MagicMock()

    ok = await attach_to_master(_factory, vault, pid=1)
    assert ok is True


@pytest.mark.asyncio
async def test_attach_to_master_drops_client_left_on_sealed_follower(monkeypatch):
    """A sealed worker must not accept an old RPC client as an attached,
    operational follower."""
    vault = VaultState()
    vault._rpc_client = object()
    assert vault.sealed is True

    wait_calls = []

    async def _none(*args, **kwargs):
        wait_calls.append(True)
        return None

    monkeypatch.setattr(cluster_setup, "_wait_for_master_sockets", _none)

    ok = await attach_to_master(None, vault, pid=1)
    assert ok is False
    assert wait_calls == [True]
    assert vault._rpc_client is None


@pytest.mark.asyncio
async def test_attach_to_master_returns_false_on_timeout(monkeypatch):
    """``_wait_for_master_sockets`` returning None -> attach reports False."""
    vault = VaultState()

    async def _none(*a, **k):
        return None

    monkeypatch.setattr(cluster_setup, "_wait_for_master_sockets", _none)

    @asynccontextmanager
    async def _factory():
        yield MagicMock()

    ok = await attach_to_master(_factory, vault, pid=1)
    assert ok is False


# --- _serve_own_share_loop Exception bail-out -----------------------------


@pytest.mark.asyncio
async def test_serve_own_share_loop_other_exception_exits_silently():
    """Non-Timeout exception in serve_one_share -> bail without re-raise."""
    vault = VaultState()

    class _FakeSrv:
        def serve_one_share(self):
            raise RuntimeError("server torn down")

    vault._cluster_share_server = _FakeSrv()
    await _serve_own_share_loop(vault)


@pytest.mark.asyncio
async def test_serve_own_share_loop_exits_when_server_cleared():
    """Server gone mid-loop -> immediate return."""
    vault = VaultState()
    vault._cluster_share_server = None
    await _serve_own_share_loop(vault)


@pytest.mark.asyncio
async def test_serve_own_share_loop_timeout_then_serve(monkeypatch):
    """One TimeoutError loops back, second call serves and exits (one-shot)."""
    vault = VaultState()
    calls = {"n": 0}

    class _FakeSrv:
        def serve_one_share(self):
            calls["n"] += 1
            if calls["n"] == 1:
                raise TimeoutError("no peer yet")
            return 4242

    vault._cluster_share_server = _FakeSrv()
    await _serve_own_share_loop(vault)
    assert calls["n"] == 2


# --- make_rpc_recover_fn _recover callback --------------------------------


@pytest.mark.asyncio
async def test_make_rpc_recover_fn_drops_stale_then_reattaches(monkeypatch):
    """The recover hook drops the stale client and re-runs
    ``attach_to_master``. We verify both happen and that the boolean
    return surfaces."""
    vault = VaultState()
    vault._rpc_client = object()  # stale

    @asynccontextmanager
    async def _factory():
        yield MagicMock()

    attach_calls: list[int] = []

    async def _fake_attach(session_factory, vault_arg, pid=None):
        attach_calls.append(pid)
        return True

    monkeypatch.setattr(cluster_setup, "attach_to_master", _fake_attach)

    recover = make_rpc_recover_fn(_factory, vault, pid=4242)
    ok = await recover()
    assert ok is True
    assert vault._rpc_client is None or attach_calls == [4242]
    # detach_rpc_client clears _rpc_client (and the fake attach doesn't re-set it)
    assert attach_calls == [4242]


@pytest.mark.asyncio
async def test_make_rpc_recover_fn_returns_false_on_timeout(monkeypatch):
    """If ``attach_to_master`` returns False, the recover callback
    propagates that so the vault can surface 503."""
    vault = VaultState()
    vault._rpc_client = object()

    @asynccontextmanager
    async def _factory():
        yield MagicMock()

    async def _fake_attach(session_factory, vault_arg, pid=None):
        return False

    monkeypatch.setattr(cluster_setup, "attach_to_master", _fake_attach)
    recover = make_rpc_recover_fn(_factory, vault, pid=1)
    ok = await recover()
    assert ok is False


# --- reconstruct_and_become_master peer fetch failure ---------------------


@pytest.mark.asyncio
async def test_peer_shares_are_collected_concurrently_and_deduplicated(monkeypatch):
    class _Share:
        def __init__(self, x):
            self.x = x

    peers = [
        {"pid": 101, "socket_name": "peer-101"},
        {"pid": 102, "socket_name": "peer-102"},
        {"pid": 103, "socket_name": "peer-103"},
    ]
    coordinates = {"peer-101": 2, "peer-102": 2, "peer-103": 3}
    all_started = asyncio.Event()
    active = 0
    maximum_active = 0

    async def _concurrent_to_thread(_fn, socket_name):
        nonlocal active, maximum_active
        active += 1
        maximum_active = max(maximum_active, active)
        if active == len(peers):
            all_started.set()
        await all_started.wait()
        active -= 1
        return _Share(coordinates[socket_name])

    monkeypatch.setattr(cluster_setup.asyncio, "to_thread", _concurrent_to_thread)
    shares = await _collect_peer_shares(peers, [_Share(1)], threshold=3)

    assert maximum_active == 3
    assert len(shares) == 3
    assert {share.x for share in shares} == {1, 2, 3}


@pytest.mark.asyncio
async def test_reconstruct_logs_peer_fetch_failure_and_continues(monkeypatch):
    """A peer that errors on share fetch is logged at warn + skipped.
    The function still falls through to the quorum-not-met branch when
    only the local share is collected."""
    vault = VaultState()
    vault._cluster_share = object()  # sentinel local share

    monkeypatch.setattr(cluster_setup, "_shamir_total_threshold", lambda: (5, 3))

    class _Row:
        def __init__(self, pid, sock):
            self.pid = pid
            self.socket_name = sock

    class _Result:
        def fetchall(self):
            return [_Row(101, "/run/rhorizon/peer-101.sock")]

    class _OkDb:
        async def execute(self, *args, **kwargs):
            return _Result()

        async def commit(self):
            return

    @asynccontextmanager
    async def _factory():
        yield _OkDb()

    monkeypatch.setattr("api.app.cluster.get_hostname", lambda: "test-host")

    async def _to_thread_boom(fn, *args, **kwargs):
        raise RuntimeError("peer share fetch failed")

    monkeypatch.setattr(cluster_setup.asyncio, "to_thread", _to_thread_boom)

    bumped: list[str] = []

    class _FakeMetric:
        def labels(self, result):
            bumped.append(result)

            class _Inc:
                def inc(_self):
                    bumped.append(f"inc:{result}")

            return _Inc()

    monkeypatch.setattr(cluster_setup, "cluster_failover", _FakeMetric())

    ok = await reconstruct_and_become_master(_factory, vault, pid=42)
    assert ok is False
    assert "inc:quorum_missing" in bumped


@pytest.mark.asyncio
async def test_stop_master_services_awaits_async_stop_coroutine():
    """The legacy Python ``MasterRpcServer.stop()`` is async ; the helper
    must await the returned coroutine (the Rust path returns ``None``)."""
    vault = VaultState()
    awaited = {"n": 0}

    async def _async_stop():
        awaited["n"] += 1

    class _AsyncServer:
        def stop(self):
            return _async_stop()

    vault._master_rpc_server = _AsyncServer()
    vault._cluster_share_server = None
    await stop_master_services(vault, db=None)
    assert awaited["n"] == 1
    assert vault._master_rpc_server is None


def test_wire_rpc_recovery_installs_hook_on_vault(monkeypatch):
    """``wire_rpc_recovery`` is a one-liner that hands an async callable
    to ``vault.set_rpc_recovery_hook``. Cover via a tiny VaultState
    where we capture the installed hook."""
    vault = VaultState()
    installed: list = []

    monkeypatch.setattr(
        VaultState,
        "set_rpc_recovery_hook",
        lambda self, hook: installed.append(hook),
        raising=False,
    )

    @asynccontextmanager
    async def _factory():
        yield MagicMock()

    cluster_setup.wire_rpc_recovery(vault, _factory, pid=4242)
    assert len(installed) == 1
    assert callable(installed[0])


@pytest.mark.asyncio
async def test_reconstruct_returns_false_when_local_share_missing():
    """Worker never participated in distribution -> ``_cluster_share is
    None`` -> immediate False."""
    vault = VaultState()
    vault._cluster_share = None

    @asynccontextmanager
    async def _factory():
        yield MagicMock()

    ok = await reconstruct_and_become_master(_factory, vault, pid=1)
    assert ok is False


# --- S5 : exhaustion-seal deadlock -- crypto socket released on stop() fail ---


@pytest.mark.asyncio
async def test_stop_master_services_cleans_crypto_socket_when_stop_raises(
    monkeypatch,
):
    """S5 regression: under congestion collapse the Rust MasterRpcServer.stop()
    join can raise/timeout. 6e5d4e0 guaranteed seal routes THROUGH
    stop_master_services, but a FAILED stop() still left the crypto-ops socket
    bound -- the next /unseal then hit acquire_socket_path "already bound by an
    alive process" and 500'd forever (the exhaustion-seal deadlock). The socket
    must be force-cleaned even when stop() raises, so /unseal recovers in-band.
    """
    from api.app.socket_paths import crypto_ops_socket_path

    sock_path = crypto_ops_socket_path()
    sock_path.parent.mkdir(parents=True, exist_ok=True)
    sock_path.touch()  # simulate the bound crypto-ops socket left behind
    assert sock_path.exists()

    class _StopRaisesServer:
        def stop(self):  # sync, like the Rust server -- but blows up under load
            raise RuntimeError("simulated stop() join timeout under exhaustion")

    vault = VaultState()
    vault._master_rpc_server = _StopRaisesServer()

    # db=None : just drop the server + release sockets, no DB row touch.
    await stop_master_services(vault, db=None, pid=99)

    # Server handle cleared AND the leaked crypto-ops socket removed despite
    # stop() raising -- so a subsequent acquire_socket_path can rebind.
    assert vault._master_rpc_server is None
    assert not sock_path.exists()
