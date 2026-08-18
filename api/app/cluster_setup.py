# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Cluster setup helpers - auto-wire RPC + Shamir distribution.

Bridges the lifecycle events (master unseal, master seal, follower boot) with
the underlying primitives (MasterRpcServer, KeyServer/KeyClient, vault state).

Two roles, two flows:

  Master post-unseal:
    1. start MasterRpcServer on the runtime-dir crypto-ops socket
    2. publish socket name in vault_workers.crypto_socket_name
    3. split sub-keys into Shamir shares, bind keys-distribution socket
    4. master keeps the first generated share (x=1); serve the rest to peers
    5. publish keys-socket name in vault_workers.socket_name

  Follower (non-master) boot:
    1. poll vault_workers for a live master with crypto_socket_name set
    2. attach MasterRpcClient to that socket
    3. mark vault logically-unsealed (workers can serve requests via RPC, no
       sub-keys locally)
    4. fetch own Shamir share from master's keys-distribution socket
    5. bind own share-back socket and expose own share for failover collection
    6. publish own share-back socket name in vault_workers.socket_name

This is the only key-distribution path: the historical /dev/shm flow was
removed (compartmentalisation is the contract, not an opt-in).
"""

import asyncio
import logging
import os
from pathlib import Path

from rhorizon_crypto import KeyClient, KeyServer, secure_zero
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from .cluster import MASTER_TIMEOUT_SECS
from .cluster_rpc import (
    CustodianPoolController,
    MasterRpcClient,
    MasterUnreachable,
    RpcError,
    crypto_socket_name,
)
from .config import settings
from .metrics import cluster_failover, master_socket_acquire

# Master RPC server selection.
# Primary path : native Rust thread that bypasses the GIL, needs the
#   rhorizon_crypto extension built with the master_rpc module. When
#   present, every master crypto-op dispatch happens off the Python
#   event loop entirely.
# Fallback path : the Python `cluster_rpc.MasterRpcServer`, used on hosts
#   that haven't rebuilt the wheel yet and as the testbed for the
#   test_cluster_rpc_more unit tests.
try:
    from rhorizon_crypto import MasterRpcServer as _RustMasterRpcServer

    _USE_RUST_MASTER_RPC = True
except ImportError:
    from .cluster_rpc import MasterRpcServer as _RustMasterRpcServer  # type: ignore

    _USE_RUST_MASTER_RPC = False
from .socket_paths import (
    acquire_socket_path,
    cleanup_socket,
    crypto_ops_socket_path,
    follower_share_back_socket_path,
    keys_distribution_socket_path,
    post_bind_chmod,
)
from .vault_state import VaultState

log = logging.getLogger("rhorizon.cluster_setup")

# How long a follower waits for a live master to appear before giving up.
# Long enough to absorb a master that's slow to unseal (operator typing
# password + 2FA), short enough to avoid hanging forever on a misconfigured
# stack.
FOLLOWER_MASTER_WAIT_SECS = 120
FOLLOWER_POLL_INTERVAL_SECS = 1.0
# One deadline for the whole failover quorum fetch. Peer sockets are local to
# this host, so waiting five seconds for all of them is already conservative;
# it must not become five seconds multiplied by the worker count.
SHARE_COLLECTION_TIMEOUT_SECS = 5.0


async def provision_rust_custodian_pool(
    vault: VaultState,
    pool: CustodianPoolController,
    *,
    generation: int,
    threshold: int,
    slots: int,
    split_opaque=None,
):
    """Split, install, and unseal without exposing a plaintext share.

    The mutable runtime bundle is wiped immediately after the native split,
    before any custodian socket operation. Durable generation allocation is a
    caller responsibility; this helper is intentionally not wired to routes
    until that database contract exists.
    """
    if split_opaque is None:
        from rhorizon_crypto import shamir_split_opaque_bytearray

        split_opaque = shamir_split_opaque_bytearray

    statuses = await pool.share_statuses()
    if any(status.get("generation") is not None for status in statuses.values()):
        raise RuntimeError(
            "Rust custodian initial provisioning requires every share slot empty"
        )

    bundle = vault.export_subkeys_for_shamir()
    opaque_shares = []
    try:
        opaque_shares = split_opaque(bundle, threshold, slots)
    finally:
        secure_zero(bundle)

    share_map = {}
    try:
        share_map = {share.x: share for share in opaque_shares}
        if len(share_map) != slots:
            raise RuntimeError("opaque split returned duplicate or missing coordinates")
        try:
            await pool.install_shares(share_map, generation)
        except Exception:
            try:
                await pool.clear_shares_all()
            except Exception as rollback_error:
                raise RuntimeError(
                    "Rust custodian provisioning failed and share rollback "
                    "is incomplete"
                ) from rollback_error
            raise
    finally:
        share_map.clear()
        opaque_shares.clear()
    return await pool.unseal()


def _shamir_total_threshold() -> tuple[int, int]:
    """Resolve the Shamir (total, threshold) pair to use at unseal time.

    If the operator left the defaults at 0, derive from the custody pool:
        quorum_base = max(5, workers) in embedded mode; custodians otherwise
        threshold   = max(2, quorum_base // 2 + 1)       # majority quorum
        total       = quorum_base + cluster_shamir_spare_shares
    so adding workers automatically scales the failover quorum without
    leaving the extra workers hors-quorum. Operators with asymmetric
    needs override either knob explicitly via the env vars.

    The spare shares matter. Shares are minted exactly once, here, and each
    one handed out is removed from the server's pool permanently. With
    total == worker count the pool is empty the moment every worker has
    attached, so a worker that dies and is replaced can never obtain one and
    the live share count only ever falls. Below ``threshold`` no failover can
    reconstruct and the node seals with no way back short of a manual unseal.
    A 3-node lab cluster went 5 shares -> 2 -> 1 that way and sealed on all
    three nodes at once.

    Spares are cut from the SAME polynomial as the rest, so any ``threshold``
    of them still reconstruct. That is why the fix is over-provisioning here
    rather than re-splitting later: a second ``shamir_split`` call draws fresh
    random coefficients, and shares from two different polynomials do not
    combine -- ``shamir_combine`` would return a plausible but wrong blob
    instead of an error.

    Threshold is deliberately pegged to ``quorum_base``, not to ``total``:
    padding the pool must not raise the number of workers required to fail
    over.
    """
    total = settings.cluster_shamir_total
    threshold = settings.cluster_shamir_threshold
    # A separated custodian pool is fixed and does not serve public requests,
    # so its explicitly supported 3-process size is a real 2-of-3 quorum. The
    # historical 5-worker floor remains correct for embedded API workers.
    if settings.custody_mode == "separated" and settings.process_role == "custodian":
        quorum_base = settings.custodian_workers
    else:
        quorum_base = max(5, settings.workers)
    if threshold <= 0:
        threshold = max(2, quorum_base // 2 + 1)
    if total <= 0:
        # GF(256) Shamir addresses shares by a 1-byte x-coordinate, so 255 is
        # the hard ceiling on the pool.
        total = min(255, quorum_base + settings.cluster_shamir_spare_shares)
    return total, threshold


def _single_worker() -> bool:
    """True for the home preset (workers=1). A lone worker holds the
    sub-keys in-process and does its crypto locally, so the crypto-ops RPC
    socket and the Shamir split have nothing to serve: no follower to delegate
    to, no peer to reconstruct from. Skip both."""
    return settings.workers == 1


def master_keys_socket_name(container_id: str | None = None) -> str:
    """Master's Shamir-share distribution socket. Followers connect here at
    boot to fetch their share. Single per master process.

    Filesystem path under the rhorizon runtime dir (default `/run/rhorizon/`).
    Replaces the Linux-only abstract-namespace path used pre-2026-05.
    """
    return str(keys_distribution_socket_path(container_id))


def follower_share_back_socket_name(
    pid: int | None = None,
    container_id: str | None = None,
) -> str:
    """Follower's per-pid socket exposing its own share to a future new
    master (failover collection). Unique per worker process."""
    return str(follower_share_back_socket_path(pid, container_id))


# -- Master side -----------------------------------------------------------


async def start_master_services(
    db: AsyncSession,
    vault: VaultState,
    pid: int | None = None,
):
    """Start the master RPC server + Shamir share distribution.

    Two responsibilities:
      1. Bind the crypto-ops RPC socket so followers can delegate operations
      2. Split the sub-keys into Shamir shares, bind the keys-distribution
         socket, keep the first generated share (x=1), spawn a task to serve the rest to
         peers as they connect

    Idempotent: if a server is already running on this VaultState, returns
    the existing instance. Caller is responsible for keeping the returned
    handle on the vault (for stop_master_services).
    """
    pid = pid if pid is not None else os.getpid()
    if vault._master_rpc_server is not None:
        log.debug("start_master_services: server already running")
        return vault._master_rpc_server

    if _single_worker():
        # Home preset: vault.unseal() already ran, so is_master is True and
        # crypto runs in-process. No RPC socket, no Shamir split. The worker
        # row keeps NULL socket columns; with no followers, nothing polls them.
        log.info(
            "start_master_services: pid=%d single-worker home mode - keys held "
            "locally, no crypto-ops RPC, no Shamir split",
            pid,
        )
        return None

    # 1. RPC server.
    sock = crypto_socket_name()

    sock_path = Path(sock)
    pre_exists = sock_path.exists()
    log.info(
        "start_master_services: pid=%d sock=%s pre_exists=%s rust_path=%s",
        pid,
        sock,
        pre_exists,
        _USE_RUST_MASTER_RPC,
    )
    try:
        acquire_socket_path(sock_path)
    except RuntimeError:
        master_socket_acquire.labels(outcome="alive_refused").inc()
        raise
    except Exception:
        master_socket_acquire.labels(outcome="error").inc()
        raise
    else:
        outcome = "stale_cleaned" if pre_exists else "ok"
        master_socket_acquire.labels(outcome=outcome).inc()
    if _USE_RUST_MASTER_RPC:  # pragma: no cover  (Rust path, integ)
        # Rust path : the WrapKey factory hands its internal master AES
        # key directly to MasterRpcState ; the encrypted subkeys cross
        # as `bytes` because they're public ciphertext (the secret is
        # the wrap key, which stays in Rust). owner_uid is what the
        # server checks against SO_PEERCRED on every connection.
        server = vault._wrap.create_master_rpc_server(
            sock,
            vault._hmac_enc,
            vault._dek_enc,
            vault._audit_enc,
            os.getuid(),
        )
        if vault._prev_hmac_enc is not None:
            server.set_prev_hmac(vault._prev_hmac_enc)
        # Ship the ha_wrap subkey at master start (always present
        # post-unseal). ha_password_enc is set later by
        # ha_password.set_ha_password / load_ha_password_into_ram via
        # the ha_password module's own propagation hook.
        if vault._ha_wrap_enc is not None:
            server.set_ha_wrap_enc(vault._ha_wrap_enc)
        if vault._pki_wrap_enc is not None:
            server.set_pki_wrap_enc(vault._pki_wrap_enc)
        if vault._ha_password_enc is not None:
            server.set_ha_password_enc(vault._ha_password_enc)
        server.start()
        post_bind_chmod(Path(sock))
    else:
        # Legacy Python path : kept for dev hosts that haven't rebuilt
        # the rhorizon_crypto wheel yet, and for the existing
        # test_cluster_rpc_more unit tests.
        server = _RustMasterRpcServer(sock, vault)  # actually the Python class
        await server.start()
    vault._master_rpc_server = server

    # 2. Shamir distribution, only if a keys server isn't already
    # running. We don't want to re-split if this is a re-call.
    keys_sock = master_keys_socket_name()
    if vault._cluster_share_server is None:
        # Clean stale socket if a previous master died ungracefully.

        keys_path = Path(keys_sock)
        acquire_socket_path(keys_path)

        sub_keys = vault.export_subkeys_for_shamir()
        total, threshold = _shamir_total_threshold()
        log.info("shamir distribution: total=%d threshold=%d", total, threshold)
        try:
            key_server = KeyServer(keys_sock)
            # bytes() is load-bearing: split_and_bind's PyO3 &[u8] binding
            # accepts bytes, not bytearray. The transient copy is GC'd; the
            # original bytearray is wiped by secure_zero below.
            key_server.split_and_bind(bytes(sub_keys), threshold, total)
        finally:
            secure_zero(sub_keys)
        post_bind_chmod(keys_path)
        # Master claims the first generated share (x=1) immediately.
        vault._cluster_share = key_server.pop_share()
        vault._cluster_share_server = key_server
        # Spawn the share-serving loop in the background. Each call to
        # serve_one_share is a 5s blocking accept; we run it via to_thread.
        vault._cluster_share_task = asyncio.create_task(_serve_shares_loop(vault))

    from .cluster import get_hostname

    await db.execute(
        text("""
            UPDATE vault_workers
            SET crypto_socket_name = :crypto_sock,
                socket_name = :keys_sock,
                last_heartbeat = NOW()
            WHERE hostname = :host AND pid = :pid
        """),
        {
            "crypto_sock": sock,
            "keys_sock": keys_sock,
            "host": get_hostname(),
            "pid": pid,
        },
    )
    await db.commit()
    log.info(
        "master services started: pid=%d crypto=%s keys=%s",
        pid,
        sock,
        keys_sock,
    )
    return server


async def _serve_shares_loop(vault: VaultState) -> None:
    """Background task: repeatedly accept peer connections and serve one
    share each. Stops when the keys server is closed (master seal) or all
    shares have been served.

    At most resolved-total - 1 peers can be served (the master keeps the first
    generated share, x=1). ``total`` now carries
    ``cluster_shamir_spare_shares`` beyond the worker count, so this loop stays
    alive after the initial followers have attached and can still serve a
    worker that was replaced mid-life. Once the pool is genuinely exhausted
    serve_one_share raises and we exit cleanly -- from that point the node is
    back to losing failover capacity on every worker death, which is what the
    spares exist to postpone.
    """
    served = 0
    total, _ = _shamir_total_threshold()
    expected = total - 1
    while served < expected:
        srv = vault._cluster_share_server
        if srv is None:
            return  # master sealed
        try:
            peer_pid = await asyncio.to_thread(srv.serve_one_share)
            served += 1
            log.info(
                "served Shamir share to peer pid=%d (%d/%d)",
                peer_pid,
                served,
                expected,
            )
        except TimeoutError:
            # No peer in 5s, keep waiting
            continue
        except Exception as e:
            # "Not bound" / "No more shares" / other errors, bail out
            log.debug("serve_one_share stopped: %s", e)
            return


async def _drain_share_server(vault: VaultState) -> None:
    """Stop a share server without racing its blocking PyO3 accept.

    ``serve_one_share`` holds a Rust/PyO3 borrow until its five-second accept
    returns. Calling ``close`` during that window raises ``Already borrowed``.
    Detach the server from the vault first so the loop cannot pick up a newly
    installed server, then wait for the outstanding accept to release it.
    """

    server = vault._cluster_share_server
    task = vault._cluster_share_task
    vault._cluster_share_server = None
    vault._cluster_share_task = None

    if task is not None and task is not asyncio.current_task():
        try:
            await asyncio.wait_for(
                asyncio.shield(task),
                timeout=SHARE_COLLECTION_TIMEOUT_SECS * 2 + 1,
            )
        except TimeoutError:
            # Do not call close while Rust may still be borrowed. The detached
            # task owns the final reference and will drop/zeroize it when the
            # blocking accept eventually returns.
            log.warning("share server accept did not drain before shutdown")
            return
        except asyncio.CancelledError:
            raise
        except Exception:
            log.debug("share server task ended with an error", exc_info=True)

    if server is not None:
        try:
            server.close()
        except Exception:
            log.debug("share server close failed after drain", exc_info=True)


async def stop_master_services(
    vault: VaultState,
    db: AsyncSession | None = None,
    pid: int | None = None,
) -> None:
    """Stop the master RPC server and clear the socket name in DB.

    Safe to call when no server is running (e.g. master was never unsealed
    or already stopped). When db is None, just drops the in-memory server
    without touching the DB row.
    """
    server = vault._master_rpc_server
    if server is not None:
        try:
            # The Rust MasterRpcServer.stop() is synchronous (it
            # internally calls Python::detach to release the GIL during
            # the join). The legacy Python MasterRpcServer.stop() is
            # async ; both paths are handled here.
            stop_result = server.stop()
            if asyncio.iscoroutine(stop_result):
                await stop_result
        except Exception:
            log.warning("stop_master_services: server.stop() raised", exc_info=True)
        vault._master_rpc_server = None
        # Guarantee the crypto-ops socket is released even if server.stop()
        # raised. stop() normally owns this cleanup, but under CPU exhaustion
        # the Rust join can time out / raise ; the socket then leaks as a live
        # listener owned by a now-sealed worker, and the next /unseal hits
        # acquire_socket_path "already bound by an alive process" and 500s
        # forever -- the exhaustion-seal deadlock (6e5d4e0 covered the
        # seal-before-stop ORDER but not a FAILED stop). cleanup_socket is
        # idempotent, so this is a no-op on the success path.
        try:
            cleanup_socket(crypto_ops_socket_path())
        except Exception:
            log.warning(
                "stop_master_services: crypto-ops socket cleanup failed",
                exc_info=True,
            )
    # Tear down the Shamir keys-distribution server too. The mlock'd
    # `_cluster_share` (Rust SecureBuffer) is dropped on next vault.seal().
    if vault._cluster_share_server is not None or vault._cluster_share_task is not None:
        await _drain_share_server(vault)
        # Unlink the filesystem socket so a next master won't see a stale entry.

        cleanup_socket(Path(master_keys_socket_name()))
    # Crypto-ops socket cleanup is owned by MasterRpcServer.stop() on the
    # success path ; the block above also force-cleans it if stop() raised.
    if db is not None:
        pid = pid if pid is not None else os.getpid()
        from .cluster import get_hostname

        try:
            await db.execute(
                text("""
                    UPDATE vault_workers
                    SET crypto_socket_name = NULL,
                        socket_name = NULL,
                        last_heartbeat = NOW()
                    WHERE hostname = :host AND pid = :pid
                """),
                {"host": get_hostname(), "pid": pid},
            )
            await db.commit()
        except Exception:
            log.debug("stop_master_services: DB clear failed", exc_info=True)


async def start_master_services_or_rollback(
    db: AsyncSession,
    vault: VaultState,
    pid: int | None = None,
):
    """Run start_master_services ; on failure, roll back the worker's
    worker_state to 'sealed' and reset local vault state, then re-raise.

    Without rollback, a failed start_master_services leaves the worker
    row with worker_state='master' (the caller commits that before this
    call) but no actual socket bound -- followers then resolve a phantom
    socket path and 500 on every authenticated request.

    Crucially, start_master_services binds the crypto-ops RPC socket
    (server.start()) *before* the later steps that may fail under load
    (Shamir split, the DB UPDATE/commit). vault.seal() zeroes the keys and
    drops the Shamir share server but does NOT stop _master_rpc_server, so
    a bare seal() leaks the crypto-ops socket as a live listener owned by
    this now-sealed worker. Every subsequent /unseal then trips the
    acquire_socket_path "already bound by an alive process" guard and 500s
    until the process is restarted. So we tear master services down first
    (mirrors the /seal route order: stop_master_services then seal).

    Container lifecycle (stop/restart on persistent failure) is the
    orchestrator's concern (systemd Restart=, docker restart policy)
    and is intentionally NOT handled here.
    """
    from .cluster import WorkerState, update_worker_state

    try:
        await start_master_services(db, vault, pid=pid)
    except Exception:
        log.error(
            "start_master_services failed -- rolling back vault_workers "
            "row to 'sealed' to avoid phantom master state",
            exc_info=True,
        )
        # Release any partially-bound master sockets (crypto-ops RPC + Shamir
        # keys) so a retry can re-acquire them. Socket teardown is
        # DB-independent, so it still happens even when the failure left the
        # db session in an aborted transaction.
        try:
            await stop_master_services(vault, db=db, pid=pid)
        except Exception:
            log.error(
                "rollback stop_master_services failed -- crypto-ops socket "
                "may stay bound until process restart",
                exc_info=True,
            )
        try:
            await update_worker_state(db, WorkerState.SEALED, pid=pid)
        except Exception:
            log.error(
                "rollback update_worker_state(SEALED) also failed -- "
                "vault_workers row may stay inconsistent until reaper",
                exc_info=True,
            )
        try:
            vault.seal()
        except Exception:
            log.debug("vault.seal() during rollback raised", exc_info=True)
        # This worker failed to become master and is rolling back to sealed --
        # a genuine "stays sealed unexpectedly" event. Surface it (counter +
        # best-effort notification); the rhorizon_vault_sealed gauge is the
        # reliable backstop.
        try:
            from .audit import record_seal

            record_seal("master_start_rollback")
        except Exception:
            log.debug("record_seal during rollback raised", exc_info=True)
        raise


# -- Follower side ---------------------------------------------------------


async def _wait_for_master_sockets(
    session_factory,
    timeout_secs: float | None = None,
    self_pid: int | None = None,
) -> tuple[str, str | None] | None:
    """Poll vault_workers until a live master appears.

    Returns (crypto_socket, keys_socket) on success - keys_socket may be None
    if the master is pre-commit-6a (RPC only, no Shamir share-back).
    Returns None on timeout (no live master with crypto_socket_name).

    `self_pid` (default: os.getpid()) is excluded from the candidate set so a
    worker that has itself become the master (via /unseal) does not try to
    RPC-connect to its own crypto socket.

    `timeout_secs` defaults to `FOLLOWER_MASTER_WAIT_SECS`. The default is
    looked up at call time (not at function-def time) so tests can
    monkeypatch the module-level constant.
    """
    if timeout_secs is None:
        timeout_secs = FOLLOWER_MASTER_WAIT_SECS
    if self_pid is None:
        self_pid = os.getpid()
    # Hostname filter: a follower must only attach to a master in its own
    # network namespace (filesystem sockets live under /run/rhorizon and
    # are not shared cross-container). With multiple rhorizon hosts
    # sharing one PG, this prevents a follower on host A from picking
    # host B's master row and failing to connect.
    from .cluster import get_hostname

    host = get_hostname()
    deadline = asyncio.get_event_loop().time() + timeout_secs
    while asyncio.get_event_loop().time() < deadline:
        try:
            async with session_factory() as db:
                # `pid != :self_pid` guards against self-attach: if this
                # worker happens to be the actual master (e.g. it received
                # the /unseal request itself), it must not try to RPC-connect
                # to its own socket. Caller decides what to do in that case
                # (typically: stop the follower-boot loop).
                result = await db.execute(
                    text("""
                        SELECT crypto_socket_name, socket_name
                        FROM vault_workers
                        WHERE worker_state = 'master'
                          AND hostname = :host
                          AND pid != :self_pid
                          AND crypto_socket_name IS NOT NULL
                          AND last_heartbeat > NOW()
                              - make_interval(secs => :master_timeout)
                        ORDER BY last_heartbeat DESC
                        LIMIT 1
                    """),
                    {
                        "self_pid": self_pid,
                        "host": host,
                        "master_timeout": MASTER_TIMEOUT_SECS,
                    },
                )
                row = result.fetchone()
                if row and row.crypto_socket_name:
                    return row.crypto_socket_name, row.socket_name
        except Exception:
            log.debug("master socket lookup failed", exc_info=True)
        await asyncio.sleep(FOLLOWER_POLL_INTERVAL_SECS)
    return None


async def attach_to_master(
    session_factory,
    vault: VaultState,
    pid: int | None = None,
    expect_master: bool = True,
) -> bool:
    """Wait for master, attach RPC client + fetch own Shamir share.

    Four steps:
      1. Poll DB for the master's crypto + keys socket names
      2. Attach MasterRpcClient - the worker can now do crypto-ops via RPC
      3. Fetch own Shamir share + bind own share-back socket for failover
      4. Publish FOLLOWER + the optional share-back socket in one DB update

    A missing keys socket remains compatible with an older master. When a
    current master advertises a keys socket, however, fetching the share is
    required: publishing a follower without one silently reduces failover
    quorum. A transient socket timeout therefore leaves this worker sealed;
    the persistent follower reconciler retries the whole attachment.

    `expect_master` False (initial pre-unseal follower-boot) logs a timeout at
    DEBUG -- no master exists until the operator unseals, so it's the steady
    state, not a fault. True (default, failover/re-attach) logs WARNING.

    Returns True only after both the local RPC attach and the database
    ``FOLLOWER`` publication succeed. Returns False on timeout or rollback.
    """
    async with vault.master_transition_lock():
        if vault._rpc_client is not None:
            if not vault.sealed:
                return True
            # A seal clears the logical unsealed state but older paths could
            # leave the follower's RPC client object attached. Treat it as
            # stale so the reconciler cannot accept a sealed follower.
            vault.detach_rpc_client()

    sockets = await _wait_for_master_sockets(session_factory, self_pid=pid)
    if sockets is None:
        if expect_master:
            log.warning("attach_to_master: timed out waiting for master crypto socket")
        else:
            # Pre-unseal: no master until the operator unseals, expected steady state.
            log.debug("attach_to_master: no master yet (sealed, awaiting unseal)")
        return False
    crypto_sock, keys_sock = sockets

    client = MasterRpcClient(crypto_sock)
    try:
        await client.call(
            "hmac_sha512",
            {"message": b"rhorizon-rpc-healthcheck".hex()},
        )
    except (MasterUnreachable, RpcError) as exc:
        log.warning(
            "attach_to_master: advertised master crypto socket is not usable (%s)",
            exc,
        )
        return False
    # The master may have changed while DB polling/RPC probing was in flight.
    # Serialize the bounded final transition (local attach, required share
    # fetch for current masters, DB publication) but never the potentially
    # 120-second poll.
    async with vault.master_transition_lock():
        if vault.is_master:
            log.info("attach_to_master: local worker became master; not attaching")
            return False
        if vault._rpc_client is not None and not vault.sealed:
            return True
        vault.attach_rpc_client(client)
        # Keep the vault logically sealed until FOLLOWER is durably published.
        # Ordinary requests do not take this transition lock, so flipping the
        # flag before the awaited share/DB steps would expose half-attached
        # state to the HTTP path.

        # A current master advertising a keys socket promises Shamir
        # distribution. Do not turn a transient transfer timeout into a
        # permanently quorumless follower: keep this worker sealed and let
        # the persistent follower reconciler retry. This occurred under K7
        # I/O pressure as EAGAIN from the 5-second Unix-socket read timeout.
        #
        # keys_sock=None remains the compatibility path for an older master
        # that predates Shamir failover.
        back_sock = None
        if keys_sock is not None:
            try:
                back_sock = await _fetch_and_expose_share(vault, keys_sock, pid=pid)
            except Exception as e:
                log.warning(
                    "attach_to_master: share fetch/expose failed (%s) - "
                    "keeping worker sealed so reconciliation retries",
                    e,
                )
                if vault._rpc_client is client:
                    vault.detach_rpc_client()
                vault.seal()
                return False

        # Local attachment is not considered successful until the same worker
        # row advertises FOLLOWER. Publish the optional share-back socket in
        # this statement too, so monitoring and failover quorum never observe
        # a half-attached process.
        from .cluster import get_hostname

        pid = pid if pid is not None else os.getpid()
        try:
            async with session_factory() as db:
                published = await db.execute(
                    text("""
                        UPDATE vault_workers
                        SET worker_state = 'follower',
                            socket_name = :sock,
                            last_heartbeat = NOW()
                        WHERE hostname = :host AND pid = :pid
                    """),
                    {
                        "sock": back_sock,
                        "host": get_hostname(),
                        "pid": pid,
                    },
                )
                await db.commit()
            if published.rowcount != 1:
                raise RuntimeError("worker registration disappeared during attach")
        except Exception:
            log.warning(
                "attach_to_master: FOLLOWER publication failed; "
                "discarding local RPC/share state",
                exc_info=True,
            )
            if vault._rpc_client is client:
                vault.detach_rpc_client()
                vault.seal()
            return False
        # Publication is durable and no await separates it from this local
        # transition. A follower holds no sub-keys; crypto delegates to client.
        vault._sealed = False
    log.info("attached to master via RPC: socket=%s", crypto_sock)
    return True


async def attach_api_to_custodian(
    session_factory,
    vault: VaultState,
    *,
    expect_master: bool = True,
) -> bool:
    """Attach a disposable API process to the custodian crypto master.

    Unlike :func:`attach_to_master`, this path deliberately does not fetch a
    Shamir share and does not publish a ``vault_workers`` row. Only the fixed
    custodian pool participates in local reconstruction; API worker churn must
    therefore have zero effect on the share generation.
    """
    async with vault.master_transition_lock():
        if vault._rpc_client is not None and not vault.sealed:
            return True
        if vault._rpc_client is not None:
            vault.detach_rpc_client()

    # API PIDs are absent from vault_workers in separated mode, so excluding
    # our PID is unnecessary and could theoretically hide a custodian after
    # host PID-namespace reuse. Zero cannot match a real process row.
    sockets = await _wait_for_master_sockets(session_factory, self_pid=0)
    if sockets is None:
        if expect_master:
            log.warning("custody attach: timed out waiting for crypto custodian")
        else:
            log.debug("custody attach: no unsealed custodian yet")
        return False
    crypto_sock, _keys_sock = sockets

    client = MasterRpcClient(crypto_sock)
    try:
        await client.call(
            "hmac_sha512",
            {"message": b"rhorizon-custody-healthcheck".hex()},
        )
    except (MasterUnreachable, RpcError) as exc:
        log.warning("custody attach: advertised crypto socket is unusable (%s)", exc)
        return False

    async with vault.master_transition_lock():
        if vault._rpc_client is not None and not vault.sealed:
            return True
        vault.attach_rpc_client(client)
        vault._sealed = False
    log.info("API attached to custodian RPC: socket=%s (no Shamir share)", crypto_sock)
    return True


async def _fetch_and_expose_share(
    vault: VaultState,
    keys_sock: str,
    pid: int | None = None,
) -> str:
    """Fetch this worker's share from master, then bind own share-back socket.

    The fetched share is held by `vault._cluster_share` (mlock'd Rust heap).
    The share-back socket is bound by a fresh KeyServer that owns its own
    copy of the share bytes; the original ShamirShare in vault stays intact
    for direct failover use.
    """
    pid = pid if pid is not None else os.getpid()

    share = await asyncio.to_thread(KeyClient.fetch_share, keys_sock)
    vault._cluster_share = share

    # Expose own share via per-pid socket (failover collection point)
    back_sock = follower_share_back_socket_name(pid=pid)

    back_path = Path(back_sock)
    acquire_socket_path(back_path)
    share_server = KeyServer(back_sock)
    share_server.bind_with_share(share)
    post_bind_chmod(back_path)
    vault._cluster_share_server = share_server
    vault._cluster_share_task = asyncio.create_task(_serve_own_share_loop(vault))
    log.info("follower share-back socket=%s ready for publication", back_sock)
    return back_sock


async def _serve_own_share_loop(vault: VaultState) -> None:
    """Follower's share-back loop. One-shot: serves the worker's single
    share to the first new-master candidate that asks, then exits.

    If no failover occurs during this worker's lifetime, the loop times out
    every 5s (KeyServer accept timeout) and retries, idle. A successful
    serve consumes the pending share - re-binding with a fresh share happens
    after failover re-distribution (commit 6b).
    """
    while True:
        srv = vault._cluster_share_server
        if srv is None:
            return
        try:
            peer_pid = await asyncio.to_thread(srv.serve_one_share)
            log.info("served own share to peer pid=%d (failover collection)", peer_pid)
            return  # one-shot - share consumed
        except TimeoutError:
            continue
        except Exception as e:
            log.debug("_serve_own_share_loop stopped: %s", e)
            return


async def detach_from_master(vault: VaultState) -> None:
    """Drop the RPC client and seal the vault locally."""
    vault.detach_rpc_client()
    await _drain_share_server(vault)
    vault.seal()


def make_rpc_recover_fn(session_factory, vault: VaultState, pid: int | None = None):
    """Build the async recover callback wired onto the vault.

    On a `MasterUnreachable` raised by a follower crypto-op, the vault
    calls this function (via `_call_rpc`). It drops
    the stale RPC client and walks `attach_to_master` against the live
    DB rows : the new master's `crypto_socket_name` is published as part
    of its post-unseal claim, so the poll converges as soon as the
    election + reconstruct sequence completes. Returns True on a fresh
    attach, False on timeout (the vault then surfaces a re-raised
    `MasterUnreachable` for the FastAPI 429 handler and fences this worker's
    readiness until its RPC data path recovers).
    """

    async def _recover() -> bool:
        # Drop the stale client before re-attaching ; `attach_to_master`
        # early-returns True when `_rpc_client is not None`, so failing to
        # clear it would mask the stale state.
        async with vault.master_transition_lock():
            if vault.is_master:
                return True
            vault.detach_rpc_client()
        log.info("rpc_recover: detached stale client, polling new master")
        return await attach_to_master(session_factory, vault, pid=pid)

    return _recover


def wire_rpc_recovery(
    vault: VaultState, session_factory, pid: int | None = None
) -> None:
    """Install the RPC recovery hook on `vault`. Idempotent.

    Called once per follower from the cluster boot path. Master workers
    that never attach an RPC client also receive the hook -- they may
    later step down (rotate-password / re-seal cycle) and need it then.
    """
    vault.set_rpc_recovery_hook(make_rpc_recover_fn(session_factory, vault, pid))


def wire_api_custody_recovery(vault: VaultState, session_factory) -> None:
    """Install RPC recovery for an API process outside the Shamir quorum."""

    async def _recover() -> bool:
        async with vault.master_transition_lock():
            vault.detach_rpc_client()
        log.info("custody RPC recovery: detached stale client, polling custodian")
        return await attach_api_to_custodian(session_factory, vault)

    vault.set_rpc_recovery_hook(_recover)


# -- Failover (commit 6b) --------------------------------------------------


async def _collect_peer_shares(peers: list[dict], shares: list, threshold: int) -> list:
    """Fetch peer shares concurrently within one fixed failover deadline."""
    if len(shares) >= threshold or not peers:
        return shares

    async def _fetch(peer: dict):
        try:
            share = await asyncio.to_thread(KeyClient.fetch_share, peer["socket_name"])
            return peer, share, None
        except Exception as exc:
            return peer, None, exc

    tasks = {asyncio.create_task(_fetch(peer)) for peer in peers}
    pending = tasks
    deadline = asyncio.get_running_loop().time() + SHARE_COLLECTION_TIMEOUT_SECS
    coordinates = {getattr(share, "x", None) for share in shares}

    try:
        while pending and len(shares) < threshold:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                break
            done, pending = await asyncio.wait(
                pending,
                timeout=remaining,
                return_when=asyncio.FIRST_COMPLETED,
            )
            if not done:
                break

            for task in done:
                peer, share, error = task.result()
                if error is not None:
                    log.warning(
                        "failover: peer pid=%d share fetch failed: %s",
                        peer["pid"],
                        error,
                    )
                    continue

                coordinate = getattr(share, "x", None)
                if coordinate is None or coordinate in coordinates:
                    log.warning(
                        "failover: peer pid=%d returned invalid or duplicate share",
                        peer["pid"],
                    )
                    continue
                coordinates.add(coordinate)
                shares.append(share)
                log.info(
                    "failover: collected share from peer pid=%d (%d/%d)",
                    peer["pid"],
                    len(shares),
                    threshold,
                )
                if len(shares) >= threshold:
                    break
    finally:
        for task in pending:
            task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)

    if len(shares) < threshold and pending:
        log.warning(
            "failover: share collection deadline reached with %d/%d shares",
            len(shares),
            threshold,
        )
    return shares


async def reconstruct_and_become_master(
    session_factory,
    vault: VaultState,
    pid: int | None = None,
) -> bool:
    """After winning the master election, collect M shares from peers,
    reconstruct sub-keys, and become the new master.

    This worker contributes its own share (cluster_share). Peers contribute
    via their share-back sockets (published in vault_workers.socket_name).
    With M = cluster_shamir_threshold shares, KeyServer.reconstruct gives
    us the original 160-byte (hmac||dek||audit||ha_wrap||pki_wrap) blob and we
    vault.unseal() locally. Then we restart master services to re-split
    + redistribute. The blob is 160B (96B -> 128B -> 160B) so Shamir failover
    preserves the cluster ha_wrap_key AND the PKI CA pki_wrap_key.

    Returns True on success. False if:
      - this worker has no own share (never participated in distribution)
      - quorum not met (fewer than M live peers responded)
      - reconstruction produced wrong-sized output (corruption)
      - master services restart fails

    On failure, the vault stays in its previous state (logically-unsealed
    follower with broken RPC client, or sealed if no share was ever held).
    Caller is expected to log and retry on the next master_watch tick.
    """
    from rhorizon_crypto import KeyServer as _KeyServer

    pid = pid if pid is not None else os.getpid()

    if vault._cluster_share is None:
        log.error("failover: pid=%d has no cluster share - cannot reconstruct", pid)
        return False

    _, threshold = _shamir_total_threshold()
    shares = [vault._cluster_share]

    # Collect shares from live peers (any non-self worker with a share-back
    # socket published in vault_workers.socket_name).
    # Hostname filter: only peers in the SAME host can be reached via
    # filesystem Unix sockets (paths under /run/rhorizon are not shared
    # cross-container). A peer on a different host's row is irrelevant
    # for this host's quorum.
    from .cluster import get_hostname

    host = get_hostname()
    async with session_factory() as db:
        result = await db.execute(
            text("""
                SELECT pid, socket_name
                FROM vault_workers
                WHERE hostname = :host
                  AND pid != :self_pid
                  AND socket_name IS NOT NULL
                  AND last_heartbeat > NOW()
                      - make_interval(secs => :master_timeout)
                ORDER BY last_heartbeat DESC
            """),
            {
                "self_pid": pid,
                "host": host,
                "master_timeout": MASTER_TIMEOUT_SECS,
            },
        )
        peers = [
            {"pid": r.pid, "socket_name": r.socket_name} for r in result.fetchall()
        ]

    shares = await _collect_peer_shares(peers, shares, threshold)

    if len(shares) < threshold:
        log.error(
            "failover: only %d shares (need %d) - quorum not met, giving up",
            len(shares),
            threshold,
        )
        cluster_failover.labels(result="quorum_missing").inc()
        return False

    # Reconstruct via KeyServer.reconstruct (returns mlock'd SecureBuffer)
    try:
        secret_buf = await asyncio.to_thread(_KeyServer.reconstruct, shares)
    except Exception as e:  # pragma: no cover  (Shamir reconstruct fail)
        log.error("failover: reconstruction failed: %s", e)
        cluster_failover.labels(result="failure").inc()
        return False

    secret_bytes = secret_buf.to_bytearray()
    del secret_buf
    if (
        len(secret_bytes) != 160
    ):  # pragma: no cover  (defensive : Shamir guarantee 160-byte secret)
        log.error(
            "failover: reconstructed key wrong size %d (expected 160)",
            len(secret_bytes),
        )
        secure_zero(secret_bytes)
        return False

    keys = {
        "hmac_key": secret_bytes[:32],
        "dek_key": secret_bytes[32:64],
        "audit_key": secret_bytes[64:96],
        "ha_wrap_key": secret_bytes[96:128],
        "pki_wrap_key": secret_bytes[128:160],
    }

    try:
        # Promote: drop RPC client + seal (releases old cluster_share +
        # share-back), then unseal with reconstructed sub-keys, then restart
        # master services.
        vault.detach_rpc_client()
        await _drain_share_server(vault)
        vault.seal()
        vault.unseal(keys)
    finally:
        for key in keys.values():
            secure_zero(key)
        keys.clear()
        secure_zero(secret_bytes)

    try:
        async with session_factory() as db:
            # the reconstructed keys belong to whatever generation
            # this host last split shares for -- which may lag another host's
            # rotation. Probe the current DEKs to decide: current keys keep the
            # DB epoch, stale keys get a lower epoch so the fence quarantines
            # this new master instead of serving 500s cluster-wide.
            from .key_epoch import resolve_reconstruct_epoch

            vault.set_key_epoch(await resolve_reconstruct_epoch(db, vault.aesgcm))
            # Mark self as master in DB before publishing socket names
            await db.execute(
                text("""
                    UPDATE vault_workers
                    SET worker_state = 'master',
                        last_heartbeat = NOW()
                    WHERE hostname = :host AND pid = :pid
                """),
                {"host": get_hostname(), "pid": pid},
            )
            await db.commit()
            await start_master_services(db, vault, pid=pid)
            # the previous master had ha_password loaded in
            # its RAM (set at /unseal or /cluster/init). The new master
            # must reload from DB or it boots with ha_loaded=false and
            # cannot serve HMAC for new JOINs.
            # load_ha_password_into_ram is idempotent and gracefully
            # returns False on pre-cluster-init clusters.
            from . import ha_password as _ha_password

            # pragma: defensive -- decrypt_fail metric already bumps
            # inside the helper ; the except path is the catastrophic
            # case (e.g. DB unreachable during the reload window).
            try:
                await _ha_password.load_ha_password_into_ram(db)
            except Exception as exc:  # pragma: no cover
                log.warning(
                    "failover: ha_password reload post-promotion failed: %s",
                    exc,
                )

            # S4b/S6: the new master must also reload the Ed25519 audit signer
            # from the shared vault_config (it now holds dek_key), or it -- and
            # therefore every follower delegating to it -- would silently revert
            # the audit chain to hmac. Idempotent ; no-op on pre-S6 clusters.
            from . import audit_identity as _audit_identity

            try:
                await _audit_identity.load_audit_identity_into_ram(db)
            except Exception as exc:  # pragma: no cover
                log.warning(
                    "failover: audit identity reload post-promotion failed: %s",
                    exc,
                )

            # Same gap for prev_hmac: a promoted master that drops it rejects
            # every token minted under the previous generation (lazy migration
            # window broken). Mirrors the /unseal endpoint + roll-forward.
            from .auth import load_prev_hmac_into_ram

            try:
                await load_prev_hmac_into_ram(db)
            except Exception as exc:  # pragma: no cover
                log.warning("failover: prev_hmac reload post-promotion failed: %s", exc)
    except (
        Exception
    ) as e:  # pragma: no cover  (failover start_master_services error path - integ)
        log.error("failover: start_master_services failed: %s", e)
        # Release the crypto-ops socket: server.start() may have bound it before
        # a later step failed, and the next master_watch retry would self-deadlock
        # on the "already bound" guard otherwise.
        try:
            await stop_master_services(vault, db=None, pid=pid)
        except Exception:
            log.error("failover: rollback stop_master_services failed", exc_info=True)
        # Full rollback (mirror start_master_services_or_rollback): the vault is
        # unsealed and worker_state='master' committed, so leaving it is a phantom
        # master (no RPC server, blocks re-election, keys live in RAM). Seal + roll
        # the row to SEALED so the next master_watch re-elects.
        try:
            vault.seal()
        except Exception:
            log.debug("failover: vault.seal() during rollback raised", exc_info=True)
        try:
            from .cluster import WorkerState, update_worker_state

            async with session_factory() as db2:
                await update_worker_state(db2, WorkerState.SEALED, pid=pid)
        except Exception:
            log.error(
                "failover: rollback update_worker_state(SEALED) failed", exc_info=True
            )
        cluster_failover.labels(result="failure").inc()
        return False

    log.warning(
        "failover: pid=%d reconstructed sub-keys + became new master "
        "(operational, peers must re-attach)",
        pid,
    )
    cluster_failover.labels(result="success").inc()
    return True
