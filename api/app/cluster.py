# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Cluster coordination for role-based workers.

Orchestrates worker registration, heartbeat, and master election.

State machine per worker:
    sealed (boot) -> follower (received share) -> candidate (during election)
                                              -> master (won election)

Master health monitoring is DB-based: master UPDATEs vault_workers.last_heartbeat
every 1s, peers SELECT to detect timeouts. The existing PostgreSQL connection
pool is reused for heartbeat -- no separate IPC mechanism.

Master election uses a random delay [0, 1s] before claiming the role to
prevent a deterministic "next master" target for adaptive DoS attacks.
"""

import asyncio
import logging
import os
import secrets
import signal
import socket
from enum import Enum

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from .config import settings

# vault_workers.worker_state is the single source of truth for a worker's
# place in the state machine. A single column (not a role/status pair)
# avoids the desync an operationally-redundant `role` caused -- every
# query keys on worker_state.

log = logging.getLogger("rhorizon.cluster")

# Heartbeat / election timing config (seconds)
HEARTBEAT_INTERVAL_SECS = 1.0
ELECTION_RANDOM_DELAY_MAX_SECS = 1.0

# Failover deadlines are operator-tunable (see config.Settings). Read through
# module-level names so existing call sites and tests keep working, but resolve
# from settings so RHORIZON_CLUSTER_MASTER_TIMEOUT_SECS actually takes effect.
#
# Defaults moved 5.0 -> 120.0: a 5s deadline treats a worker starved on iowait
# as dead and triggers a full Shamir reconstruction on a box that is already
# collapsing, which is the failure separated custody exists to survive.
MASTER_TIMEOUT_SECS = settings.cluster_master_timeout_secs
MASTER_WATCH_INTERVAL_SECS = settings.cluster_master_watch_interval_secs


def get_hostname() -> str:
    """Container/host identifier -- read at call time so tests can
    monkeypatch the HOSTNAME env var. All workers in the same container
    share the same HOSTNAME and form one cluster. Different
    hosts (multi-VM, Swarm replicas, K8s pods) get distinct HOSTNAMEs
    and run as independent clusters on the shared PG.

    Resolution order:
      1. HOSTNAME env var -- container runtime (Docker, K8s) injects it
         and tests monkeypatch it.
      2. socket.gethostname() -- bare-metal systemd does NOT inherit the
         host environment by default, so HOSTNAME is absent ; the kernel
         uname() is still available and gives the real per-host id.
      3. literal "default" -- defensive last resort if both fail.

    Without step 2, all bare-metal workers fall back to "default" and
    the composite PK (hostname, pid) loses its per-host scoping: every
    SELECT WHERE hostname=:host matches workers across all hosts (which
    is how the F2 ghost-master bug surfaced).
    """
    env_host = os.environ.get("HOSTNAME")
    if env_host:
        return env_host
    try:
        sys_host = socket.gethostname()
    except OSError:
        sys_host = ""
    return sys_host or "default"


def crypto_socket_prefix(hostname: str | None = None) -> str:
    """Return the host-distinguishing fragment for the master crypto-ops
    socket path. The full stored value is now a filesystem path like
    `/run/rhorizon/crypto-ops-{HOSTNAME}.sock` - the unique part that
    identifies a host is the filename. SQL filters use:
        crypto_socket_name LIKE '%' || :prefix || '%'
    so the runtime dir prefix doesn't matter."""
    return f"crypto-ops-{hostname or get_hostname()}.sock"


# -- Cluster-wide singleton lock registry -----------------------------------
#
# Operations that must run at most ONCE across all hosts (DEK rotation,
# audit log compression, master-password rotation) acquire a named
# advisory lock at xact start. Other hosts that try to acquire the same
# lock get False from pg_try_advisory_xact_lock and skip silently.
#
# Locks are transaction-scoped: a node crash releases them automatically
# (PostgreSQL detects the connection drop and rolls back the xact).
#
# The registry below maps symbolic names to their hashtext() values so
# the /cluster endpoint can decode `pg_locks.objid` back to a name.

KNOWN_CLUSTER_LOCKS: list[str] = [
    "rhorizon:cluster:dek_rotation",
    "rhorizon:cluster:reaper",
    "rhorizon:cluster:audit_compress",
    "rhorizon:cluster:rotate_password",
    "rhorizon:cluster:rotate_dek_key",
    "rhorizon:cluster:key_rotation",
    "rhorizon:cluster:2fa_config",
    "rhorizon:cluster:audit_chain",
    "rhorizon:cluster:audit_lite_checkpoint",
]

# `LOCK_NAME_BY_HASH` is populated lazily on first use because hashtext()
# is a PG function, we need a DB session to compute the values. The
# /cluster endpoint resolves names via `resolve_lock_name(db, objid)`.
_LOCK_NAME_BY_HASH: dict[int, str] | None = None


async def _populate_lock_registry(db: AsyncSession) -> dict[int, str]:
    """Compute hashtext() for every KNOWN_CLUSTER_LOCKS name and cache."""
    global _LOCK_NAME_BY_HASH
    if _LOCK_NAME_BY_HASH is not None:
        return _LOCK_NAME_BY_HASH
    mapping: dict[int, str] = {}
    for name in KNOWN_CLUSTER_LOCKS:
        r = await db.execute(text("SELECT hashtext(:n)::int"), {"n": name})
        mapping[int(r.scalar())] = name
    _LOCK_NAME_BY_HASH = mapping
    return mapping


async def resolve_lock_name(db: AsyncSession, objid: int) -> str | None:
    """Return the symbolic name of a cluster lock by its hashtext value,
    or None if the objid does not match any known lock."""
    mapping = await _populate_lock_registry(db)
    return mapping.get(int(objid))


async def with_cluster_lock(db: AsyncSession, lock_name: str, fn) -> bool:
    """Acquire `rhorizon:cluster:{lock_name}` advisory lock and run fn().

    Returns True if the lock was acquired and fn() ran. Returns False if
    another host holds the lock right now - caller skips silently.

    The lock is transaction-scoped: it is released on commit/rollback,
    or automatically when the connection drops (crash recovery).

    Caller is responsible for committing/rolling back the transaction.
    """
    full_name = f"rhorizon:cluster:{lock_name}"
    r = await db.execute(
        text("SELECT pg_try_advisory_xact_lock(hashtext(:n))"),
        {"n": full_name},
    )
    if not r.scalar():
        return False
    await fn()
    return True


class WorkerState(str, Enum):
    # The four legitimate process states. MASTER is exclusive
    # (one per host) and holds the sub-keys ; FOLLOWER is unbounded and
    # delegates crypto to MASTER via Unix socket ; SEALED is the boot
    # state ; CANDIDATE is the transient state during master election.
    SEALED = "sealed"
    FOLLOWER = "follower"
    CANDIDATE = "candidate"
    MASTER = "master"


class WorkerRegistrationLost(RuntimeError):
    """This process was reaped from the worker registry and must be replaced."""


# -- DB-level primitives ----------------------------------------------------


def _own_custodian_http_socket() -> str | None:
    """This custodian's addressable HTTP socket, if the launcher gave it one.

    The launcher passes RH_CUSTODIAN_SLOT when it starts one uvicorn per slot.
    Absent it, the pool is still on the historical shared listener and there is
    nothing to address -- return None and the control plane keeps its old path.
    """
    slot = os.environ.get("RH_CUSTODIAN_SLOT")
    if not slot or not slot.isdigit():
        return None
    from .socket_paths import custodian_http_socket_path

    return str(custodian_http_socket_path(int(slot)))


async def register_worker(
    db: AsyncSession,
    socket_name: str | None = None,
    pid: int | None = None,
    hostname: str | None = None,
    node_uuid: str | None = None,
) -> int:
    """Register a newly started worker process as sealed.

    ``(hostname, pid)`` can collide with a stale row after PID reuse. A startup
    registration therefore resets all process-role state and socket ownership
    on conflict; only explicit post-registration transitions may elect a master
    or attach a follower. The hostname column isolates workers across
    containers/VMs sharing one Patroni cluster.

    `node_uuid` (32 lowercase hex, sourced from the persistent
    `/var/lib/rhorizon/node-uuid` file) identifies the container itself.
    On conflict we COALESCE so a re-registration that omits node_uuid
    does not erase a previously stored value.
    """
    pid = pid if pid is not None else os.getpid()
    host = hostname if hostname is not None else get_hostname()
    # Separated custody only. A row has to say WHICH process it is, because the
    # two kinds share a hostname and answer very different questions: a
    # custodian holds key material, a disposable API worker holds none. NULL in
    # embedded, where the distinction does not exist and nothing reads it.
    from .config import settings

    role = settings.process_role if settings.custody_mode == "separated" else None
    # The python custodian's own HTTP socket, so the control plane can address
    # it instead of re-dialling a shared listener until the kernel hands over
    # the master. Only a custodian has one.
    http_socket = _own_custodian_http_socket() if role == "custodian" else None
    await db.execute(
        text("""
            INSERT INTO vault_workers
                (hostname, pid, worker_state, socket_name,
                 last_heartbeat, started_at, node_uuid,
                 process_role, http_socket_name)
            VALUES (:host, :pid, 'sealed', :sock, NOW(), NOW(), :uuid,
                    :role, :http_sock)
            ON CONFLICT (hostname, pid) DO UPDATE SET
                worker_state = 'sealed',
                socket_name = EXCLUDED.socket_name,
                crypto_socket_name = NULL,
                last_heartbeat = NOW(),
                started_at = NOW(),
                node_uuid = COALESCE(EXCLUDED.node_uuid, vault_workers.node_uuid),
                -- Reset on PID reuse, like every other process-role field
                -- above: a stale row must never lend its identity to whatever
                -- process inherited its pid.
                process_role = EXCLUDED.process_role,
                http_socket_name = EXCLUDED.http_socket_name
        """),
        {
            "host": host,
            "pid": pid,
            "sock": socket_name,
            "uuid": node_uuid,
            "role": role,
            "http_sock": http_socket,
        },
    )
    await db.commit()
    return pid


async def update_worker_state(
    db: AsyncSession,
    worker_state: WorkerState,
    pid: int | None = None,
    hostname: str | None = None,
):
    """Transition this worker's state."""
    pid = pid if pid is not None else os.getpid()
    host = hostname if hostname is not None else get_hostname()
    await db.execute(
        text("""
            UPDATE vault_workers
            SET worker_state = :s, last_heartbeat = NOW()
            WHERE hostname = :host AND pid = :pid
        """),
        {"s": worker_state.value, "host": host, "pid": pid},
    )
    await db.commit()


async def heartbeat_once(
    db: AsyncSession,
    pid: int | None = None,
    hostname: str | None = None,
):
    """Refresh this worker or fail if the reaper removed its registration."""
    pid = pid if pid is not None else os.getpid()
    host = hostname if hostname is not None else get_hostname()
    result = await db.execute(
        text(
            "UPDATE vault_workers SET last_heartbeat = NOW() "
            "WHERE hostname = :host AND pid = :pid"
        ),
        {"host": host, "pid": pid},
    )
    await db.commit()
    if result.rowcount != 1:
        raise WorkerRegistrationLost(
            f"worker registration missing for hostname={host!r} pid={pid}"
        )


async def deregister_worker(
    db: AsyncSession,
    pid: int | None = None,
    hostname: str | None = None,
):
    """Remove this worker's row (graceful shutdown)."""
    pid = pid if pid is not None else os.getpid()
    host = hostname if hostname is not None else get_hostname()
    await db.execute(
        text("DELETE FROM vault_workers WHERE hostname = :host AND pid = :pid"),
        {"host": host, "pid": pid},
    )
    await db.commit()


# -- Master discovery + election --------------------------------------------


async def find_master(db: AsyncSession, hostname: str | None = None) -> dict | None:
    """Return the current alive master row for THIS host, or None.

    Filters by `hostname = :host` so masters of other hosts (multi-VM /
    Swarm replicas / K8s pods) are ignored - each host runs its own
    cluster on the shared PG.
    """
    host = hostname if hostname is not None else get_hostname()
    result = await db.execute(
        text("""
            SELECT pid, worker_state, socket_name, crypto_socket_name, last_heartbeat
            FROM vault_workers
            WHERE worker_state = 'master'
              AND hostname = :host
              AND crypto_socket_name IS NOT NULL
              AND last_heartbeat > NOW() - make_interval(secs => :timeout)
            ORDER BY last_heartbeat DESC
            LIMIT 1
        """),
        {
            "timeout": MASTER_TIMEOUT_SECS,
            "host": host,
        },
    )
    row = result.fetchone()
    if not row:
        return None
    return {
        "pid": row.pid,
        "worker_state": row.worker_state,
        "socket_name": row.socket_name,
        "last_heartbeat": row.last_heartbeat,
    }


async def claim_master_role(
    db: AsyncSession, pid: int | None = None, hostname: str | None = None
) -> bool:
    """Atomically claim master worker_state for this worker. Returns True on
    success, False if another live master already holds it on this host.

    pg_advisory_xact_lock keyed on `role:master:hostname` serialises
    concurrent claims ; the NOT EXISTS check then refuses the transition
    if a live master already exists on this host. Without the lock, two
    transactions in READ COMMITTED can both pass the check and split-
    brain. Each host elects its own master independently - cross-host
    rows are ignored.
    """
    pid = pid if pid is not None else os.getpid()
    host = hostname if hostname is not None else get_hostname()
    await db.execute(
        text("SELECT pg_advisory_xact_lock(hashtext(:lk))"),
        {"lk": f"role:master:{host}"},
    )
    result = await db.execute(
        text("""
            UPDATE vault_workers
            SET worker_state = 'master', last_heartbeat = NOW()
            WHERE hostname = :host AND pid = :pid
              AND NOT EXISTS (
                  SELECT 1 FROM vault_workers w2
                  WHERE w2.worker_state = 'master'
                    AND w2.hostname = :host
                    AND w2.pid != :pid
                    AND w2.last_heartbeat > NOW() - make_interval(secs => :timeout)
              )
            RETURNING pid
        """),
        {
            "host": host,
            "pid": pid,
            "timeout": MASTER_TIMEOUT_SECS,
        },
    )
    row = result.fetchone()
    await db.commit()  # releases advisory lock
    return row is not None


async def acquire_master_or_follower(
    db: AsyncSession, pid: int | None = None, hostname: str | None = None
) -> WorkerState:
    """Boot-time race: try to claim master worker_state. The winner returns
    WorkerState.MASTER ; losers stay at WorkerState.SEALED and let the
    follower-boot loop (in main.py) transition them to FOLLOWER once
    they attach to the master's crypto-ops RPC socket.

    There is no application-level upper bound on follower count; scaling the
    validated worker setting is purely a config dial (Shamir caps it at 255).
    """
    if await claim_master_role(db, pid=pid, hostname=hostname):
        return WorkerState.MASTER
    return WorkerState.SEALED


async def run_election(session_factory, pid: int | None = None) -> bool:
    """Random-delay election: wait [0, 1s], then try to claim master role.

    Returns True if this worker won. Random delay uses the cryptographic
    secrets module so an attacker cannot predict the next master's PID
    (anti-DoS hardening).
    """
    pid = pid if pid is not None else os.getpid()
    # secrets.randbelow gives us crypto-quality randomness for the delay
    delay_ms = secrets.randbelow(int(ELECTION_RANDOM_DELAY_MAX_SECS * 1000) + 1)
    delay = delay_ms / 1000.0
    log.info("election: pid=%d waiting %.3fs before claim", pid, delay)
    await asyncio.sleep(delay)

    async with session_factory() as db:
        won = await claim_master_role(db, pid=pid)

    if won:
        log.warning("election: pid=%d WON master role", pid)
    else:
        log.info("election: pid=%d lost (another worker claimed first)", pid)
    return won


# -- Background loops -------------------------------------------------------


async def _reregister_after_reap(session_factory) -> bool:
    """Restore this live worker's reaped row, preserving its current role.

    The reaper deletes rows whose heartbeat is older than 5 minutes, on the
    assumption that they are leftovers from containers that died without
    deregistering. When the process is in fact alive -- a wedged event loop, a
    run of `UPDATE` timeouts -- the row is gone but the worker still holds
    valid key state, including its Shamir share.

    Terminating here is what turned a recoverable stall into an outage: shares
    are minted once at unseal and never replenished, so every replaced worker
    permanently reduces the live share count. Once it falls below
    ``cluster_shamir_threshold`` no failover can reconstruct, and the node
    seals with no way back short of a manual unseal. Observed on a 3-node lab
    cluster, which went 5 shares -> 2 -> 1 and sealed on all three nodes.

    Re-registering keeps the share where it is. ``register_worker`` is not
    usable for this: it resets ``worker_state`` to 'sealed' and clears
    ``crypto_socket_name`` on conflict, which would demote a live master or
    follower. This restores the row as the process actually is.
    """
    from .cluster_rpc import crypto_socket_name
    from .cluster_setup import (
        follower_share_back_socket_name,
        master_keys_socket_name,
    )
    from .node_uuid import get_node_uuid
    from .vault_state import vault

    if vault.sealed:
        state = WorkerState.SEALED
    elif vault.is_master:
        state = WorkerState.MASTER
    else:
        state = WorkerState.FOLLOWER
    pid = os.getpid()
    host = get_hostname()
    node_uuid = get_node_uuid()
    crypto_sock = None
    share_sock = None
    if state is WorkerState.MASTER:
        if vault._master_rpc_server is not None:
            crypto_sock = crypto_socket_name()
        if vault._cluster_share_server is not None:
            share_sock = master_keys_socket_name()
    elif state is WorkerState.FOLLOWER and vault._cluster_share_server is not None:
        share_sock = follower_share_back_socket_name(pid=pid)
    try:
        async with session_factory() as db:
            await db.execute(
                text("""
                    INSERT INTO vault_workers
                        (hostname, pid, worker_state, socket_name,
                         crypto_socket_name, last_heartbeat, started_at,
                         node_uuid)
                    VALUES (:host, :pid, :state, :share_sock,
                            :crypto_sock, NOW(), NOW(), :node_uuid)
                    ON CONFLICT (hostname, pid) DO UPDATE SET
                        worker_state = EXCLUDED.worker_state,
                        socket_name = EXCLUDED.socket_name,
                        crypto_socket_name = EXCLUDED.crypto_socket_name,
                        node_uuid = EXCLUDED.node_uuid,
                        last_heartbeat = NOW()
                """),
                {
                    "host": host,
                    "pid": pid,
                    "state": state.value,
                    "share_sock": share_sock,
                    "crypto_sock": crypto_sock,
                    "node_uuid": node_uuid,
                },
            )
            await db.commit()
    except Exception:
        log.critical("re-registration after reap failed for pid=%d", pid, exc_info=True)
        return False
    log.warning(
        "worker registration was reaped but pid=%d is alive; re-registered as "
        "%s (share retained)",
        pid,
        state.value,
    )
    return True


def _terminate_lost_worker() -> None:
    """Fail-close this process, then ask its supervisor to replace it.

    Last resort only -- see ``_reregister_after_reap``. Sealing here erases
    this worker's Shamir share, which cannot be reissued while the vault is
    unsealed, so reaching this path costs the node one unit of failover
    capacity permanently.
    """
    from .vault_state import vault

    try:
        # Process-local only: latch the Rust RPC server closed and erase this
        # worker's wrapped key material before SIGTERM begins lifespan teardown.
        vault.seal()
    except Exception:
        log.critical("lost worker could not erase local key state", exc_info=True)
    os.kill(os.getpid(), signal.SIGTERM)


async def heartbeat_loop(session_factory, stop_event: asyncio.Event | None = None):
    """Background task: UPDATE last_heartbeat every HEARTBEAT_INTERVAL_SECS.

    Loops until stop_event is set (or forever if None).
    """
    while True:
        if stop_event is not None and stop_event.is_set():
            return
        try:
            async with session_factory() as db:
                await heartbeat_once(db)
        except WorkerRegistrationLost:
            # Alive process, missing row: restore it rather than destroying a
            # live Shamir share. Only fail-close if the row cannot be restored.
            # Deliberately no `continue` -- fall through to the normal sleep so
            # a persistent reap does not turn into a tight DB retry loop.
            if not await _reregister_after_reap(session_factory):
                log.critical(
                    "worker registration was reaped and could not be restored; "
                    "terminating pid=%d for supervisor replacement",
                    os.getpid(),
                )
                _terminate_lost_worker()
                return
        except Exception:
            log.warning("heartbeat update failed", exc_info=True)
        try:
            if stop_event is not None:
                await asyncio.wait_for(
                    stop_event.wait(), timeout=HEARTBEAT_INTERVAL_SECS
                )
                return  # event was set
            else:
                await asyncio.sleep(HEARTBEAT_INTERVAL_SECS)
        except asyncio.TimeoutError:
            continue


async def master_watch_loop(
    session_factory,
    on_master_lost,
    stop_event: asyncio.Event | None = None,
):
    """Background task: monitor master health, call on_master_lost on timeout.

    on_master_lost is an async callable invoked when no master is alive.
    The callable typically runs run_election() and, if won, performs the
    failover sequence (Shamir reconstruction, share redistribution).
    """
    while True:
        if stop_event is not None and stop_event.is_set():
            return
        try:
            async with session_factory() as db:
                master = await find_master(db)
            if master is None:
                log.info("master_watch: no live master detected")
                try:
                    await on_master_lost()
                except Exception:
                    log.error(
                        "master_watch: on_master_lost handler raised", exc_info=True
                    )
        except Exception:
            log.error("master_watch_loop error", exc_info=True)
        try:
            if stop_event is not None:
                await asyncio.wait_for(
                    stop_event.wait(), timeout=MASTER_WATCH_INTERVAL_SECS
                )
                return
            else:
                await asyncio.sleep(MASTER_WATCH_INTERVAL_SECS)
        except asyncio.TimeoutError:
            continue
