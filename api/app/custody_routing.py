# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Where a key-lifecycle request goes, per custody mode.

There are three modes and they route three different ways. Keeping the three
apart, named and separately testable is the whole point of this module -- the
alternative is one middleware full of mode branches, which is how the rust path
ended up with no routing at all while looking like it had some.

    embedded    NOT ROUTED. Every worker serves every route; the sub-key
                operation itself is delegated per call over the crypto-ops
                socket by VaultState. Nothing in this module runs. That mode
                works and is deliberately untouched.

    separated   PROXIED to the elected custodian. Key material lives in a
    + python    separate process pool, so the request has to cross a process
                boundary. This module addresses the master's own HTTP socket
                directly, read from vault_workers.http_socket_name.

    separated   NOT PROXIED. The custodian is a Rust daemon that speaks a
    + rust      fixed JSON op protocol, not HTTP, and CustodianPoolController
                already addresses each slot's socket directly. What routing
                means here is narrower: which worker may REOPEN a pool, and
                what happens to a request that arrives at a worker not yet
                attached to one.

The reason separated custody exists at all is throughput: the key holder must
not be the thing every request queues behind. Routing that makes a request
hunt for the key holder gives that back, which is why the python path stopped
doing it -- see custodian_http_socket_path() for the measurements.
"""

from __future__ import annotations

import logging

from sqlalchemy import text

log = logging.getLogger("rhorizon.custody_routing")

# Slot addressing is only possible once the launcher gives each custodian its
# own socket. A pool still on the shared listener publishes no socket name, and
# the caller falls back to the historical rejection-sampling path rather than
# failing -- an upgrade must not need the launcher and the app to restart in
# lockstep.
MASTER_LOOKUP_TIMEOUT_SECS = 5.0

# Which key-lifecycle routes the Rust custodian can actually serve.
#
# Stated as a PARTITION of custody._CUSTODY_ROUTES rather than an allow-list
# read inline by the middleware. A bare allow-list fails open in the direction
# that matters: adding a custody route and forgetting the rust side leaves the
# route falling through to a backend that cannot perform it, and nothing says
# so. Splitting the set makes the omission a failing test
# (test_rust_route_decision_partitions_every_custody_route) instead of a
# runtime surprise on the one deployment that enabled rust custody.
RUST_CONTROL_ROUTES = frozenset(
    {
        ("POST", "/api/v1/vault/unseal"),
        ("POST", "/api/v1/vault/seal"),
        ("POST", "/api/v1/vault/rotate-password"),
        ("POST", "/api/v1/vault/admin/rotate-dek-key"),
        ("POST", "/api/v1/vault/backup/restore"),
    }
)

# Refused, each for a reason, not merely "not implemented yet":
#
#   shamir/init, DELETE shamir  -- both rewrite how the master key is split.
#       Under rust custody the shares live in the daemons' own sealed state,
#       so a Python-side reshare would write a split the pool does not hold.
#   oneshot                     -- unseal, read, re-seal in one call. The
#       re-seal races the maintenance leader's reopen, and a half-applied
#       oneshot leaves the pool sealed with the API believing otherwise.
RUST_BLOCKED_ROUTES = frozenset(
    {
        ("POST", "/api/v1/vault/shamir/init"),
        ("DELETE", "/api/v1/vault/shamir"),
        ("POST", "/api/v1/vault/oneshot"),
    }
)


def rust_route_decision(method: str, path: str) -> str:
    """One of "serve", "refuse", "not-custody" for the rust backend.

    "not-custody" is the common case and must stay cheap: every request on a
    rust-custody API worker passes through here.
    """
    route = (method.upper(), path)
    if route in RUST_CONTROL_ROUTES:
        return "serve"
    if route in RUST_BLOCKED_ROUTES:
        return "refuse"
    return "not-custody"


async def elected_custodian_socket(session_factory) -> str | None:
    """The HTTP socket of the custodian currently holding the sub-keys.

    Returns None when the pool cannot be addressed -- either no master has been
    elected yet (the vault is sealed, or an election is in flight), or the
    custodians are still on the shared listener and publish no socket. Both
    mean "fall back", never "fail": this is a routing hint, and the caller
    already has a correct, slower path.

    Read from vault_workers rather than probed, because the master publishes
    that row as part of becoming master. Asking the pool who is master would
    itself need a route to the pool.
    """
    from .cluster import MASTER_TIMEOUT_SECS, get_hostname

    async with session_factory() as db:
        row = (
            await db.execute(
                text("""
                    SELECT http_socket_name
                    FROM vault_workers
                    WHERE hostname = :host
                      AND worker_state = 'master'
                      AND process_role = 'custodian'
                      AND http_socket_name IS NOT NULL
                      AND last_heartbeat > NOW() - make_interval(secs => :timeout)
                    ORDER BY last_heartbeat DESC
                    LIMIT 1
                """),
                {"host": get_hostname(), "timeout": MASTER_TIMEOUT_SECS},
            )
        ).fetchone()
    return row.http_socket_name if row is not None else None


class CustodyQuorumUnavailable(RuntimeError):
    """This worker could not reach a coordinator, and attaching did not help.

    Distinct from CustodianPoolUnavailable, which the pool raises for any
    momentary shortfall including ones an attach fixes. This one is the verdict
    AFTER trying, so it is the only custody condition that deserves a 503.
    """


async def ensure_control_plane(
    pool,
    vault,
    *,
    session_factory=None,
    attempts: int = 3,
    delay_secs: float = 0.25,
) -> None:
    """Make this worker able to serve a key-lifecycle route, or fail honestly.

    A disposable API worker is not attached to a coordinator until something
    attaches it, and the thing that does is a background loop. So a control
    route can genuinely arrive first -- most often right after the restart that
    IO pressure caused, which is when an operator is most likely to be sealing
    or rotating. Refusing it then reports "no quorum" for what is really "not
    attached yet", the recoverable condition custody was built to survive.

    Three outcomes, deliberately different:

      - already attached, or attachable      -> return, the route proceeds
      - the operator sealed the vault        -> VaultSealedError (503 sealed)
      - attach genuinely failed              -> CustodyQuorumUnavailable (503)

    The middle case must not be reported as a quorum failure: the vault is
    sealed because someone sealed it, and telling an operator their quorum is
    broken sends them repairing a pool that is fine.

    attach_live_rust_coordinator is the right primitive here and the leader
    paths are not: it takes no orchestration lock, seals nothing, and moves no
    share material. A request-serving worker must never do leader-grade work
    just to answer a route.
    """
    import asyncio

    from .custody_generation import (
        get_custody_generation_state,
        get_rust_custody_activation,
    )
    from .database import async_session
    from .rust_custody_backend import attach_live_rust_coordinator
    from .vault_state import VaultSealedError

    if session_factory is None:
        session_factory = async_session
    if attempts < 1:
        raise ValueError("ensure_control_plane needs at least one attempt")

    # "Not sealed" is the whole predicate. Also demanding an _rpc_client makes
    # this gate enforce an invariant it does not own: a worker can be unsealed
    # and able to serve without one, and treating that as "detached" sends it
    # to the durable read, which reports the vault SEALED for a rotation that
    # would have succeeded. Phantom-unsealed workers are caught elsewhere.
    if not vault.sealed:
        return

    async with session_factory() as db:
        enabled = await get_rust_custody_activation(db)
        state = await get_custody_generation_state(db) if enabled else None
    if state is None or state.active_generation is None:
        # Durable decision, not a probe: the pool being unreachable does not
        # make the vault sealed, and the vault being sealed does not make the
        # pool broken. Reporting the wrong one sends the operator to the wrong
        # place.
        raise VaultSealedError()

    for attempt in range(attempts):
        try:
            if await attach_live_rust_coordinator(
                pool, vault, session_factory=session_factory
            ):
                return
        except Exception:
            # A failed attach is the condition we are here to handle. Keep the
            # daemon-level detail in the log -- it names slot numbers, which
            # must never reach a response body.
            log.warning(
                "custody routing: control-plane attach attempt %d failed",
                attempt + 1,
                exc_info=True,
            )
        if attempt + 1 < attempts:
            await asyncio.sleep(delay_secs)

    raise CustodyQuorumUnavailable(
        f"no custodian quorum after {attempts} attach attempts"
    )


async def run_custody_routing(
    pool,
    vault,
    *,
    session_factory=None,
    interval_seconds: float = 5.0,
) -> None:
    """Keep this node's rust custody pool reachable, forever.

    Exactly one worker PER NODE leads. The leader repairs and reopens the local
    pool; everyone else takes the read-only attach path, which can join a
    coordinator that is already open but can never create one.

    That split is the reason leadership must be node-scoped. Separated custody
    exists because the processes serving requests are the ones that die under
    IO pressure -- and a node that loses its pool in that moment has to bring
    it back itself. A cluster-wide leader would be on another machine, unable
    to reach these sockets, so the node would stay down exactly when the box is
    under stress.
    """
    import asyncio

    from .custody_generation import custody_maintenance_lock
    from .database import async_session
    from .rust_custody_backend import (
        attach_live_rust_coordinator,
        refresh_rust_custody,
    )

    if session_factory is None:
        session_factory = async_session
    if interval_seconds <= 0:
        raise ValueError("Rust custody maintenance interval must be positive")
    lock_name = custody_maintenance_lock()
    while True:
        leader = False
        async with session_factory() as lock_db:
            async with lock_db.begin():
                leader = (
                    await lock_db.execute(
                        text("SELECT pg_try_advisory_xact_lock(hashtext(:lock_name))"),
                        {"lock_name": lock_name},
                    )
                ).scalar_one()
                if leader:
                    # Name the scope: reading two nodes' logs must make it
                    # obvious they each elected their OWN leader, and a node
                    # whose identity file is unreadable (scope falls back to
                    # "standalone") has to be visible rather than silently
                    # sharing a lock with its neighbours.
                    log.info("custody routing: leadership acquired for %s", lock_name)
                    while True:
                        try:
                            await refresh_rust_custody(
                                pool, vault, session_factory=session_factory
                            )
                        except Exception:
                            log.warning(
                                "custody routing: maintenance failed; retrying",
                                exc_info=True,
                            )
                        await asyncio.sleep(interval_seconds)
        if not leader:
            # Followers are not idle: without this they stay sealed until they
            # happen to win leadership, so an unseal reaches only the worker
            # that served it and the rest 503 indefinitely.
            try:
                await attach_live_rust_coordinator(
                    pool, vault, session_factory=session_factory
                )
            except Exception:
                log.warning(
                    "custody routing: follower attach failed; retrying", exc_info=True
                )
            await asyncio.sleep(interval_seconds)
