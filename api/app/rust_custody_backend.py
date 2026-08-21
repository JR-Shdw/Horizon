# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Opt-in API adapter for the standalone fixed Rust custodian pool."""

from __future__ import annotations

import asyncio
import hmac
import logging
from pathlib import Path
from typing import TYPE_CHECKING

from sqlalchemy import text

from .cluster_rpc import CustodianPoolController, CustodianPoolUnavailable
from .custody_generation import (
    CustodyOrchestrationBusy,
    get_custody_generation_state,
    get_rust_custody_activation,
    set_rust_custody_activation,
)
from .custody_reshare import (
    abort_staged_rust_rotation,
    finish_staged_rust_rotation,
    open_rust_custody_for_local_unseal,
    refresh_rust_custody_generation,
)
from .database import async_session

if TYPE_CHECKING:
    from .cluster_rpc import CustodianRpcClient
    from .vault_state import VaultState

log = logging.getLogger("rhorizon.rust_custody")
_configured_pool: CustodianPoolController | None = None

# Every API worker runs the same reconcile when it boots, and
# CUSTODY_ORCHESTRATION_LOCK is a non-blocking try-lock, so all but one lose
# it. Losing is expected rather than fatal: the winner is performing the
# identical reconcile. Wait it out, but stay bounded, because main.py treats a
# raised init error as a refusal to start the worker and a genuinely stuck
# holder must still fail closed instead of hanging startup forever.
_STARTUP_ATTACH_LOCK_ATTEMPTS = 40
_STARTUP_ATTACH_LOCK_DELAY_SECS = 0.25

# The same wait, for the same reason, on the operator's unseal. /health answers
# as soon as the FIRST worker is ready while the rest are still reconciling
# under this lock, so the busy window grows with the worker count: at 16
# workers an unseal issued the moment the port answers lands inside it and used
# to escape as an uncaught 500. Measured: first unseal 500, the identical call
# 15s later 200.
_UNSEAL_LOCK_ATTEMPTS = 40
_UNSEAL_LOCK_DELAY_SECS = 0.25


def configure_rust_custody_pool(pool: CustodianPoolController) -> None:
    global _configured_pool
    _configured_pool = pool


def configured_rust_custody_pool() -> CustodianPoolController:
    if _configured_pool is None:
        raise RuntimeError("Rust custody pool is not configured in this API process")
    return _configured_pool


async def _persist_rust_custody_activation(session_factory, *, unsealed: bool) -> None:
    async with session_factory() as db:
        await set_rust_custody_activation(db, unsealed=unsealed)
        await db.commit()


async def _reload_external_ancillary_state(session_factory) -> None:
    """Reinstall the envelopes a seal dropped from every custodian.

    Sealing clears the whole locked runtime object, so the audit seed, the HA
    password, and the previous HMAC key are gone after ANY seal/unseal cycle,
    including the one a restored rotation performs. These loaders re-send the
    stored database envelopes; Python never reconstructs their plaintext.
    """
    from .audit_identity import load_audit_identity_into_ram
    from .auth import load_prev_hmac_into_ram
    from .ha_password import load_ha_password_into_ram

    async with session_factory() as db:
        await load_prev_hmac_into_ram(db)
        await load_ha_password_into_ram(db)
        await load_audit_identity_into_ram(db)


def _seal_api_view_locked(vault: VaultState) -> None:
    vault.detach_rpc_client()
    vault.seal()


async def _seal_api_view(vault: VaultState) -> None:
    async with vault.master_transition_lock():
        _seal_api_view_locked(vault)


def build_rust_custodian_pool(
    *,
    runtime_directory: str | Path,
    control_token_file: str | Path,
    slots: int,
    threshold: int | None = None,
) -> CustodianPoolController:
    """Build the fixed-slot controller without starting or replacing daemons."""
    runtime_path = Path(runtime_directory)
    token_path = Path(control_token_file)
    if not runtime_path.is_absolute() or runtime_path == Path("/"):
        raise ValueError("Rust custody runtime directory must be an absolute subpath")
    if not token_path.is_absolute() or token_path == Path("/"):
        raise ValueError("Rust custody control token must be an absolute file path")
    if token_path.parent != runtime_path:
        raise ValueError(
            "Rust custody control token must be directly under the runtime directory"
        )
    if isinstance(slots, bool) or slots not in {3, 5, 7, 9}:
        raise ValueError("Rust custody slots must be one of 3, 5, 7, or 9")
    resolved_threshold = slots // 2 + 1 if threshold is None else threshold
    sockets = {
        slot: str(runtime_path / f"rust-custodian-{slot}.sock")
        for slot in range(1, slots + 1)
    }
    return CustodianPoolController(
        sockets,
        str(token_path),
        resolved_threshold,
    )


async def _retry_while_orchestration_busy(
    operation,
    *,
    what: str,
    attempts: int,
    delay_secs: float,
):
    """Re-run ``operation`` while the orchestration lock is merely busy.

    Only CustodyOrchestrationBusy is retried. A durable
    CustodyGenerationConflict states a fact about the generation, so retrying
    would spend the whole budget re-deriving the same refusal and delay a real
    answer; it propagates on the first attempt.

    The wait is bounded either way, because a genuinely stuck holder must fail
    closed rather than hang the caller forever.
    """
    busy: CustodyOrchestrationBusy | None = None
    for attempt in range(attempts):
        try:
            return await operation()
        except CustodyOrchestrationBusy as exc:
            busy = exc
            if attempt + 1 < attempts:
                await asyncio.sleep(delay_secs)
    assert busy is not None
    log.error(
        "Rust custody: orchestration lock still held after %d attempts; %s",
        attempts,
        what,
    )
    raise busy


async def _refresh_generation_waiting_out_peer_workers(
    pool: CustodianPoolController,
    *,
    session_factory,
) -> "CustodianRpcClient | None":
    """Reconcile at startup, tolerating a peer worker that holds the lock.

    The maintenance loop deliberately does NOT retry: it already re-runs on its
    own interval under a separate leadership lock, so blocking there would only
    delay the next tick.
    """
    return await _retry_while_orchestration_busy(
        lambda: refresh_rust_custody_generation(pool, session_factory=session_factory),
        what="refusing worker startup",
        attempts=_STARTUP_ATTACH_LOCK_ATTEMPTS,
        delay_secs=_STARTUP_ATTACH_LOCK_DELAY_SECS,
    )


async def attach_reconciled_rust_custody(
    pool: CustodianPoolController,
    vault: VaultState,
    *,
    session_factory=async_session,
) -> bool:
    """Reconcile one durable generation and attach its selected RPC client."""
    # Never overlap a local or stale RPC generation with external recovery.
    # This also wipes any compatibility-backend keys before the API can attach
    # to Rust, so a canary switch cannot leave two custody owners in memory.
    await _seal_api_view(vault)
    client = await _refresh_generation_waiting_out_peer_workers(
        pool, session_factory=session_factory
    )
    if client is None:
        return False
    async with vault.master_transition_lock():
        vault.attach_rpc_client(client)
        vault._sealed = False
        return True


async def deactivate_rust_custody(
    pool: CustodianPoolController,
    vault: VaultState,
    *,
    session_factory=async_session,
    local_transition_locked: bool = False,
) -> None:
    """Persist manual seal first, then seal daemons and the local API view."""
    await _persist_rust_custody_activation(session_factory, unsealed=False)
    try:
        await pool.seal_all()
    finally:
        if local_transition_locked:
            _seal_api_view_locked(vault)
        else:
            await _seal_api_view(vault)


async def seal_custodians_offline() -> bool:
    """Drop the custodians' key material with NO database access.

    ``deactivate_rust_custody`` is the operator path and cannot be reused by
    the fence: it persists ``unsealed=False`` FIRST, and that is a database
    write. The fence fires precisely because the database is unreachable, so
    routing through it would block on the write and never reach the seal --
    the same shape as the bug it exists to prevent.

    Skipping the persistence is safe, and specifically NOT a weaker seal. The
    flag is a RECORD of a decision this function has already enforced
    locally; the key material is gone either way, and the row reconciles when
    the database comes back. Deferring a record is recoverable. Retaining keys
    is not.

    This matters more than "the API view is sealed" suggests. Under Rust
    custody the runtime bundle lives in the custodians, not in this worker --
    ``activate_rust_custody_from_local`` says so outright: the local keys are
    wiped either way and "the custodians stay the only holders of the runtime
    bundle". Sealing only the API view would therefore zeroize the wrong
    process and leave the actual key material resident on the host.

    ``pool.seal_all()`` reaches the custodians over local Unix sockets
    (``cluster_rpc.CustodianPoolController``), so it stays available in exactly
    the isolation this runs under.

    Returns True if a pool was configured and sealed, False when custody is not
    in use in this process (a no-op, not a failure).
    """
    pool = _configured_pool
    if pool is None:
        return False
    await pool.seal_all()
    return True


async def _verify_attached_master_generation(
    vault: VaultState,
    *,
    session_factory,
) -> None:
    """Prove the attached quorum serves the generation the password unlocked.

    The operator authenticated against ``master_check``, which is derived from
    the hmac subkey alone. Recomputing it through the custodian is the only
    check that the bundle the pool holds is the one the password just verified:
    a reopened pool reconstructs its own shares, and adopting a divergent
    generation would hash new tokens and wrap new DEKs under keys no stored row
    can match. On the migration path the same call proves the split, install,
    and quorum unseal round-tripped the bundle byte-for-byte.
    """
    async with session_factory() as db:
        row = (
            await db.execute(
                text("SELECT value FROM vault_config WHERE key = 'master_check'")
            )
        ).fetchone()
    if row is None:
        raise RuntimeError("vault master check is missing")
    computed = await vault.hmac_sha512_hex("master-check-value")
    if not hmac.compare_digest(computed, row.value):
        raise RuntimeError(
            "Rust custody generation does not match the verified master password"
        )


async def activate_rust_custody_from_local(
    pool: CustodianPoolController,
    vault: VaultState,
    *,
    key_epoch: int,
    threshold: int,
    slots: int,
    session_factory=async_session,
) -> None:
    """Adopt Rust custody for verified local keys, holding the vault lock.

    A pool that already owns a durable generation is reopened from its own
    shares; only an empty pool receives the local bundle. Reopening is what
    makes a manual seal, a restore, or any other durable seal decision
    recoverable: the local keys are wiped either way, and the custodians stay
    the only holders of the runtime bundle.
    """
    client = await _retry_while_orchestration_busy(
        lambda: open_rust_custody_for_local_unseal(
            vault,
            pool,
            threshold=threshold,
            slots=slots,
            session_factory=session_factory,
        ),
        what="refusing the unseal",
        attempts=_UNSEAL_LOCK_ATTEMPTS,
        delay_secs=_UNSEAL_LOCK_DELAY_SECS,
    )
    _seal_api_view_locked(vault)
    vault.attach_rpc_client(client)
    vault._sealed = False
    vault.set_key_epoch(key_epoch)

    try:
        await _verify_attached_master_generation(vault, session_factory=session_factory)
    except BaseException:
        # Fail closed on both views AND on the durable decision: a pool whose
        # bundle does not match this vault must not be reopened by the
        # maintenance leader on the next tick.
        await deactivate_rust_custody(
            pool,
            vault,
            session_factory=session_factory,
            local_transition_locked=True,
        )
        raise

    # These values are already authenticated database envelopes under keys now
    # held by Rust. Their loaders send ciphertext to the selected custodian;
    # Python never reconstructs the ancillary plaintext after migration.
    await _reload_external_ancillary_state(session_factory)


async def abort_rust_custody_key_rotation(
    pool: CustodianPoolController,
    vault: VaultState,
    *,
    target: int,
    previous: int,
    key_epoch: int,
    session_factory=async_session,
) -> None:
    """Restore the selected old generation after application-DB rollback."""
    client = await abort_staged_rust_rotation(
        pool,
        target=target,
        previous=previous,
        session_factory=session_factory,
    )
    async with vault.master_transition_lock():
        vault.attach_rpc_client(client)
        vault._sealed = False
        vault.set_key_epoch(key_epoch)

    # The rolled-back transaction left every ancillary envelope wrapped under
    # the restored generation's keys, but the seal that preceded the rollback
    # dropped them from the daemons. Without this the vault comes back unable
    # to sign the audit chain or answer an HA proof.
    await _reload_external_ancillary_state(session_factory)


async def resync_rust_custody_attachment(
    pool: CustodianPoolController,
    vault: VaultState,
    *,
    key_epoch: int,
    session_factory=async_session,
) -> None:
    """Re-adopt the coordinator a self-restoring staging failure left behind.

    Staging seals the pool before it prepares anything, and its own restore
    path unseals the previous generation again. It cannot re-attach the API or
    reinstall ancillary envelopes, so the caller does it here before failing.
    """
    client = pool.active_client
    if client is None:
        return
    async with vault.master_transition_lock():
        vault.attach_rpc_client(client)
        vault._sealed = False
        vault.set_key_epoch(key_epoch)
    await _reload_external_ancillary_state(session_factory)


async def finish_rust_custody_key_rotation(
    pool: CustodianPoolController,
    vault: VaultState,
    *,
    target: int,
    key_epoch: int,
    session_factory=async_session,
) -> None:
    """Adopt a replacement generation after the application DB committed."""
    client = await finish_staged_rust_rotation(
        pool,
        target=target,
        session_factory=session_factory,
    )
    async with vault.master_transition_lock():
        vault.attach_rpc_client(client)
        vault._sealed = False
        vault.set_key_epoch(key_epoch)

    await _reload_external_ancillary_state(session_factory)


async def attach_live_rust_coordinator(
    pool: CustodianPoolController,
    vault: VaultState,
    *,
    session_factory=async_session,
) -> bool:
    """Attach a disposable API worker to a coordinator the leader already opened.

    An unseal only attaches the worker that served it. Every other worker has
    to reach the quorum somehow, and it must do so without leader-grade work:
    the design requires that an API worker holds no share and that replacing
    one never changes the custody generation. So this path takes no
    orchestration lock, never seals the pool, never repairs or reshares, and
    moves no share material. It reads the durable decision, probes slot status,
    and attaches a client this process already built from socket paths.

    Repair and seal stay with the maintenance leader, which
    custody_maintenance_lock() elects one worker PER NODE for -- the pool
    is reached over this host's sockets, so its authority has to be local.

    Ancillary envelopes are deliberately not reloaded here. They live in the
    custodian runtime, not in the worker, so the coordinator already holds them
    for every worker attached to it.
    """
    async with session_factory() as db:
        enabled = await get_rust_custody_activation(db)
        state = await get_custody_generation_state(db) if enabled else None
    if state is None or state.active_generation is None:
        # The durable decision is authoritative in BOTH directions. A follower
        # that stayed attached through an operator seal keeps answering
        # /status with sealed=false while every crypto op fails against sealed
        # daemons, which is worse than being sealed.
        await _seal_api_view(vault)
        return False
    client = await pool.unsealed_coordinator(state.active_generation)
    if client is None:
        # Transient: a leader may be mid-transition. Leave the attachment
        # alone and retry next tick; a genuinely broken client fails its next
        # crypto op and routes into the RPC recovery hook.
        #
        # One refutation is NOT transient: every slot answering and none of
        # them unsealed. The attachment points into this same pool, so a
        # worker still claiming unsealed is provably stale. Nothing else
        # catches that worker -- a daemon that ANSWERS "vault sealed" never
        # trips the MasterUnreachable recovery hook -- and it would keep
        # short-circuiting /unseal with already_unsealed while every crypto
        # op fails. A slot that does not answer keeps the conservative wait.
        try:
            observed = await pool.statuses()
        except CustodianPoolUnavailable:
            return False
        if all(status.get("state") != "unsealed" for status in observed.values()):
            await _seal_api_view(vault)
        return False
    async with vault.master_transition_lock():
        vault.attach_rpc_client(client)
        vault._sealed = False
    return True


async def refresh_rust_custody(
    pool: CustodianPoolController,
    vault: VaultState,
    *,
    session_factory=async_session,
) -> bool:
    """Maintain an active pool without disrupting a healthy API attachment."""
    client = await refresh_rust_custody_generation(
        pool, session_factory=session_factory
    )
    if client is None:
        await _seal_api_view(vault)
        return False
    async with vault.master_transition_lock():
        vault.attach_rpc_client(client)
        vault._sealed = False
    await _restore_ancillary_state_if_missing(pool, session_factory=session_factory)
    return True


async def _restore_ancillary_state_if_missing(
    pool: CustodianPoolController, *, session_factory
) -> None:
    """Put the envelopes back that a custodian restart dropped.

    Persisted share state survives a restart; nothing else in the custodian
    runtime does. The HA password, the audit identity seed and the previous
    HMAC key are held in memory by the daemons, so a pool that reopens itself
    from disk comes back holding shares and nothing else -- and because that
    reopen never goes through /unseal, the loaders that route normally calls
    never run either.

    The symptom is not a failure, which is what makes it dangerous: the vault
    serves secrets perfectly while /cluster/ha reports ha_loaded=false, HA
    proofs cannot be computed, and tokens from a lazy rotation window stop
    authenticating early.

    Only the maintenance leader reaches this, and only when the coordinator
    says it is missing the envelope -- so a healthy pool costs one status call
    per tick, and the loaders themselves re-send stored ciphertext that Python
    never reconstructs.
    """
    # Everything here is best-effort: a pool that cannot answer the probe (a
    # double, or a controller mid-transition) simply gets checked on the next
    # tick. Maintenance must not fail because a status question went
    # unanswered.
    accessor = getattr(pool, "coordinator_client", None)
    coordinator = accessor() if accessor is not None else None
    if coordinator is None:
        return
    try:
        if await coordinator.call("has_ha_password", {}) == "1":
            return
    except Exception:
        # A status probe must not break maintenance; the next tick retries.
        log.debug("custody: has_ha_password probe failed", exc_info=True)
        return
    log.info(
        "custody: coordinator holds no HA password envelope (restart drops the "
        "runtime, only shares persist); reinstalling ancillary state"
    )
    await _reload_external_ancillary_state(session_factory)


def wire_rust_custody_recovery(
    pool: CustodianPoolController,
    vault: VaultState,
    *,
    session_factory=async_session,
) -> None:
    """Recover a failed selected custodian without giving the API a share."""

    async def _recover() -> bool:
        return await attach_reconciled_rust_custody(
            pool,
            vault,
            session_factory=session_factory,
        )

    vault.set_rpc_recovery_hook(_recover)
