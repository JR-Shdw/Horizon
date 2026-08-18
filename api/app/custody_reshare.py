# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Crash-recoverable orchestration for the unwired Rust custody migration."""

from __future__ import annotations

import logging
from collections.abc import Callable
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Any

from sqlalchemy import text

from . import custody_generation as generation_state
from .database import async_session

log = logging.getLogger("rhorizon.custody")

if TYPE_CHECKING:
    from .cluster_rpc import CustodianPoolController, CustodianRpcClient
    from .vault_state import VaultState


async def _read_state(session_factory) -> generation_state.CustodyGenerationState:
    async with session_factory() as db:
        return await generation_state.get_custody_generation_state(db)


async def _commit_transition(session_factory, transition, *args, **kwargs):
    async with session_factory() as db:
        state = await transition(db, *args, **kwargs)
        await db.commit()
        return state


@asynccontextmanager
async def _serialized_custody_operation(session_factory):
    """Hold one transaction-scoped lock across database and daemon steps."""
    async with session_factory() as db:
        async with db.begin():
            acquired = (
                await db.execute(
                    text("SELECT pg_try_advisory_xact_lock(hashtext(:lock_name))"),
                    {"lock_name": generation_state.CUSTODY_ORCHESTRATION_LOCK},
                )
            ).scalar_one()
            if acquired is not True:
                raise generation_state.CustodyOrchestrationBusy(
                    "another custody generation operation is in progress"
                )
            yield


async def reconcile_rust_custody_generation(
    pool: CustodianPoolController,
    *,
    session_factory=async_session,
) -> CustodianRpcClient | None:
    """Apply the durable rollback/roll-forward decision to every custodian."""
    async with _serialized_custody_operation(session_factory):
        return await _reconcile_rust_custody_generation_locked(
            pool, session_factory=session_factory
        )


async def refresh_rust_custody_generation(
    pool: CustodianPoolController,
    *,
    session_factory=async_session,
) -> CustodianRpcClient | None:
    """Apply the durable operator intent to the pool under one held lock.

    The activation decision is read inside ``CUSTODY_ORCHESTRATION_LOCK``, not
    before it: a maintenance tick that read "sealed" outside the lock could
    otherwise seal a pool an operator finished reopening in between, and the
    API would flap sealed until the next tick reopened it again.

    ``None`` means the caller must seal its own view, either because the
    operator's durable decision is sealed or because no generation exists.
    """
    async with _serialized_custody_operation(session_factory):
        async with session_factory() as db:
            enabled = await generation_state.get_rust_custody_activation(db)
        if not enabled:
            await pool.seal_all()
            return None
        return await _repair_rust_custody_generation_locked(
            pool, session_factory=session_factory
        )


async def _repair_rust_custody_generation_locked(
    pool: CustodianPoolController,
    *,
    session_factory,
) -> CustodianRpcClient | None:
    """Reconcile, then replace empty fixed slots from a surviving quorum."""
    from .cluster_rpc import CustodianPoolUnavailable

    client = await _reconcile_rust_custody_generation_locked(
        pool, session_factory=session_factory
    )
    state = await _read_state(session_factory)
    active = state.active_generation
    if active is None:
        return client

    statuses = await pool.share_statuses()
    live = 0
    missing = 0
    for slot, status in statuses.items():
        if (
            status.get("slot") != slot
            or status.get("threshold") != state.threshold
            or status.get("slots") != state.slots
            or status.get("prepared_generation") is not None
            or status.get("previous_generation") is not None
            or status.get("reshare_generation") is not None
        ):
            raise CustodianPoolUnavailable(
                f"custodian slot {slot} has inconsistent stable share state"
            )
        generation = status.get("generation")
        if generation == active:
            live += 1
        elif generation is None:
            missing += 1
        else:
            raise CustodianPoolUnavailable(
                f"custodian slot {slot} has unexpected share generation"
            )
    if missing == 0:
        return client
    if live < state.threshold:
        raise CustodianPoolUnavailable(
            "Rust custodian share repair requires a surviving current quorum"
        )
    return await _reshare_rust_custodians_locked(
        pool,
        threshold=state.threshold,
        slots=state.slots,
        session_factory=session_factory,
    )


async def _pool_topology(pool: CustodianPoolController) -> tuple[int, int]:
    """The shape the daemons were actually launched with.

    Read from the custodians rather than from configuration: they are the ones
    that decide what a delivery may install into, and a launcher and an API
    process can disagree about the environment.
    """
    from .cluster_rpc import CustodianPoolUnavailable

    shapes = {
        (status.get("threshold"), status.get("slots"))
        for status in (await pool.share_statuses()).values()
    }
    if len(shapes) != 1:
        raise CustodianPoolUnavailable("custodian pool reports more than one topology")
    threshold, slots = shapes.pop()
    if not isinstance(threshold, int) or not isinstance(slots, int):
        raise CustodianPoolUnavailable("custodian pool reported an invalid topology")
    return threshold, slots


async def _reconcile_rust_custody_topology_locked(
    pool: CustodianPoolController,
    *,
    session_factory,
) -> generation_state.CustodyGenerationState:
    """Resolve an in-flight topology change against the shape now running.

    The operator's restart IS the decision. A pool running the target shape
    gets the recorded envelopes and the transition closes; a pool still
    running the current shape means the environment was put back, so the
    target is dropped and the generation it would have replaced stays live.
    Neither outcome can produce a mixed quorum, because a custodian only
    accepts a delivery sealed for the topology it was launched with.
    """
    from .cluster_rpc import CustodianPoolUnavailable

    state = await _read_state(session_factory)
    if state.phase != "resharding":
        return state
    target = state.target_generation
    assert target is not None

    async with session_factory() as db:
        recorded = await generation_state.get_custody_topology_deliveries(db)
    launched = await _pool_topology(pool)
    if recorded is None or launched == (state.threshold, state.slots):
        # Either the coordinator never got as far as recording its envelopes,
        # or the operator reverted. Both keep the current generation, which no
        # step of this transition ever touched.
        return await _commit_transition(
            session_factory,
            generation_state.abort_custody_topology_change,
            target,
        )

    generation, threshold, slots, deliveries = recorded
    if generation != target:
        raise generation_state.CustodyGenerationCorrupt(
            "recorded custody topology deliveries do not match the transition"
        )
    if launched != (threshold, slots):
        raise CustodianPoolUnavailable(
            "custodian pool runs neither the current nor the target topology"
        )

    await pool.seal_all()
    await pool.deliver_topology_reshare(generation, deliveries)
    resolved = await _commit_transition(
        session_factory,
        generation_state.finish_custody_topology_change,
        generation,
        threshold=threshold,
        slots=slots,
    )
    # The shape that was live until this line is now dead: reconciliation
    # refuses to run under it, so nothing can go back to it. Its share state is
    # still on disk and still decrypts, so sweep it here rather than leaving an
    # operator to remember. This is the ONLY moment the sweep is certainly
    # right -- the transition just closed and the pool is the target shape.
    await _sweep_superseded_after_topology_change(pool, session_factory=session_factory)
    return resolved


async def _sweep_superseded_after_topology_change(
    pool: CustodianPoolController, *, session_factory
) -> None:
    """Put the shape this change superseded below its threshold, best effort.

    Hygiene, not correctness. The transition is already durable, so a refusal
    or a filesystem error must not undo it or stop the pool from opening; the
    next resolved change sweeps again, and the same sweep can be run by hand.
    Runs the lock-free variant because reconciliation holds the orchestration
    lock already.
    """
    from .config import settings
    from .custody_shred import (
        CustodyShredRefused,
        shred_superseded_custody_state_locked,
    )

    try:
        report = await shred_superseded_custody_state_locked(
            pool,
            key_dir=settings.rust_custodian_key_dir,
            session_factory=session_factory,
        )
    except (CustodyShredRefused, OSError) as exc:
        log.warning(
            "custody: superseded share state was left in place (%s); "
            "it is inert only once swept, so re-run the sweep",
            exc,
        )
        return
    if report["superseded_share_state"] or report["orphan_transport_keys"]:
        log.info(
            "custody: swept %d superseded share state(s) and %d orphan "
            "transport key(s); %s",
            len(report["superseded_share_state"]),
            len(report["orphan_transport_keys"]),
            "; ".join(report["residual"]) or "nothing left over",
        )


async def _reconcile_rust_custody_generation_locked(
    pool: CustodianPoolController,
    *,
    session_factory,
) -> CustodianRpcClient | None:
    state = await _reconcile_rust_custody_topology_locked(
        pool, session_factory=session_factory
    )
    if state.phase == "preparing":
        target = state.target_generation
        assert target is not None
        await pool.seal_all()
        await pool.rollback_generation_all(target)
        state = await _commit_transition(
            session_factory, generation_state.abort_custody_generation, target
        )
    elif state.phase == "committing":
        target = state.target_generation
        assert target is not None
        await pool.seal_all()
        await pool.commit_generation_all(target)
        await pool.finalize_generation_all(target)
        state = await _commit_transition(
            session_factory, generation_state.finish_custody_generation, target
        )

    active = state.active_generation
    if active is None:
        return None
    return await pool.unseal(generation=active)


async def migrate_local_keys_to_rust_custodians(
    vault: VaultState,
    pool: CustodianPoolController,
    *,
    threshold: int,
    slots: int,
    session_factory=async_session,
    split_opaque: Callable[[bytearray, int, int], list[Any]] | None = None,
) -> CustodianRpcClient:
    """Move one local runtime bundle through a durable opaque reshare.

    This helper remains unwired. A committed ``preparing`` state always owns
    rollback; once ``committing`` is durable, no error path may roll backward.
    """
    async with _serialized_custody_operation(session_factory):
        return await _migrate_local_keys_to_rust_custodians_locked(
            vault,
            pool,
            threshold=threshold,
            slots=slots,
            session_factory=session_factory,
            split_opaque=split_opaque,
        )


async def open_rust_custody_for_local_unseal(
    vault: VaultState,
    pool: CustodianPoolController,
    *,
    threshold: int,
    slots: int,
    session_factory=async_session,
    split_opaque: Callable[[bytearray, int, int], list[Any]] | None = None,
) -> CustodianRpcClient:
    """Adopt Rust custody for a password-verified local generation.

    A pool that already holds a durable generation is REOPENED from the shares
    the custodians still own; only an empty one receives a fresh split of the
    local runtime bundle. Both outcomes are decided under one held lock, so two
    concurrent unseals cannot have one migrate while the other reopens.

    Reopening records the unsealed intent only after the daemons actually
    unsealed. The reverse order fails open: a failed reopen would leave a
    durable "unsealed" decision that the maintenance leader keeps acting on.
    """
    async with _serialized_custody_operation(session_factory):
        state = await _read_state(session_factory)
        if state.active_generation is not None and (
            state.threshold != threshold or state.slots != slots
        ):
            raise generation_state.CustodyGenerationConflict(
                "configured custodian topology does not match the durable "
                "Rust generation"
            )
        if state.phase == "stable" and state.active_generation is not None:
            # With share persistence off, a host reboot leaves a durable
            # generation that NO daemon holds -- and repair refuses that,
            # correctly, because below a surviving quorum the durable row is
            # the no-silent-rekey guard. Refute it here instead: this path is
            # password-verified, share_statuses() raises unless every slot
            # answers, and a pool that verifiably holds nothing of any
            # generation is protected by nothing but the password the caller
            # just proved. Abandon under the held lock and fall through to a
            # fresh split. One surviving share anywhere keeps the refusal.
            statuses = await pool.share_statuses()
            if all(
                status.get("generation") is None
                and status.get("prepared_generation") is None
                and status.get("previous_generation") is None
                and status.get("reshare_generation") is None
                for status in statuses.values()
            ):
                log.warning(
                    "custody: durable generation %d survives in no custodian "
                    "slot; abandoning it for a password-verified re-split",
                    state.active_generation,
                )
                await _commit_transition(
                    session_factory,
                    generation_state.abandon_custody_generation,
                    state.active_generation,
                )
                state = await _read_state(session_factory)

        client = await _repair_rust_custody_generation_locked(
            pool, session_factory=session_factory
        )
        if client is None:
            # Nothing survives reconciliation, so this is the first activation
            # and the verified local bundle becomes the initial generation.
            return await _migrate_local_keys_to_rust_custodians_locked(
                vault,
                pool,
                threshold=threshold,
                slots=slots,
                session_factory=session_factory,
                split_opaque=split_opaque,
            )
        await _commit_transition(
            session_factory,
            generation_state.set_rust_custody_activation,
            unsealed=True,
        )
        return client


async def _migrate_local_keys_to_rust_custodians_locked(
    vault: VaultState,
    pool: CustodianPoolController,
    *,
    threshold: int,
    slots: int,
    session_factory,
    split_opaque: Callable[[bytearray, int, int], list[Any]] | None,
) -> CustodianRpcClient:
    from rhorizon_crypto import secure_zero

    state = await _read_state(session_factory)
    if state.phase != "stable" or state.active_generation is not None:
        raise generation_state.CustodyGenerationConflict(
            "local-key migration requires an empty stable Rust generation"
        )

    if split_opaque is None:
        from rhorizon_crypto import shamir_split_opaque_bytearray

        split_opaque = shamir_split_opaque_bytearray

    await pool.seal_all()
    preparing = await _commit_transition(
        session_factory,
        generation_state.begin_custody_generation,
        threshold=threshold,
        slots=slots,
    )
    target = preparing.target_generation
    assert target is not None

    bundle: bytearray | None = None
    opaque_shares: list[Any] = []
    share_map: dict[int, Any] = {}
    try:
        bundle = vault.export_subkeys_for_shamir()
        try:
            opaque_shares = split_opaque(bundle, threshold, slots)
        finally:
            secure_zero(bundle)
            bundle = None
        share_map = {share.x: share for share in opaque_shares}
        if len(share_map) != slots:
            raise RuntimeError("opaque split returned duplicate or missing coordinates")
        await pool.prepare_shares(share_map, target)
    except Exception:
        await pool.rollback_generation_all(target)
        await _commit_transition(
            session_factory,
            generation_state.abort_custody_generation,
            target,
        )
        raise
    finally:
        if bundle is not None:
            secure_zero(bundle)
        share_map.clear()
        opaque_shares.clear()

    await _commit_transition(
        session_factory, generation_state.choose_custody_generation, target
    )
    await pool.commit_generation_all(target)
    await pool.finalize_generation_all(target)
    await _commit_transition(
        session_factory, generation_state.finish_custody_generation, target
    )
    await _commit_transition(
        session_factory,
        generation_state.set_rust_custody_activation,
        unsealed=True,
    )
    return await pool.unseal(generation=target)


async def stage_local_bundle_for_rust_rotation(
    bundle: bytearray,
    pool: CustodianPoolController,
    *,
    threshold: int,
    slots: int,
    session_factory=async_session,
    split_opaque: Callable[[bytearray, int, int], list[Any]] | None = None,
) -> tuple[int, int]:
    """Stage replacement runtime keys before the application DB decision.

    The caller must hold ``CUSTODY_ORCHESTRATION_LOCK`` in the transaction that
    will rewrap application data and call ``choose_custody_generation``. The
    preparing decision is committed first, so a crash before that application
    transaction commits can only roll back the staged generation.
    """
    from rhorizon_crypto import secure_zero

    previous: int | None = None
    target: int | None = None
    pool_transition_started = False
    bundle_wiped = False
    opaque_shares: list[Any] = []
    share_map: dict[int, Any] = {}
    try:
        state = await _read_state(session_factory)
        if state.phase != "stable" or state.active_generation is None:
            raise generation_state.CustodyGenerationConflict(
                "key rotation requires a stable active Rust generation"
            )
        if state.threshold != threshold or state.slots != slots:
            raise generation_state.CustodyGenerationConflict(
                "key rotation topology does not match the active Rust generation"
            )
        previous = state.active_generation
        if split_opaque is None:
            from rhorizon_crypto import shamir_split_opaque_bytearray

            split_opaque = shamir_split_opaque_bytearray

        pool_transition_started = True
        await pool.seal_all()
        preparing = await _commit_transition(
            session_factory,
            generation_state.begin_custody_generation,
            threshold=threshold,
            slots=slots,
        )
        target = preparing.target_generation
        assert target is not None
        try:
            opaque_shares = split_opaque(bundle, threshold, slots)
        finally:
            secure_zero(bundle)
            bundle_wiped = True
        share_map = {share.x: share for share in opaque_shares}
        if len(share_map) != slots:
            raise RuntimeError("opaque split returned duplicate or missing coordinates")
        await pool.prepare_shares(share_map, target)
        pool_transition_started = False
    except BaseException:
        if pool_transition_started and previous is not None:
            if target is None:
                await pool.unseal(generation=previous)
            else:
                await abort_staged_rust_rotation(
                    pool,
                    target=target,
                    previous=previous,
                    session_factory=session_factory,
                )
        raise
    finally:
        if not bundle_wiped:
            secure_zero(bundle)
        share_map.clear()
        opaque_shares.clear()
    assert target is not None and previous is not None
    return target, previous


async def abort_staged_rust_rotation(
    pool: CustodianPoolController,
    *,
    target: int,
    previous: int,
    session_factory=async_session,
) -> CustodianRpcClient:
    """Restore the old generation while the durable phase is preparing."""
    await pool.seal_all()
    await pool.rollback_generation_all(target)
    await _commit_transition(
        session_factory,
        generation_state.abort_custody_generation,
        target,
    )
    return await pool.unseal(generation=previous)


async def finish_staged_rust_rotation(
    pool: CustodianPoolController,
    *,
    target: int,
    session_factory=async_session,
) -> CustodianRpcClient:
    """Apply a committed application-DB roll-forward decision."""
    await pool.seal_all()
    await pool.commit_generation_all(target)
    await pool.finalize_generation_all(target)
    await _commit_transition(
        session_factory,
        generation_state.finish_custody_generation,
        target,
    )
    return await pool.unseal(generation=target)


def _transport_key(value: object, slot: int) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"custodian slot {slot} has an invalid transport public key")
    return value


async def begin_rust_custodian_topology_change(
    pool: CustodianPoolController,
    *,
    threshold: int,
    slots: int,
    new_peer_keys: dict[int, str] | None = None,
    session_factory=async_session,
) -> int:
    """Record a target shape's shares, then hand the pool to the operator.

    This is the half of a topology change an API process can do. It ends with
    the envelopes durable and the running pool untouched, still holding the
    current generation: until the operator relaunches under the target, the
    whole thing is undone by leaving the environment alone.

    Surviving slots' transport keys are read from the daemons themselves, so
    a caller cannot re-point one at a key of its own -- only genuinely new
    slots may bring one, and Rust checks the same thing again.
    """
    async with _serialized_custody_operation(session_factory):
        return await _begin_rust_custodian_topology_change_locked(
            pool,
            threshold=threshold,
            slots=slots,
            new_peer_keys=new_peer_keys or {},
            session_factory=session_factory,
        )


async def _begin_rust_custodian_topology_change_locked(
    pool: CustodianPoolController,
    *,
    threshold: int,
    slots: int,
    new_peer_keys: dict[int, str],
    session_factory,
) -> int:
    state = await _read_state(session_factory)
    if state.phase != "stable" or state.active_generation is None:
        raise generation_state.CustodyGenerationConflict(
            "custodian topology change requires a stable active generation"
        )
    launched = await _pool_topology(pool)
    if launched != (state.threshold, state.slots):
        raise generation_state.CustodyGenerationConflict(
            "the running custodian pool does not match the durable topology"
        )

    statuses = await pool.share_statuses()
    peer_keys = {
        slot: _transport_key(status.get("transport_public_key"), slot)
        for slot, status in statuses.items()
        if slot <= slots
    }
    added = set(range(1, slots + 1)) - set(peer_keys)
    if set(new_peer_keys) != added:
        raise ValueError(
            "a topology change needs a transport public key for exactly the "
            f"slots it adds: {sorted(added)}"
        )
    peer_keys |= {
        slot: _transport_key(key, slot) for slot, key in new_peer_keys.items()
    }

    previous = state.active_generation
    await pool.unseal(generation=previous)
    resharding = await _commit_transition(
        session_factory,
        generation_state.begin_custody_topology_change,
        threshold=threshold,
        slots=slots,
    )
    target = resharding.target_generation
    assert target is not None
    try:
        deliveries = await pool.generate_topology_reshare(
            target, threshold=threshold, slots=slots, peer_keys=peer_keys
        )
        await _commit_transition(
            session_factory,
            generation_state.record_custody_topology_deliveries,
            generation=target,
            threshold=threshold,
            slots=slots,
            deliveries=deliveries,
        )
    except BaseException:
        # Nothing in the pool moved, so the target is always safe to drop.
        await _commit_transition(
            session_factory,
            generation_state.abort_custody_topology_change,
            target,
        )
        raise
    return target


async def reshare_rust_custodians(
    pool: CustodianPoolController,
    *,
    threshold: int,
    slots: int,
    session_factory=async_session,
) -> CustodianRpcClient:
    """Rotate Rust-held shares without exposing key material to Python."""
    async with _serialized_custody_operation(session_factory):
        return await _reshare_rust_custodians_locked(
            pool,
            threshold=threshold,
            slots=slots,
            session_factory=session_factory,
        )


async def _reshare_rust_custodians_locked(
    pool: CustodianPoolController,
    *,
    threshold: int,
    slots: int,
    session_factory,
) -> CustodianRpcClient:
    state = await _read_state(session_factory)
    if state.phase != "stable" or state.active_generation is None:
        raise generation_state.CustodyGenerationConflict(
            "native reshare requires a stable active generation"
        )
    previous = state.active_generation
    await pool.unseal(generation=previous)

    preparing = await _commit_transition(
        session_factory,
        generation_state.begin_custody_generation,
        threshold=threshold,
        slots=slots,
    )
    target = preparing.target_generation
    assert target is not None

    try:
        await pool.prepare_native_reshare(target)
    except Exception:
        await pool.seal_all()
        await pool.rollback_generation_all(target)
        await _commit_transition(
            session_factory,
            generation_state.abort_custody_generation,
            target,
        )
        await pool.unseal(generation=previous)
        raise

    # Custodian generation transitions are intentionally unavailable while any
    # daemon is unsealed. A seal failure leaves the durable phase at preparing,
    # so startup reconciliation remains rollback-safe.
    await pool.seal_all()
    await _commit_transition(
        session_factory, generation_state.choose_custody_generation, target
    )
    await pool.commit_generation_all(target)
    await pool.finalize_generation_all(target)
    await _commit_transition(
        session_factory, generation_state.finish_custody_generation, target
    )
    return await pool.unseal(generation=target)
