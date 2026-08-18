# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Durable recovery decision for transactional Rust custodian reshares."""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, replace
from typing import Literal

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

log = logging.getLogger("rhorizon.custody_generation")

# Pre-node-scoping name. Kept as the legacy row a single-host deployment still
# has, and as the prefix the per-node key is built from.
CUSTODY_STATE_CONFIG_KEY = "rust_custody_generation_state"
CUSTODY_ACTIVATION_CONFIG_KEY = "rust_custody_activation_state"
# Deliberately under the CUSTODY_STATE_CONFIG_KEY prefix: the mark IS part
# of the generation state, split into its own row only because the state
# blob is parsed with a strict field set. Sharing the prefix means every
# existing "DELETE ... LIKE '<state key>%'" cleanup already clears it,
# instead of each one leaking a raised floor until someone notices.
CUSTODY_HIGH_WATER_CONFIG_KEY = "rust_custody_generation_state_high_water"


_NODE_SCOPE: str | None = None


def _node_scope() -> str:
    """This host's identity, resolved once and identically in EVERY process.

    Two properties matter, and both were learned the hard way. It must not
    depend on the cached value the API lifespan sets, or a helper process on
    the same host addresses a different row -- reading an empty generation
    while the daemons hold a real one. And it must not CHANGE inside a
    process: resolving to one name before the identity is loaded and another
    after moves the row out from under a caller mid-transaction, which is how
    a generation counter silently restarts at 1.

    So: the identity file first, because that is the one answer every process
    can reach, then whatever the lifespan cached, then a single-host name --
    and the result is frozen for the life of the process.
    """
    global _NODE_SCOPE
    if _NODE_SCOPE is not None:
        return _NODE_SCOPE
    scope = None
    try:
        from .config import settings
        from .node_uuid import load_or_create_node_uuid

        scope = load_or_create_node_uuid(settings.node_uuid_path)
    except Exception:
        try:
            from .node_uuid import get_node_uuid

            scope = get_node_uuid()
        except Exception:
            # No identity reachable at all: not clustered, so a single scope
            # is the correct answer rather than an error.
            scope = "standalone"
    _NODE_SCOPE = scope
    return scope


def _reset_node_scope_for_tests() -> None:
    global _NODE_SCOPE
    _NODE_SCOPE = None


def custody_state_key(node_uuid: str | None = None) -> str:
    """The generation row belongs to ONE host's custodian pool.

    Custodians are reached over Unix sockets, so a pool is per host and cannot
    be shared: a second node reading a generation the first node's daemons hold
    would try to unseal its own empty slots, and that failure is the one with
    no soft landing -- the API does not start and no master password recovers
    it. Scoping the row is what lets every node in a cluster own its own
    quorum. The activation row stays global on purpose: it records the
    operator's seal decision for the VAULT, which every node must obey.
    """
    return f"{CUSTODY_STATE_CONFIG_KEY}:{node_uuid or _node_scope()}"


def custody_high_water_key(node_uuid: str | None = None) -> str:
    """Highest generation this node's pool has EVER minted, never reset.

    Kept out of the generation-state blob deliberately: that blob is parsed
    with a strict field set and an exact version match, so widening it would
    reject every existing row as corrupt. This is a separate row, read and
    written under the same CUSTODY_GENERATION_LOCK transaction.

    It exists because abandon_custody_generation clears active_generation, and
    the mint is `(active or 0) + 1` -- so without it the counter restarts at 1
    after every abandon, which with share persistence off is every host
    reboot. Transport envelopes bind the generation INSIDE the AEAD
    (transport.rs), so a repeated number lets an envelope captured from a
    previous incarnation authenticate against the new one. It fails closed
    today -- mixing polynomials yields a bundle master_check rejects -- but
    that is the last line, not the binding, and a replayed share is a cheap
    way to make an unseal fail. Monotonic numbering restores the binding
    without touching the wire format.
    """
    return f"{CUSTODY_HIGH_WATER_CONFIG_KEY}:{node_uuid or _node_scope()}"


CUSTODY_GENERATION_LOCK = "rhorizon:cluster:rust_custody_generation"
CUSTODY_ORCHESTRATION_LOCK = "rhorizon:cluster:rust_custody_orchestration"
CUSTODY_MAINTENANCE_LOCK = "rhorizon:cluster:rust_custody_maintenance"


def custody_maintenance_lock(node_uuid: str | None = None) -> str:
    """Maintenance leadership belongs to ONE worker PER NODE, not per cluster.

    The leader elected by this lock repairs and reopens the local custodian
    pool, over this host's Unix sockets. A single advisory lock in a shared
    database elects one worker for the whole cluster, so every other node has
    no authority to reopen its own pool -- its workers can attach to a
    coordinator that is already open, and nothing more.

    That is precisely the failure separated custody exists to prevent. Under IO
    pressure the processes serving requests are the ones that get killed, and a
    node that loses its pool in that moment must be able to bring it back
    ITSELF. Waiting on a leader that lives on another node, and that will never
    touch this node's sockets, means the node stays down exactly when the
    machine is under stress.

    Same scoping as ``custody_state_key()``, and the same reason: the resource
    is per host, so its coordination must be too.
    """
    return f"{CUSTODY_MAINTENANCE_LOCK}:{node_uuid or _node_scope()}"


CUSTODY_STATE_VERSION = 1
CUSTODY_GENERATION_MAX = 9_223_372_036_854_775_807

CustodyPhase = Literal["stable", "preparing", "committing", "resharding"]

# One topology-reshare envelope: a clear sender slot, a 24-byte nonce, the
# 18-byte authenticated header, the 161-byte share and a 16-byte tag, hex
# encoded. Mirrors CUSTODY_TOPOLOGY_RESHARE_ENVELOPE_BYTES in custody-core.
CUSTODY_TOPOLOGY_ENVELOPE_HEX = (1 + 24 + 18 + 161 + 16) * 2


class CustodyGenerationCorrupt(RuntimeError):
    """Persisted custody metadata is malformed or violates state invariants."""


class CustodyGenerationConflict(RuntimeError):
    """A requested transition conflicts with the durable recovery decision."""


class CustodyOrchestrationBusy(CustodyGenerationConflict):
    """The orchestration lock was held, so the operation never began.

    Split from its parent because the two need opposite handling. A plain
    CustodyGenerationConflict reports a durable fact -- this generation is not
    in a state that permits what was asked -- and retrying only re-derives the
    same refusal. This one reports that someone else took the lock first, so
    nothing was attempted and a retry a moment later is the right answer.

    A subclass rather than a sibling, so existing `except
    CustodyGenerationConflict` sites keep catching it.
    """


@dataclass(frozen=True)
class CustodyGenerationState:
    version: int
    phase: CustodyPhase
    active_generation: int | None
    target_generation: int | None
    previous_generation: int | None
    threshold: int
    slots: int

    @classmethod
    def empty(cls) -> CustodyGenerationState:
        return cls(
            version=CUSTODY_STATE_VERSION,
            phase="stable",
            active_generation=None,
            target_generation=None,
            previous_generation=None,
            threshold=0,
            slots=0,
        )


def _generation(value: object, field: str, *, optional: bool) -> int | None:
    if value is None and optional:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise CustodyGenerationCorrupt(f"{field} must be an integer")
    if not 1 <= value <= CUSTODY_GENERATION_MAX:
        raise CustodyGenerationCorrupt(f"{field} is outside the supported range")
    return value


def _topology(
    threshold: object, slots: object, *, allow_empty: bool
) -> tuple[int, int]:
    if isinstance(threshold, bool) or not isinstance(threshold, int):
        raise CustodyGenerationCorrupt("threshold must be an integer")
    if isinstance(slots, bool) or not isinstance(slots, int):
        raise CustodyGenerationCorrupt("slots must be an integer")
    if allow_empty and threshold == slots == 0:
        return 0, 0
    if slots < 3 or slots > 255 or threshold < 2 or threshold > slots:
        raise CustodyGenerationCorrupt("custody topology is invalid")
    return threshold, slots


def parse_custody_generation_state(raw: str) -> CustodyGenerationState:
    try:
        value = json.loads(raw)
    except (TypeError, json.JSONDecodeError) as exc:
        raise CustodyGenerationCorrupt(
            "custody generation state is not valid JSON"
        ) from exc
    expected = {
        "version",
        "phase",
        "active_generation",
        "target_generation",
        "previous_generation",
        "threshold",
        "slots",
    }
    if not isinstance(value, dict) or set(value) != expected:
        raise CustodyGenerationCorrupt("custody generation state has invalid fields")
    if value["version"] != CUSTODY_STATE_VERSION:
        raise CustodyGenerationCorrupt("unsupported custody generation state version")
    phase = value["phase"]
    if phase not in {"stable", "preparing", "committing", "resharding"}:
        raise CustodyGenerationCorrupt("custody generation phase is invalid")
    active = _generation(value["active_generation"], "active_generation", optional=True)
    target = _generation(value["target_generation"], "target_generation", optional=True)
    previous = _generation(
        value["previous_generation"], "previous_generation", optional=True
    )
    allow_empty = phase == "stable" and active is None
    threshold, slots = _topology(
        value["threshold"], value["slots"], allow_empty=allow_empty
    )

    if phase == "stable":
        if target is not None or previous is not None:
            raise CustodyGenerationCorrupt(
                "stable custody state has pending generations"
            )
    elif phase == "preparing":
        if target is None or previous is not None:
            raise CustodyGenerationCorrupt("preparing custody state is incomplete")
        if active is not None and target <= active:
            raise CustodyGenerationCorrupt("custody target generation is not newer")
    elif phase == "resharding":
        # The threshold/slots here stay the CURRENT shape, the one an aborted
        # transition returns to. The target shape lives with the deliveries,
        # because it is only real once a daemon of that shape has installed one.
        if target is None or previous is not None:
            raise CustodyGenerationCorrupt("resharding custody state is incomplete")
        if active is None:
            raise CustodyGenerationCorrupt(
                "resharding custody state has no current generation"
            )
        if target <= active:
            raise CustodyGenerationCorrupt("custody target generation is not newer")
    elif target != active or active is None:
        raise CustodyGenerationCorrupt("committing custody state has no active target")
    elif previous is not None and previous >= active:
        # The invariant is that `previous` is strictly OLDER than `active`.
        # This used to be spelled `previous == active - 1`, which additionally
        # assumed the counter is contiguous. It no longer is: the mint takes a
        # never-reset high-water mark, so after an abandon the next generation
        # skips the numbers the abandoned incarnation used, and a first commit
        # in the new incarnation supersedes nothing at all (previous is None
        # with active > 1). Contiguity was incidental; strict ordering is the
        # property that makes a crash rollback well-defined.
        raise CustodyGenerationCorrupt(
            "committing custody state has an invalid previous generation"
        )

    return CustodyGenerationState(
        version=CUSTODY_STATE_VERSION,
        phase=phase,
        active_generation=active,
        target_generation=target,
        previous_generation=previous,
        threshold=threshold,
        slots=slots,
    )


def encode_custody_generation_state(state: CustodyGenerationState) -> str:
    parsed = parse_custody_generation_state(
        json.dumps(asdict(state), separators=(",", ":"), sort_keys=True)
    )
    return json.dumps(asdict(parsed), separators=(",", ":"), sort_keys=True)


async def _lock_and_read(db: AsyncSession) -> CustodyGenerationState:
    await db.execute(
        text("SELECT pg_advisory_xact_lock(hashtext(:lock_name))"),
        {"lock_name": CUSTODY_GENERATION_LOCK},
    )
    key = custody_state_key()
    result = await db.execute(
        text("SELECT value FROM vault_config WHERE key = :key FOR UPDATE"),
        {"key": key},
    )
    row = result.fetchone()
    if row is not None:
        return parse_custody_generation_state(row.value)

    # A deployment that predates node scoping has one unscoped row, and its
    # shares are held by the only pool that existed. Claim it for this host and
    # remove the old key in the same transaction, so exactly one node can adopt
    # it and a second node starts empty rather than inheriting a generation its
    # own custodians never received.
    legacy = (
        await db.execute(
            text("SELECT value FROM vault_config WHERE key = :key FOR UPDATE"),
            {"key": CUSTODY_STATE_CONFIG_KEY},
        )
    ).fetchone()
    if legacy is None:
        return CustodyGenerationState.empty()
    state = parse_custody_generation_state(legacy.value)
    await db.execute(
        text(
            "INSERT INTO vault_config (key, value) VALUES (:key, :value) "
            "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value"
        ),
        {"key": key, "value": legacy.value},
    )
    await db.execute(
        text("DELETE FROM vault_config WHERE key = :key"),
        {"key": CUSTODY_STATE_CONFIG_KEY},
    )
    return state


async def _read_generation_high_water(db: AsyncSession) -> int:
    """Highest generation ever minted for this node. 0 when never recorded.

    A malformed row is treated as 0 rather than raising: this is a
    monotonicity floor, and refusing to mint would turn a cosmetic corruption
    into an unrecoverable vault. The mint takes max() with the LIVE generation
    too, so a lost floor can still never yield a number below one in use.
    """
    row = (
        await db.execute(
            text("SELECT value FROM vault_config WHERE key = :key FOR UPDATE"),
            {"key": custody_high_water_key()},
        )
    ).fetchone()
    if row is None:
        return 0
    try:
        value = int(row.value)
    except (TypeError, ValueError):
        log.warning("custody generation high-water mark is malformed; treating as 0")
        return 0
    return value if 0 <= value <= CUSTODY_GENERATION_MAX else 0


async def _raise_generation_high_water(db: AsyncSession, generation: int) -> None:
    """Record `generation` as reached. Never lowers an existing mark.

    The max is computed here rather than in a conditional ON CONFLICT, because
    that form has to cast the EXISTING row to bigint and Postgres does not
    guarantee the non-numeric guard short-circuits first. The caller already
    holds CUSTODY_GENERATION_LOCK and the read takes FOR UPDATE, so
    read-then-write is race-free.
    """
    current = await _read_generation_high_water(db)
    if generation <= current:
        return
    await db.execute(
        text(
            "INSERT INTO vault_config (key, value) VALUES (:key, :value) "
            "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value"
        ),
        {"key": custody_high_water_key(), "value": str(generation)},
    )


async def _write(db: AsyncSession, state: CustodyGenerationState) -> None:
    await db.execute(
        text(
            "INSERT INTO vault_config (key, value) VALUES (:key, :value) "
            "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value"
        ),
        {
            "key": custody_state_key(),
            "value": encode_custody_generation_state(state),
        },
    )


async def get_custody_generation_state(db: AsyncSession) -> CustodyGenerationState:
    """Read this host's generation, falling back to an unadopted legacy row.

    Read-only on purpose: adoption belongs to the locked path, so a boot-time
    probe never rewrites durable custody state.
    """
    for key in (custody_state_key(), CUSTODY_STATE_CONFIG_KEY):
        row = (
            await db.execute(
                text("SELECT value FROM vault_config WHERE key = :key"),
                {"key": key},
            )
        ).fetchone()
        if row is not None:
            return parse_custody_generation_state(row.value)
    return CustodyGenerationState.empty()


async def get_rust_custody_activation(db: AsyncSession) -> bool:
    """Return whether automatic Rust quorum recovery is operator-enabled."""
    result = await db.execute(
        text("SELECT value FROM vault_config WHERE key = :key"),
        {"key": CUSTODY_ACTIVATION_CONFIG_KEY},
    )
    row = result.fetchone()
    if row is None or row.value == "sealed":
        return False
    if row.value == "unsealed":
        return True
    raise CustodyGenerationCorrupt("Rust custody activation state is invalid")


async def set_rust_custody_activation(db: AsyncSession, *, unsealed: bool) -> None:
    """Persist the operator's seal decision in the caller's transaction."""
    if not isinstance(unsealed, bool):
        raise ValueError("Rust custody activation must be boolean")
    await db.execute(
        text(
            "INSERT INTO vault_config (key, value) VALUES (:key, :value) "
            "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value"
        ),
        {
            "key": CUSTODY_ACTIVATION_CONFIG_KEY,
            "value": "unsealed" if unsealed else "sealed",
        },
    )


async def begin_custody_generation(
    db: AsyncSession, *, threshold: int, slots: int
) -> CustodyGenerationState:
    """Reserve a monotonic target; commit this transaction before share prepare."""
    try:
        checked_threshold, checked_slots = _topology(
            threshold, slots, allow_empty=False
        )
    except CustodyGenerationCorrupt as exc:
        raise ValueError(str(exc)) from exc
    state = await _lock_and_read(db)
    if state.phase != "stable":
        raise CustodyGenerationConflict(
            f"custody generation transition already {state.phase}"
        )
    if state.active_generation is not None and (
        state.threshold != checked_threshold or state.slots != checked_slots
    ):
        raise CustodyGenerationConflict(
            "custodian topology change requires the later maintenance protocol"
        )
    # max() with the high-water mark, not just the live generation: abandon
    # clears active_generation, so `(active or 0) + 1` alone restarts at 1 and
    # a transport envelope captured from a previous incarnation would
    # authenticate against the reused number.
    target = (
        max(state.active_generation or 0, await _read_generation_high_water(db)) + 1
    )
    if target > CUSTODY_GENERATION_MAX:
        raise CustodyGenerationConflict("custody generation counter is exhausted")
    await _raise_generation_high_water(db, target)
    preparing = CustodyGenerationState(
        version=CUSTODY_STATE_VERSION,
        phase="preparing",
        active_generation=state.active_generation,
        target_generation=target,
        previous_generation=None,
        threshold=checked_threshold,
        slots=checked_slots,
    )
    await _write(db, preparing)
    return preparing


async def begin_custody_topology_change(
    db: AsyncSession, *, threshold: int, slots: int
) -> CustodyGenerationState:
    """Reserve a target generation for a change of SHAPE, not of polynomial.

    A same-shape target is refused here on purpose: rotating the polynomial
    inside one topology is the transactional native reshare, which prepares
    and commits inside the running daemons. This one cannot, because the
    daemons that will hold the new shares do not exist yet.
    """
    try:
        checked_threshold, checked_slots = _topology(
            threshold, slots, allow_empty=False
        )
    except CustodyGenerationCorrupt as exc:
        raise ValueError(str(exc)) from exc
    state = await _lock_and_read(db)
    if state.phase != "stable":
        raise CustodyGenerationConflict(
            f"custody generation transition already {state.phase}"
        )
    if state.active_generation is None:
        raise CustodyGenerationConflict(
            "custodian topology change requires an active Rust generation"
        )
    if state.threshold == checked_threshold and state.slots == checked_slots:
        raise CustodyGenerationConflict(
            "custodian topology change requires a different topology"
        )
    target = max(state.active_generation, await _read_generation_high_water(db)) + 1
    if target > CUSTODY_GENERATION_MAX:
        raise CustodyGenerationConflict("custody generation counter is exhausted")
    await _raise_generation_high_water(db, target)
    resharding = replace(state, phase="resharding", target_generation=target)
    await _write(db, resharding)
    return resharding


def _validate_topology_deliveries(
    deliveries: dict[int, str], slots: int
) -> list[tuple[int, str]]:
    if set(deliveries) != set(range(1, slots + 1)):
        raise ValueError("topology reshare deliveries must cover every target slot")
    validated = []
    for slot in sorted(deliveries):
        envelope = deliveries[slot]
        if (
            not isinstance(envelope, str)
            or len(envelope) != CUSTODY_TOPOLOGY_ENVELOPE_HEX
            or any(character not in "0123456789abcdef" for character in envelope)
        ):
            raise ValueError(
                f"topology reshare delivery for slot {slot} is not a custody envelope"
            )
        validated.append((slot, envelope))
    return validated


async def record_custody_topology_deliveries(
    db: AsyncSession,
    *,
    generation: int,
    threshold: int,
    slots: int,
    deliveries: dict[int, str],
) -> None:
    """Persist the coordinator's envelopes so they outlive its process.

    Recording is once-only. A second coordinator asked for the same target
    would split a DIFFERENT polynomial, and the two share sets would not
    combine; the daemons cannot detect that, so the refusal lives here.
    """
    try:
        checked_threshold, checked_slots = _topology(
            threshold, slots, allow_empty=False
        )
    except CustodyGenerationCorrupt as exc:
        raise ValueError(str(exc)) from exc
    rows = _validate_topology_deliveries(deliveries, checked_slots)
    state = await _lock_and_read(db)
    if state.phase != "resharding" or state.target_generation != generation:
        raise CustodyGenerationConflict(
            "custody topology deliveries do not match the durable transition"
        )
    if state.threshold == checked_threshold and state.slots == checked_slots:
        raise CustodyGenerationConflict(
            "custodian topology change requires a different topology"
        )
    existing = await _read_topology_deliveries(db)
    if existing is not None:
        if existing == (generation, checked_threshold, checked_slots, deliveries):
            return
        raise CustodyGenerationConflict(
            "different custody topology deliveries are already recorded"
        )
    await db.execute(
        text(
            "INSERT INTO vault_custody_topology_reshare "
            "(slot, generation, threshold, slots, envelope) "
            "VALUES (:slot, :generation, :threshold, :slots, :envelope)"
        ),
        [
            {
                "slot": slot,
                "generation": generation,
                "threshold": checked_threshold,
                "slots": checked_slots,
                "envelope": envelope,
            }
            for slot, envelope in rows
        ],
    )


async def _read_topology_deliveries(
    db: AsyncSession,
) -> tuple[int, int, int, dict[int, str]] | None:
    result = await db.execute(
        text(
            "SELECT slot, generation, threshold, slots, envelope "
            "FROM vault_custody_topology_reshare ORDER BY slot"
        )
    )
    rows = result.fetchall()
    if not rows:
        return None
    generations = {(row.generation, row.threshold, row.slots) for row in rows}
    if len(generations) != 1:
        raise CustodyGenerationCorrupt(
            "custody topology deliveries describe more than one transition"
        )
    generation, threshold, slots = generations.pop()
    deliveries = {row.slot: row.envelope for row in rows}
    try:
        _topology(threshold, slots, allow_empty=False)
        _generation(generation, "generation", optional=False)
        _validate_topology_deliveries(deliveries, slots)
    except (CustodyGenerationCorrupt, ValueError) as exc:
        raise CustodyGenerationCorrupt(
            f"custody topology deliveries are malformed: {exc}"
        ) from exc
    return generation, threshold, slots, deliveries


async def get_custody_topology_deliveries(
    db: AsyncSession,
) -> tuple[int, int, int, dict[int, str]] | None:
    """Return ``(generation, threshold, slots, {slot: envelope})`` or None."""
    return await _read_topology_deliveries(db)


async def finish_custody_topology_change(
    db: AsyncSession, generation: int, *, threshold: int, slots: int
) -> CustodyGenerationState:
    """Adopt the target shape, once every target slot holds its share."""
    try:
        checked_threshold, checked_slots = _topology(
            threshold, slots, allow_empty=False
        )
    except CustodyGenerationCorrupt as exc:
        raise ValueError(str(exc)) from exc
    state = await _lock_and_read(db)
    if (
        state.phase == "stable"
        and state.active_generation == generation
        and state.threshold == checked_threshold
        and state.slots == checked_slots
    ):
        return state
    if state.phase != "resharding" or state.target_generation != generation:
        raise CustodyGenerationConflict(
            "custody topology change is not ready to finalize"
        )
    stable = replace(
        state,
        phase="stable",
        active_generation=generation,
        target_generation=None,
        previous_generation=None,
        threshold=checked_threshold,
        slots=checked_slots,
    )
    await _write(db, stable)
    await _clear_topology_deliveries(db)
    return stable


async def abort_custody_topology_change(
    db: AsyncSession, generation: int
) -> CustodyGenerationState:
    """Drop the target and keep the current shape and generation.

    Only legitimate while no daemon of the target shape has installed
    anything. Once one has, the target is the only generation a target-shaped
    pool can reach, and the way back is the operator's environment, not this.
    """
    state = await _lock_and_read(db)
    if state.phase == "stable" and (
        state.active_generation is None or state.active_generation < generation
    ):
        await _clear_topology_deliveries(db)
        return state
    if state.phase != "resharding" or state.target_generation != generation:
        raise CustodyGenerationConflict(
            "custody topology change is not rollback-eligible"
        )
    stable = replace(state, phase="stable", target_generation=None)
    await _write(db, stable)
    await _clear_topology_deliveries(db)
    return stable


async def _clear_topology_deliveries(db: AsyncSession) -> None:
    await db.execute(text("DELETE FROM vault_custody_topology_reshare"))


async def choose_custody_generation(
    db: AsyncSession, generation: int
) -> CustodyGenerationState:
    """Choose roll-forward durably; commit before any daemon commit request."""
    state = await _lock_and_read(db)
    if (
        state.phase == "committing"
        and state.active_generation == generation
        and state.target_generation == generation
    ):
        return state
    if state.phase != "preparing" or state.target_generation != generation:
        raise CustodyGenerationConflict("custody generation is not awaiting commit")
    committing = replace(
        state,
        phase="committing",
        active_generation=generation,
        previous_generation=state.active_generation,
    )
    await _write(db, committing)
    return committing


async def abort_custody_generation(
    db: AsyncSession, generation: int
) -> CustodyGenerationState:
    """Return to stable only after every daemon rolled back the target."""
    state = await _lock_and_read(db)
    if (
        state.phase == "stable"
        and state.target_generation is None
        and (state.active_generation is None or state.active_generation < generation)
    ):
        return state
    if state.phase != "preparing" or state.target_generation != generation:
        raise CustodyGenerationConflict("custody generation is not rollback-eligible")
    stable = replace(
        state,
        phase="stable",
        target_generation=None,
        previous_generation=None,
    )
    await _write(db, stable)
    return stable


async def abandon_custody_generation(
    db: AsyncSession, generation: int
) -> CustodyGenerationState:
    """Forget a stable generation that no custodian holds any part of.

    Only the password-verified unseal path may call this, and only after
    proving that every configured slot answered and holds nothing. Below a
    surviving quorum this row is what refuses a silent rekey; once the pool
    is verifiably empty it protects nothing -- the caller's password already
    derives the very bundle the generation split. Forgetting it is what lets
    /unseal re-split after a host reboot, which with share persistence off is
    the normal state, not a disaster.

    Generation numbering restarts from the empty state. That is safe because
    the precondition is a pool holding no share of ANY generation that a
    reused number could be confused with.
    """
    state = await _lock_and_read(db)
    if state.phase == "stable" and state.active_generation is None:
        return state
    if state.phase != "stable" or state.active_generation != generation:
        raise CustodyGenerationConflict(
            "custody generation is not stable or does not match abandon"
        )
    # Record it BEFORE forgetting it. This row is the only thing that stops
    # the next mint from reusing the number an old envelope was sealed under.
    await _raise_generation_high_water(db, generation)
    empty = CustodyGenerationState.empty()
    await _write(db, empty)
    return empty


async def finish_custody_generation(
    db: AsyncSession, generation: int
) -> CustodyGenerationState:
    """Mark stable only after every daemon finalized the chosen generation."""
    state = await _lock_and_read(db)
    if state.phase == "stable" and state.active_generation == generation:
        return state
    if (
        state.phase != "committing"
        or state.active_generation != generation
        or state.target_generation != generation
    ):
        raise CustodyGenerationConflict("custody generation is not ready to finalize")
    stable = replace(
        state,
        phase="stable",
        target_generation=None,
        previous_generation=None,
    )
    await _write(db, stable)
    return stable
