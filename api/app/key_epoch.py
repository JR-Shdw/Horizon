# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Unified key-generation marker for multi-host key rotation safety.

Problem: a ``rotate-password`` or ``rotate-dek-key`` on one host re-wraps the
DB DEKs under a new generation, but every OTHER host keeps the previous keys
in RAM (autonomous-host HA, no cross-host key propagation). Stale hosts then
serve 500s and false audit-chain breaks, and a second rotation can roll the
cluster into an unrecoverable state.

``vault_config['key_epoch']`` is a single monotonic counter bumped by EVERY
key-changing operation (master-password AND dek_key rotation). Each unsealed
process records in ``vault_state.key_epoch`` the generation its in-RAM keys
belong to; the per-node fence loop (cluster_ha_loops) quarantines any process
whose RAM epoch lags the DB epoch out of ``/readiness`` until re-unseal.

This is the backstop: it does NOT propagate keys, only makes a desync
observable and fail-closed instead of silently corrupting reads. The signed
rekey envelope later rolls peers forward automatically; this epoch is the
generation marker it keys off.
"""

from __future__ import annotations

import logging

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from .crypto import decrypt_dek, dek_aad

_log = logging.getLogger("rhorizon.key_epoch")

KEY_EPOCH_CONFIG_KEY = "key_epoch"
KEY_ROTATION_LOCK = "rhorizon:cluster:key_rotation"
KEY_EPOCH_MAX = 2_147_483_647


def validate_key_epoch(epoch: int | None) -> int | None:
    """Validate an in-memory epoch against the PostgreSQL INTEGER domain."""
    if epoch is None:
        return None
    if isinstance(epoch, bool) or not isinstance(epoch, int):
        raise ValueError("key_epoch must be an integer or None")
    if not 0 <= epoch <= KEY_EPOCH_MAX:
        raise ValueError(f"key_epoch must be between 0 and {KEY_EPOCH_MAX}")
    return epoch


class KeyEpochCorrupt(Exception):
    """vault_config['key_epoch'] is present but not a valid non-negative integer.

    Should never happen. Raised by the raw reader so the stale-key WRITE FENCE
    can fail CLOSED (quarantine the host) instead of mistaking a corrupt epoch
    for "fresh install -> fence nobody". The audit hot path coerces it to 0 to
    stay writable, but logs CRITICAL.
    """

    def __init__(self, value):
        super().__init__(f"key_epoch present but invalid or unparseable: {value!r}")
        self.value = value


async def _read_key_epoch_raw(db: AsyncSession) -> int | None:
    """Parse ``vault_config['key_epoch']``: int when present+valid, None when ABSENT.

    Raises :class:`KeyEpochCorrupt` when the row is PRESENT but is not an integer
    in PostgreSQL's non-negative INTEGER range. Callers decide whether that is
    fatal (the fence, fail-closed) or coerced to 0 (the audit hot path).
    """
    r = await db.execute(
        text("SELECT value FROM vault_config WHERE key = :k"),
        {"k": KEY_EPOCH_CONFIG_KEY},
    )
    row = r.fetchone()
    if not row:
        return None
    try:
        if isinstance(row.value, bool) or not isinstance(row.value, (str, int)):
            raise ValueError
        return validate_key_epoch(int(row.value))
    except (ValueError, TypeError) as exc:
        raise KeyEpochCorrupt(row.value) from exc


async def get_key_epoch(db: AsyncSession) -> int:
    """Read the current key generation from vault_config (audit-hot-path safe).

    Returns 0 when the row is ABSENT (fresh install or a vault predating this
    marker) -- the first rotation bumps it to 1. A row that is PRESENT but
    unparseable is a should-never-happen corruption: it still returns 0 so the
    audit hot path keeps working, but logs CRITICAL. Returning 0 here does NOT
    reopen the stale-key fence: the WRITE fence reads the epoch via
    :func:`is_generation_current`, which fails CLOSED on the same corruption
    (it does not route through this coercion). Operators must treat the log as a
    fence-integrity alarm.
    """
    try:
        epoch = await _read_key_epoch_raw(db)
    except KeyEpochCorrupt as exc:
        _log.critical(
            "vault_config['key_epoch'] is present but unparseable (%r); coercing "
            "to 0 for the audit hot path. The stale-key write fence fails closed "
            "on this independently. Investigate immediately.",
            exc.value,
        )
        return 0
    return epoch or 0


async def bump_key_epoch(db: AsyncSession) -> int:
    """Atomically increment the key generation and return the new value.

    Must run inside the rotation's own transaction, BEFORE the commit that
    persists the new generation, so the epoch and the re-wrapped DEKs land
    atomically. A single SQL upsert (the ON CONFLICT row lock serializes
    concurrent bumps, so two parallel rotations can't lose an increment); an
    absent/empty value starts at 1. A non-numeric (corrupt) value makes the
    cast raise rather than silently resetting the counter.
    """
    r = await db.execute(
        text(
            "INSERT INTO vault_config (key, value) VALUES (:k, '1') "
            "ON CONFLICT (key) DO UPDATE SET value = "
            "(COALESCE(NULLIF(vault_config.value, '')::bigint, 0) + 1)::text "
            "RETURNING value"
        ),
        {"k": KEY_EPOCH_CONFIG_KEY},
    )
    epoch = validate_key_epoch(int(r.scalar()))
    assert epoch is not None
    return epoch


async def keys_match_current_data(
    db: AsyncSession, aesgcm, *, require_sample: bool = False
) -> bool:
    """Probe whether the in-RAM dek_key can unwrap the current DB DEKs.

    Both rotations re-derive the dek_key and re-wrap every ``vault_dek`` row,
    so a process holding a stale dek_key fails to decrypt them (AES-GCM tag
    mismatch). This is the ground-truth currency test, independent of the
    epoch counter -- used where the epoch a set of keys belongs to cannot be
    read off the DB directly (Shamir failover reconstructs whatever generation
    the host last split). A freshly bootstrapped vault can allow an empty probe;
    post-rotation callers set ``require_sample=True`` because no wrapped DEK row
    means there is no proof that the loaded key belongs to the persisted epoch.
    """
    r = await db.execute(text("SELECT id, encrypted_key, nonce FROM vault_dek LIMIT 1"))
    row = r.fetchone()
    if row is None:
        return not require_sample
    try:
        decrypt_dek(
            bytes(row.encrypted_key),
            bytes(row.nonce),
            None,
            aesgcm,
            dek_aad(str(row.id)),
        )
        return True
    except Exception:
        return False


async def stamp_node_generation(
    db: AsyncSession, node_uuid: str, epoch: int, *, commit: bool = True
) -> None:
    """Publish the key generation this host's MASTER currently holds in RAM.

    Called only from the master (``cluster_ha_loops`` heartbeat, gated on
    ``is_master``). Followers on the same host delegate every DEK wrap to this
    master but cannot read its in-RAM ``key_epoch`` ; they read the persisted
    ``active_key_epoch`` instead (see :func:`require_generation_current`). The
    UPDATE touches the single per-host row (PK ``node_uuid``); a 0-row update on
    a non-HA deployment (no cluster node row) is a harmless no-op.
    """
    await db.execute(
        text(
            "UPDATE vault_cluster_nodes SET active_key_epoch = :e WHERE node_uuid = :u"
        ),
        {"e": epoch, "u": node_uuid},
    )
    if commit:
        await db.commit()


async def is_generation_current(db: AsyncSession, vault) -> bool:
    """True when a DEK wrap on this host would land under the CURRENT dek_key.

    A rotation on any host bumps ``key_epoch`` and re-wraps every DEK under the
    new ``dek_key``. Until this host's master adopts that generation (in-place
    on the rotating worker, or via the rekey-envelope roll-forward, <=1 heart-
    beat), a fresh DEK wrapped here lands under the OLD ``dek_key`` and becomes
    permanently unreadable once the cluster converges.

    Master worker : it wraps locally, so its in-RAM ``key_epoch`` is ground
    truth. Follower worker : the wrap is delegated to the host master, whose
    generation it reads from ``active_key_epoch`` (stamped by the master each
    heartbeat). Returns True (allow) when no rotation has ever happened, or when
    the per-node marker is absent (non-HA single host, or a master that has not
    stamped yet) -- there is no cross-process wrap delegation to fence.
    """
    try:
        db_epoch = await _read_key_epoch_raw(db)
    except KeyEpochCorrupt:
        # Fail closed: a corrupt epoch means we cannot prove this host's keys are
        # current, so fence it (quarantine) rather than wave a key-material write
        # through under possibly-stale keys and corrupt data permanently. A
        # recoverable write outage beats silent unreadable DEKs.
        _log.critical(
            "vault_config['key_epoch'] corrupt; fencing this host's key-material "
            "writes (fail-closed) until the row is repaired."
        )
        return False
    if not db_epoch:
        return True  # absent/0 -- no rotation has ever happened, nothing stale

    if vault.is_master:
        local = vault.key_epoch
        if local is not None:
            return local >= db_epoch
        # Legacy in-RAM state predates key_epoch stamping. Do not assume current
        # keys after a DB epoch exists; prove current-DEK decryptability instead.
        aesgcm = getattr(vault, "aesgcm", None)
        if aesgcm is None:
            return False
        return await keys_match_current_data(db, aesgcm, require_sample=True)

    from .node_uuid import get_node_uuid

    r = await db.execute(
        text("SELECT active_key_epoch FROM vault_cluster_nodes WHERE node_uuid = :u"),
        {"u": get_node_uuid()},
    )
    row = r.fetchone()
    if row is None or row.active_key_epoch is None:
        return True
    return row.active_key_epoch >= db_epoch


async def require_generation_current(db: AsyncSession, vault) -> None:
    """Fence a key-material WRITE request when this host would wrap it under a
    stale generation, returning 503 + Retry-After instead of corrupting data.

    The shared transaction lock closes the check-to-wrap race with rotations:
    password and DEK-key rotations take the matching exclusive lock, so a
    writer either finishes under the old generation before rotation or checks
    again after rotation and fails closed until its local keys converge.

    The readiness fence pulls a stale host from the load balancer, but only on
    the heartbeat -- this guard closes the per-request gap so the convergence
    window can only ever yield retryable 503s, never silent corruption.
    Non-HTTP callers can use :func:`is_generation_current` when they need the
    same fence without an HTTP exception.
    """
    from fastapi import HTTPException

    lock = await db.execute(
        text("SELECT pg_try_advisory_xact_lock_shared(hashtext(:lock_name))"),
        {"lock_name": KEY_ROTATION_LOCK},
    )
    if not lock.scalar():
        raise HTTPException(
            status_code=503,
            detail="key rotation in progress; retry shortly",
            headers={"Retry-After": "1"},
        )
    if await is_generation_current(db, vault):
        return

    raise HTTPException(
        status_code=503,
        detail=(
            "key generation converging on this host; retry shortly "
            "(a rotation is propagating to this node's master)"
        ),
        headers={"Retry-After": "1"},
    )


async def resolve_reconstruct_epoch(db: AsyncSession, aesgcm) -> int:
    """Epoch to assign a master that just unsealed from reconstructed shares.

    If the reconstructed dek_key unwraps the current DEKs the keys ARE the
    current generation -> return the DB epoch. If not, the host failed over
    onto a generation that another host has already rotated past; return an
    epoch strictly below the DB value so the fence loop quarantines it instead
    of silently serving 500s. (db_epoch never reaches this branch at 0: with
    no rotation there is nothing to be stale against.)
    """
    db_epoch = await get_key_epoch(db)
    if not db_epoch:
        return 0
    if await keys_match_current_data(db, aesgcm, require_sample=True):
        return db_epoch
    return db_epoch - 1
