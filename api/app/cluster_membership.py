# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Cluster membership operator triggers.

Helpers shared between :

- ``POST /cluster/promote/{node_uuid}`` and ``/demote/{node_uuid}`` --
  primary election trigger (target a specific node) :
  ``pg_advisory_xact_lock`` cluster-wide singleton + cryptographic
  random delay [0, 1s] before the claim.
- ``POST /cluster/drain/{node_uuid}`` -- set ``ha_state='draining'`` +
  ``drain_deadline_at = NOW() + settings.cluster_drain_deadline_secs``.
- ``POST /cluster/evict/{node_uuid}`` -- set ``ha_state='evicted'`` +
  append ``node_uuid`` to ``vault_cluster_config(key='revoked_node_uuids')``.
- ``POST /cluster/unrevoke/{node_uuid}`` -- remove from the revoked
  list. Audit-tracked, admin:w-gated escape hatch for an operator mistake.

The election lock ``cluster_ha_primary_election`` is a cluster-wide
singleton (single primary per cluster). Concurrent promote/demote/drain/
evict calls serialise on it ; on contention the route layer raises 409
``cluster_op_in_flight``.

Cross-version compat : promote refuses a target whose ``cluster_version``
is below ``settings.cluster_min_compatible_version`` (bidirectional with
the JOIN-time check).
"""

from __future__ import annotations

import asyncio
import json
import logging
import secrets
from datetime import datetime, timezone

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from . import metrics as _metrics
from .audit import log_action

log = logging.getLogger("rhorizon.cluster_membership")


_REVOKED_KEY = "revoked_node_uuids"
_PRIMARY_UUID_KEY = "primary_uuid"
_PRIMARY_LEASE_KEY = "primary_lease_expires_at"

# Advisory lock serialising the revoked-list read-modify-write. Its three
# writers (evict route, auto-evict reaper, unrevoke) otherwise hold
# different locks (or none) and could lose a revocation.
_REVOKED_LOCK = "rhorizon:cluster:revoked_node_uuids"


class RevokedListError(RuntimeError):
    """revoked_node_uuids exists but is not decodable as a list.

    Raised (not returned-as-empty) so the revocation control fails CLOSED:
    a corrupt value must deny, never silently admit every node.
    """


# Election random-delay ceiling. Crypto-quality jitter avoids attacker
# bias on "who claims next". Operator triggers serialise on an advisory
# lock anyway; the delay keeps parity with the autonomous failover path.
ELECTION_RANDOM_DELAY_MAX_SECS = 1.0

PRIMARY_ELECTION_LOCK = "cluster_ha_primary_election"


# -- revoked_node_uuids list ------------------------------------------------


async def read_revoked_uuids(session: AsyncSession) -> set[str]:
    """Return the set of currently-revoked node_uuids.

    Empty set if the row does not exist yet (no evict has happened in
    the cluster's lifetime).
    """
    row = (
        await session.execute(
            text("SELECT value FROM vault_cluster_config WHERE key = :k"),
            {"k": _REVOKED_KEY},
        )
    ).fetchone()
    if row is None:
        return set()
    try:
        data = json.loads(row.value)
    except (ValueError, TypeError) as exc:
        log.error("revoked_node_uuids is not valid JSON -- failing closed")
        raise RevokedListError("revoked_node_uuids is not valid JSON") from exc
    if not isinstance(data, list):
        log.error("revoked_node_uuids is not a JSON list -- failing closed")
        raise RevokedListError("revoked_node_uuids is not a JSON list")
    return {str(u) for u in data}


async def add_revoked_uuid(
    session: AsyncSession, node_uuid: str, actor: str, ip_address: str | None = None
) -> bool:
    """Append ``node_uuid`` to revoked_node_uuids. Idempotent (no double-add).

    Returns True if the uuid was newly added, False if it was already
    present. Emits an audit row on a newly-added uuid only.
    """
    await session.execute(
        text("SELECT pg_advisory_xact_lock(hashtext(:n))"), {"n": _REVOKED_LOCK}
    )
    current = await read_revoked_uuids(session)
    if node_uuid in current:
        return False
    new_list = sorted(current | {node_uuid})
    await session.execute(
        text(
            "INSERT INTO vault_cluster_config (key, value) "
            "VALUES (:k, :v) "
            "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value"
        ),
        {"k": _REVOKED_KEY, "v": json.dumps(new_list)},
    )
    await log_action(
        session,
        actor=actor,
        action="cluster_node_revoked",
        target=node_uuid,
        detail={"revoked_count": len(new_list)},
        ip_address=ip_address,
    )
    return True


async def remove_revoked_uuid(
    session: AsyncSession, node_uuid: str, actor: str, ip_address: str | None = None
) -> bool:
    """Remove ``node_uuid`` from the revoked list. Returns True iff present.

    Audit row emitted on successful removal. Caller maps False to 404.
    """
    await session.execute(
        text("SELECT pg_advisory_xact_lock(hashtext(:n))"), {"n": _REVOKED_LOCK}
    )
    current = await read_revoked_uuids(session)
    if node_uuid not in current:
        return False
    new_list = sorted(current - {node_uuid})
    await session.execute(
        text(
            "INSERT INTO vault_cluster_config (key, value) "
            "VALUES (:k, :v) "
            "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value"
        ),
        {"k": _REVOKED_KEY, "v": json.dumps(new_list)},
    )
    await log_action(
        session,
        actor=actor,
        action="cluster_node_unrevoked",
        target=node_uuid,
        detail={"revoked_count": len(new_list)},
        ip_address=ip_address,
    )
    return True


async def is_revoked(session: AsyncSession, node_uuid: str) -> bool:
    """Convenience predicate for the /cluster/join revoke-check path."""
    revoked = await read_revoked_uuids(session)
    return node_uuid in revoked


# -- primary_uuid scalar ---------------------------------------------------


async def read_primary_uuid(session: AsyncSession) -> str | None:
    """Return the current primary's node_uuid, or None if unset."""
    row = (
        await session.execute(
            text("SELECT value FROM vault_cluster_config WHERE key = :k"),
            {"k": _PRIMARY_UUID_KEY},
        )
    ).fetchone()
    if row is None:
        return None
    return row.value or None


async def read_canonical_primary(
    session: AsyncSession,
) -> tuple[str | None, datetime | None]:
    """Return (primary_uuid, primary_lease_expires_at) in one round-trip.

    Centralises the two ``vault_cluster_config`` reads used by both the
    auto-promote eligibility cascade and the per-host self-demote check
    (split-brain detection : ex-primary that observes a canonical primary
    elsewhere with a fresh lease).

    Either component may be None independently :

    - ``primary_uuid is None`` : pre-cluster-init state, no primary has
      ever been elected.
    - ``lease_expires_at is None`` : either the lease row is absent
      (pre-auto-promote-v1 cluster) or its value is not parseable as
      ISO-8601 (logged at WARNING ; caller treats as no signal).

    Returned datetime is always tz-aware UTC ; a naive value found in
    storage is defensively re-tagged.
    """
    rows = (
        await session.execute(
            text(
                "SELECT key, value FROM vault_cluster_config "
                "WHERE key IN (:k_uuid, :k_lease)"
            ),
            {"k_uuid": _PRIMARY_UUID_KEY, "k_lease": _PRIMARY_LEASE_KEY},
        )
    ).fetchall()
    by_key = {r.key: r.value for r in rows}

    primary_uuid: str | None = by_key.get(_PRIMARY_UUID_KEY) or None

    lease_raw = by_key.get(_PRIMARY_LEASE_KEY)
    lease_dt: datetime | None = None
    if lease_raw is not None:
        try:
            lease_dt = datetime.fromisoformat(lease_raw)
        except (TypeError, ValueError):
            log.warning(
                "primary_lease_expires_at has invalid ISO-8601 value : %r",
                lease_raw,
            )
            lease_dt = None
        else:
            if lease_dt.tzinfo is None:
                lease_dt = lease_dt.replace(tzinfo=timezone.utc)

    return primary_uuid, lease_dt


async def set_primary_uuid(session: AsyncSession, node_uuid: str | None) -> None:
    """Update primary_uuid in vault_cluster_config.

    None clears the row (DELETE) -- used when demoting the current
    primary without electing a replacement in the same transaction.
    """
    if node_uuid is None:
        await session.execute(
            text("DELETE FROM vault_cluster_config WHERE key = :k"),
            {"k": _PRIMARY_UUID_KEY},
        )
    else:
        await session.execute(
            text(
                "INSERT INTO vault_cluster_config (key, value) "
                "VALUES (:k, :v) "
                "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value"
            ),
            {"k": _PRIMARY_UUID_KEY, "v": node_uuid},
        )


# -- election random delay -------------------------------------------------


async def election_random_delay() -> float:
    """Sleep [0, 1s] before claiming the primary role.

    Crypto-quality randomness (``secrets.randbelow``) -- an observer
    cannot predict which node will claim first under contention.

    Returns the slept duration in seconds (for test assertions).
    """
    delay_ms = secrets.randbelow(int(ELECTION_RANDOM_DELAY_MAX_SECS * 1000) + 1)
    delay = delay_ms / 1000.0
    await asyncio.sleep(delay)
    return delay


# -- atomic state transition helper ---------------------------------------


async def transition_node(
    session: AsyncSession,
    node_uuid: str,
    from_state: str | None,
    to_state: str,
    set_drain_deadline_secs: int | None = None,
    clear_drain_deadline: bool = False,
) -> bool:
    """Atomically transition a node's ha_state, optionally setting the deadline.

    Returns True if exactly one row was updated. False means the row's
    ``ha_state`` did not match ``from_state`` (concurrent transition or
    unknown node_uuid).

    ``from_state=None`` skips the source-state guard (used for
    quarantine-bypass admin promotes).
    """
    params: dict[str, object] = {"u": node_uuid, "to": to_state}
    # role_changed_at feeds the auto-promote demotion cooldown: a node
    # can't re-enter the election pool until it has dwelt in its new state
    # for cluster_auto_promote_cooldown_secs. Stamped on every transition.
    set_clause = ["ha_state = :to", "role_changed_at = NOW()"]
    where_clause = ["node_uuid = :u"]

    if from_state is not None:
        where_clause.append("ha_state = :from")
        params["from"] = from_state

    if set_drain_deadline_secs is not None:
        set_clause.append("drain_deadline_at = NOW() + make_interval(secs => :dd)")
        params["dd"] = set_drain_deadline_secs
    elif clear_drain_deadline:
        set_clause.append("drain_deadline_at = NULL")

    sql = (
        f"UPDATE vault_cluster_nodes "
        f"SET {', '.join(set_clause)} "
        f"WHERE {' AND '.join(where_clause)} "
        f"RETURNING node_uuid"
    )
    result = await session.execute(text(sql), params)
    row = result.fetchone()
    if row is None:
        return False
    if from_state is not None:
        _metrics.cluster_state_transitions.labels(
            from_state=from_state, to_state=to_state
        ).inc()
    return True


async def promote_node_singleton(
    session: AsyncSession,
    node_uuid: str,
    from_state: str = "secondary",
) -> tuple[bool, list[str]]:
    """Promote one node while atomically demoting every other primary row.

    The caller must hold :data:`PRIMARY_ELECTION_LOCK`.  Locking the target row
    first makes the source-state check stable, then every stale/previous primary
    is demoted *before* the target is promoted.  That ordering is compatible
    with the database's partial unique index on ``ha_state='primary'`` and
    closes the recovery window where both the returning old node and the newly
    elected survivor were observable as primary.

    Returns ``(False, [])`` if the target no longer has ``from_state``.
    Otherwise returns ``(True, demoted_uuids)``.
    """
    target = (
        await session.execute(
            text(
                "SELECT ha_state FROM vault_cluster_nodes "
                "WHERE node_uuid = :u FOR UPDATE"
            ),
            {"u": node_uuid},
        )
    ).fetchone()
    if target is None or target.ha_state != from_state:
        return False, []

    demoted_result = await session.execute(
        text(
            "UPDATE vault_cluster_nodes "
            "SET ha_state = 'secondary', role_changed_at = NOW() "
            "WHERE node_uuid != :u AND ha_state = 'primary' "
            "RETURNING node_uuid"
        ),
        {"u": node_uuid},
    )
    demoted = [row.node_uuid for row in demoted_result.fetchall()]
    if demoted:
        _metrics.cluster_state_transitions.labels(
            from_state="primary", to_state="secondary"
        ).inc(len(demoted))

    promoted = await transition_node(
        session,
        node_uuid,
        from_state=from_state,
        to_state="primary",
    )
    if not promoted:  # target is row-locked; this is a database invariant fault
        raise RuntimeError(f"locked election target disappeared: {node_uuid}")
    return True, demoted
