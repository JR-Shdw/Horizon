# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Background loops for the inter-host HA cluster.

Three asyncio tasks registered from the lifespan when
``settings.cluster_ha_enabled`` is true :

- ``cluster_ha_state_machine_loop`` (cluster-wide singleton via
  ``with_cluster_lock('cluster_ha_state_machine', ...)``) flips
  ``vault_cluster_nodes`` rows from ``ha_state='joining'`` to
  ``'secondary'`` once their ``quarantine_until`` has elapsed AND a
  fresh ``last_heartbeat`` proves the joiner is still alive.

- ``cluster_ha_reaper_loop`` (cluster-wide singleton via
  ``with_cluster_lock('cluster_ha_reaper', ...)``) deletes rows
  stuck in ``ha_state='joining'`` past
  ``cluster_joining_orphan_ttl_secs`` (JOIN request crashed
  mid-flight, orphan row would otherwise leak forever).

- ``cluster_ha_heartbeat_loop`` (per-node, NOT a singleton) writes
  ``last_heartbeat = NOW()`` on the row owned by this container's
  ``node_uuid``. No advisory lock -- each node touches its own row.
  Decoupled from the state-machine loop on purpose : if the state
  machine is wedged (DB contention, deadlock applicative), the
  heartbeat still produces a liveness signal that ops can
  distinguish from "process gone".

All three loops are no-ops when ``vault_state.sealed`` is true. The
heartbeat additionally short-circuits when no row exists for the
local ``node_uuid`` (pre-cluster-init or pre-/cluster/join state).
"""

import asyncio
import logging
import os
import secrets
import time
from datetime import datetime, timedelta, timezone

from rhorizon_crypto import secure_zero
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from . import cluster_ca, cluster_membership
from . import metrics as _metrics
from .audit import log_action
from .cluster import with_cluster_lock
from .cluster_rekey import consume_envelope, delete_consumed_row, publish_envelope
from .config import settings
from .database import async_session
from .key_epoch import get_key_epoch, keys_match_current_data, stamp_node_generation
from .node_uuid import NodeUUIDError, get_node_uuid
from .vault_state import vault as vs

log = logging.getLogger("rhorizon.cluster_ha_loops")


# -- state machine ---------------------------------------------------------


async def _state_machine_body(db: AsyncSession) -> int:
    """Flip eligible ``joining`` rows + maybe auto-promote. Returns total.

    Two independent operations executed in sequence :

    1. **joining -> secondary** flip. Eligibility :
       - ``ha_state = 'joining'``
       - ``quarantine_until <= NOW()`` (quarantine window has elapsed)
       - ``last_heartbeat`` is recent : the joiner has touched its own
         row within ``3 * cluster_heartbeat_interval_secs``. A node
         that stops heartbeating during quarantine is treated as dead
         and left in ``joining`` -- the reaper will eventually purge.

    2. **auto-promote on stale lease**.
       Reads ``vault_cluster_config('primary_lease_expires_at')`` ;
       if the lease has expired beyond the skew window AND self is an
       eligible secondary with a fresh heartbeat, attempts to claim
       primary under ``PRIMARY_ELECTION_LOCK``. See
       :func:`_maybe_auto_promote` for the full guard cascade.

    The two operations are independent : the joining-flip commits its
    own UPDATE+RETURNING tx, the auto-promote acquires its own
    advisory lock in a fresh tx. Failure of one does not block the
    other (a sticky orphan in 'joining' should not gate failover).
    """
    # Tolerance window : 3x the heartbeat interval. Picks up the
    # "two missed heartbeats + 1 grace" pattern that maps onto the
    # standard 3-tick liveness convention.
    liveness_window_secs = settings.cluster_heartbeat_interval_secs * 3
    result = await db.execute(
        text(
            "UPDATE vault_cluster_nodes "
            "SET ha_state = 'secondary', role_changed_at = NOW() "
            "WHERE ha_state = 'joining' "
            "  AND quarantine_until IS NOT NULL "
            "  AND quarantine_until <= NOW() "
            "  AND last_heartbeat IS NOT NULL "
            "  AND last_heartbeat > NOW() - "
            "      make_interval(secs => :w) "
            "RETURNING node_uuid"
        ),
        {"w": liveness_window_secs},
    )
    promoted = result.fetchall()
    if promoted:
        await db.commit()
        _metrics.cluster_state_transitions.labels(
            from_state="joining", to_state="secondary"
        ).inc(len(promoted))
        log.info(
            "cluster_ha_state_machine: promoted %d node(s) joining -> secondary",
            len(promoted),
        )

    elected = await _maybe_auto_promote(db)

    return len(promoted) + elected


# -- auto-promote ----------------------------------------------------------


async def _maybe_auto_promote(db: AsyncSession) -> int:
    """Attempt to claim primary if the lease is stale and self is eligible.

    Returns 1 if this node was elected primary, 0 in every other case
    (lease still fresh, self ineligible, lock contended, or someone
    else won under the lock). Idempotent and safe to call repeatedly :
    each guard short-circuits cleanly before any mutation.

    Guard cascade (in order ; each gate skips silently on miss) :

    1. self != current primary (avoid self-vote when already primary)
    2. lease row exists and is parseable
    3. NOW() > lease_expires_at + skew (skew = ttl // 3)
    4. self row exists, ha_state == 'secondary', heartbeat fresh
    5. random jitter [0, ttl/6 / weight] secs (anti-thundering-herd)
    6. ``pg_try_advisory_xact_lock(PRIMARY_ELECTION_LOCK)`` acquired
    7. re-check lease + primary_uuid under the lock (snapshot may have
       moved while we slept on the jitter ; an honest primary that
       re-extended its lease in between wins)
    8. demote every old/stale primary + promote self with
       ``promote_node_singleton`` + ``set_primary_uuid`` + reset lease +
       audit row, all in the same tx
    9. commit -> lock released

    A failure at any gate after step 5 still releases the advisory
    lock on the next commit (``with_cluster_lock`` semantics). The
    tx is empty in that case ; commit is a no-op other than releasing
    the lock.
    """
    try:
        node_uuid = get_node_uuid()
    except NodeUUIDError:
        # Pre-init state -- no on-disk node UUID yet. The state-machine
        # loop wrapper only ever fires when ``vs.sealed`` is False, but
        # the body itself is also exercised directly by the
        # joining-flip unit tests which never touch get_node_uuid().
        # Skipping silently keeps both call sites correct.
        return 0

    # 1-3. Already primary, no lease, or lease still fresh -- skip.
    current_primary, lease_dt = await cluster_membership.read_canonical_primary(db)
    if current_primary == node_uuid:
        return 0
    if lease_dt is None:
        return 0
    ttl_secs = settings.cluster_primary_lease_ttl_secs
    skew_secs = ttl_secs / 3.0
    now = datetime.now(timezone.utc)
    if now < lease_dt + timedelta(seconds=skew_secs):
        return 0

    # 4. Self eligibility : secondary with a fresh heartbeat.
    self_row = (
        await db.execute(
            text(
                "SELECT ha_state, last_heartbeat, role_changed_at "
                "FROM vault_cluster_nodes WHERE node_uuid = :u"
            ),
            {"u": node_uuid},
        )
    ).fetchone()
    if self_row is None or self_row.ha_state != "secondary":
        return 0
    if self_row.last_heartbeat is None:
        return 0
    last_hb = self_row.last_heartbeat
    if last_hb.tzinfo is None:
        last_hb = last_hb.replace(tzinfo=timezone.utc)
    liveness_window_secs = settings.cluster_heartbeat_interval_secs * 3
    if (now - last_hb).total_seconds() > liveness_window_secs:
        return 0

    # 4b. Demotion cooldown (anti-thrash). A node that changed ha_state
    # within cluster_auto_promote_cooldown_secs is held out of the
    # election pool : a returning ex-primary lands directly in 'secondary'
    # (no quarantine) and must dwell before it can re-claim primary, so a
    # flapping link cannot ping-pong the role. role_changed_at NULL
    # (pre-migration rows, the /cluster/init primary that never
    # transitioned) means "no cooldown" -- eligible. Other healthy
    # secondaries, whose role_changed_at is old, are unaffected and fail
    # over immediately.
    cooldown_secs = settings.cluster_auto_promote_cooldown_secs
    role_changed_at = self_row.role_changed_at
    if cooldown_secs > 0 and role_changed_at is not None:
        if role_changed_at.tzinfo is None:
            role_changed_at = role_changed_at.replace(tzinfo=timezone.utc)
        if (now - role_changed_at).total_seconds() < cooldown_secs:
            return 0

    # 5. Weighted jitter. operator_weight scales the local jitter
    # ceiling : a higher weight = earlier attempt. Crypto-quality
    # randomness mirrors cluster_membership.election_random_delay.
    weight = max(settings.cluster_operator_weight, 0.01)
    jitter_ceiling_ms = max(1, int((ttl_secs * 1000.0 / 6.0) / weight))
    jitter_ms = secrets.randbelow(jitter_ceiling_ms + 1)
    await asyncio.sleep(jitter_ms / 1000.0)

    # 6-9. Acquire PRIMARY_ELECTION_LOCK + run the claim body.
    election_result: dict[str, int] = {"elected": 0}

    async def _election_body() -> None:
        # 7. Re-read under lock : the snapshot may have moved while we
        # slept on the jitter. An honest primary that re-extended its
        # lease in between wins ; we back off cleanly.
        (
            primary_under_lock,
            lease_under_lock,
        ) = await cluster_membership.read_canonical_primary(db)
        if primary_under_lock == node_uuid:
            return  # Defensive : a concurrent path won us (e.g. operator
            #          /promote called targeting self between guard and lock).
        now_under_lock = datetime.now(timezone.utc)
        if (
            lease_under_lock is not None
            and now_under_lock < lease_under_lock + timedelta(seconds=skew_secs)
        ):
            return  # Old primary refreshed its lease in the gap ; back off.

        # 8. Atomic singleton promote.  Demote all previous/stale primary
        # rows in this transaction rather than waiting for each returning
        # host's heartbeat self-demotion.
        flipped, demoted_primaries = await cluster_membership.promote_node_singleton(
            db,
            node_uuid,
            from_state="secondary",
        )
        if not flipped:
            return  # Concurrent transition won the row.

        await cluster_membership.set_primary_uuid(db, node_uuid)
        now_iso = now_under_lock.isoformat()
        new_lease_iso = (now_under_lock + timedelta(seconds=ttl_secs)).isoformat()
        await db.execute(
            text(
                "INSERT INTO vault_cluster_config (key, value) "
                "VALUES ('primary_since', :v) "
                "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value"
            ),
            {"v": now_iso},
        )
        await db.execute(
            text(
                "INSERT INTO vault_cluster_config (key, value) "
                "VALUES ('primary_lease_expires_at', :v) "
                "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value"
            ),
            {"v": new_lease_iso},
        )
        await log_action(
            db,
            actor="auto-promote",
            action="cluster_primary_auto_elected",
            target=node_uuid,
            detail={
                "prev_primary": primary_under_lock,
                "demoted_primary_uuids": demoted_primaries,
                "lease_expired_at": lease_dt.isoformat(),
                "operator_weight": weight,
            },
            ip_address=None,
        )
        election_result["elected"] = 1

    acquired = await with_cluster_lock(
        db, cluster_membership.PRIMARY_ELECTION_LOCK, _election_body
    )
    await db.commit()  # release advisory lock (idempotent when not acquired)

    if not acquired:
        return 0
    elected = election_result["elected"]
    if elected:
        log.info(
            "cluster_ha_state_machine: auto-elected primary node=%s "
            "(prev=%s lease_expired_at=%s)",
            node_uuid,
            current_primary,
            lease_dt.isoformat(),
        )
    return elected


async def cluster_ha_state_machine_loop():  # pragma: no cover  (daemon loop)
    """Singleton cluster-wide state-machine loop."""
    interval = settings.cluster_state_machine_interval_secs
    while True:
        await asyncio.sleep(interval)
        try:
            if vs.sealed:
                continue
            async with async_session() as db:

                async def _body():
                    await _state_machine_body(db)

                acquired = await with_cluster_lock(
                    db, "cluster_ha_state_machine", _body
                )
                await db.commit()  # release advisory lock
            if not acquired:
                log.debug("cluster_ha_state_machine: another host holds the lock")
        except Exception:
            log.warning("cluster_ha_state_machine_loop error", exc_info=True)


# -- reaper ---------------------------------------------------------------


async def _reaper_body(db: AsyncSession) -> int:
    """Reap orphans + finish drains + close CA grace. Returns total count.

    Three operations, all idempotent and singleton-locked at the caller :

    1. **joining orphans** -- DELETE rows stuck in
       ``ha_state='joining'`` past ``cluster_joining_orphan_ttl_secs``.
       Counter ``cluster_nodes_reaped_total{reason=joining_orphan}``.

    2. **drain deadline expiry** -- UPDATE rows in
       ``ha_state='draining'`` whose ``drain_deadline_at`` is now past
       to ``ha_state='evicted'`` + APPEND ``node_uuid`` to
       ``revoked_node_uuids``. Counter
       ``cluster_nodes_reaped_total{reason=drain_deadline_expired}``
       + ``cluster_state_transitions_total{from=draining,to=evicted}``.
       Each evicted row emits a ``cluster_node_drain_expired`` audit
       row attributed to ``actor='reaper'``.

    3. **CA grace window close** -- if
       ``cluster_ca_cert_prev`` is set, drop it once either
       (a) every active node has ``force_renew_at IS NULL`` (the
       renewal loops have all picked up new certs under the new CA),
       or (b) ``NOW - cluster_ca_rotated_at > cluster_ca_grace_window_secs``.
       Audit ``cluster_ca_grace_dropped{reason=all_rotated|grace_expired}``
       + bump ``cluster_ca_grace_drops_total{reason}``.

    Operation order : drain expiry first (more specific transition than
    joining-orphan), then joining-orphan, then CA grace. The CA grace
    op queries ``vault_cluster_nodes`` for the all-rotated predicate,
    so running it after the previous two ensures any rows the reaper
    just evicted are excluded from the active count.
    """
    drained = await _reap_drained_past_deadline(db)

    ttl = settings.cluster_joining_orphan_ttl_secs
    result = await db.execute(
        text(
            "DELETE FROM vault_cluster_nodes "
            "WHERE ha_state = 'joining' "
            "  AND joined_at < NOW() - make_interval(secs => :ttl) "
            "RETURNING node_uuid"
        ),
        {"ttl": ttl},
    )
    reaped = result.fetchall()
    if reaped:
        await db.commit()
        _metrics.cluster_nodes_reaped.labels(reason="joining_orphan").inc(len(reaped))
        log.info(
            "cluster_ha_reaper: purged %d joining-orphan row(s) (TTL %ds)",
            len(reaped),
            ttl,
        )

    ca_dropped = await _reap_ca_grace(db)

    return drained + len(reaped) + ca_dropped


async def _reap_drained_past_deadline(db: AsyncSession) -> int:
    """Bascule draining -> evicted past drain_deadline_at. Returns the count.

    Reads the candidate rows first (a single
    SELECT) so we can emit per-row audit + revoked_node_uuids appends
    in the same transaction as the UPDATE. Single-transaction commit
    keeps the counter, the audit chain, and the revoked list in sync.
    """
    candidates = (
        await db.execute(
            text(
                "SELECT node_uuid "
                "FROM vault_cluster_nodes "
                "WHERE ha_state = 'draining' "
                "  AND drain_deadline_at IS NOT NULL "
                "  AND drain_deadline_at < NOW()"
            )
        )
    ).fetchall()
    if not candidates:
        return 0

    evicted_count = 0
    for row in candidates:
        node_uuid = row.node_uuid
        flipped = await cluster_membership.transition_node(
            db,
            node_uuid,
            from_state="draining",
            to_state="evicted",
            clear_drain_deadline=True,
        )
        if not flipped:
            # Concurrent transition (operator promoted/evicted while
            # the reaper was iterating). Skip silently -- the next
            # tick will pick up whatever still matches.
            continue
        await cluster_membership.add_revoked_uuid(
            db, node_uuid, actor="reaper", ip_address=None
        )
        await log_action(
            db,
            actor="reaper",
            action="cluster_node_drain_expired",
            target=node_uuid,
            detail={},
            ip_address=None,
        )
        evicted_count += 1

    if evicted_count:
        await db.commit()
        _metrics.cluster_nodes_reaped.labels(reason="drain_deadline_expired").inc(
            evicted_count
        )
        log.info(
            "cluster_ha_reaper: bascule %d draining row(s) -> evicted (expired)",
            evicted_count,
        )
    return evicted_count


async def _reap_ca_grace(db: AsyncSession) -> int:
    """Close the CA rotation grace window. Returns 1 iff dropped.

    Hybrid drop trigger -- the reaper closes the grace window via the
    earlier of two predicates :

    A. **All-nodes-rotated** (fast path) : every non-evicted /
       non-draining membership row has ``force_renew_at IS NULL``.
       The renewal loop clears this flag immediately after a
       successful refresh-cert, so an all-NULL state means every node
       picked up a fresh cert under the new CA. Vault_cluster_nodes
       with ha_state IN ('evicted','draining') are excluded -- evicted
       rows will never refresh again, draining rows are on their way
       to evicted, neither is load-bearing for grace validity. A node
       that is ``joining`` and not yet bound to a cert IS included :
       its force_renew_at starts NULL (just-inserted row), so it
       trivially satisfies the predicate without holding the grace
       open.

    B. **Grace expired** (time fallback) : ``NOW - cluster_ca_rotated_at``
       exceeds ``cluster_ca_grace_window_secs``. Audit row carries
       reason=grace_expired ; operations team should investigate which
       nodes failed to refresh (logs of the per-node renewal loops).

    Both predicates short-circuit the grace window safely : path A
    means no node still needs the prev CA, path B means we waited long
    enough that any node still on the prev CA is at fault.

    The drop itself is a single DELETE of two rows (cert_prev +
    rotated_at). No-op idempotent if cluster_ca_cert_prev was already
    dropped between the predicate check and the DELETE (rare race
    between concurrent reaper invocations -- caller is singleton-locked
    so this is mostly a no-op safety net).
    """
    if not await cluster_ca.has_active_rotation(db):
        return 0

    rotated_at = await cluster_ca.get_rotated_at(db)
    grace_window = settings.cluster_ca_grace_window_secs
    now = datetime.now(timezone.utc)
    grace_expired = (
        rotated_at is not None and (now - rotated_at).total_seconds() > grace_window
    )

    # Path A : count rows that still hold force_renew_at, scoped to
    # the "actively serving" subset (primary, secondary, joining ;
    # not draining or evicted).
    row = (
        await db.execute(
            text(
                "SELECT COUNT(*) AS n FROM vault_cluster_nodes "
                "WHERE ha_state NOT IN ('evicted','draining') "
                "  AND force_renew_at IS NOT NULL"
            )
        )
    ).fetchone()
    pending = int(row.n) if row is not None else 0
    all_rotated = pending == 0

    if not all_rotated and not grace_expired:
        return 0

    reason = "all_rotated" if all_rotated else "grace_expired"

    # Collect lagging nodes BEFORE the drop so the audit row can list
    # them under reason=grace_expired (path B). Path A : the list is
    # empty by predicate.
    lagging: list[str] = []
    if reason == "grace_expired":
        rows = (
            await db.execute(
                text(
                    "SELECT node_uuid FROM vault_cluster_nodes "
                    "WHERE ha_state NOT IN ('evicted','draining') "
                    "  AND force_renew_at IS NOT NULL"
                )
            )
        ).fetchall()
        lagging = [r.node_uuid for r in rows]

    dropped = await cluster_ca.drop_cluster_ca_prev(db)
    if not dropped:
        # Concurrent reaper already dropped -- no-op.
        return 0

    await log_action(
        db,
        actor="reaper",
        action="cluster_ca_grace_dropped",
        target="cluster",
        detail={"reason": reason, "lagging_nodes": lagging},
        ip_address=None,
    )
    await db.commit()
    _metrics.cluster_ca_grace_drops.labels(reason=reason).inc()
    log.info(
        "cluster_ha_reaper: dropped cluster_ca_cert_prev (reason=%s, lagging=%d)",
        reason,
        len(lagging),
    )
    return 1


async def cluster_ha_reaper_loop():  # pragma: no cover  (daemon loop)
    """Singleton cluster-wide reaper loop."""
    interval = settings.cluster_reaper_interval_secs
    while True:
        await asyncio.sleep(interval)
        try:
            if vs.sealed:
                continue
            async with async_session() as db:

                async def _body():
                    await _reaper_body(db)

                acquired = await with_cluster_lock(db, "cluster_ha_reaper", _body)
                await db.commit()  # release advisory lock
            if not acquired:
                log.debug("cluster_ha_reaper: another host holds the lock")
        except Exception:
            log.warning("cluster_ha_reaper_loop error", exc_info=True)


# -- per-node heartbeat ---------------------------------------------------


async def _heartbeat_body(db: AsyncSession, node_uuid: str) -> bool:
    """Touch ``last_heartbeat`` on our own row. Returns True iff updated.

    Skips silently when no row exists for this ``node_uuid`` -- the
    container has not yet been registered via ``/cluster/init`` or
    ``/cluster/join``. Pre-cluster-init state is normal, not a fault.

    Auto-promote : if this node is the current
    cluster primary (vault_cluster_config('primary_uuid') == us), the
    heartbeat ALSO extends ``primary_lease_expires_at`` in the same
    transaction. The lease is the autonomous failover signal read by
    every secondary's state-machine loop ; co-locating the lease write
    with the heartbeat guarantees a fresh lease never lags behind a
    successful liveness signal. If the heartbeat task wedges, the lease
    naturally expires within ``cluster_primary_lease_ttl_secs`` and an
    eligible secondary auto-promotes.

    Split-brain self-demote : if our
    row still claims ``ha_state='primary'`` but the canonical
    ``primary_uuid`` points elsewhere with a fresh lease, we lost the
    election while down (typical : kill -9 + restart after the auto-
    promote window). Transition self ``primary -> secondary`` in this
    same heartbeat tick and emit a ``cluster_primary_self_demoted`` audit
    row. The state-machine loop runs cluster-wide-singleton, so the lock
    holder is usually NOT the ex-primary -- the per-host heartbeat is
    the only loop guaranteed to fire on the ex-primary itself. Recovery
    is bounded by one heartbeat interval.
    """
    result = await db.execute(
        text(
            "UPDATE vault_cluster_nodes "
            "SET last_heartbeat = NOW() "
            "WHERE node_uuid = :u "
            "RETURNING node_uuid, ha_state"
        ),
        {"u": node_uuid},
    )
    row = result.fetchone()
    if row is None:
        return False

    # Initial releases registered the node that called /cluster/init under a
    # reserved 192.0.2.1 placeholder.  Once an installer supplies the stable
    # inventory address, make membership authoritative and request a new cert
    # whose IP SAN matches it.  A savepoint contains a duplicate-IP operator
    # error: liveness and lease renewal must continue even when two nodes were
    # accidentally configured with the same address.
    advertise_ip = settings.cluster_advertise_ip
    certificate_renewal_requested = False
    if advertise_ip:
        try:
            async with db.begin_nested():
                changed = await db.execute(
                    text(
                        "UPDATE vault_cluster_nodes "
                        "SET source_ip = CAST(:ip AS INET), force_renew_at = NOW() "
                        "WHERE node_uuid = :u "
                        "  AND source_ip IS DISTINCT FROM CAST(:ip AS INET) "
                        "RETURNING node_uuid"
                    ),
                    {"u": node_uuid, "ip": advertise_ip},
                )
                if changed.fetchone() is not None:
                    certificate_renewal_requested = True
                    log.warning(
                        "cluster heartbeat reconciled node %s advertised IP to %s; "
                        "certificate renewal requested",
                        node_uuid,
                        advertise_ip,
                    )
        except IntegrityError:
            log.error(
                "cluster heartbeat cannot advertise %s for node %s: the address "
                "belongs to another active node; heartbeat remains operational",
                advertise_ip,
                node_uuid,
            )

    primary_uuid, lease_dt = await cluster_membership.read_canonical_primary(db)
    now = datetime.now(timezone.utc)
    if primary_uuid == node_uuid:
        ttl_secs = settings.cluster_primary_lease_ttl_secs
        lease_expires_iso = (now + timedelta(seconds=ttl_secs)).isoformat()
        await db.execute(
            text(
                "INSERT INTO vault_cluster_config (key, value) "
                "VALUES ('primary_lease_expires_at', :v) "
                "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value"
            ),
            {"v": lease_expires_iso},
        )
    elif (
        row.ha_state == "primary"
        and primary_uuid is not None
        and lease_dt is not None
        and now < lease_dt
    ):
        # Our row says primary, but the cluster's canonical primary is
        # someone else holding a fresh lease. We are an ex-primary that
        # came back after kill -9 + restart and missed the election.
        flipped = await cluster_membership.transition_node(
            db,
            node_uuid,
            from_state="primary",
            to_state="secondary",
        )
        if flipped:
            await log_action(
                db,
                actor="self-demote",
                action="cluster_primary_self_demoted",
                target=node_uuid,
                detail={
                    "reason": "lost_lease",
                    "canonical_primary": primary_uuid,
                    "lease_expires": lease_dt.isoformat(),
                },
                ip_address=None,
            )
            log.warning(
                "cluster_ha_heartbeat: self-demoted primary -> secondary "
                "(canonical=%s lease_expires=%s)",
                primary_uuid,
                lease_dt.isoformat(),
            )

    await db.commit()
    if certificate_renewal_requested:
        # Wake this worker's per-node renewal loop only after membership is
        # committed; refresh-cert must mint from the newly visible source_ip.
        from . import cluster_cert_renewal

        cluster_cert_renewal.request_renewal()
    return True


async def _publish_rekey_pub(
    db: AsyncSession, node_uuid: str, pub: bytes, commit: bool = True
) -> bool:
    """Publish this node's X25519 rekey pubkey to its membership row.

    Writes only when the stored value differs (``IS DISTINCT FROM``) so the
    per-second heartbeat does not churn the row. Returns True if a write
    happened. ``commit=False`` lets the caller batch this into a larger txn
    (the roll-forward path republishes the regenerated key alongside the row
    teardown in one commit).
    """
    res = await db.execute(
        text(
            "UPDATE vault_cluster_nodes SET rekey_pub = :p "
            "WHERE node_uuid = :u AND rekey_pub IS DISTINCT FROM :p"
        ),
        {"p": pub, "u": node_uuid},
    )
    changed = bool(res.rowcount)
    if changed and commit:
        await db.commit()
    return changed


async def _rekey_roll_forward_body(db: AsyncSession, node_uuid: str) -> str | None:
    """S2 rekey roll-forward -- adopt the signed envelope when our keys lag.

    Runs on the heartbeat BEFORE the fence and only on the key-holding master
    (followers delegate crypto and hold no keys). Two responsibilities :

    1. Keep this node's ``rekey_pub`` published so the next rotation can seal a
       roll-forward envelope to us.
    2. When our in-RAM generation lags the DB and a verified envelope exists,
       adopt the new key bundle in place -- mirroring the failover tail
       (stop master services -> seal -> unseal(new) -> restart = re-split
       Shamir on the new generation + fresh RPC so this host's followers
       re-fetch). On success we are current and the fence leaves us alone; on
       absence/rejection we fall through to the fence (quarantine).

    Returns ``"rolled_forward"`` on a successful adoption, else None.
    """
    if vs.sealed or not vs.is_master:
        return None

    # 1. Ensure + publish our rekey pubkey (idempotent ; stable across rotations).
    pub = vs.ensure_rekey_keypair()
    if pub is not None:
        try:
            await _publish_rekey_pub(db, node_uuid, pub)
        except Exception:
            log.warning("rekey: publishing rekey_pub failed", exc_info=True)

    # 2. Roll forward if our generation lags and a verified envelope is present.
    bundle = await consume_envelope(db, node_uuid)
    if bundle is None:
        return None
    try:
        db_epoch = await get_key_epoch(db)
        keys = {
            "hmac_key": bytes(bundle[0:32]),
            "dek_key": bytes(bundle[32:64]),
            "audit_key": bytes(bundle[64:96]),
            "ha_wrap_key": bytes(bundle[96:128]),
            "pki_wrap_key": bytes(bundle[128:160]),
        }
        pid = os.getpid()
        # Lazy imports : cluster_setup imports vault_state + cluster ; importing
        # it at module load from here would risk a cycle. ha_password reload
        # mirrors the failover path (seal() drops _ha_password_enc).
        from .audit_identity import load_audit_identity_into_ram
        from .auth import load_prev_hmac_into_ram
        from .cluster_setup import start_master_services, stop_master_services
        from .ha_password import load_ha_password_into_ram

        # Release old master services (old crypto socket + Shamir share server)
        # BEFORE seal() -- seal() does NOT stop the RPC server, so skipping this
        # would leak the live listener and block the restart below.
        await stop_master_services(vs, db, pid=pid)
        # seal()->unseal() are sync and back-to-back (no await between), so the
        # vault is never observably sealed to a concurrent request.
        vs.seal()
        vs.unseal(keys)
        vs.set_key_epoch(db_epoch)
        await start_master_services(db, vs, pid=pid)
        await load_ha_password_into_ram(db)
        # seal() above dropped every RAM-only secret ; the bare unseal(keys)
        # only restores the sub-keys. Reload the rest, exactly like the /unseal
        # endpoint, or this rolled-forward node would: (a) write hmac audit
        # entries (lost the ed25519 signer -> hmac_fallback, re-mixing the
        # chain) and (b) reject every token minted under the previous
        # generation (lost prev_hmac -> breaks lazy migration cross-host).
        await load_audit_identity_into_ram(db)
        await load_prev_hmac_into_ram(db)

        # Regenerate + republish our rekey keypair (seal() zeroed it) in the
        # SAME commit as the row teardown -- closes the window where the DB pub
        # would point at a privkey we no longer hold.
        newpub = vs.ensure_rekey_keypair()
        if newpub is not None:
            await _publish_rekey_pub(db, node_uuid, newpub, commit=False)
        await delete_consumed_row(db, node_uuid, db_epoch)
        await log_action(
            db,
            actor="rekey-envelope",
            action="cluster_node_rolled_forward",
            target=node_uuid,
            detail={"key_epoch": db_epoch, "reason": "verified rekey envelope adopted"},
            ip_address=None,
        )
        await db.commit()
        _metrics.cluster_node_rolled_forward.inc()
        log.warning(
            "rekey: node=%s rolled forward to epoch=%d (no operator action needed)",
            node_uuid,
            db_epoch,
        )
        return "rolled_forward"
    finally:
        secure_zero(bundle)


async def _key_epoch_fence_body(db: AsyncSession, node_uuid: str) -> str | None:
    """Generation fence -- quarantine this node when its keys are a stale generation.

    Only the key-holding master process can judge currency (followers delegate
    crypto via RPC and hold no keys), so this is gated on ``vs.is_master()``.
    Compares the master's in-RAM ``key_epoch`` to the DB ``key_epoch``:

    - in-RAM < DB : another host rotated past us; our keys can no longer unwrap
      the re-wrapped DEKs, so every read 500s and the audit chain false-breaks.
      Transition a serving node to ``quarantined`` (fails ``/readiness``, pulls
      it out of the load balancer) and raise a critical audit event.
    - in-RAM == DB and currently quarantined : an operator re-unsealed us onto
      the current generation; re-enter the pool as ``secondary``.

    Returns the action taken (``"quarantined"`` / ``"recovered"``) or None.
    Recovery is in-band here ONLY because S1 ships without the rekey envelope;
    once S2/S3 land, a peer rolls forward automatically instead of waiting for
    an operator. The fence stays as the fail-closed backstop either way.
    """
    if vs.sealed or not vs.is_master:
        return None
    local_epoch = vs.key_epoch
    db_epoch = await get_key_epoch(db)
    if local_epoch is None:
        if not db_epoch:
            # No rotation marker exists, so there is nothing to be stale against.
            return None
        if vs.aesgcm is not None and await keys_match_current_data(
            db, vs.aesgcm, require_sample=True
        ):
            # Legacy unseal, but the live DEK key proves it can unwrap current
            # rows. Adopt the persisted epoch so subsequent checks are explicit.
            vs.set_key_epoch(db_epoch)
            local_epoch = db_epoch
        else:
            # Unknown epoch after rotations is unsafe unless decryptability is
            # proven. Drive the normal stale-key quarantine path below.
            local_epoch = db_epoch - 1

    row = await db.execute(
        text("SELECT ha_state FROM vault_cluster_nodes WHERE node_uuid = :u"),
        {"u": node_uuid},
    )
    r = row.fetchone()
    if r is None:
        # Not cluster-initialised -- nothing to fence.
        return None
    state = r.ha_state

    if local_epoch < db_epoch and state in ("secondary", "primary"):
        flipped = await cluster_membership.transition_node(
            db, node_uuid, from_state=state, to_state="quarantined"
        )
        if flipped:
            await log_action(
                db,
                actor="key-epoch-fence",
                action="cluster_node_quarantined_stale_keys",
                target=node_uuid,
                detail={
                    "local_key_epoch": local_epoch,
                    "db_key_epoch": db_epoch,
                    "from_state": state,
                    "reason": "another host rotated; in-RAM keys are stale",
                },
                ip_address=None,
                critical=True,
            )
            await db.commit()
            log.error(
                "key-epoch fence: node=%s QUARANTINED (local_epoch=%d < db_epoch=%d) "
                "-- stale keys, failing readiness until re-unseal",
                node_uuid,
                local_epoch,
                db_epoch,
            )
            return "quarantined"
        return None

    if local_epoch == db_epoch and state == "quarantined":
        flipped = await cluster_membership.transition_node(
            db, node_uuid, from_state="quarantined", to_state="secondary"
        )
        if flipped:
            await log_action(
                db,
                actor="key-epoch-fence",
                action="cluster_node_unquarantined",
                target=node_uuid,
                detail={
                    "key_epoch": db_epoch,
                    "reason": "re-unsealed to current generation",
                },
                ip_address=None,
            )
            await db.commit()
            log.warning(
                "key-epoch fence: node=%s recovered (epoch=%d) -- re-entering pool",
                node_uuid,
                db_epoch,
            )
            return "recovered"

    return None


async def _rekey_republish_body(db: AsyncSession, node_uuid: str) -> int:
    """Red-timing reconciler -- the primary re-seals the CURRENT-epoch rekey
    envelope for peers that quarantined behind because they published their
    rekey_pub only AFTER the one-shot post-rotation publish_envelope.

    publish_envelope runs once, post-commit, sealing K only to peers that had a
    rekey_pub at that instant ; a peer absent/late at that moment is excluded ->
    no envelope row -> consume returns None -> the fence quarantines it -> it
    stays stuck until the NEXT rotation (s4_cdi D3/SH convergence blew past the
    30s gate). This closes the gap: while a quarantined peer with a rekey_pub
    still lacks a current-epoch row, re-publish (idempotent + supersedes lower
    epochs) ; the peer rolls forward on its own next heartbeat and the fence
    recovers it. A peer that already rolled forward is 'secondary' (not
    quarantined) and a peer mid-consume already has a row, so neither retriggers
    -- no steady-state churn.

    Single-owner: gated on the cluster PRIMARY so node-masters do not all re-seal
    the same epoch (which would churn K and race consumers). Master-side, current
    generation only. Returns the recipient count re-sealed (0 = nothing to do).
    """
    if vs.sealed or not vs.is_master:
        return 0
    local_epoch = vs.key_epoch
    if local_epoch is None or local_epoch <= 0:
        return 0  # genesis / pre-rotation : no prior generation to roll forward
    db_epoch = await get_key_epoch(db)
    if local_epoch != db_epoch:
        return 0  # not the current generation -- not our envelope to seal
    self_row = (
        await db.execute(
            text("SELECT ha_state FROM vault_cluster_nodes WHERE node_uuid = :u"),
            {"u": node_uuid},
        )
    ).fetchone()
    if self_row is None or self_row.ha_state != "primary":
        return 0  # single re-publisher : the primary owns reconciliation
    waiting = (
        await db.execute(
            text("""
                SELECT n.node_uuid FROM vault_cluster_nodes n
                WHERE n.node_uuid != :self
                  AND n.ha_state = 'quarantined'
                  AND n.rekey_pub IS NOT NULL
                  AND NOT EXISTS (
                      SELECT 1 FROM vault_rekey_envelope e
                      WHERE e.key_epoch = :epoch AND e.node_uuid = n.node_uuid)
            """),
            {"self": node_uuid, "epoch": db_epoch},
        )
    ).fetchall()
    if not waiting:
        return 0
    bundle = vs.current_subkey_bundle()
    try:
        sealed = await publish_envelope(db, bundle, db_epoch)
    finally:
        secure_zero(bundle)
    if sealed:
        _metrics.rekey_envelope_republished.inc()
        log.warning(
            "rekey republish: epoch=%d re-sealed to %d recipient(s) for %d "
            "behind peer(s) still awaiting an envelope",
            db_epoch,
            sealed,
            len(waiting),
        )
    return sealed


def _lease_fence_should_seal(last_confirm: float | None, now_monotonic: float) -> bool:
    """Lease-loss self-fence decision (active-node step-down semantics).

    ``last_confirm`` is the ``time.monotonic()`` reading of the last heartbeat
    tick on which this node confirmed it holds the primary lease
    (``primary_uuid == self``), or ``None`` when it is not / no longer the
    canonical primary. Returns True iff the node held the lease but has not
    re-confirmed it within ``cluster_primary_lease_ttl_secs``.

    That is exactly the partitioned-primary case the DB-driven self-demote in
    ``_heartbeat_body`` cannot reach : self-demote needs a live read to observe
    the new canonical primary, but a node cut off from Patroni gets no reads at
    all. By the time the TTL has elapsed the old lease has expired cluster-wide
    and an eligible secondary has auto-promoted, so the caller seals : dropping
    the CA / master keys is a fail-closed fence -- a node with no keys cannot
    issue certs or admit members under stale authority.
    """
    if last_confirm is None:
        return False
    return now_monotonic - last_confirm > settings.cluster_primary_lease_ttl_secs


async def _lease_fence_seal(vault_state) -> None:
    """Fence a possibly-stale primary: release master services THEN seal.

    ``seal()`` is sync and does NOT stop the master RPC server, so a bare seal
    on the key-holding master worker leaks the crypto-ops socket and wedges the
    next ``/unseal`` (same hazard the roll-forward path + the /seal route guard
    against). The DB is unreachable here -- that is WHY the fence fired -- so we
    stop with ``db=None`` : a local socket teardown only, no DB access. On a
    follower worker (no master server) the stop is a clean no-op.
    """
    from .cluster_setup import stop_master_services

    try:
        await stop_master_services(vault_state, db=None)
    except Exception:
        log.warning("lease-fence: stop_master_services failed", exc_info=True)
    vault_state.seal()


async def cluster_ha_heartbeat_loop():  # pragma: no cover  (daemon loop)
    """Per-node heartbeat loop. Each container updates its own row."""
    interval = settings.cluster_heartbeat_interval_secs
    node_uuid = get_node_uuid()
    # Lease-loss self-fence state : time.monotonic() of the last tick on which
    # we confirmed we hold the primary lease, else None when we are not (or no
    # longer) the canonical primary. See _lease_fence_should_seal.
    last_lease_confirm: float | None = None
    while True:
        await asyncio.sleep(interval)
        try:
            if vs.sealed:
                last_lease_confirm = None
                continue
            async with async_session() as db:
                await _heartbeat_body(db, node_uuid)
                # S2 rekey roll-forward rides the heartbeat BEFORE the fence:
                # publish our rekey_pub and, if our generation lags, adopt the
                # verified envelope. A successful roll-forward makes us current
                # so the fence below leaves us alone; absence/rejection falls
                # through to the fence (quarantine). Isolated so an error here
                # never suppresses the fence or the liveness signal.
                try:
                    await _rekey_roll_forward_body(db, node_uuid)
                except Exception:
                    log.warning("rekey roll-forward error", exc_info=True)
                # the generation fence rides the heartbeat: same per-node cadence,
                # already gated on unsealed. Isolated so a fence error never
                # suppresses the liveness signal above.
                try:
                    await _key_epoch_fence_body(db, node_uuid)
                except Exception:
                    log.warning("key-epoch fence error", exc_info=True)
                # write-path guard: publish the generation this master
                # now holds so followers on this host can fence delegated writes
                # against a stale master. Runs AFTER roll-forward+fence, so the
                # iteration that adopts a new generation also stamps it (no extra
                # lag on the convergence path). Master-only -- followers hold no
                # keys and must not clobber the marker with their inert epoch.
                try:
                    if vs.is_master and vs.key_epoch is not None:
                        await stamp_node_generation(db, node_uuid, vs.key_epoch)
                except Exception:
                    log.warning("active_key_epoch stamp error", exc_info=True)
                # Red-timing reconciler rides the heartbeat AFTER the fence: the
                # primary re-seals the current-epoch envelope for peers the fence
                # just quarantined (they published their rekey_pub after the
                # one-shot publish). Isolated so an error never suppresses
                # liveness ; a noop on every non-primary / converged tick.
                try:
                    await _rekey_republish_body(db, node_uuid)
                except Exception:
                    log.warning("rekey republish error", exc_info=True)
                # Arm / disarm the lease-loss self-fence : a successful tick
                # that still sees us as the canonical primary refreshes the
                # lease we must keep proving ; anything else (secondary, no
                # primary) disarms. This read rides the same tx -- if it raises
                # (DB unreachable) we fall through to the except below with
                # last_lease_confirm UNCHANGED, which is precisely what arms the
                # fence.
                primary_uuid, _ = await cluster_membership.read_canonical_primary(db)
                last_lease_confirm = (
                    time.monotonic() if primary_uuid == node_uuid else None
                )
        except Exception:
            log.warning("cluster_ha_heartbeat_loop error", exc_info=True)
        # Lease-loss self-fence : runs every tick INCLUDING after the body
        # raised -- a Patroni partition is precisely when the DB-driven
        # self-demote cannot fire. If we last held the primary lease but could
        # not re-confirm it within the TTL, we may no longer be the leader;
        # seal to fence a possibly-stale primary control plane.
        if not vs.sealed and _lease_fence_should_seal(
            last_lease_confirm, time.monotonic()
        ):
            log.error(
                "cluster_ha_heartbeat: primary lease unconfirmed for >%ds -- "
                "self-sealing to fence a possibly-stale primary (cannot reach "
                "the DB to self-demote)",
                settings.cluster_primary_lease_ttl_secs,
            )
            _metrics.seal_events.labels(trigger="lease_loss_fence").inc()
            await _lease_fence_seal(vs)
            last_lease_confirm = None
