# DO NOT REMOVE: SPDX header + copyright are part of the AGPL-3.0 license terms.
# Stripping or rewriting these notices on redistribution is a license violation.
# Project: Resurgamus Horizon, Author: shdw, License: AGPL-3.0-or-later
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
# -----------------------------------------------------------------------------
# Resurgamus Horizon, (c) 2024-2026 shdw <horizon@resurgamus.com>, AGPL-3.0
# Self-hosted secrets vault
# -----------------------------------------------------------------------------
"""Resurgamus Horizon - self-hosted secrets vault (FastAPI entry point).

Author: shdw <horizon@resurgamus.com>
Project: Resurgamus Horizon - minimal AGPL-3.0 vault for infra automation.
License: AGPL-3.0-or-later - closed-source relicensing prohibited.

Lifespan handles schema migration at startup and worker
compartmentalization (master + RPC-attached followers, intra-host).
RPC compartmentalization is the only multi-worker path.
"""

import asyncio
import json
import logging
import os
import random
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

import asyncpg
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from . import metrics as _metrics
from .cluster_rpc import CustodianPoolUnavailable, MasterUnreachable
from .config import settings
from .custody import CustodyBoundaryMiddleware
from .custody_generation import CustodyOrchestrationBusy
from .custody_routing import CustodyQuorumUnavailable
from .routes import (
    audit,
    auth_ldap,
    auth_proxy,
    backup,
    dynamic,
    groups,
    namespaces,
    notifications,
    observability,
    oneshot,
    pki,
    secrets,
    tokens,
    vault,
    webauthn,
)
from .routes import (
    cluster as cluster_route,
)
from .vault_state import VaultSealedError
from .vault_state import vault as vs

log = logging.getLogger("rhorizon")

_SEALED_REJECTION_LOG_INTERVAL_SECS = 10.0
_DATABASE_READINESS_TIMEOUT_SECS = 1.0
_sealed_rejection_last_log_at: float | None = None
_sealed_rejection_suppressed = 0


def _log_sealed_rejection(
    method: str,
    path: str,
    client_ip: str,
    *,
    now: float | None = None,
) -> bool:
    """Sample sealed-request warnings while the metric counts every attempt."""
    global _sealed_rejection_last_log_at, _sealed_rejection_suppressed

    current = time.monotonic() if now is None else now
    if (
        _sealed_rejection_last_log_at is not None
        and current - _sealed_rejection_last_log_at
        < _SEALED_REJECTION_LOG_INTERVAL_SECS
    ):
        _sealed_rejection_suppressed += 1
        return False

    suppressed = _sealed_rejection_suppressed
    _sealed_rejection_last_log_at = current
    _sealed_rejection_suppressed = 0
    log.warning(
        "sealed: rejected method=%r path=%r client_ip=%r suppressed_since_previous=%d",
        method,
        path,
        client_ip,
        suppressed,
    )
    return True


async def _boot_connect():
    """Raw asyncpg connection for the boot migrations, honoring database_ssl.
    The raw connect bypasses the SQLAlchemy engine, so without this the
    schema/namespace migrations would ignore a configured verify-full and fall
    back to asyncpg's unverified default -- a TLS downgrade for the boot
    connections (where the DB password is sent)."""
    from .database import _pg_ssl_context

    raw_dsn = settings.database_url.replace("postgresql+asyncpg://", "postgresql://")
    ssl_arg = False if settings.database_ssl == "disable" else _pg_ssl_context()
    return await asyncpg.connect(raw_dsn, ssl=ssl_arg)


async def _apply_schema():
    """Apply schema.sql at startup using advisory lock (same pattern as CMDB)."""
    conn = await _boot_connect()
    try:
        # Advisory lock to prevent concurrent migrations
        await conn.execute("SELECT pg_advisory_lock(8675309)")
        schema_path = Path(os.environ.get("RHORIZON_SCHEMA_PATH", "/app/schema.sql"))
        if schema_path.exists():
            sql = schema_path.read_text()
            await conn.execute(sql)
            log.info("Schema applied from %s", schema_path)
        else:
            log.warning("schema.sql not found at %s", schema_path)
        await conn.execute("SELECT pg_advisory_unlock(8675309)")
    finally:
        await conn.close()


async def _migrate_namespaces():
    """Populate `vault_namespaces` from existing namespace strings.

    The default namespace is always present, including on an empty vault.
    Legacy secret and dynamic-engine namespace strings are adopted before the
    dynamic-engine foreign key is validated. Idempotent - safe on every restart.

    Shares the schema advisory lock (8675309) with `_apply_schema` so the
    two boot-time steps run strictly serially across all uvicorn workers.
    A distinct lock per step deadlocks under concurrent worker boot:
    worker A holds AccessExclusiveLock on vault_namespaces (schema.sql
    ALTER/CREATE INDEX) while worker B holds AccessShareLock on
    vault_secrets (this migration's SELECT), each waiting on the other.
    Symptom: repeated DeadlockDetectedError at startup, crashed worker,
    uvicorn re-spawning indefinitely. A single boot-migration lock
    serializes both steps -- workers boot one-at-a-time.

    Each existing namespace string becomes a row owned by an auto-created
    `vault-admins` group, with `enforce_membership=false` (agnostic mode)
    so existing tokens with `permissions.namespaces=[...]` keep working
    unchanged. The operator opts in to strict RBAC per-namespace later
    via PUT /vault/namespaces/{name}.
    """
    conn = await _boot_connect()
    try:
        await conn.execute("SELECT pg_advisory_lock(8675309)")

        # 1. Ensure vault-admins group exists with admin:rw permissions.
        admins_id = await conn.fetchval(
            "SELECT id FROM vault_groups WHERE name = 'vault-admins'"
        )
        if admins_id is None:
            admins_id = await conn.fetchval(
                """
                INSERT INTO vault_groups (name, permissions, source)
                VALUES ('vault-admins', '{"admin": "rw"}'::jsonb, 'local')
                RETURNING id
                """
            )
            log.info(
                "Auto-created vault-admins group %s for namespace ownership", admins_id
            )

        # 2. Keep `default` available on an empty vault and adopt every legacy
        #    namespace string. Agnostic mode (enforce_membership=false) avoids
        #    locking existing tokens out during an upgrade. Explicit UUID cast
        #    keeps asyncpg from inferring the SELECT parameter as text.
        await conn.execute(
            """
            INSERT INTO vault_namespaces
                (name, owner_group_id, enforce_membership, created_by)
            SELECT source.name, $1::uuid, false, 'migration'
            FROM (
                SELECT 'default'::text AS name
                UNION
                SELECT namespace FROM vault_secrets
                UNION
                SELECT namespace FROM vault_dynamic_engines
            ) AS source
            WHERE source.name IS NOT NULL
            ON CONFLICT (name) DO NOTHING
            """,
            str(admins_id),
        )

        # 3. Backfill vault_secrets.namespace_id from the matching row.
        await conn.execute(
            """
            UPDATE vault_secrets s
            SET namespace_id = n.id
            FROM vault_namespaces n
            WHERE s.namespace = n.name
              AND s.namespace_id IS NULL
            """
        )

        # 4. Fail closed if any secret remains outside the namespace model.
        #    Authorization uses namespace_id for live RBAC checks; accepting a
        #    NULL here would silently fall back to the legacy claim-only path.
        unmapped = await conn.fetchval(
            "SELECT count(*) FROM vault_secrets WHERE namespace_id IS NULL"
        )
        if unmapped:
            log.critical(
                "%d vault_secrets rows still have NULL namespace_id after migration",
                unmapped,
            )
            raise RuntimeError(
                f"namespace migration incomplete: {unmapped} secret(s) unmapped"
            )

        # Existing dynamic-engine tables receive the FK as NOT VALID in
        # schema.sql so their legacy namespace strings can be adopted above.
        # New writes are already checked; validation now proves old rows too.
        await conn.execute(
            """
            ALTER TABLE vault_dynamic_engines
            VALIDATE CONSTRAINT vault_dynamic_engines_namespace_fkey
            """
        )
        log.info("vault_namespaces migration complete (all secrets mapped)")

        await conn.execute("SELECT pg_advisory_unlock(8675309)")
    finally:
        await conn.close()


def _observe_dek_key_age(raw_value: object | None, db_now: datetime) -> None:
    """Publish DEK-key age, failing closed when its timestamp is untrustworthy."""
    invalid_reason = None
    try:
        if not isinstance(raw_value, str) or not raw_value.strip():
            raise ValueError("missing")
        last = datetime.fromisoformat(raw_value)
        if last.tzinfo is None or last.utcoffset() is None:
            raise ValueError("timezone_missing")
        age_secs = (db_now - last.astimezone(timezone.utc)).total_seconds()
        # The marker is written with an API host clock. Tolerate ordinary NTP
        # skew, but do not let a forged far-future marker hide an old key.
        if age_secs < -300:
            raise ValueError("future")
        age_secs = max(age_secs, 0.0)
    except (OverflowError, TypeError, ValueError) as exc:
        invalid_reason = (
            str(exc)
            if str(exc)
            in {
                "missing",
                "timezone_missing",
                "future",
            }
            else "malformed"
        )

    if invalid_reason is not None:
        _metrics.dek_key_age_seconds.set(-1)
        _metrics.dek_key_stale.set(1)
        log.warning(
            "dek_key rotation timestamp is %s; age is unknown - "
            "verify vault_config and POST /admin/rotate-dek-key if required",
            invalid_reason,
        )
        return

    _metrics.dek_key_age_seconds.set(age_secs)
    max_secs = settings.dek_key_max_age_days * 86400
    is_stale = age_secs > max_secs
    _metrics.dek_key_stale.set(1 if is_stale else 0)
    if is_stale:
        log.warning(
            "dek_key is stale (age=%dd, max=%dd) - "
            "POST /admin/rotate-dek-key to refresh",
            int(age_secs / 86400),
            settings.dek_key_max_age_days,
        )


async def _refresh_derived_gauges():
    """Set gauges derived from shared database state.

    Called per-worker each reaper cycle -- NOT inside the cluster-singleton
    reaper body -- so every worker sets the same value and the ``livemax``
    multiprocess aggregation stays correct on both increase and decrease.
    """
    from sqlalchemy import text as sa_text

    from . import metrics as _m
    from .database import async_session

    async with async_session() as db:
        ar = await db.execute(
            sa_text(
                "SELECT COUNT(*) AS n FROM vault_tokens WHERE active = true "
                "AND (expires_at IS NULL OR expires_at > NOW())"
            )
        )
        _m.active_tokens.set(ar.fetchone().n)
        lr = await db.execute(
            sa_text(
                "SELECT COUNT(*) AS n FROM vault_rate_limits WHERE locked_until > NOW()"
            )
        )
        _m.locked_ips.set(lr.fetchone().n)
        if settings.dek_key_lazy_check:
            age_result = await db.execute(
                sa_text(
                    "SELECT ("
                    "  SELECT value FROM vault_config "
                    "  WHERE key = 'dek_key_rotated_at'"
                    ") AS value, NOW() AS db_now"
                )
            )
            age_row = age_result.fetchone()
            _observe_dek_key_age(age_row.value, age_row.db_now)


async def _purge_pending_ha_password_rotation(db) -> str | None:
    """Remove an expired or corrupt HA-password rotation intent.

    The config value is TEXT because vault_cluster_config stores heterogeneous
    values. Parse this one row outside SQL so malformed metadata cannot abort
    every reaper cycle. Corruption cancels the pending intent fail-closed; no
    password or key material is present in this metadata row.
    """
    from sqlalchemy import text as sa_text

    pending = (
        await db.execute(
            sa_text(
                "SELECT value, NOW() AS db_now FROM vault_cluster_config "
                "WHERE key = 'pending_ha_password_rotation'"
            )
        )
    ).fetchone()
    if pending is None:
        return None

    staged_by = None
    outcome = "corrupt"
    error_type = None
    try:
        meta = json.loads(pending.value)
        if not isinstance(meta, dict):
            raise TypeError("rotation metadata is not an object")
        staged_by = meta["staged_by"]
        if (
            not isinstance(staged_by, str)
            or not staged_by.strip()
            or len(staged_by) > 256
        ):
            raise ValueError("rotation actor is invalid")
        staged_at = datetime.fromisoformat(meta["staged_at"])
        if staged_at.tzinfo is None or staged_at.utcoffset() is None:
            raise ValueError("rotation staging time has no timezone")
        expires_at = datetime.fromisoformat(meta["expires_at"])
        if expires_at.tzinfo is None or expires_at.utcoffset() is None:
            raise ValueError("rotation expiry has no timezone")
        if staged_at >= expires_at:
            raise ValueError("rotation expiry must follow staging time")
        if (expires_at - staged_at).total_seconds() > 86400:
            raise ValueError("rotation window exceeds the configured maximum")
        # Stage uses the API host clock while expiry is judged against DB time;
        # allow five minutes of skew, but never retain a far-future forged row.
        if (staged_at - pending.db_now).total_seconds() > 300:
            raise ValueError("rotation staging time is implausibly far in the future")
        if expires_at >= pending.db_now:
            return None
        outcome = "expired"
    except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        error_type = type(exc).__name__

    deleted = (
        await db.execute(
            sa_text(
                "DELETE FROM vault_cluster_config "
                "WHERE key = 'pending_ha_password_rotation' AND value = :value "
                "RETURNING value"
            ),
            {"value": pending.value},
        )
    ).fetchone()
    if deleted is None:
        return None

    from .audit import log_action as _log_action

    await _log_action(
        db,
        actor="reaper",
        action=f"ha_password_rotate_{outcome}",
        detail={"staged_by": staged_by, "error_type": error_type},
    )
    return outcome


async def _expire_prev_hmac_if_due(db) -> tuple[str, str | None] | None:
    """Expire inconsistent or out-of-window lazy-token migration state.

    The master-password rotation and this cleanup share one transaction lock,
    so the reaper cannot inspect or delete a half-published/new generation.
    Returns the outcome and observed encrypted envelope only when both config
    rows were deleted and the matching audit entry was staged in the caller's
    transaction.
    """
    from sqlalchemy import text as sa_text

    lock = await db.execute(
        sa_text(
            "SELECT pg_try_advisory_xact_lock("
            "hashtext('rhorizon:cluster:rotate_password'))"
        )
    )
    if not lock.scalar():
        return None

    rows = (
        await db.execute(
            sa_text(
                "SELECT key, value FROM vault_config "
                "WHERE key IN ('prev_hmac_key', 'prev_hmac_rotated_at') "
                "FOR UPDATE"
            )
        )
    ).fetchall()
    values = {row.key: row.value for row in rows}
    if not values:
        return None

    outcome = "corrupt"
    error_type = None
    rotated_at = None
    try:
        if set(values) != {"prev_hmac_key", "prev_hmac_rotated_at"}:
            raise ValueError("previous HMAC metadata is incomplete")
        rotated_at = datetime.fromisoformat(values["prev_hmac_rotated_at"])
        if rotated_at.tzinfo is None or rotated_at.utcoffset() is None:
            raise ValueError("previous HMAC rotation time has no timezone")
        db_now = (await db.execute(sa_text("SELECT NOW() AS db_now"))).scalar_one()
        if (rotated_at - db_now).total_seconds() > 300:
            raise ValueError("previous HMAC rotation time is implausibly future")
        window = timedelta(days=settings.token_migration_window_days)
        if db_now <= rotated_at + window:
            return None
        outcome = "expired"
    except (TypeError, ValueError) as exc:
        error_type = type(exc).__name__

    await db.execute(
        sa_text(
            "DELETE FROM vault_config "
            "WHERE key IN ('prev_hmac_key', 'prev_hmac_rotated_at')"
        )
    )

    from .audit import log_action as _log_action

    await _log_action(
        db,
        actor="reaper",
        action=f"prev_hmac_{outcome}",
        detail={
            "error_type": error_type,
            "rotated_at": rotated_at.isoformat() if rotated_at else None,
            "migration_window_days": settings.token_migration_window_days,
        },
    )
    return outcome, values.get("prev_hmac_key")


async def _reaper_loop():
    """Run periodic database, key-migration, and audit-file maintenance.

    Every worker refreshes the DB-derived gauges, including DEK-key age, every
    five minutes so multiprocess metric aggregation remains accurate. Database
    mutations run cluster-wide once per cycle under the ``reaper`` advisory
    lock: expired tokens and leases, purged secrets, stale workers,
    token-rotation stubs, rate-limit and join caches, HA-password intents,
    previous token-HMAC state, and stale rekey envelopes. The elected worker
    also compresses old audit files.

    Cleanup statements are idempotent, but executing them from every host would
    waste work and duplicate logs. A failed cycle is retried five minutes later
    by whichever host next acquires the lock.
    """
    from sqlalchemy import text as sa_text

    from .cluster import with_cluster_lock
    from .database import async_session

    async def _reaper_body():
        # Delete expired tokens + revoke expired leases
        async with async_session() as db:
            result = await db.execute(
                sa_text("""
                    DELETE FROM vault_tokens
                    WHERE expires_at IS NOT NULL
                      AND expires_at < NOW()
                    RETURNING name
                """)
            )
            expired_tokens = result.fetchall()

            # Purge soft-deleted secrets past their retention window.
            # `purge_after IS NULL` means "never auto-purge" (used by
            # 'protected' mode with retention=0, operator must manually
            # restore or the tombstone stays forever).
            purge_candidates_res = await db.execute(
                sa_text(
                    """
                    SELECT
                        s.id AS secret_id,
                        s.dek_id AS current_dek_id,
                        ARRAY(
                            SELECT v.dek_id
                            FROM vault_secret_versions AS v
                            WHERE v.secret_id = s.id
                        ) AS version_dek_ids
                    FROM vault_secrets AS s
                    WHERE s.deleted_at IS NOT NULL
                      AND s.purge_after IS NOT NULL
                      AND s.purge_after < NOW()
                    FOR UPDATE OF s
                    """
                )
            )
            purge_candidates = purge_candidates_res.fetchall()
            purged_secrets = []
            if purge_candidates:
                secret_ids = [row.secret_id for row in purge_candidates]
                candidate_dek_ids = {
                    dek_id
                    for row in purge_candidates
                    for dek_id in [row.current_dek_id, *row.version_dek_ids]
                }
                purge_res = await db.execute(
                    sa_text(
                        "DELETE FROM vault_secrets WHERE id = ANY(:ids) RETURNING id"
                    ),
                    {"ids": secret_ids},
                )
                purged_secrets = purge_res.fetchall()
                await db.execute(
                    sa_text(
                        "DELETE FROM vault_dek AS d "
                        "WHERE d.id = ANY(:ids) "
                        "AND NOT EXISTS ("
                        "  SELECT 1 FROM vault_secrets "
                        "  WHERE dek_id = d.id"
                        ") AND NOT EXISTS ("
                        "  SELECT 1 FROM vault_secret_versions "
                        "  WHERE dek_id = d.id"
                        ")"
                    ),
                    {"ids": list(candidate_dek_ids)},
                )

            # Drop the target-DB user behind each expired lease, then mark it
            # revoked. This enforces the lease TTL on the engine itself, not
            # just in our bookkeeping (see expire_due_leases). No-op if sealed.
            from .routes.dynamic import expire_due_leases

            expired_leases = await expire_due_leases(db)

            # Drop vault_workers rows that have not heartbeated in
            # worker_reap_stale_secs (default 300s). These are typically
            # leftovers from previous container runs (HOSTNAME changed, old
            # containers killed without graceful deregister).
            #
            # A live process whose row is reaped no longer terminates itself:
            # it re-registers (cluster._reregister_after_reap) and keeps its
            # Shamir share. The old fail-close turned a recoverable stall into
            # an outage, because shares are minted once and every replaced
            # worker permanently reduced the count until failover quorum was
            # unreachable and the node sealed.
            result = await db.execute(
                sa_text("""
                    DELETE FROM vault_workers
                    WHERE last_heartbeat
                          < NOW() - (CAST(:stale AS int) * INTERVAL '1 second')
                    RETURNING pid
                """),
                {"stale": settings.worker_reap_stale_secs},
            )
            stale_workers = result.fetchall()

            # Purge pending token rotation stubs that are older than the
            # configured grace period. After this they are functionally
            # equivalent to revoked tokens, the admin missed the window.
            stub_res = await db.execute(
                sa_text(
                    "DELETE FROM vault_pending_token_rotations "
                    "WHERE created_at < NOW() - "
                    "(CAST(:days AS int) * INTERVAL '1 day') "
                    "RETURNING name, namespace"
                ),
                {"days": settings.restore_rotation_grace_days},
            )
            purged_stubs = stub_res.fetchall()

            # Purge dead rate-limit rows: an IP whose lockout has expired AND
            # whose last failure aged out of the findtime window is back to a
            # clean slate (record_failure would reset it to 1 anyway). Dropping
            # it keeps vault_rate_limits small -- housekeeping, no security
            # effect (the windowed counting already de-escalates live rows).
            rl_res = await db.execute(
                sa_text(
                    "DELETE FROM vault_rate_limits "
                    "WHERE (locked_until IS NULL OR locked_until < NOW()) "
                    "  AND updated_at < NOW() - make_interval(secs => :window) "
                    "RETURNING ip_address"
                ),
                {"window": settings.rate_limit_findtime},
            )
            purged_rate_limits = rl_res.fetchall()

            # Purge expired /cluster/join
            # idempotency cache rows. Each row is (nonce -> response
            # JSON) bounded by expires_at = created_at +
            # cluster_join_idempotency_ttl_secs. The cached payload
            # carries a node_cert_pem (public material, fine at rest)
            # and a wrapped node_key_pem (wrapped under HKDF(ha_password,
            # info=...)). It does not reveal the private key without the
            # ha_password; the TTL limits retained ciphertext and table size.
            join_cache_res = await db.execute(
                sa_text(
                    "DELETE FROM vault_join_idempotency "
                    "WHERE expires_at < NOW() RETURNING nonce"
                )
            )
            purged_join_cache = join_cache_res.fetchall()

            # The pending row is metadata only. Expired and malformed intents
            # are cancelled, audited, and counted without risking a permanent
            # reaper failure on a bad TEXT value.
            rotation_outcome = await _purge_pending_ha_password_rotation(db)

            changes_reaped = (
                expired_tokens
                or purged_secrets
                or expired_leases
                or stale_workers
                or purged_stubs
                or purged_join_cache
                or rotation_outcome
                or purged_rate_limits
            )
            # Commit unconditionally: every cleanup statement above is
            # idempotent, and this prevents a new cleanup category from being
            # silently rolled back if it is omitted from the logging predicate.
            await db.commit()
            if rotation_outcome is not None:
                _metrics.cluster_ha_password_rotations.labels(
                    outcome=rotation_outcome
                ).inc()
            if changes_reaped:
                log.info(
                    "Reaper: %d token(s), %d secret(s), %d lease(s), "
                    "%d stale worker(s), %d pending stub(s), "
                    "%d join-cache row(s), %d removed rotation intent(s), "
                    "%d rate-limit row(s) reaped",
                    len(expired_tokens),
                    len(purged_secrets),
                    len(expired_leases),
                    len(stale_workers),
                    len(purged_stubs),
                    len(purged_join_cache),
                    int(rotation_outcome is not None),
                    len(purged_rate_limits),
                )

        # Expire the previous token-HMAC generation after the configured
        # migration window. Incomplete/malformed metadata is removed
        # fail-closed instead of extending old-token validity indefinitely.
        prev_hmac_generation = vs.prev_hmac_generation
        async with async_session() as db2:
            prev_hmac_expiry = await _expire_prev_hmac_if_due(db2)
            if prev_hmac_expiry is not None:
                prev_hmac_outcome, prev_hmac_envelope = prev_hmac_expiry
                await db2.commit()
                # DB is the authorization source of truth (auth.py checks row
                # presence atomically with the old-token lookup). Clear this
                # process's observed cache only after the durable commit, and
                # never erase a newer generation installed concurrently.
                from .auth import clear_prev_hmac_if_observed

                await clear_prev_hmac_if_observed(
                    prev_hmac_generation, prev_hmac_envelope
                )
                log.warning(
                    "Reaper: previous token-HMAC generation removed "
                    "(outcome=%s, migration_window_days=%d); "
                    "unmigrated tokens invalidated",
                    prev_hmac_outcome,
                    settings.token_migration_window_days,
                )

        # Rekey-envelope reaper backstop -- purge envelope
        # rows unconsumed past the migration window (nodes that never came
        # back, emergency rotations that left stragglers, partial publishes).
        # Per-row consume teardown + superseding rotations handle the happy
        # path; this is the safety net so the table cannot grow unbounded.
        # Retention is forward-secrecy-relevant: stale sealed-K + blob rows
        # let a future node-privkey compromise retro-recover that generation,
        # so the window mirrors token_migration_window_days (one knob). The
        # remaining-row count feeds an alertable gauge (0 at steady state).
        async with async_session() as db_re:
            from . import metrics as _m

            reaped = await db_re.execute(
                sa_text(
                    "DELETE FROM vault_rekey_envelope WHERE created_at < NOW() - "
                    "(CAST(:days AS int) * INTERVAL '1 day')"
                ),
                {"days": settings.token_migration_window_days},
            )
            remaining = await db_re.execute(
                sa_text("SELECT COUNT(*) AS n FROM vault_rekey_envelope")
            )
            await db_re.commit()
            n_reaped = reaped.rowcount or 0
            if n_reaped:
                _m.rekey_envelope_reaped.inc(n_reaped)
                log.info("Reaper: purged %d stale rekey envelope row(s)", n_reaped)
            remaining_row = remaining.fetchone()
            _m.rekey_envelope_rows.set(remaining_row.n if remaining_row else 0)

        # Seal completed archive days BEFORE compressing them. Both orders are
        # correct -- the digest is over logical content, so gzip does not move
        # it -- but sealing first means a day is attested in the form it was
        # written, and a compression bug can never silently change what a seal
        # was computed over.
        #
        # Sealing cross-checks the file against the database rows for that day
        # while both copies still exist. A day that disagrees is refused, logged
        # and counted, and stays unsealed -- which is what keeps it out of any
        # future prune.
        from .audit import _audit_dir
        from .audit_archive import (
            prune_archived_audit_rows,
            seal_completed_archives,
        )

        try:
            async with async_session() as seal_db:
                sealed = await seal_completed_archives(seal_db, audit_dir=_audit_dir())
                await seal_db.commit()
            if sealed["sealed_days"]:
                log.info(
                    "Sealed %d completed audit archive day(s): %s",
                    len(sealed["sealed_days"]),
                    ", ".join(sealed["sealed_days"]),
                )
            for refusal in sealed["refused"]:
                log.error(
                    "Audit archive for %s REFUSED a seal: %s",
                    refusal["day"],
                    refusal["reason"],
                )
        except Exception:
            # Never let sealing break the reaper: an unsealed day is simply a
            # day that cannot be pruned yet.
            log.warning("Audit archive sealing failed this cycle", exc_info=True)

        # Prune chain rows the archive provably holds. Opt-in, and gated three
        # ways inside: past the retention window, the day is sealed, and that
        # seal still verifies against the file. An anchor is written first, in
        # the same transaction, so the surviving chain stays verifiable and a
        # crash between the two leaves either both or neither.
        if settings.audit_db_prune_enabled:
            try:
                async with async_session() as prune_db:
                    pruned = await prune_archived_audit_rows(
                        prune_db,
                        audit_dir=_audit_dir(),
                        retention_days=settings.audit_db_retention_days,
                    )
                    await prune_db.commit()
                if pruned["pruned_rows"]:
                    log.info(
                        "Pruned %d audit chain row(s) through %s; the archive "
                        "holds them and verification now anchors there",
                        pruned["pruned_rows"],
                        pruned["pruned_through_day"],
                    )
            except Exception:
                # A failed prune leaves the rows in place, which is the safe
                # direction: storage grows, evidence does not disappear.
                log.warning("Audit chain prune failed this cycle", exc_info=True)

        # Compress old audit log files
        from .routes.audit import compress_old_files

        compressed = await asyncio.to_thread(compress_old_files)
        if compressed:
            log.info("Compressed %d old audit log file(s)", compressed)

    while True:  # pragma: no cover  (daemon 5min loop)
        await asyncio.sleep(300)
        try:
            if vs.sealed:
                continue
            await _refresh_derived_gauges()
            # cluster-wide singleton, exactly one host runs the
            # reaper per cycle. Others see the lock held and skip silently.
            async with async_session() as db_lock:
                acquired = await with_cluster_lock(db_lock, "reaper", _reaper_body)
                await db_lock.commit()  # release advisory lock
            if not acquired:
                log.debug("reaper: another host holds the lock - skipping")
        except Exception:
            _metrics.reaper_failures.inc()
            log.warning(
                "reaper_loop cycle failed; retrying in 5 minutes", exc_info=True
            )


async def _audit_lite_checkpoint_loop():
    """Periodically seal read-audit windows into the signed audit chain."""
    if not settings.audit_lite_checkpoint_enabled:
        log.info("audit_lite_checkpoint_loop disabled")
        return

    from .cluster import with_cluster_lock
    from .database import async_session

    interval = settings.audit_lite_checkpoint_interval_secs

    async def _checkpoint_body():
        from .audit_mtree import create_audit_lite_checkpoint

        async with async_session() as db:
            try:
                result = await create_audit_lite_checkpoint(
                    db,
                    max_rows=settings.audit_lite_checkpoint_max_rows,
                )
                if result.get("created"):
                    await db.commit()
                    _metrics.audit_lite_checkpoints.labels(result="success").inc()
                    _metrics.audit_lite_checkpoint_rows.inc(result["row_count"])
                    log.info(
                        "audit_lite_checkpoint: sealed %d read row(s) root=%s",
                        result["row_count"],
                        result["merkle_root"],
                    )
                else:
                    await db.rollback()
                    _metrics.audit_lite_checkpoints.labels(result="empty").inc()
            except Exception:
                await db.rollback()
                raise

    while True:  # pragma: no cover  (daemon loop)
        await asyncio.sleep(interval)
        try:
            if vs.sealed:
                continue
            async with async_session() as db_lock:
                acquired = await with_cluster_lock(
                    db_lock,
                    "audit_lite_checkpoint",
                    _checkpoint_body,
                )
                await db_lock.commit()
            if not acquired:
                log.debug("audit_lite_checkpoint: another host holds the lock")
        except Exception:
            _metrics.audit_lite_checkpoints.labels(result="failure").inc()
            log.warning(
                "audit_lite_checkpoint cycle failed; retrying after interval",
                exc_info=True,
            )


async def _init_cluster() -> list[asyncio.Task]:
    """claim a worker role and start cluster background loops.

    Each worker registers then races for the single master claim
    (acquire_master_or_follower). The first to claim master is the one the
    operator will subsequently unseal; every other worker runs as a follower.
    Only MASTER/FOLLOWER exist - the decorative secret/token/ephemeral/rotation
    roles were removed.

    Returns the list of created asyncio.Task - caller must cancel on shutdown.
    """
    import os
    import secrets

    from .cluster import (
        acquire_master_or_follower,
        heartbeat_loop,
        master_watch_loop,
        register_worker,
        run_election,
    )
    from .database import async_session
    from .socket_paths import sweep_orphan_share_sockets

    # Every worker that did not exit cleanly left its share-back socket behind
    # -- the name embeds the pid, so nothing else ever reclaims it. Swept here
    # because this runs once per worker start, which is exactly when the
    # runtime directory has just been inherited across a restart. Failure to
    # sweep must never stop a worker from starting: the leak is an
    # availability trend, not a correctness precondition.
    try:
        sweep_orphan_share_sockets()
    except Exception:
        log.warning("could not sweep orphaned share sockets", exc_info=True)

    # Tiny random delay to spread the boot race across workers
    await asyncio.sleep(secrets.randbelow(100) / 1000.0)

    # every worker row for this container carries the same
    # node_uuid (one container = one identity, N worker processes share it).
    from .node_uuid import get_node_uuid

    node_uuid_val = get_node_uuid()

    async with async_session() as db:
        # Register the worker row (worker_state defaults to 'sealed'), then
        # race for the master claim. The winner returns WorkerState.MASTER ;
        # losers stay SEALED until the follower-boot loop attaches them to
        # the master's RPC socket and bumps them to FOLLOWER. There is no
        # upper bound on follower count; the validated worker setting is the
        # only process-count knob.
        await register_worker(db, node_uuid=node_uuid_val)
        state = await acquire_master_or_follower(db)
        log.info("Cluster: pid=%d boot worker_state=%s", os.getpid(), state.value)

    async def on_master_lost():
        """Master heartbeat went stale. Run for the open role; if won,
        reconstruct sub-keys via Shamir from peer share-backs and become
        the new master. If lost (or this worker has no share to contribute),
        drop the dead RPC client and re-attach to whoever wins.

        At first-boot (before any operator unseal) every worker is sealed
        and has no share. Running for election would just create churn -
        the winner can't reconstruct, fails, the next tick another worker
        wins, etc. Skip entirely if we have nothing to contribute. The
        operator-driven /unseal is the only path that creates the FIRST
        master.
        """
        from .cluster_rpc import MasterUnreachable, RpcError
        from .cluster_setup import (
            attach_to_master as _reattach,
        )
        from .cluster_setup import (
            detach_from_master as _detach,
        )
        from .cluster_setup import (
            reconstruct_and_become_master,
        )

        # A saturated event loop or DB pool can delay the 1s SQL heartbeat
        # beyond MASTER_TIMEOUT_SECS even though the local master process and
        # its Rust RPC thread are still healthy. Do not turn that scheduling
        # delay into a destructive failover:
        #
        # - the operational master never elects against itself;
        # - a follower probes its already-attached RPC channel before treating
        #   the DB heartbeat as proof of master death.
        #
        # A genuinely dead process fails the RPC probe and still takes the
        # normal election path.
        if vs.is_master:
            log.warning(
                "Cluster: master DB heartbeat is stale but pid=%d is still "
                "the operational master - skipping self-election",
                os.getpid(),
            )
            return
        if vs._rpc_client is not None and not vs.sealed:
            try:
                await vs._rpc_client.call(
                    "hmac_sha512",
                    {"message": b"rhorizon-master-watch-healthcheck".hex()},
                )
            except (MasterUnreachable, RpcError):
                log.warning(
                    "Cluster: master DB heartbeat and RPC healthcheck both failed"
                )
            else:
                log.warning(
                    "Cluster: master DB heartbeat is stale but RPC is healthy - "
                    "skipping election"
                )
                return

        if vs._cluster_share is None:
            # Either we're at first boot (no operator unseal yet) or we never
            # received a share. Either way, can't be a new master. Wait.
            log.debug(
                "Cluster: pid=%d master not detected, but no share to "
                "contribute - waiting for operator unseal",
                os.getpid(),
            )
            return

        log.info("Cluster: master not detected - running election")
        won = await run_election(async_session)
        # /unseal may have landed on this worker while its election delay was
        # in flight. In that case it is now the real operational master; an
        # election rollback must never seal it or latch its RPC server closed.
        if vs.is_master:
            log.warning(
                "Cluster: pid=%d became operational master during election - "
                "keeping the unsealed state",
                os.getpid(),
            )
            return
        if won:  # pragma: no cover  (failover, integ-only)
            reattach_after_failure = False
            # Serialize reconstruction + any rollback with operator unseal.
            # The potentially long wait for a replacement master happens after
            # releasing this lock, so an operator is never blocked for 120s.
            async with vs.master_transition_lock():
                if vs.is_master:
                    log.warning(
                        "Cluster: pid=%d became operational master before "
                        "failover reconstruction - keeping the unsealed state",
                        os.getpid(),
                    )
                    return
                log.warning("Cluster: pid=%d won master election", os.getpid())
                ok = await reconstruct_and_become_master(async_session, vs)
                if not ok:
                    # Quorum failed. The shared transition lock makes this
                    # check + DB rollback + local detach atomic against
                    # operator unseal and follower attachment.
                    if vs.is_master:
                        log.warning(
                            "Cluster: pid=%d became operational master during "
                            "failed failover - skipping rollback",
                            os.getpid(),
                        )
                        return
                    log.error(
                        "Cluster: pid=%d failover failed - reverting worker_state",
                        os.getpid(),
                    )
                    from sqlalchemy import text as _sa_text

                    from .cluster import get_hostname as _gh

                    async with async_session() as _db:
                        rollback_result = await _db.execute(
                            _sa_text(
                                "UPDATE vault_workers "
                                "SET worker_state = 'sealed', "
                                "last_heartbeat = NOW() "
                                "WHERE hostname = :h AND pid = :p"
                            ),
                            {"h": _gh(), "p": os.getpid()},
                        )
                        await _db.commit()
                    if rollback_result.rowcount != 1:
                        log.critical(
                            "Cluster: pid=%d election rollback lost worker row; "
                            "leaving local state untouched for heartbeat fencing",
                            os.getpid(),
                        )
                        return
                    await _detach(vs)
                    reattach_after_failure = True
            if reattach_after_failure:
                # Re-attach immediately rather than waiting for the persistent
                # reconciler's next pass. attach_to_master publishes FOLLOWER
                # atomically with the optional share-back socket.
                await _reattach(async_session, vs)
        else:
            # We lost, the winner will become master shortly. Detach our
            # dead RPC client and re-attach to the new master.
            log.info("Cluster: pid=%d lost election - re-attaching", os.getpid())
            async with vs.master_transition_lock():
                if vs.is_master:
                    log.warning(
                        "Cluster: pid=%d became operational master after losing "
                        "election - keeping the unsealed state",
                        os.getpid(),
                    )
                    return
                await _detach(vs)
            await _reattach(async_session, vs)

    tasks = [
        asyncio.create_task(heartbeat_loop(async_session)),
        asyncio.create_task(master_watch_loop(async_session, on_master_lost)),
    ]

    # Every worker (including the one that won the master claim at boot)
    # spawns the follower-boot loop. The boot-time master claim is purely
    # advisory: the *actual* operational master is whichever worker
    # happens to receive the operator's /unseal request (uvicorn round-
    # robins, we cannot pin it). So worker_state='master' in DB at boot
    # is just "first one to claim" ; the post-unseal handler in vault.py
    # is what rewires the real master. The follower-boot loop:
    #
    #   - polls for any other worker with worker_state='master' +
    #     crypto_socket_name (self-pid is excluded, see
    #     _wait_for_master_sockets)
    #   - attaches via RPC when found, sets vault._sealed=False
    #   - stays idle while THIS worker is the master itself (vault.is_master)
    #     because /unseal landed on us
    from .cluster_setup import attach_to_master, wire_rpc_recovery

    # install the proactive RPC recovery hook before
    # the follower boot loop. A master process that later steps down still
    # benefits ; calling the setter twice is idempotent.
    wire_rpc_recovery(vs, async_session, pid=os.getpid())

    async def _follower_boot():
        # Persistent reconciliation, not a one-shot boot task. A follower may
        # later be detached and sealed by a failed election; it must then be
        # able to attach to the still-live master again without a process
        # restart or another operator /unseal.
        while True:
            try:
                if not vs.is_master and (vs._rpc_client is None or vs.sealed):
                    # expect_master=False: pre-unseal there is legitimately no
                    # master, so a timeout is the awaiting-unseal steady state.
                    ok = await attach_to_master(async_session, vs, expect_master=False)
                    if ok:
                        log.info(
                            "Cluster: pid=%d became follower (RPC attached)",
                            os.getpid(),
                        )
            except Exception:
                log.warning(
                    "Cluster: follower reconciliation failed; retrying",
                    exc_info=True,
                )
            # No master yet (or newly attached); pause before the next state
            # reconciliation so this task stays cheap in the steady state.
            await asyncio.sleep(2.0)

    tasks.append(asyncio.create_task(_follower_boot()))

    return tasks


async def _shutdown_cluster():
    """Deregister this worker on graceful shutdown."""
    from .custody import is_separated_api

    if is_separated_api():
        return

    from .cluster import deregister_worker
    from .database import async_session

    try:
        async with async_session() as db:
            await deregister_worker(db)
    except Exception:
        log.warning("cluster shutdown deregister failed", exc_info=True)


async def _stop_local_cluster_services() -> None:
    """Stop local RPC/share servers and detach any follower client."""
    from .cluster_setup import stop_master_services

    try:
        # The worker row is deleted immediately afterwards, so there is no
        # value in first publishing cleared socket names to PostgreSQL.
        await stop_master_services(vs, db=None)
    except Exception:
        log.warning("cluster local-service shutdown failed", exc_info=True)
    finally:
        vs.detach_rpc_client()


async def _register_disposable_worker() -> asyncio.Task | None:
    """Put a disposable API worker in the registry, without a share or a vote.

    Separated custody makes these workers hold no key material, and the boot
    path that registers them in embedded mode is exactly the path that also
    hands out shares and runs master elections -- so skipping it took the whole
    registry with it. /cluster then reported no hosts at all, which is what an
    operator, the observability view and the HA tooling read to know a node is
    serving.

    FOLLOWER is the honest state here rather than a new one: it already means
    "delegates crypto over a Unix socket instead of holding the sub-keys", and
    that is precisely what these workers do -- they delegate to the custodian
    coordinator. No master claim, no election loop, no share: the custodian
    quorum owns all three, and a disposable worker must never contend for them.

    Failure is reported and swallowed. This row exists so operators and tools
    can SEE the worker; a vault that serves secrets perfectly well must not
    refuse to start because it could not describe itself.
    """
    from sqlalchemy import text

    from .cluster import WorkerState, get_hostname, heartbeat_loop, register_worker
    from .database import async_session

    try:
        node_uuid_val = _resolve_worker_node_uuid()
        async with async_session() as db:
            await register_worker(db, node_uuid=node_uuid_val)
            await db.execute(
                text(
                    "UPDATE vault_workers SET worker_state = :state "
                    "WHERE hostname = :host AND pid = :pid"
                ),
                {
                    "state": WorkerState.FOLLOWER.value,
                    "host": get_hostname(),
                    "pid": os.getpid(),
                },
            )
            await db.commit()
    except Exception:
        log.warning(
            "custody: disposable worker could not register; it will serve but "
            "will not appear in /cluster",
            exc_info=True,
        )
        return None
    return asyncio.create_task(heartbeat_loop(async_session), name="worker-heartbeat")


def _resolve_worker_node_uuid() -> str | None:
    """The container identity, or None when this process has none."""
    try:
        from .node_uuid import get_node_uuid

        return get_node_uuid()
    except Exception:
        return None


async def _init_disposable_api_custody() -> list[asyncio.Task]:
    """Attach public API workers to custody without registering a share row."""
    from .cluster_setup import attach_api_to_custodian, wire_api_custody_recovery
    from .database import async_session

    wire_api_custody_recovery(vs, async_session)

    async def _reconcile():
        while True:
            try:
                if vs._rpc_client is None or vs.sealed:
                    await attach_api_to_custodian(
                        async_session,
                        vs,
                        expect_master=False,
                    )
            except Exception:
                log.warning(
                    "custody API reconciliation failed; retrying", exc_info=True
                )
            await asyncio.sleep(2.0)

    tasks = [asyncio.create_task(_reconcile())]
    registered = await _register_disposable_worker()
    return tasks + [registered] if registered else tasks


async def _init_rust_api_custody() -> list[asyncio.Task]:
    """Attach an API worker to the opt-in standalone Rust custody pool."""
    # Resolve the shape the way the launcher did, from the same durable state.
    # Building the controller from the configuration instead would point it at
    # a shape the pool is not running: the extra sockets do not exist and the
    # live slots reject every call as exceeding their slot count, so the API
    # would fail to start whenever the configuration has moved ahead.
    from .custody_launch import launch_topology
    from .custody_routing import run_custody_routing
    from .database import async_session
    from .rust_custody_backend import (
        attach_reconciled_rust_custody,
        build_rust_custodian_pool,
        configure_rust_custody_pool,
        wire_rust_custody_recovery,
    )
    from .socket_paths import runtime_dir

    decided = await launch_topology(
        async_session,
        (settings.rust_custodian_threshold, settings.rust_custodian_slots),
    )
    pool = build_rust_custodian_pool(
        runtime_directory=runtime_dir(),
        control_token_file=settings.custodian_token_file,
        slots=decided.slots,
        threshold=decided.threshold,
    )
    configure_rust_custody_pool(pool)
    wire_rust_custody_recovery(pool, vs, session_factory=async_session)
    try:
        attached = await attach_reconciled_rust_custody(
            pool,
            vs,
            session_factory=async_session,
        )
    except CustodianPoolUnavailable:
        # No slot holds the durable generation. That is the NORMAL state after
        # a restart now that shares are not persisted, and it must not be
        # fatal: coming up sealed lets /unseal re-derive from the master
        # password and re-split into the pool, while exiting leaves no path
        # back at all -- the API is the only thing that can serve the unseal
        # that would fix it. Refusing to start is the break-glass trap in its
        # purest form, and it took the whole lab down when persistence went
        # away.
        #
        # The maintenance loop keeps retrying, so a pool that merely lost
        # quorum transiently still reattaches on its own.
        log.warning(
            "Rust custody: no reachable quorum at startup; "
            "serving sealed until unsealed",
            exc_info=True,
        )
        attached = False
    if attached:
        log.info("Rust custody: API attached to reconciled fixed quorum")
    else:
        log.info("Rust custody: API remains sealed by durable operator intent")
    tasks = [
        asyncio.create_task(
            run_custody_routing(
                pool,
                vs,
                session_factory=async_session,
                interval_seconds=settings.rust_custody_maintenance_interval_secs,
            ),
            name="rust-custody-maintenance",
        ),
    ]
    registered = await _register_disposable_worker()
    if registered is not None:
        tasks.append(registered)
    return tasks


async def _cancel_background_tasks(tasks: list[asyncio.Task]) -> None:
    """Cancel tasks and wait until every cancellation cleanup has run."""
    for task in tasks:
        task.cancel()
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for task, result in zip(tasks, results, strict=True):
        if isinstance(result, BaseException) and not isinstance(
            result, asyncio.CancelledError
        ):
            log.warning(
                "background task %s ended with an error during shutdown: %r",
                task.get_name(),
                result,
            )


@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("rhorizon %s starting", settings.version)
    # Attempt to pin pages into RAM and forbid core dumps before secrets are
    # decrypted. Memory locking follows the operator-selected policy.
    from .mem_hardening import harden_process_memory

    memory_capacity_workers = settings.workers
    memory_capacity_rust_slots = 0
    if settings.custody_mode == "separated" and settings.process_role == "api":
        # Both pools share one container/cgroup. The public process retains the
        # operator's API count, so it can issue the combined headroom warning;
        # custodian children see only their own fixed pool size.
        #
        # A Python custodian IS a worker -- the same uvicorn app under a
        # different role -- so it costs a worker. A Rust custodian is a small
        # daemon holding one share and is budgeted as such; charging it a full
        # worker warned operators off limits with over a gigabyte to spare.
        if settings.custody_backend == "rust":
            memory_capacity_rust_slots = settings.rust_custodian_slots
        else:
            memory_capacity_workers += settings.custodian_workers
    harden_process_memory(
        memlock_all=settings.memlock_all,
        disable_core_dumps=settings.disable_core_dumps,
        # uvicorn worker count drives the mlockall memory-headroom guard.
        workers=memory_capacity_workers,
        rust_custodian_slots=memory_capacity_rust_slots,
        memory_lock_required=settings.memory_lock_mode == "required",
    )
    # Refuse-to-boot if HA is enabled without TLS. Run before DB access or
    # background loops so a misconfigured container exits without serving.
    from .ha_boot_check import (
        enforce_cluster_cert_perms_invariant,
        enforce_ha_tls_invariant,
    )

    enforce_ha_tls_invariant(settings.cluster_ha_enabled, settings.tls_enabled)
    # If a cluster-cert pair is already on disk (returning node),
    # validate file mode before any cluster RPC kicks in.
    if settings.cluster_ha_enabled:
        enforce_cluster_cert_perms_invariant(
            settings.cluster_cert_path, settings.cluster_cert_key_path
        )
    await _apply_schema()
    await _migrate_namespaces()

    # Parse the cluster-wide fine-grained state only after schema availability,
    # then import the enabled subset. The initializer also refuses to strand
    # persisted engines behind a disabled module.
    from .database import async_session as _dynamic_session

    async with _dynamic_session() as _db:
        await dynamic.initialize_engine_registry(_db)

    # load (or generate at first boot) this container's node_uuid
    # from the persistent volume. Corruption raises and aborts startup -
    # an unreliable identity is worse than a clean refuse-to-boot.
    from .node_uuid import init_node_uuid

    node_uuid_val = init_node_uuid(settings.node_uuid_path)
    log.info("node_uuid initialised (prefix=%s...)", node_uuid_val[:8])

    # seed the in-process trusted-proxy list from the DB-backed
    # proxy_config (if any) so UI-edited values take effect at boot
    # without needing the env var to be set. Falls back to env (already
    # parsed at module import) if no DB config exists yet.
    from .client_ip import get_identity_trusted_proxies as _get_identity_proxies
    from .client_ip import set_trusted_proxies as _set_proxies

    _db_proxy_enabled = False
    _db_proxy_config_present = False
    try:
        from sqlalchemy import text as _sa_text

        from .database import async_session as _async_session

        async with _async_session() as _db:
            r = await _db.execute(
                _sa_text("SELECT value FROM vault_config WHERE key = 'proxy_config'")
            )
            row = r.fetchone()
            if row:
                _db_proxy_config_present = True
                import json as _json

                cfg = _json.loads(row.value)
                if not isinstance(cfg, dict):
                    raise ValueError("proxy_config must be a JSON object")
                trusted_ips = cfg.get("trusted_ips") or ""
                if not isinstance(trusted_ips, str):
                    raise ValueError("proxy_config.trusted_ips must be a string")
                enabled = cfg.get("enabled", False)
                if not isinstance(enabled, bool):
                    raise ValueError("proxy_config.enabled must be a boolean")
                _set_proxies(trusted_ips, reject_invalid=True)
                _db_proxy_enabled = enabled
    except Exception:
        # A present but unreadable DB override must never leave a potentially
        # broader environment trust list active.
        _set_proxies("")
        log.warning(
            "trusted-proxy seed from DB failed; identity proxies cleared; "
            "XFF-only trust unchanged",
            exc_info=True,
        )

    _effective_proxy_auth_enabled = (
        _db_proxy_enabled if _db_proxy_config_present else settings.proxy_auth_enabled
    )
    if (
        _effective_proxy_auth_enabled or settings.cluster_ha_enabled
    ) and not _get_identity_proxies():
        raise RuntimeError(
            "trusted proxy IPs are required when proxy authentication "
            "or cluster HA is enabled"
        )

    # Any trusted proxy can supply the client IP used by token ACLs, rate
    # limiting and audit. Wide ranges remain supported for dedicated cloud-LB
    # subnets, but always surface their enlarged trust boundary.
    from .client_ip import overly_broad_proxies as _broad_proxies

    _broad = _broad_proxies()
    if _broad:
        log.warning(
            "trusted proxy configuration has wide range(s) %s; every host in "
            "those ranges can supply X-Forwarded-For values used by token "
            "IP ACLs, rate limiting and audit; prefer dedicated proxy "
            "subnets or individual proxy addresses",
            _broad,
        )

    log.info("Vault is SEALED - POST /api/v1/vault/unseal to unlock")

    # In embedded mode the public workers form the Shamir quorum. In separated
    # mode only the fixed UDS-only custodian pool registers here; disposable
    # API workers attach RPC-only and never consume a share.
    from .custody import is_rust_custody_api, is_separated_api

    cluster_tasks: list[asyncio.Task] = []
    try:
        if is_rust_custody_api():
            cluster_tasks = await _init_rust_api_custody()
            log.info("Rust custody: disposable API worker started without share")
        elif is_separated_api():
            cluster_tasks = await _init_disposable_api_custody()
            log.info("separated custody: disposable API worker started without share")
        else:
            cluster_tasks = await _init_cluster()
    except Exception:
        log.critical(
            "Cluster init failed; refusing worker startup",
            exc_info=True,
        )
        raise

    # Maintenance belongs to the disposable API pool. Custodians run only
    # custody/election and the key-holder HA heartbeat; keeping audit scans,
    # lease cleanup and notification work out of their cgroup is the point of
    # the process separation.
    from .custody import is_custodian

    reaper_task: asyncio.Task | None = None
    audit_lite_checkpoint_task: asyncio.Task | None = None
    audit_verify_task: asyncio.Task | None = None
    if not is_custodian():
        reaper_task = asyncio.create_task(_reaper_loop())
        audit_lite_checkpoint_task = asyncio.create_task(_audit_lite_checkpoint_loop())
        from .audit_verify_jobs import audit_verify_job_loop

        audit_verify_task = asyncio.create_task(audit_verify_job_loop())

    # inter-host HA loops. Three asyncio tasks
    # (state machine, joining-orphan reaper, per-node heartbeat) gated
    # on settings.cluster_ha_enabled. When HA is off, none of the loops
    # run -- the rest of the vault behaves exactly as a single-node
    # deployment.
    ha_loop_tasks: list[asyncio.Task] = []
    if settings.cluster_ha_enabled:
        from .cluster_ha_loops import (
            cluster_ha_heartbeat_loop,
            cluster_ha_reaper_loop,
            cluster_ha_state_machine_loop,
        )

        if is_custodian():
            # Only the custody master can publish/recover the node rekey
            # generation. The loop is otherwise harmless on share followers.
            ha_loop_tasks = [asyncio.create_task(cluster_ha_heartbeat_loop())]
            log.info("custodian HA key-holder heartbeat started")
        else:
            ha_loop_tasks = [
                asyncio.create_task(cluster_ha_state_machine_loop()),
                asyncio.create_task(cluster_ha_reaper_loop()),
                asyncio.create_task(cluster_ha_heartbeat_loop()),
            ]
            log.info("HA loops started (state-machine + reaper + heartbeat)")

    # one-shot auto-JOIN task. The task gates
    # itself on the unseal transition and the absence of an on-disk
    # cluster cert, so it is safe to always create when HA is on -- it
    # exits early when there is nothing to do.
    auto_join_task: asyncio.Task | None = None
    if settings.cluster_ha_enabled and settings.ha_auto_join and not is_custodian():
        from .cluster_auto_join import cluster_auto_join_task

        auto_join_task = asyncio.create_task(cluster_auto_join_task())
        log.info("auto-JOIN task scheduled")

    # per-node cert renewal loop. Polls the
    # on-disk cert against the renewal threshold + the force_renew_at
    # flag. Each node runs its own loop (NOT singleton -- cert renewal
    # is local data with no cross-node coordination needed). Gated on
    # cluster_ha_enabled ; the loop's own first check short-circuits
    # when no cert is on disk yet.
    cert_renewal_task: asyncio.Task | None = None
    if settings.cluster_ha_enabled and not is_custodian():
        from .cluster_cert_renewal import cluster_cert_renewal_loop

        cert_renewal_task = asyncio.create_task(cluster_cert_renewal_loop())
        log.info("cert renewal loop scheduled")

    yield

    # Shutdown: wait for every task's cancellation cleanup before tearing down
    # the local RPC services and zeroizing key material.
    background_tasks = [
        *([cert_renewal_task] if cert_renewal_task is not None else []),
        *([auto_join_task] if auto_join_task is not None else []),
        *ha_loop_tasks,
        *(
            [audit_lite_checkpoint_task]
            if audit_lite_checkpoint_task is not None
            else []
        ),
        *([audit_verify_task] if audit_verify_task is not None else []),
        *([reaper_task] if reaper_task is not None else []),
        *cluster_tasks,
    ]
    await _cancel_background_tasks(background_tasks)
    await _stop_local_cluster_services()
    if not vs.sealed:
        vs.seal()
        _metrics.seal_events.labels(trigger="shutdown").inc()
        _metrics.set_vault_sealed(True)
        log.info("Vault sealed on shutdown")
    # DB cleanup comes last: a slow/unavailable database must never delay local
    # RPC teardown or in-memory key zeroization.
    await _shutdown_cluster()


app = FastAPI(
    title="rhorizon",
    description="Self-hosted secrets vault - API reference",
    version=settings.version,
    docs_url="/docs" if settings.enable_docs else None,
    redoc_url="/redoc" if settings.enable_docs else None,
    openapi_url="/openapi.json" if settings.enable_docs else None,
    lifespan=lifespan,
)


# -- Request body size limit --------------------------------------------------


class RequestBodyTooLarge(Exception):
    def __init__(self, max_size: int):
        self.max_size = max_size


def _max_body_size(path: str, method: str) -> int:
    if method == "POST" and path == "/api/v1/vault/backup/restore":
        return settings.max_body_backup
    return settings.max_body_bytes


def _body_too_large_response(max_size: int) -> JSONResponse:
    return JSONResponse(
        status_code=413,
        content={
            "error": "Request body too large",
            "max_bytes": max_size,
        },
    )


def _invalid_body_framing_response(reason: str) -> JSONResponse:
    return JSONResponse(
        status_code=400,
        content={
            "error": "Invalid request body framing",
            "detail": reason,
        },
    )


class RequestBodyLimitMiddleware:
    """Reject oversized request bodies, including streamed/chunked bodies."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        max_size = _max_body_size(
            scope.get("path", ""),
            scope.get("method", ""),
        )
        raw_headers = scope.get("headers") or []
        content_lengths = [
            value for name, value in raw_headers if name.lower() == b"content-length"
        ]
        transfer_encodings = [
            value for name, value in raw_headers if name.lower() == b"transfer-encoding"
        ]

        if len(content_lengths) > 1:
            await _invalid_body_framing_response("duplicate Content-Length")(
                scope, receive, send
            )
            return
        if content_lengths and transfer_encodings:
            await _invalid_body_framing_response(
                "Content-Length conflicts with Transfer-Encoding"
            )(scope, receive, send)
            return
        if content_lengths:
            content_length = content_lengths[0]
            if not content_length or not content_length.isdigit():
                await _invalid_body_framing_response("invalid Content-Length")(
                    scope, receive, send
                )
                return

            # Compare decimal strings instead of parsing an attacker-controlled
            # unbounded integer (Python deliberately rejects huge int strings).
            normalized = content_length.lstrip(b"0") or b"0"
            max_ascii = str(max_size).encode("ascii")
            if len(normalized) > len(max_ascii) or (
                len(normalized) == len(max_ascii) and normalized > max_ascii
            ):
                await _body_too_large_response(max_size)(scope, receive, send)
                return

        received = 0

        async def limited_receive():
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > max_size:
                    raise RequestBodyTooLarge(max_size)
            return message

        try:
            await self.app(scope, limited_receive, send)
        except RequestBodyTooLarge as exc:
            await _body_too_large_response(exc.max_size)(scope, receive, send)


app.add_middleware(RequestBodyLimitMiddleware)


# -- Admission control / load shedding ----------------------------------------

# Cheap probes remain fully exempt so overload cannot hide node health.
_ADMISSION_PROBE_EXEMPT = (
    "/health",
    "/readiness",
    "/metrics",
)
_UNSEAL_PATH = "/api/v1/vault/unseal"
_UNSEAL_CONCURRENCY_CAP = 1


def _retry_after(base: int = 1, spread: int = 2) -> str:
    """Jittered Retry-After (seconds). Spreads synchronized client retries so
    a shed crowd doesn't re-stampede in lockstep one second later (thundering
    herd). Returns base..base+spread as an integer-seconds string."""
    return str(base + random.randint(0, spread))


def _load_shed_response(
    reason: str = "request_concurrency_limit",
) -> JSONResponse:
    # 429, NOT 503 : this is transient backpressure ("I'm busy, retry shortly"),
    # not unavailability. A 503 here makes a passive LB / outlier-detector
    # (HAProxy on-error mark-down, Envoy consecutive_5xx, nginx http_503) eject
    # a healthy-but-busy node -- which cascades a traffic spike into an outage
    # as every node sheds and gets pulled at once. 429 is not a 5xx, so the
    # connection chain backs off WITHOUT ejecting. Persistent unavailability
    # (sealed / quarantined) deliberately stays 503 so the chain DOES pull the
    # node.
    retry_after = _retry_after()
    message = (
        "Another unseal attempt is active; retry after backoff"
        if reason == "unseal_concurrency_limit"
        else "Node request capacity reached; retry after backoff"
    )
    return JSONResponse(
        status_code=429,
        content={
            "error": "capacity_overloaded",
            "reason": reason,
            "message": message,
            "retryable": True,
        },
        headers={
            "Retry-After": retry_after,
            "X-Rhorizon-Overload": reason,
        },
    )


def _req_transport(scope) -> str:
    """http | https from X-Forwarded-Proto (set by the nginx TLS frontend).
    Direct API clients have no such header -> http. Metric label only; no trust
    or security decision hangs on it."""
    for name, value in scope.get("headers", ()):
        if name == b"x-forwarded-proto":
            return "https" if value.strip().lower() == b"https" else "http"
    return "http"


class MaxConcurrencyMiddleware:
    """Shed load above a per-worker in-flight request cap (admission control).

    Bounds the request pile-up that, under congestion collapse, starves the
    event loop and the cluster coordination loops (heartbeat / master-RPC)
    into a defensive seal. Requests above the cap get an immediate 429 +
    Retry-After instead of queueing until the client timeout. Disabled when
    settings.max_concurrent_requests == 0. Cheap probes are exempt. Unseal has
    one reserved slot per worker so recovery remains possible without building
    an unbounded queue around the master-transition lock and Argon2.
    """

    def __init__(self, app):
        self.app = app
        self._inflight = 0
        self._unseal_inflight = 0

    async def __call__(self, scope, receive, send):
        cap = settings.max_concurrent_requests
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "")
        if path in _ADMISSION_PROBE_EXEMPT:
            await self.app(scope, receive, send)
            return

        if path == _UNSEAL_PATH and scope.get("method") == "POST":
            if self._unseal_inflight >= _UNSEAL_CONCURRENCY_CAP:
                _metrics.requests_shed.labels(reason="unseal_concurrency_limit").inc()
                await _load_shed_response("unseal_concurrency_limit")(
                    scope, receive, send
                )
                return
            self._unseal_inflight += 1
            _metrics.requests_inflight.inc()
            _metrics.requests_by_transport.labels(transport=_req_transport(scope)).inc()
            try:
                await self.app(scope, receive, send)
            finally:
                self._unseal_inflight -= 1
                _metrics.requests_inflight.dec()
            return

        if cap <= 0:
            _metrics.requests_by_transport.labels(transport=_req_transport(scope)).inc()
            await self.app(scope, receive, send)
            return
        if self._inflight >= cap:
            _metrics.requests_shed.labels(reason="request_concurrency_limit").inc()
            await _load_shed_response()(scope, receive, send)
            return
        self._inflight += 1
        _metrics.requests_inflight.inc()
        _metrics.requests_by_transport.labels(transport=_req_transport(scope)).inc()
        try:
            await self.app(scope, receive, send)
        finally:
            self._inflight -= 1
            _metrics.requests_inflight.dec()


app.add_middleware(MaxConcurrencyMiddleware)

# Outermost local custody boundary. In embedded mode this is a no-op. In
# separated API processes it proxies only key-generation lifecycle handlers to
# the UDS pool; in custodian processes it rejects every request without the
# file-backed control capability.
app.add_middleware(CustodyBoundaryMiddleware)


# Routes
app.include_router(vault.router)
app.include_router(secrets.router)
app.include_router(tokens.router)
app.include_router(namespaces.router)
app.include_router(audit.router)
app.include_router(auth_ldap.router)
app.include_router(auth_proxy.router)
app.include_router(groups.router)
app.include_router(notifications.router)
app.include_router(backup.router)
app.include_router(dynamic.router)
app.include_router(pki.router)
app.include_router(webauthn.router)
app.include_router(oneshot.router)
app.include_router(cluster_route.router)
app.include_router(observability.router)
app.include_router(_metrics.router)


@app.exception_handler(VaultSealedError)
async def sealed_handler(request: Request, exc: VaultSealedError):
    # Bump the sealed-attempt counter, bucketed by HTTP method (read vs
    # write) for ops dashboards. Steady non-zero rate after an unseal
    # is the canary for "automation still calling with stale config".
    from .client_ip import get_client_ip
    from .metrics import sealed_op_attempts

    op = (
        "read"
        if request.method in ("GET", "HEAD")
        else (
            "write" if request.method in ("POST", "PUT", "DELETE", "PATCH") else "other"
        )
    )
    sealed_op_attempts.labels(op=op).inc()
    # The Prometheus counter is intentionally label-free for IP (high
    # cardinality kills the index). For investigation, log IP + path
    # here so an operator can grep the journal once the alert fires :
    # "which client kept hitting us post-seal?". Counter stays bounded.
    try:
        client_ip = get_client_ip(request)
    except Exception:
        client_ip = "unknown"
    _log_sealed_rejection(
        request.method,
        request.url.path,
        client_ip,
    )
    return JSONResponse(
        status_code=503,
        content={"error": "Vault is sealed", "detail": "POST /api/v1/vault/unseal"},
    )


@app.exception_handler(MasterUnreachable)
async def _master_unreachable_handler(request: Request, exc: MasterUnreachable):
    """A crypto-op exhausted this worker's RPC recovery budget.

    The in-flight request gets ``429 + jittered Retry-After`` so a transient
    failover does not count as an upstream 5xx. ``VaultState`` simultaneously
    fences this worker: its next readiness probe returns 503 until a direct
    RPC healthcheck succeeds. This removes a persistently broken follower from
    rotation without electing against a master whose DB heartbeat is fresh.
    """
    log.warning(
        "rpc: master unreachable on %s %s (%s)",
        request.method,
        request.url.path,
        exc,
    )
    return JSONResponse(
        status_code=429,
        headers={"Retry-After": _retry_after()},
        content={"error": "cluster_recovering", "detail": "retry shortly"},
    )


@app.exception_handler(CustodyQuorumUnavailable)
async def _custody_quorum_handler(request: Request, exc: CustodyQuorumUnavailable):
    """This worker tried to attach to a coordinator and could not.

    503, not the 429 orchestration contention gets: attaching was already
    retried inside ensure_control_plane, so by the time this surfaces the
    quorum really is unreachable and an immediate client retry only repeats
    the same wait. Sealed is reported separately -- an operator told this
    vault to seal, and calling that a quorum failure sends them to repair a
    pool that is fine.

    The exception message names slot numbers, so it stays in the log. The body
    says only that the quorum is unavailable.
    """
    log.error(
        "custody: quorum unavailable on %s %s (%s)",
        request.method,
        request.url.path,
        exc,
    )
    return JSONResponse(
        status_code=503,
        content={
            "error": "custody_quorum_unavailable",
            "detail": "the custodian quorum could not be reached",
        },
    )


@app.exception_handler(CustodianPoolUnavailable)
async def _custodian_pool_handler(request: Request, exc: CustodianPoolUnavailable):
    """A custody operation could not assemble a quorum from the slot pool.

    This was an UNHANDLED 500 until now: the class is a bare RuntimeError, it
    is not a MasterUnreachable so _call_rpc's recovery hook never sees it, and
    only custody_shred and backup/restore caught it. Every other raise -- the
    rotate-password and rotate-dek-key paths above all -- reached the client as
    a server error, which reads as "the vault is broken" for what is usually
    one slot being briefly short.

    503 with Retry-After, because the shortfall is normally transient: the
    maintenance leader reopens the pool on its own tick.

    The message names slot numbers and daemon state, so it is logged and never
    returned. The body says only that the quorum was unavailable.
    """
    log.error(
        "custody: pool unavailable on %s %s (%s)",
        request.method,
        request.url.path,
        exc,
    )
    return JSONResponse(
        status_code=503,
        headers={"Retry-After": _retry_after()},
        content={
            "error": "custody_quorum_unavailable",
            "detail": "the custodian quorum could not be reached",
        },
    )


@app.exception_handler(CustodyOrchestrationBusy)
async def _custody_busy_handler(request: Request, exc: CustodyOrchestrationBusy):
    """Another custody operation held the orchestration lock; nothing ran.

    Reaches here only when contention outlasts the caller's bounded wait, which
    the boot of a large worker pool can do: /health answers as soon as the
    FIRST worker is ready while the rest still reconcile under this lock.

    429 for the same reason as ``cluster_recovering`` (see
    tests/test_admission_429.py): this is TRANSIENT, and a 5xx would let a
    passive load balancer eject a healthy-but-busy node over a routine restart
    race. Persistent unavailability keeps 503. Deliberately not the uncaught
    500 this used to be, which made a restart race look like a broken vault at
    exactly the moment an operator is unsealing.
    """
    log.warning(
        "custody: orchestration lock busy on %s %s (%s)",
        request.method,
        request.url.path,
        exc,
    )
    return JSONResponse(
        status_code=429,
        headers={"Retry-After": _retry_after()},
        content={"error": "custody_busy", "detail": "retry shortly"},
    )


@app.get("/health")
async def health():
    """Liveness probe - process is up. Returns 200 even if sealed.
    Use as Kubernetes `livenessProbe`."""
    return {"status": "ok"}


@app.get("/readiness")
async def readiness():
    """Readiness probe - 200 only if vault is unsealed.

    Use as Kubernetes `readinessProbe` to keep the load balancer from
    routing traffic to a sealed pod. A pod that just started or just
    restarted is sealed by design and can serve `/health` (liveness)
    but should NOT receive auth-bearing traffic - that traffic would
    get 503 anyway, and pollute the audit log with auth failures.

    PostgreSQL is required in every deployment, including single-node mode, so
    an unavailable database also blocks readiness. In HA mode, additionally
    fail when this worker exhausted master-RPC recovery or when this node has
    been quarantined by the key-epoch fence (another host rotated past us; our
    in-RAM keys are stale and every read would fail).
    """
    if vs.sealed:
        return JSONResponse({"status": "sealed"}, status_code=503)
    if not await _database_ready():
        return JSONResponse(
            {
                "status": "database_unreachable",
                "component": "postgresql",
            },
            status_code=503,
        )
    if settings.cluster_ha_enabled and vs.rpc_fenced:
        if not await vs.probe_fenced_rpc():
            return JSONResponse({"status": "rpc_unreachable"}, status_code=503)
    if settings.cluster_ha_enabled:
        quarantine_state = await _node_quarantine_blocking_state()
        if quarantine_state is not None:
            return JSONResponse(
                {
                    "status": quarantine_state,
                    "component": "cluster_membership",
                },
                status_code=503,
            )
    auto_join_state = await _auto_join_blocking_state()
    if auto_join_state is not None:
        return JSONResponse(
            {
                "status": "auto_join_pending",
                "ha_state": auto_join_state,
            },
            status_code=503,
        )
    return {"status": "ready"}


async def _database_ready() -> bool:
    """Run the universal PostgreSQL readiness probe within a strict budget."""
    from sqlalchemy import text

    from .database import async_session

    async def _probe() -> None:
        async with async_session() as db:
            await db.execute(text("SELECT 1"))

    try:
        await asyncio.wait_for(_probe(), timeout=_DATABASE_READINESS_TIMEOUT_SECS)
    except Exception:
        return False
    return True


async def _auto_join_blocking_state() -> str | None:
    """Return the non-serving HA state of an expected auto-joiner.

    ``ha_primary_url`` marks this node as one that must join an existing
    cluster. PostgreSQL membership is authoritative: a local certificate can
    be stale after eviction or a database restore. Only ``primary`` and
    ``secondary`` may enter rotation. Missing or unreadable membership fails
    closed so an exhausted auto-JOIN task cannot expose a standalone node.
    """
    if not (
        settings.cluster_ha_enabled
        and settings.ha_auto_join
        and settings.ha_primary_url.strip()
    ):
        return None

    from sqlalchemy import text

    from .database import async_session
    from .node_uuid import get_node_uuid

    try:
        async with async_session() as db:
            row = (
                await db.execute(
                    text(
                        "SELECT ha_state FROM vault_cluster_nodes WHERE node_uuid = :u"
                    ),
                    {"u": get_node_uuid()},
                )
            ).fetchone()
    except Exception:
        # Readiness probes are frequent; the database health signal already
        # carries the detailed error. The safe result here is simply not-ready.
        return "unknown"

    if row is None:
        return "unjoined"
    return None if row.ha_state in {"primary", "secondary"} else row.ha_state


async def _node_quarantine_blocking_state() -> str | None:
    """Return the cluster-membership state that must block readiness.

    ``quarantined`` is the durable key-epoch fence. ``unknown`` means its
    PostgreSQL state could not be verified. Both fail closed: uncertainty must
    not route requests to a worker that may hold stale cryptographic keys.
    """
    from sqlalchemy import text

    from .database import async_session
    from .node_uuid import get_node_uuid

    try:
        node_uuid = get_node_uuid()
        async with async_session() as db:
            r = await db.execute(
                text(
                    "SELECT 1 FROM vault_cluster_nodes "
                    "WHERE node_uuid = :u AND ha_state = 'quarantined'"
                ),
                {"u": node_uuid},
            )
            return "quarantined" if r.fetchone() is not None else None
    except Exception:
        return "unknown"
