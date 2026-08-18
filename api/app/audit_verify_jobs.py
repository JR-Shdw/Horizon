# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Persistent, cluster-wide background jobs for full audit verification."""

import asyncio
import json
import logging
import os
from contextlib import suppress
from uuid import UUID

from sqlalchemy import text

from .cluster import get_hostname
from .database import async_session
from .vault_state import vault

log = logging.getLogger("rhorizon.audit_verify_jobs")

_POLL_SECONDS = 2
_HEARTBEAT_SECONDS = 10
_STALE_AFTER = "1 minute"


def _job_dict(row) -> dict[str, object]:
    result = row.result
    if isinstance(result, str):
        result = json.loads(result)
    return {
        "job_id": str(row.id),
        "status": row.status,
        "requested_at": row.requested_at.isoformat(),
        "started_at": row.started_at.isoformat() if row.started_at else None,
        "finished_at": row.finished_at.isoformat() if row.finished_at else None,
        "requested_by": row.requested_by,
        "worker_host": row.worker_host,
        "worker_pid": row.worker_pid,
        "heartbeat_at": row.heartbeat_at.isoformat() if row.heartbeat_at else None,
        "result": result,
        "error": row.error,
    }


async def enqueue_audit_verify(requested_by: str) -> tuple[dict[str, object], bool]:
    """Create a job, or return the already-active cluster-wide job."""
    async with async_session() as db:
        await db.execute(
            text(
                "SELECT pg_advisory_xact_lock(hashtext('rhorizon:audit_verify_submit'))"
            )
        )
        active = (
            await db.execute(
                text(
                    "SELECT * FROM vault_audit_verify_jobs "
                    "WHERE status IN ('pending', 'running') "
                    "ORDER BY requested_at LIMIT 1"
                )
            )
        ).fetchone()
        if active is not None:
            await db.commit()
            return _job_dict(active), False

        row = (
            await db.execute(
                text(
                    "INSERT INTO vault_audit_verify_jobs (requested_by) "
                    "VALUES (:requested_by) RETURNING *"
                ),
                {"requested_by": requested_by or "unknown"},
            )
        ).fetchone()
        await db.commit()
        return _job_dict(row), True


async def get_audit_verify_job(job_id: UUID) -> dict[str, object] | None:
    async with async_session() as db:
        row = (
            await db.execute(
                text(
                    "SELECT * FROM vault_audit_verify_jobs "
                    "WHERE id = CAST(:job_id AS uuid)"
                ),
                {"job_id": str(job_id)},
            )
        ).fetchone()
    return _job_dict(row) if row is not None else None


async def _claim_job() -> UUID | None:
    """Atomically recover a stale job and claim the oldest pending one."""
    # A sealed worker can verify Ed25519 rows but cannot authoritatively verify
    # legacy HMAC rows. Leave the durable job pending for an unsealed worker.
    if vault.sealed:
        return None
    async with async_session() as db:
        await db.execute(
            text(
                "UPDATE vault_audit_verify_jobs "
                "SET status = 'pending', started_at = NULL, worker_host = NULL, "
                "worker_pid = NULL, heartbeat_at = NULL, "
                "error = 'recovered after stale worker' "
                "WHERE status = 'running' "
                "AND COALESCE(heartbeat_at, started_at) "
                f"< clock_timestamp() - INTERVAL '{_STALE_AFTER}'"
            )
        )
        row = (
            await db.execute(
                text(
                    "SELECT id FROM vault_audit_verify_jobs "
                    "WHERE status = 'pending' ORDER BY requested_at "
                    "FOR UPDATE SKIP LOCKED LIMIT 1"
                )
            )
        ).fetchone()
        if row is None:
            await db.commit()
            return None

        job_id = row.id
        await db.execute(
            text(
                "UPDATE vault_audit_verify_jobs "
                "SET status = 'running', started_at = clock_timestamp(), "
                "finished_at = NULL, worker_host = :host, worker_pid = :pid, "
                "heartbeat_at = clock_timestamp(), result = NULL, error = NULL "
                "WHERE id = :job_id"
            ),
            {"host": get_hostname(), "pid": os.getpid(), "job_id": job_id},
        )
        await db.commit()
        return UUID(str(job_id))


async def _finish_job(
    job_id: UUID,
    *,
    status: str,
    result: dict[str, object] | None = None,
    error: str | None = None,
) -> None:
    async with async_session() as db:
        await db.execute(
            text(
                "UPDATE vault_audit_verify_jobs "
                "SET status = :status, finished_at = clock_timestamp(), "
                "result = CAST(:result AS jsonb), error = :error "
                "WHERE id = CAST(:job_id AS uuid) AND status = 'running' "
                "AND worker_host = :host AND worker_pid = :pid"
            ),
            {
                "job_id": str(job_id),
                "status": status,
                "result": json.dumps(result) if result is not None else None,
                "error": error,
                "host": get_hostname(),
                "pid": os.getpid(),
            },
        )
        await db.commit()


async def _requeue_cancelled_job(job_id: UUID) -> None:
    async with async_session() as db:
        await db.execute(
            text(
                "UPDATE vault_audit_verify_jobs "
                "SET status = 'pending', started_at = NULL, worker_host = NULL, "
                "worker_pid = NULL, heartbeat_at = NULL, "
                "error = 'worker stopped; job requeued' "
                "WHERE id = CAST(:job_id AS uuid) AND status = 'running' "
                "AND worker_host = :host AND worker_pid = :pid"
            ),
            {
                "job_id": str(job_id),
                "host": get_hostname(),
                "pid": os.getpid(),
            },
        )
        await db.commit()


async def _heartbeat_job(job_id: UUID) -> None:
    while True:
        await asyncio.sleep(_HEARTBEAT_SECONDS)
        try:
            async with async_session() as db:
                await db.execute(
                    text(
                        "UPDATE vault_audit_verify_jobs "
                        "SET heartbeat_at = clock_timestamp() "
                        "WHERE id = CAST(:job_id AS uuid) "
                        "AND status = 'running' "
                        "AND worker_host = :host AND worker_pid = :pid"
                    ),
                    {
                        "job_id": str(job_id),
                        "host": get_hostname(),
                        "pid": os.getpid(),
                    },
                )
                await db.commit()
        except asyncio.CancelledError:
            raise
        except Exception:
            log.warning("audit verification heartbeat failed", exc_info=True)


async def _execute_job(job_id: UUID) -> None:
    # Lazy import avoids routes -> jobs -> routes import cycles.
    from .routes.audit import verify_chain

    heartbeat_task = asyncio.create_task(_heartbeat_job(job_id))
    try:
        async with async_session() as db:
            result = await verify_chain(
                db=db,
                token_info={
                    "name": "audit-verify-background",
                    "permissions": {"audit": "r"},
                },
            )
        await _finish_job(job_id, status="succeeded", result=result)
    except asyncio.CancelledError:
        await asyncio.shield(_requeue_cancelled_job(job_id))
        raise
    except Exception as exc:
        # Do not persist a traceback or request material. The bounded exception
        # string is enough for operators; full details stay in protected logs.
        error = f"{type(exc).__name__}: {exc}"[:1000]
        log.exception("audit verification job %s failed", job_id)
        await _finish_job(job_id, status="failed", error=error)
    finally:
        heartbeat_task.cancel()
        with suppress(asyncio.CancelledError):
            await heartbeat_task


async def audit_verify_job_loop() -> None:
    """Claim and execute persisted jobs on any healthy API worker."""
    while True:  # pragma: no cover - exercised through helpers
        try:
            job_id = await _claim_job()
            if job_id is None:
                await asyncio.sleep(_POLL_SECONDS)
                continue
            await _execute_job(job_id)
        except asyncio.CancelledError:
            raise
        except Exception:
            log.warning("audit verification job loop error", exc_info=True)
            await asyncio.sleep(_POLL_SECONDS)
