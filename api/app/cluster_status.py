# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Read-only cluster projections shared by routes and HA preflight."""

import os

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from .cluster import crypto_socket_prefix, get_hostname, resolve_lock_name
from .cluster_health import cluster_health
from .node_uuid import get_node_uuid
from .vault_state import VaultState


async def health_snapshot(db: AsyncSession, vault: VaultState) -> dict:
    """Return the provider-neutral health projection for this cluster node."""
    quarantined = False
    try:
        result = await db.execute(
            text(
                "SELECT 1 FROM vault_cluster_nodes "
                "WHERE node_uuid = :u AND ha_state = 'quarantined'"
            ),
            {"u": get_node_uuid()},
        )
        quarantined = result.fetchone() is not None
    except Exception:
        # A failed quarantine probe must not hide the rest of the health
        # result. The database component carries the actual DB failure.
        quarantined = False
    return await cluster_health(db, vault, quarantined=quarantined)


async def topology_snapshot(db: AsyncSession) -> dict:
    """Return fresh worker topology and currently-held Rhorizon locks."""
    workers = (
        await db.execute(
            text("""
                SELECT pid, hostname, worker_state, process_role,
                       crypto_socket_name, last_heartbeat,
                       EXTRACT(EPOCH FROM (NOW() - last_heartbeat)) AS age_sec
                FROM vault_workers
                WHERE last_heartbeat > NOW() - INTERVAL '30 seconds'
                ORDER BY hostname, pid
            """)
        )
    ).fetchall()

    hosts: dict = {}
    for worker in workers:
        host = worker.hostname or "unknown"
        slot = hosts.setdefault(
            host, {"master": None, "followers": [], "max_age_sec": 0.0}
        )
        info = {
            "pid": worker.pid,
            "worker_state": worker.worker_state,
            "process_role": worker.process_role,
            "age_sec": float(worker.age_sec or 0.0),
        }
        if worker.worker_state == "master" and worker.crypto_socket_name:
            slot["master"] = {
                "pid": worker.pid,
                "process_role": worker.process_role,
                "age_sec": info["age_sec"],
            }
        else:
            slot["followers"].append(info)
        slot["max_age_sec"] = max(slot["max_age_sec"], info["age_sec"])

    locks = (
        await db.execute(
            text("""
                SELECT l.classid, l.objid, a.application_name, a.pid,
                       a.query_start,
                       EXTRACT(EPOCH FROM (NOW() - a.query_start)) AS held_for_sec
                FROM pg_locks l
                JOIN pg_stat_activity a ON l.pid = a.pid
                WHERE l.locktype = 'advisory'
                  AND a.application_name LIKE 'rhorizon:%'
                  AND l.granted = true
                ORDER BY a.query_start
            """)
        )
    ).fetchall()
    held_locks = []
    for lock in locks:
        name = await resolve_lock_name(db, int(lock.objid))
        if name is None:
            name = f"unknown:{lock.classid}:{lock.objid}"
        holder_host = (
            lock.application_name.split(":", 1)[1]
            if ":" in lock.application_name
            else "?"
        )
        held_locks.append(
            {
                "lock": name,
                "holder_host": holder_host,
                "holder_pid": lock.pid,
                "held_for_sec": float(lock.held_for_sec or 0.0),
            }
        )
    return {
        "this_host": get_hostname(),
        "this_pid": os.getpid(),
        "this_host_crypto_prefix": crypto_socket_prefix(),
        "hosts": hosts,
        "held_cluster_locks": held_locks,
    }
