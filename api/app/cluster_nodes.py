# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Inter-host HA cluster membership table.

Membership state lives in a dedicated ``vault_cluster_nodes`` table
(PK ``node_uuid``) rather than reusing ``vault_workers`` with synthetic
``(hostname, pid)`` keys :

- ``vault_workers`` carries process-level state (one row per uvicorn
  worker) and its PK is correctly ``(hostname, pid)``. A node is a
  container, not a process, so forcing a "node" row into it would have
  demanded a synthetic key and a permanent ``ha_state IS NOT NULL``
  filter on every downstream query.
- Volume-wipe rejoin is enforced by a partial UNIQUE index on
  ``source_ip`` (``WHERE ha_state != 'evicted'``) -- at most one active
  node per IP, atomic at INSERT. ``check_source_ip_unbound`` is a
  pre-check for a descriptive 409, not the guarantee.
- ``evict`` / ``promote`` / ``drain`` and ``rotate-cert`` key on
  ``node_uuid`` ; the dedicated PK avoids a ``(node_uuid -> hostname,
  pid)`` translation at every op.

This module is a thin DB helper layer ; the actual /cluster/join and
/cluster/challenge orchestration lives in ``api/app/routes/cluster.py``.
"""

import logging

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

log = logging.getLogger("rhorizon.cluster_nodes")

# Valid `ha_state` values -- mirrored on the DB CHECK constraint. Any
# write going through this module passes through one of the helpers
# below ; the enum lives here to give the linter a single place to
# audit, and to let the application short-circuit obvious typos before
# hitting the DB.
HA_STATES = frozenset(
    {"joining", "secondary", "primary", "draining", "evicted", "quarantined"}
)


class ClusterNodeConflictError(RuntimeError):
    """Raised when a JOIN attempt collides with an existing membership row.

    Two distinct collision shapes are surfaced :

    - ``node_uuid`` already present (REJOIN territory -- the operator
      did not use the REJOIN path).
    - ``source_ip`` already bound to a different ``node_uuid`` (a host
      wiped its volume and tries to JOIN as a fresh identity from the
      same IP).

    The route layer maps both to ``409 Conflict`` ; the distinct
    sub-classes let the audit trail capture which one fired.
    """


class NodeUuidExistsError(ClusterNodeConflictError):
    """The (node_uuid) PK already exists. Use REJOIN, not JOIN."""


class SourceIpRebindError(ClusterNodeConflictError):
    """The (source_ip) is already bound to a different node_uuid."""


async def insert_joining_node(
    session: AsyncSession,
    node_uuid: str,
    source_ip: str,
    cluster_version: str,
    cert_fingerprint: str,
    cert_not_after,
    quarantine_secs: int,
) -> None:
    """Insert a fresh ``joining`` row for a newly-accepted JOIN.

    Sets ``ha_state='joining'`` and computes ``quarantine_until = NOW()
    + quarantine_secs``. The row stays in this state until the
    state-machine loop flips it to ``secondary`` (after the quarantine
    window has elapsed AND a healthcheck-pass tick has been observed).

    Raises :

    - :class:`NodeUuidExistsError` -- the PK already exists. The caller
      is expected to have routed the request to the REJOIN path
      first ; reaching JOIN with an existing UUID is a client bug.
    - :class:`SourceIpRebindError` -- the IP is already bound to a
      different UUID. Volume-wipe mitigation : an operator who wipes
      a node's volume cannot silently re-bind by JOINing as a fresh
      identity ; they must explicitly evict the previous node first.
    """
    if cluster_version is None or cluster_version == "":
        raise ValueError("cluster_version is required for vault_cluster_nodes insert")
    if cert_fingerprint is None or cert_fingerprint == "":
        raise ValueError("cert_fingerprint is required for vault_cluster_nodes insert")

    try:
        await session.execute(
            text(
                "INSERT INTO vault_cluster_nodes ("
                "    node_uuid, source_ip, ha_state, quarantine_until,"
                "    cluster_version, cert_fingerprint, cert_not_after"
                ") VALUES ("
                "    :uuid, CAST(:ip AS INET), 'joining',"
                "    NOW() + make_interval(secs => :qs),"
                "    :ver, :fpr, :nbf"
                ")"
            ),
            {
                "uuid": node_uuid,
                "ip": source_ip,
                "qs": quarantine_secs,
                "ver": cluster_version,
                "fpr": cert_fingerprint,
                "nbf": cert_not_after,
            },
        )
    except IntegrityError as exc:
        # Disambiguate the two uniqueness guards by constraint name in the
        # wrapped DBAPI error. PK (vault_cluster_nodes_pkey) -> the node_uuid
        # already exists (REJOIN territory). Partial unique on source_ip
        # (vault_cluster_nodes_active_ip) -> a different active node holds this
        # IP. A same-uuid retry collides on both; the PK (lower OID) fires
        # first, so the REJOIN path wins.
        msg = str(getattr(exc, "orig", exc))
        if "vault_cluster_nodes_pkey" in msg:
            raise NodeUuidExistsError(node_uuid) from exc
        if "vault_cluster_nodes_active_ip" in msg:
            raise SourceIpRebindError(source_ip) from exc
        raise


async def insert_primary_node(
    session: AsyncSession,
    node_uuid: str,
    source_ip: str,
    cluster_version: str,
    cert_fingerprint: str,
    cert_not_after,
) -> None:
    """Insert the primary's membership row at /cluster/init time.

    The node that runs /cluster/init must
    appear in ``vault_cluster_nodes`` so /cluster/ha can list it like
    any other member, the heartbeat loop has a row to update,
    and the (uuid, ip) UNIQUE index gives a JOIN-collision guard from
    day one. Previously, only ``primary_uuid`` lived in
    ``vault_cluster_config`` as a scalar -- never in the membership
    table.

    Differs from :func:`insert_joining_node` in three points :

    - ``ha_state='primary'`` directly (no quarantine -- the cluster-init
      caller already proved write-admin and there is nothing yet to be
      elected against).
    - ``quarantine_until = NULL`` (not applicable -- nothing to wait
      for).
    - ``last_heartbeat = NOW()`` (the heartbeat loop is the
      authoritative writer afterwards, but seeding now keeps the row
      observably fresh from the moment it lands).
    """
    if cluster_version is None or cluster_version == "":
        raise ValueError("cluster_version is required for vault_cluster_nodes insert")
    if cert_fingerprint is None or cert_fingerprint == "":
        raise ValueError("cert_fingerprint is required for vault_cluster_nodes insert")

    await session.execute(
        text(
            "INSERT INTO vault_cluster_nodes ("
            "    node_uuid, source_ip, ha_state, quarantine_until,"
            "    cluster_version, cert_fingerprint, cert_not_after,"
            "    last_heartbeat"
            ") VALUES ("
            "    :uuid, CAST(:ip AS INET), 'primary', NULL,"
            "    :ver, :fpr, :nbf, NOW()"
            ")"
        ),
        {
            "uuid": node_uuid,
            "ip": source_ip,
            "ver": cluster_version,
            "fpr": cert_fingerprint,
            "nbf": cert_not_after,
        },
    )


async def list_nodes(session: AsyncSession):
    """Return all non-evicted membership rows ordered by ``joined_at``.

    /cluster/ha consumer. ``evicted`` rows are
    filtered out by the partial index ``vault_cluster_nodes_ha_state``
    (see schema) ; we mirror the filter here so an evicted node never
    surfaces in the visibility endpoint.

    ``host(source_ip)`` strips the PG INET ``/32`` (resp. ``/128``)
    mask the column carries when cast to text -- API consumers see a
    bare IP literal, not a network notation.
    """
    rows = (
        await session.execute(
            text(
                "SELECT node_uuid, host(source_ip) AS source_ip, ha_state, "
                "       quarantine_until, joined_at, cluster_version, "
                "       cert_fingerprint, cert_not_after, last_heartbeat "
                "FROM vault_cluster_nodes "
                "WHERE ha_state != 'evicted' "
                "ORDER BY joined_at"
            )
        )
    ).fetchall()
    return rows


async def get_node(session: AsyncSession, node_uuid: str):
    """Return the row for ``node_uuid`` or ``None`` if absent."""
    row = (
        await session.execute(
            text(
                "SELECT node_uuid, source_ip::TEXT AS source_ip, ha_state, "
                "       quarantine_until, joined_at, cluster_version, "
                "       cert_fingerprint, cert_not_after, last_heartbeat, "
                "       drain_deadline_at "
                "FROM vault_cluster_nodes WHERE node_uuid = :u"
            ),
            {"u": node_uuid},
        )
    ).fetchone()
    return row


async def set_force_renew_one(session: AsyncSession, node_uuid: str) -> bool:
    """Flag a single non-evicted row for force-renew at the next tick.

    POST /cluster/rotate-cert/{node_uuid}. UPDATE sets
    ``force_renew_at = NOW()`` so the per-node renewal loop trips on
    the OR branch (``force_renew_at IS NOT NULL AND force_renew_at <=
    NOW()``) regardless of the cert validity. Evicted rows are skipped
    -- an evicted node will never poll its loop again.

    Returns True iff a row was actually UPDATEd. False = unknown uuid
    or already evicted ; the route layer maps to 404.
    """
    result = await session.execute(
        text(
            "UPDATE vault_cluster_nodes "
            "SET force_renew_at = NOW() "
            "WHERE node_uuid = :u "
            "  AND ha_state != 'evicted' "
            "RETURNING node_uuid"
        ),
        {"u": node_uuid},
    )
    return result.fetchone() is not None


async def set_force_renew_all(session: AsyncSession) -> int:
    """Flag every non-evicted row. Returns the count flipped.

    POST /cluster/rotate-cert/all. Useful as a forward-
    compatibility primitive for CA rotation broadcast -- the
    new CA can't validate the old certs, so every node has to refresh
    in lockstep). Skips evicted rows for the same reason as
    :func:`set_force_renew_one`.
    """
    result = await session.execute(
        text(
            "UPDATE vault_cluster_nodes "
            "SET force_renew_at = NOW() "
            "WHERE ha_state != 'evicted' "
            "RETURNING node_uuid"
        )
    )
    return len(result.fetchall())


async def clear_force_renew(session: AsyncSession, node_uuid: str) -> None:
    """Clear the force-renew flag on a single row after a successful refresh.

    Called by the renewal loop right after the cert+key are persisted
    on disk + the row updated with the new fingerprint/not_after.
    Idempotent : a NULL row stays NULL.
    """
    await session.execute(
        text(
            "UPDATE vault_cluster_nodes SET force_renew_at = NULL WHERE node_uuid = :u"
        ),
        {"u": node_uuid},
    )


async def refresh_joining_row(
    session: AsyncSession,
    node_uuid: str,
    cert_fingerprint: str,
    cert_not_after,
    quarantine_secs: int,
) -> bool:
    """Bug 3+4 idempotency helper -- bump cert + reset quarantine on retry.

    Used by /cluster/join when ``insert_joining_node`` raises
    :class:`NodeUuidExistsError`. The caller has just re-minted a fresh
    cert/key pair for the same (uuid, ip) and needs to swap the row's
    metadata atomically without leaving the membership table in an
    inconsistent state.

    Gated on ``ha_state = 'joining'`` so a node that already integrated
    (secondary/primary/draining/evicted) cannot be silently rolled back
    -- those states go to REJOIN, not idempotent retry. Returns True if
    the row was UPDATEd. False = the row exists but is no longer
    'joining' ; the caller surfaces 409 "use REJOIN flow".
    """
    result = await session.execute(
        text(
            "UPDATE vault_cluster_nodes "
            "SET cert_fingerprint = :fpr, "
            "    cert_not_after = :nbf, "
            "    quarantine_until = NOW() + make_interval(secs => :qs), "
            "    force_renew_at = NULL "
            "WHERE node_uuid = :u "
            "  AND ha_state = 'joining' "
            "RETURNING node_uuid"
        ),
        {
            "u": node_uuid,
            "fpr": cert_fingerprint,
            "nbf": cert_not_after,
            "qs": quarantine_secs,
        },
    )
    return result.fetchone() is not None


async def update_cert_metadata(
    session: AsyncSession,
    node_uuid: str,
    cert_fingerprint: str,
    cert_not_after,
) -> bool:
    """Update cert_fingerprint + cert_not_after + clear force_renew_at.

    Atomic post-refresh metadata bump. Returns True if a
    row was UPDATEd. False = uuid unknown ; the caller treats as a
    drift between cert and membership table and surfaces 404 / 500.
    """
    result = await session.execute(
        text(
            "UPDATE vault_cluster_nodes "
            "SET cert_fingerprint = :fpr, "
            "    cert_not_after = :nbf, "
            "    force_renew_at = NULL "
            "WHERE node_uuid = :u "
            "RETURNING node_uuid"
        ),
        {"u": node_uuid, "fpr": cert_fingerprint, "nbf": cert_not_after},
    )
    return result.fetchone() is not None


async def check_source_ip_unbound(
    session: AsyncSession, source_ip: str, node_uuid: str
) -> bool:
    """True iff no *other* active node already owns this source_ip.

    Faille 12 (uuid, ip) binding pre-check : called by the JOIN route
    before the INSERT so the 409 can be issued with a descriptive
    message instead of letting the UNIQUE catch fire generically.

    "Other" excludes the row identified by ``node_uuid`` itself
    (REJOIN paths re-use the same UUID and may legitimately match the
    IP). "Active" excludes ``evicted`` -- a previously-evicted node
    no longer holds its IP binding.
    """
    row = (
        await session.execute(
            text(
                "SELECT 1 FROM vault_cluster_nodes "
                "WHERE source_ip = CAST(:ip AS INET) "
                "  AND node_uuid != :u "
                "  AND ha_state != 'evicted' "
                "LIMIT 1"
            ),
            {"ip": source_ip, "u": node_uuid},
        )
    ).fetchone()
    return row is None
