# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Cluster topology + lock visibility + HA init.

Read-only endpoint (admin:r) :

  - ``GET  /api/v1/vault/cluster`` -- host topology + held cluster locks.

HA init endpoints (admin:w) :

  - ``POST /api/v1/vault/cluster/init``   -- atomic cluster bootstrap
    (cluster_id, ha_password, cluster CA, primary_uuid).
  - ``POST /api/v1/vault/cluster/repair`` -- complete a partially-initialised
    cluster (only the missing rows are filled in, idempotent).

The init transaction either succeeds in full or rolls back to the
pre-init state. The PK on ``vault_cluster_config(key)`` is the
idempotency guard : a concurrent init that wins the race INSERTs
``cluster_id`` ; the loser's INSERT raises ``IntegrityError`` which
is mapped to ``409 cluster_already_initialised``.
"""

import base64
import hmac as _hmac
import json
import logging
import re as _re
import secrets
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from rhorizon_crypto import secure_zero
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from .. import (
    cluster_ca,
    cluster_cert,
    cluster_membership,
    cluster_nodes,
    ha_password,
)
from .. import metrics as _metrics
from ..audit import log_action
from ..auth import require_permission, require_vault_token
from ..client_ip import get_client_ip
from ..cluster import with_cluster_lock
from ..config import settings
from ..database import get_db
from ..node_uuid import get_node_uuid
from ..rate_limit import check_rate_limit
from ..vault_state import vault
from .cluster_certs import router as certs_router
from .cluster_read import router as read_router

log = logging.getLogger("rhorizon.routes.cluster")

router = APIRouter(prefix="/api/v1/vault", tags=["cluster"])
router.include_router(read_router)
router.include_router(certs_router)

_HA_PASSWORD_BYTES = 32  # 256 bits, matches ha_password_min_length floor

# Compatibility address for manual/local initialisation where the operator did
# not configure RH_CLUSTER_ADVERTISE_IP.  Managed HA installers set a real,
# stable per-node address; the reserved TEST-NET literal remains useful for
# ASGI tests and cannot collide with a joining node observed on a real network.
_PRIMARY_SOURCE_IP = "192.0.2.1"


def _primary_source_ip() -> str:
    return settings.cluster_advertise_ip or _PRIMARY_SOURCE_IP


# ---------------------------------------------------------------------------
# /cluster/init and /cluster/repair
# ---------------------------------------------------------------------------


class ClusterInitRequest(BaseModel):
    cluster_name: str = Field(
        default="rhorizon-cluster",
        min_length=1,
        max_length=128,
        description="Human-readable label embedded as CN in the cluster CA. "
        "Does not need to be unique ; cluster_id is the identity.",
    )


class ClusterInitResponse(BaseModel):
    cluster_id: str
    ha_password: str  # base64, shown once -- not stored in clear anywhere
    primary_uuid: str
    ca_fingerprint: str
    warning: str


class ClusterRepairResponse(BaseModel):
    cluster_id: str
    repaired: list[str]
    ha_password: str | None = None  # only present when ha_password was missing
    ca_fingerprint: str
    primary_uuid: str
    warning: str | None = None


async def _existing_keys(db: AsyncSession) -> set[str]:
    rows = (await db.execute(text("SELECT key FROM vault_cluster_config"))).fetchall()
    return {r.key for r in rows}


@router.post(
    "/cluster/init",
    response_model=ClusterInitResponse,
)
async def cluster_init(
    request: Request,
    body: ClusterInitRequest = ClusterInitRequest(),
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("cluster", "w")),
):
    """Atomically initialise the HA cluster on this node.

    Five operations executed in one PG transaction :

    1. INSERT ``cluster_id`` -- PK guards against double-init.
    2. Generate ``ha_password`` and persist via :mod:`api.app.ha_password`
       (AES-GCM-wrapped under ``ha_wrap_key`` + AAD).
    3. Mint the cluster CA and persist via :mod:`api.app.cluster_ca`
       (Ed25519 self-signed, 10y validity).
    4. INSERT ``primary_uuid`` (this node's UUID) + ``primary_since``.
    5. ``log_action(cluster_init)`` -- captures actor, cluster_id, and
       CA fingerprint. Plaintext ha_password is never logged.

    On any failure the transaction rolls back ; the cluster stays
    callable via /cluster/init. The ``ha_password`` is returned in the
    response **once** -- the operator MUST capture it now and distribute
    it out-of-band via ``RHORIZON_HA_PASSWORD_FILE``.

    Idempotency : a second call detects the existing ``cluster_id`` row
    and returns ``409 cluster_already_initialised`` ; the existing
    cluster state is untouched.
    """
    # Pre-flight : surface the 409 before generating any secret material.
    # The PK INSERT below is the authoritative guard, but pre-checking
    # keeps the response body free of state side-effects on the easy path.
    existing = await _existing_keys(db)
    if "cluster_id" in existing:
        raise HTTPException(status_code=409, detail="cluster already initialised")

    # A follower serves init too: set_ha_password + set_cluster_ca route their
    # ha_wrap_key wraps through VaultState.ha_wrap_encrypt, which RPCs to master
    # when the local worker holds no subkeys. Only the wrap primitives cross the
    # socket; the DB session + audit + commit stay on the request task. A
    # master-loss mid-call surfaces 503 + Retry-After:1 (3s budget).
    cluster_id = str(uuid.uuid4())
    ha_password_plain = secrets.token_bytes(_HA_PASSWORD_BYTES)
    primary_uuid = get_node_uuid()
    client_ip = get_client_ip(request)
    actor = token_info.get("name") or "admin"

    try:
        # Step 1 : cluster_id -- PK violation here is the 409 trigger
        # under genuine concurrent /cluster/init.
        await db.execute(
            text(
                "INSERT INTO vault_cluster_config (key, value) "
                "VALUES ('cluster_id', :v)"
            ),
            {"v": cluster_id},
        )

        # Step 2 : ha_password (module owns audit + RAM cache).
        await ha_password.set_ha_password(
            db, ha_password_plain, actor=actor, ip_address=client_ip
        )

        # Step 3 : mint + persist the cluster CA. The mint is inside the
        # try block so a cryptography-level failure (entropy starvation,
        # Ed25519 backend missing) rolls back the cluster_id and
        # ha_password rows + clears the RAM cache.
        cert_pem, key_pem, ca_fingerprint = cluster_ca.mint_cluster_ca(
            common_name=body.cluster_name
        )
        await cluster_ca.set_cluster_ca(db, cert_pem, key_pem)

        # Step 4 : primary identity (config scalars).
        await db.execute(
            text(
                "INSERT INTO vault_cluster_config (key, value) "
                "VALUES ('primary_uuid', :v)"
            ),
            {"v": primary_uuid},
        )
        await db.execute(
            text(
                "INSERT INTO vault_cluster_config (key, value) "
                "VALUES ('primary_since', :v)"
            ),
            {"v": _now_iso()},
        )

        # Step 4b : mint the
        # primary's own node cert and INSERT its vault_cluster_nodes row.
        # Without this the heartbeat loop has nothing to update
        # and /cluster/ha cannot surface the primary alongside the
        # secondaries. The cert is signed by the CA we just minted ;
        # the node persists the private key to disk so the primary
        # holds its own identity end-to-end (the renewal loop
        # uses this file as the source of truth).
        # A managed HA deployment provides its stable inventory address.  The
        # reserved fallback is retained only for local/manual compatibility.
        primary_source_ip = _primary_source_ip()
        primary_cert_pem, primary_key_pem = cluster_ca.sign_node_cert(
            cert_pem, key_pem, primary_uuid, primary_source_ip
        )
        cluster_cert.save_cluster_cert(
            primary_cert_pem,
            primary_key_pem,
            settings.cluster_cert_path,
            settings.cluster_cert_key_path,
        )
        primary_cert_fingerprint = cluster_ca.compute_fingerprint(primary_cert_pem)
        primary_cert_not_after = cluster_ca.parse_cert(
            primary_cert_pem
        ).not_valid_after_utc
        await cluster_nodes.insert_primary_node(
            db,
            node_uuid=primary_uuid,
            source_ip=primary_source_ip,
            cluster_version=settings.version,
            cert_fingerprint=primary_cert_fingerprint,
            cert_not_after=primary_cert_not_after,
        )

        # Step 5 : audit trail. Detail captures the public identifiers
        # only ; ha_password plaintext NEVER appears in the audit chain.
        await log_action(
            db,
            actor=actor,
            action="cluster_init",
            target=cluster_id,
            detail={
                "cluster_name": body.cluster_name,
                "primary_uuid": primary_uuid,
                "ca_fingerprint": ca_fingerprint,
                "primary_cert_fingerprint": primary_cert_fingerprint,
            },
            ip_address=client_ip,
        )

        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status_code=409, detail="cluster already initialised"
        ) from None
    except Exception:
        await db.rollback()
        # ha_password.set_ha_password may have updated vault._ha_password_enc
        # in RAM before the rollback. Drop it so the singleton matches the
        # rolled-back DB state -- a subsequent retry of /cluster/init
        # generates a fresh password and re-caches.
        ha_password.clear()
        raise

    log.info(
        "cluster_init: cluster_id=%s primary=%s ca_fpr=%s actor=%s",
        cluster_id,
        primary_uuid,
        ca_fingerprint,
        actor,
    )
    return ClusterInitResponse(
        cluster_id=cluster_id,
        ha_password=base64.b64encode(ha_password_plain).decode("ascii"),
        primary_uuid=primary_uuid,
        ca_fingerprint=ca_fingerprint,
        warning=(
            "Save ha_password now -- it is shown only this once. "
            "Provision other nodes with it via RHORIZON_HA_PASSWORD_FILE."
        ),
    )


@router.post(
    "/cluster/repair",
    response_model=ClusterRepairResponse,
)
async def cluster_repair(
    request: Request,
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("cluster", "w")),
):
    """Complete a partially-initialised cluster.

    /cluster/init runs all five steps in a single transaction, so the
    partial state can only happen if a previous init crashed mid-flight
    *with* a connection-level commit between steps (e.g. an operator
    drove the steps manually) -- the legitimate path here is an admin
    rolling forward after an outage. Per-key INSERTs let us complete
    only the missing rows ; existing rows are left untouched.

    Repaired keys are reported in the response. ``ha_password`` is
    returned plaintext **only** if the row was missing and we minted a
    fresh one in this call. If the cluster_id row is missing the call
    returns ``409 cluster_not_initialised`` -- /cluster/init owns the
    bootstrap, /cluster/repair owns the roll-forward.
    """
    existing = await _existing_keys(db)
    if "cluster_id" not in existing:
        raise HTTPException(
            status_code=409, detail="cluster not initialised -- call /cluster/init"
        )

    # Follower-safe: set_ha_password + set_cluster_ca route their ha_wrap_key
    # wraps through VaultState.ha_wrap_encrypt (RPC to master from any worker);
    # master-loss mid-call surfaces 503 (3s recovery budget).
    cluster_id_row = (
        await db.execute(
            text("SELECT value FROM vault_cluster_config WHERE key = 'cluster_id'")
        )
    ).fetchone()
    cluster_id = cluster_id_row.value

    repaired: list[str] = []
    fresh_ha_password: bytes | None = None
    client_ip = get_client_ip(request)
    actor = token_info.get("name") or "admin"

    try:
        # ha_password row -- mint fresh if absent (operator has nothing
        # to compare against, so a fresh value is the only safe move).
        if "ha_password_encrypted" not in existing:
            fresh_ha_password = secrets.token_bytes(_HA_PASSWORD_BYTES)
            await ha_password.set_ha_password(
                db, fresh_ha_password, actor=actor, ip_address=client_ip
            )
            repaired.append("ha_password_encrypted")

        # CA rows -- mint fresh if either is absent. Mismatched
        # cert/key (only one present) would be operator-induced ; we
        # delete the orphan first so set_cluster_ca's plain INSERTs do
        # not collide.
        cert_present = "cluster_ca_cert" in existing
        key_present = "cluster_ca_key" in existing
        ca_fingerprint: str
        if not (cert_present and key_present):
            if cert_present:
                await db.execute(
                    text(
                        "DELETE FROM vault_cluster_config WHERE key = 'cluster_ca_cert'"
                    )
                )
            if key_present:
                await db.execute(
                    text(
                        "DELETE FROM vault_cluster_config WHERE key = 'cluster_ca_key'"
                    )
                )
            cert_pem, key_pem, ca_fingerprint = cluster_ca.mint_cluster_ca()
            await cluster_ca.set_cluster_ca(db, cert_pem, key_pem)
            repaired.append("cluster_ca")
        else:
            row = (
                await db.execute(
                    text(
                        "SELECT value FROM vault_cluster_config "
                        "WHERE key = 'cluster_ca_cert'"
                    )
                )
            ).fetchone()
            ca_fingerprint = cluster_ca.compute_fingerprint(row.value.encode("ascii"))

        # Primary identity rows.
        if "primary_uuid" not in existing:
            await db.execute(
                text(
                    "INSERT INTO vault_cluster_config (key, value) "
                    "VALUES ('primary_uuid', :v)"
                ),
                {"v": get_node_uuid()},
            )
            repaired.append("primary_uuid")
        if "primary_since" not in existing:
            await db.execute(
                text(
                    "INSERT INTO vault_cluster_config (key, value) "
                    "VALUES ('primary_since', :v)"
                ),
                {"v": _now_iso()},
            )
            repaired.append("primary_since")

        primary_row = (
            await db.execute(
                text(
                    "SELECT value FROM vault_cluster_config WHERE key = 'primary_uuid'"
                )
            )
        ).fetchone()
        primary_uuid = primary_row.value

        await log_action(
            db,
            actor=actor,
            action="cluster_repair",
            target=cluster_id,
            detail={"repaired": repaired, "ca_fingerprint": ca_fingerprint},
            ip_address=client_ip,
        )

        await db.commit()
    except Exception:
        await db.rollback()
        ha_password.clear()
        raise

    return ClusterRepairResponse(
        cluster_id=cluster_id,
        repaired=repaired,
        ha_password=(
            base64.b64encode(fresh_ha_password).decode("ascii")
            if fresh_ha_password is not None
            else None
        ),
        ca_fingerprint=ca_fingerprint,
        primary_uuid=primary_uuid,
        warning=(
            "Save ha_password now -- it is shown only this once."
            if fresh_ha_password is not None
            else None
        ),
    )


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# two-phase ha_password rotation
# ---------------------------------------------------------------------------
#
# Three admin-driven actions (stage / confirm / cancel) plus a status GET.
# Storage is meta-only : a single vault_cluster_config row carrying a JSON
# payload ``{staged_by, staged_at, expires_at}``. No plaintext is ever
# persisted between stage and confirm -- the new ha_password is minted at
# confirm time, applied via the setter (audit + RAM cache
# bookkeeping), and returned to the caller exactly once.
#
# Why two phases at all, given no pre-minted plaintext to protect:
#   - explicit "intent to rotate" leaves an auditable trace before the
#     destructive action ;
#   - operator (or a second admin) can review/cancel before bootstrap
#     credentials change ;
#   - keeps a symmetry with the post-restore pending_restore_review
#     pattern (operator confirms each stub before plaintext is minted).
#
# Cert independence : rotating ha_password does NOT touch vault_cluster_nodes
# rows ; per-node certs minted at /cluster/init and
# /cluster/join continue to authenticate REJOINs.
# The rotation invalidates only the bootstrap path for NEW nodes.


_PENDING_ROTATION_KEY = "pending_ha_password_rotation"


class ClusterRotateStageResponse(BaseModel):
    staged_by: str
    staged_at: str  # ISO 8601 UTC
    expires_at: str  # ISO 8601 UTC


class ClusterRotateConfirmResponse(BaseModel):
    ha_password: str  # base64, shown once
    rotated_at: str  # ISO 8601 UTC
    warning: str


class ClusterRotateStatusResponse(BaseModel):
    pending: ClusterRotateStageResponse | None


async def _read_pending_rotation(
    db: AsyncSession,
) -> ClusterRotateStageResponse | None:
    """Decode the JSON meta row. Returns None if absent."""
    row = (
        await db.execute(
            text("SELECT value FROM vault_cluster_config WHERE key = :k"),
            {"k": _PENDING_ROTATION_KEY},
        )
    ).fetchone()
    if row is None:
        return None
    payload = json.loads(row.value)
    return ClusterRotateStageResponse(
        staged_by=payload["staged_by"],
        staged_at=payload["staged_at"],
        expires_at=payload["expires_at"],
    )


def _require_cluster_initialised_msg() -> str:
    return "cluster not initialised -- call /cluster/init first"


async def _require_cluster_initialised(db: AsyncSession) -> None:
    existing = await _existing_keys(db)
    if "cluster_id" not in existing:
        raise HTTPException(status_code=409, detail=_require_cluster_initialised_msg())


@router.post(
    "/cluster/rotate-ha-password/stage",
    response_model=ClusterRotateStageResponse,
    status_code=201,
)
async def cluster_rotate_ha_password_stage(
    request: Request,
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("admin", "w")),
):
    """Record an intent to rotate the cluster ha_password.

    The pending row is metadata only ; no new plaintext is minted at
    this step. Operator confirms via POST ../confirm or aborts via
    POST ../cancel. A pending row past its TTL is purged by the reaper
    (cluster_pending_ha_rotation_ttl_secs, default 1h).

    409 if a pending rotation is already staged -- operator must
    cancel it before staging another.
    """
    await _require_cluster_initialised(db)

    actor = token_info.get("name") or "admin"
    client_ip = get_client_ip(request)
    staged_at = datetime.now(timezone.utc)
    expires_at = staged_at + timedelta(
        seconds=settings.cluster_pending_ha_rotation_ttl_secs
    )
    payload = {
        "staged_by": actor,
        "staged_at": staged_at.isoformat(),
        "expires_at": expires_at.isoformat(),
    }

    # ON CONFLICT DO NOTHING + RETURNING is the 409 guard. An INSERT
    # that returns no row means the key was already present ; we read
    # back the existing meta only to keep the error body informative.
    result = await db.execute(
        text(
            "INSERT INTO vault_cluster_config (key, value) "
            "VALUES (:k, :v) "
            "ON CONFLICT (key) DO NOTHING RETURNING value"
        ),
        {"k": _PENDING_ROTATION_KEY, "v": json.dumps(payload)},
    )
    if result.fetchone() is None:
        existing_pending = await _read_pending_rotation(db)
        raise HTTPException(
            status_code=409,
            detail={
                "error": "rotation already pending",
                "pending": existing_pending.model_dump() if existing_pending else None,
            },
        )

    await log_action(
        db,
        actor=actor,
        action="ha_password_rotate_staged",
        detail={"expires_at": payload["expires_at"]},
        ip_address=client_ip,
    )
    await db.commit()
    _metrics.cluster_ha_password_rotations.labels(outcome="staged").inc()
    log.info(
        "ha_password rotation staged by %s, expires_at=%s",
        actor,
        payload["expires_at"],
    )
    return ClusterRotateStageResponse(**payload)


@router.post(
    "/cluster/rotate-ha-password/confirm",
    response_model=ClusterRotateConfirmResponse,
)
async def cluster_rotate_ha_password_confirm(
    request: Request,
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("admin", "w")),
):
    """Mint a fresh ha_password, apply it, and return it once.

    The pending meta row must be present and not expired -- the reaper
    will normally remove an expired row before this call lands, but a
    race window between expiry and reap is handled here by treating
    the row as gone (410).

    Behaviour :
      1. Generate 32 bytes of cryptographic randomness.
      2. ``ha_password.set_ha_password`` -- the setter handles the
         at-rest re-wrap, RAM cache swap, length check, and the
         ``ha_password_set`` audit row.
      3. DELETE the pending meta row in the same transaction.
      4. ``ha_password_rotate_confirmed`` audit row (no plaintext).
      5. Return plaintext base64-encoded ; warning the operator that
         this is the only time it appears.

    Existing per-node certs in ``vault_cluster_nodes`` are NOT touched
    -- REJOIN-by-cert continues to work after the rotation. Only the
    bootstrap path for new nodes uses the new password.
    """
    await _require_cluster_initialised(db)
    # /cluster/rotate-ha-password/confirm no longer
    # 503s on a follower. The wrap of the new ha_password is delegated
    # via :meth:`VaultState.ha_wrap_encrypt` (RPC to master from any
    # follower worker), same pattern as /cluster/init.

    pending = await _read_pending_rotation(db)
    if pending is None:
        raise HTTPException(
            status_code=409,
            detail="no pending rotation to confirm -- call /stage first",
        )
    expires_at = datetime.fromisoformat(pending.expires_at)
    if expires_at < datetime.now(timezone.utc):
        # The reaper should have nuked this row by now. Race window
        # between expiry and reap : tell the operator the staged
        # intent has expired and let them restage.
        raise HTTPException(
            status_code=410,
            detail="pending rotation expired -- call /stage again",
        )

    actor = token_info.get("name") or "admin"
    client_ip = get_client_ip(request)
    new_ha_password = secrets.token_bytes(_HA_PASSWORD_BYTES)

    try:
        await ha_password.set_ha_password(
            db, new_ha_password, actor=actor, ip_address=client_ip
        )
        await db.execute(
            text("DELETE FROM vault_cluster_config WHERE key = :k"),
            {"k": _PENDING_ROTATION_KEY},
        )
        rotated_at = _now_iso()
        await log_action(
            db,
            actor=actor,
            action="ha_password_rotate_confirmed",
            detail={"staged_by": pending.staged_by, "rotated_at": rotated_at},
            ip_address=client_ip,
        )
        await db.commit()
    except Exception:
        await db.rollback()
        # set_ha_password swaps the RAM cache before commit ; if the
        # transaction rolls back, the in-RAM buffer no longer matches
        # the on-disk row. Reload from DB so the singleton converges
        # back to the rolled-back state.
        try:
            await ha_password.load_ha_password_into_ram(db)
        except Exception:
            ha_password.clear()
        raise

    _metrics.cluster_ha_password_rotations.labels(outcome="confirmed").inc()
    log.info(
        "ha_password rotated by %s (staged_by=%s, rotated_at=%s)",
        actor,
        pending.staged_by,
        rotated_at,
    )
    return ClusterRotateConfirmResponse(
        ha_password=base64.b64encode(new_ha_password).decode("ascii"),
        rotated_at=rotated_at,
        warning=(
            "Save the new ha_password now -- it is shown only this once. "
            "Provision new nodes with it via RHORIZON_HA_PASSWORD_FILE. "
            "Existing nodes keep their per-node certs and are unaffected."
        ),
    )


@router.post(
    "/cluster/rotate-ha-password/cancel",
    status_code=204,
)
async def cluster_rotate_ha_password_cancel(
    request: Request,
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("admin", "w")),
):
    """Drop a staged rotation without minting a new password.

    404 if no pending row is present (nothing to cancel).
    """
    await _require_cluster_initialised(db)

    actor = token_info.get("name") or "admin"
    client_ip = get_client_ip(request)

    result = await db.execute(
        text("DELETE FROM vault_cluster_config WHERE key = :k RETURNING value"),
        {"k": _PENDING_ROTATION_KEY},
    )
    row = result.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="no pending rotation")

    try:
        meta = json.loads(row.value)
        staged_by = meta.get("staged_by")
    except (json.JSONDecodeError, KeyError, TypeError):
        staged_by = None

    await log_action(
        db,
        actor=actor,
        action="ha_password_rotate_cancelled",
        detail={"staged_by": staged_by},
        ip_address=client_ip,
    )
    await db.commit()
    _metrics.cluster_ha_password_rotations.labels(outcome="cancelled").inc()
    log.info("ha_password rotation cancelled by %s (staged_by=%s)", actor, staged_by)
    return None


@router.get(
    "/cluster/rotate-ha-password",
    response_model=ClusterRotateStatusResponse,
)
async def cluster_rotate_ha_password_status(
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("cluster", "r")),
):
    """Read the current pending rotation, if any.

    Returns ``{pending: null}`` if nothing staged ; otherwise the
    staged_by / staged_at / expires_at triple. Read-only -- never
    consumes or extends the row.
    """
    return ClusterRotateStatusResponse(pending=await _read_pending_rotation(db))


# ---------------------------------------------------------------------------
# /cluster/challenge and /cluster/join
# ---------------------------------------------------------------------------


class ClusterChallengeRequest(BaseModel):
    node_uuid: str = Field(min_length=1, max_length=64)
    rhorizon_version: str = Field(min_length=1, max_length=64)


class ClusterChallengeResponse(BaseModel):
    nonce: str
    issued_at: str  # ISO 8601 UTC
    expires_at: str  # ISO 8601 UTC
    cluster_version: str
    cluster_min_compatible_version: str
    # Echo the server-observed source_ip back so the joiner can
    # reconstruct the canonical HMAC message bit-for-bit. The joiner cannot
    # reliably guess what the server sees (NAT, multi-homing, X-Forwarded-For
    # chains all add layers). The server is the authoritative source here ;
    # the joiner uses this value verbatim in its proof and the server
    # validates the (uuid, ip) match on the /cluster/join row anyway.
    observed_source_ip: str
    # Bug 5 fix : ship cluster_id in the challenge response so a fresh joiner
    # discovers it on the wire instead of needing the operator to set
    # ``RHORIZON_HA_CLUSTER_ID`` out-of-band. cluster_id is public material
    # (it identifies the cluster, not its secrets), already echoed in
    # /cluster/init response and stored as a public key in vault_cluster_config.
    cluster_id: str


class ClusterJoinRequest(BaseModel):
    cluster_id: str = Field(min_length=1, max_length=64)
    node_uuid: str = Field(min_length=1, max_length=64)
    nonce: str = Field(min_length=1, max_length=128)
    ha_password_proof: str = Field(min_length=1, max_length=256)  # hex
    rhorizon_version: str = Field(min_length=1, max_length=64)


class ClusterJoinResponse(BaseModel):
    accepted: bool
    ha_state: str
    quarantine_until: str  # ISO 8601 UTC
    primary_uuid: str
    cluster_version: str
    node_cert_pem: str
    node_cert_key_wrapped_hex: str
    ca_cert_pem: str
    # Cluster CA signs the joiner's nginx server cert and
    # ships it in the same response. SAN = [source_ip] (the IP the
    # primary observed on the JOIN call -- same authoritative source as
    # the node identity cert). Validity tracks
    # cluster_server_cert_validity_days. The wrapped key is HKDF
    # (ha_password, info="cluster-server-key-wrap:<uuid>") -- separate
    # domain from the node-key wrap.
    server_cert_pem: str
    server_cert_key_wrapped_hex: str


_VERSION_RE = _re.compile(r"^(\d+)\.(\d+)\.(\d+)(?:[.\-+].*)?$")


def _version_tuple(v: str) -> tuple[int, int, int] | None:
    """Parse a semver-shaped version into a comparable tuple.

    We only compare the (major, minor, patch) triple ; pre-release
    suffixes are dropped for the compat gate. A future version may adopt a
    proper PEP 440 / semver parser if the version scheme grows
    structure (RC tags, build metadata) ; the project is
    on ``0.9.5-beta`` and exact-match-or-newer is enough.
    """
    m = _VERSION_RE.match(v.strip())
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)))


def _version_at_least(v: str, floor: str) -> bool:
    """True if ``v`` >= ``floor`` on (major, minor, patch). Bad input rejects."""
    vt = _version_tuple(v)
    ft = _version_tuple(floor)
    if vt is None or ft is None:
        return False
    return vt >= ft


async def _refuse_if_self_draining_or_evicted(db: AsyncSession) -> None:
    """RPC gate : refuse cluster ops if THIS node is leaving.

    A node in ``draining`` or ``evicted`` state must not service new
    cluster RPC ops (accept a JOIN, sign a fresh node cert, etc.). The
    client retries against another cluster member -- the unhealthy node
    is on its way out and may have its CA + ha_password material wiped
    at any moment by the reaper or operator.

    Called from /cluster/join ; future endpoints that accept
    cluster RPC for the primary's account should call this helper at the
    top of their handler.

    No-op when the local node has no ``vault_cluster_nodes`` row yet
    (pre-cluster-init or pre-/cluster/join) -- /cluster/join handles the
    cluster_id-not-found path elsewhere.
    """
    my_uuid = get_node_uuid()
    row = await cluster_nodes.get_node(db, my_uuid)
    if row is None:
        return
    if row.ha_state in {"draining", "evicted"}:
        raise HTTPException(
            status_code=503,
            detail=(
                f"this node is {row.ha_state} -- retry against another cluster member"
            ),
            headers={"Retry-After": "5"},
        )


@router.post(
    "/cluster/challenge",
    response_model=ClusterChallengeResponse,
)
async def cluster_challenge(
    request: Request,
    body: ClusterChallengeRequest,
    db: AsyncSession = Depends(get_db),
):
    """Step 1 of JOIN -- issue a server-issued single-use nonce.

    Public endpoint. The nonce is bound to ``(node_uuid, source_ip)``
    at issue time and replayed back in the /cluster/join body ; the
    primary verifies the binding before recomputing the HMAC proof.

    Pre-flight :
    - Vault unsealed (``VaultSealedError`` -> 409).
    - Cluster initialised (cluster_id + ha_password + CA present).
    - Rate-limit per source IP (shared engine with auth attempts ;
      whitelist via ``RHORIZON_RATE_LIMIT_WHITELIST`` for cluster
      ingress paths, keeping a single bypass mechanism).
    - Version compat : ``rhorizon_version >= cluster_min_compatible_version``.

    No master-only gate : nonce issuance is ``secrets.token_hex`` +
    DB INSERT. No subkey crypto is touched. Any worker (master or
    follower) can serve this endpoint, which keeps the JOIN bootstrap
    funneled through a single 503 retry surface (/cluster/join,
    which does the HMAC + wrap and so genuinely needs the master).

    The 401/409 split works as follows :
    - 401 for proof failures (here : nonce won't be issued to a stale
      version client, but the body is otherwise unverified).
    - 409 for state/version issues (cluster not init, version too old).

    Persists one row in ``vault_challenges`` with ``purpose='cluster_join'``,
    ``node_uuid``, ``source_ip``, ``issued_at`` (DB ``NOW()``) and
    ``expires_at = NOW() + settings.cluster_challenge_ttl_secs``.
    /cluster/join consumes the row via DELETE+RETURNING (single-use).
    """
    if vault.sealed:
        raise HTTPException(status_code=409, detail="vault is sealed")
    await _refuse_if_self_draining_or_evicted(db)

    source_ip = get_client_ip(request)
    await check_rate_limit(db, source_ip)

    if not await cluster_ca.is_initialised(db):
        raise HTTPException(status_code=409, detail="cluster not initialised")

    if not _version_at_least(
        body.rhorizon_version, settings.cluster_min_compatible_version
    ):
        raise HTTPException(
            status_code=409,
            detail=(
                f"rhorizon_version {body.rhorizon_version} below cluster floor "
                f"{settings.cluster_min_compatible_version}"
            ),
        )

    # Ship cluster_id in the response so the joiner discovers it on the wire
    # (no out-of-band env var needed).
    cluster_id_row = (
        await db.execute(
            text("SELECT value FROM vault_cluster_config WHERE key = 'cluster_id'")
        )
    ).fetchone()
    cluster_id_value = cluster_id_row.value if cluster_id_row else ""

    nonce = secrets.token_hex(16)
    row = (
        await db.execute(
            text(
                "INSERT INTO vault_challenges "
                "(challenge, expires_at, purpose, node_uuid, source_ip, issued_at) "
                "VALUES ("
                "    :c, NOW() + make_interval(secs => :ttl),"
                "    'cluster_join', :u, :ip, NOW()"
                ") "
                "RETURNING issued_at, expires_at"
            ),
            {
                "c": nonce,
                "ttl": settings.cluster_challenge_ttl_secs,
                "u": body.node_uuid,
                "ip": source_ip,
            },
        )
    ).fetchone()
    await db.commit()

    return ClusterChallengeResponse(
        nonce=nonce,
        issued_at=row.issued_at.isoformat(),
        expires_at=row.expires_at.isoformat(),
        cluster_version=settings.version,
        cluster_min_compatible_version=settings.cluster_min_compatible_version,
        observed_source_ip=source_ip,
        cluster_id=cluster_id_value,
    )


@router.post(
    "/cluster/join",
    response_model=ClusterJoinResponse,
)
async def cluster_join(
    request: Request,
    body: ClusterJoinRequest,
    db: AsyncSession = Depends(get_db),
):
    """Step 2 of JOIN -- consume the nonce, verify the HMAC proof, mint a cert.

    Public endpoint. The proof is :

        HMAC-SHA512(ha_password,
                    cluster_id || node_uuid || source_ip || nonce
                    || str(int(issued_at.timestamp())))

    where ``issued_at`` is the DB-recorded timestamp from the
    /cluster/challenge row (epoch seconds). The cluster recomputes it
    by reading the stored row, never trusting any timestamp the
    joiner supplies.

    Single-use is enforced by ``DELETE ... RETURNING`` on the challenge
    row in the same transaction. A replayed nonce will miss in the
    DELETE and surface as 401.

    Error mapping :
    - 401 : bad nonce / replayed nonce / expired nonce / mismatched
      (uuid, ip) binding / wrong cluster_id / bad HMAC proof. All are
      proof-style failures -- the joiner has insufficient credentials.
    - 409 : version below floor (joiner too old) / cluster not init /
      vault sealed / (uuid, ip) conflict. All are
      state-style failures -- the JOIN cannot proceed regardless of
      what the joiner supplies.
    - 503 : not the master worker.

    On success, mints a fresh Ed25519 keypair, signs the cert with the
    cluster CA, wraps the private key under HKDF(ha_password,
    info="cluster-node-key-wrap:<uuid>"), persists one row in
    ``vault_cluster_nodes`` with ``ha_state='joining'`` and a
    quarantine timer, and emits an audit row.
    """
    if vault.sealed:
        raise HTTPException(status_code=409, detail="vault is sealed")
    # A follower serves JOIN too: the master-only ops below (ha_password_hmac,
    # load_cluster_ca via ha_wrap_decrypt, the key-wrap dispatch wrappers) route
    # to master over cluster_rpc. A master-loss mid-call surfaces 503 +
    # Retry-After:1 (3s recovery budget) rather than hanging.
    await _refuse_if_self_draining_or_evicted(db)

    source_ip = get_client_ip(request)
    await check_rate_limit(db, source_ip)

    # Idempotency cache check BEFORE any state mutation. A retrying joiner
    # whose previous attempt succeeded server-side but never saw the reply
    # replays the same nonce; serving the cached payload returns the identical
    # cert + wrapped key. Without this the challenge row is already consumed
    # (step 1 below) so the retry would 401 and then either fail permanently
    # or mint a fresh divergent cert via the NodeUuidExistsError refresh path.
    #
    # The (node_uuid, source_ip) binding is cross-checked in Python, not the
    # WHERE clause, so a nonce-but-mismatch surfaces as 401 instead of a silent
    # miss that would leak the cache row's existence to a nonce-probing attacker.
    cache_row = (
        await db.execute(
            text(
                "SELECT response_json, node_uuid, source_ip "
                "FROM vault_join_idempotency "
                "WHERE nonce = :n AND expires_at > NOW()"
            ),
            {"n": body.nonce},
        )
    ).fetchone()
    if cache_row is not None:
        if cache_row.node_uuid != body.node_uuid or cache_row.source_ip != source_ip:
            raise HTTPException(
                status_code=401,
                detail="nonce binding mismatch on cache replay",
            )
        _metrics.cluster_join_idempotency_hits.inc()
        log.info(
            "cluster_join: idempotent replay served from cache node=%s ip=%s",
            body.node_uuid,
            source_ip,
        )
        return ClusterJoinResponse.model_validate_json(cache_row.response_json)

    if not await cluster_ca.is_initialised(db):
        raise HTTPException(status_code=409, detail="cluster not initialised")

    if not _version_at_least(
        body.rhorizon_version, settings.cluster_min_compatible_version
    ):
        raise HTTPException(
            status_code=409,
            detail=(
                f"rhorizon_version {body.rhorizon_version} below cluster floor "
                f"{settings.cluster_min_compatible_version}"
            ),
        )

    # Step 1 : consume the challenge row atomically. DELETE+RETURNING is
    # the single-use guard ; a concurrent JOIN with the same nonce would
    # see the row gone here. Filter on (purpose, expires_at > NOW())
    # so an expired nonce is treated as gone, not as a replay.
    challenge_row = (
        await db.execute(
            text(
                "DELETE FROM vault_challenges "
                "WHERE challenge = :c "
                "  AND purpose = 'cluster_join' "
                "  AND expires_at > NOW() "
                "RETURNING node_uuid, source_ip, issued_at"
            ),
            {"c": body.nonce},
        )
    ).fetchone()
    if challenge_row is None:
        raise HTTPException(status_code=401, detail="invalid or expired nonce")

    # Step 2/3 : binding checks. The body fields are what the joiner
    # *claims* ; the row carries what was bound at challenge time + the
    # IP we observed *now*. Both must agree.
    if challenge_row.node_uuid != body.node_uuid:
        raise HTTPException(status_code=401, detail="node_uuid mismatch")
    if challenge_row.source_ip != source_ip:
        raise HTTPException(status_code=401, detail="source_ip mismatch")

    # Step 3b : revoked-uuid gate. A previously-evicted node cannot re-onboard
    # under the same identity. Checked AFTER the (uuid, ip) binding so an
    # attacker who doesn't already know the uuid can't probe the revoked list
    # for a 403/401 oracle. Operator re-onboards via POST /cluster/unrevoke.
    if await cluster_membership.is_revoked(db, body.node_uuid):
        await log_action(
            db,
            actor=f"node:{body.node_uuid}",
            action="cluster_join_revoked",
            target=body.cluster_id,
            detail={"node_uuid": body.node_uuid, "source_ip": source_ip},
            ip_address=source_ip,
        )
        await db.commit()
        raise HTTPException(
            status_code=403,
            detail="node_uuid is revoked -- operator must /cluster/unrevoke first",
        )

    # Step 4 : cluster_id must match what /cluster/init stored. A joiner
    # pointing at the wrong cluster would otherwise mint a valid-looking
    # cert here ; we refuse pre-HMAC because the cluster_id is part of
    # the HMAC message and any mismatch would cascade anyway.
    cluster_id_row = (
        await db.execute(
            text("SELECT value FROM vault_cluster_config WHERE key = 'cluster_id'")
        )
    ).fetchone()
    if cluster_id_row is None or cluster_id_row.value != body.cluster_id:
        raise HTTPException(status_code=401, detail="cluster_id mismatch")

    # Step 5 : pre-check for a descriptive 409. The partial unique on source_ip
    # is the atomic guarantee at INSERT (Step 10); a concurrent same-IP JOIN that
    # races past here is still caught (SourceIpRebindError handler).
    if not await cluster_nodes.check_source_ip_unbound(db, source_ip, body.node_uuid):
        _metrics.cluster_uuid_ip_conflicts.inc()
        raise HTTPException(
            status_code=409,
            detail="source_ip already bound to a different active node",
        )

    # Step 6 : recompute the HMAC proof. The message is the same
    # canonical bytes the joiner used : cluster_id || node_uuid ||
    # source_ip || nonce || str(issued_at_epoch_secs). issued_at
    # comes from the DB row, not the body.
    issued_at_epoch = int(challenge_row.issued_at.timestamp())
    canonical = (
        body.cluster_id.encode()
        + body.node_uuid.encode()
        + source_ip.encode()
        + body.nonce.encode()
        + str(issued_at_epoch).encode()
    )
    expected_hex = await vault.ha_password_hmac(canonical)
    if not _hmac.compare_digest(expected_hex, body.ha_password_proof):
        raise HTTPException(status_code=401, detail="ha_password proof mismatch")

    # Step 7 : load CA + sign a per-node cert.
    ca_pair = await cluster_ca.load_cluster_ca(db)
    if ca_pair is None:
        # Should never fire after the is_initialised check above, but
        # the race window is non-zero in principle (a CA rotation in
        # flight) -- treat as a transient 503.
        raise HTTPException(
            status_code=503,
            detail="cluster CA not loaded",
            headers={"Retry-After": "1"},
        )
    ca_cert_pem, ca_key_pem = ca_pair

    # No election/signing gate here on purpose: the node cert is a pure identity
    # bundle (CN=node_uuid, SAN=source_ip) signed by the cluster CA, encodes no
    # primary state, and the joining-row INSERT below doesn't race primary_uuid
    # -- so minting mid-election is equally valid. Auth is already enforced
    # upstream (HMAC proof + (uuid, source_ip) binding).
    try:
        node_cert_pem, node_key_pem = cluster_ca.sign_node_cert(
            ca_cert_pem, ca_key_pem, body.node_uuid, source_ip
        )

        # Step 7b : mint the joiner's nginx server cert under the same CA. SAN
        # carries the observed source_ip; no DNS at JOIN time (IP is
        # authoritative, DNS would be an out-of-band claim). Validity tracks
        # the dedicated server-cert setting, independent of the node-identity
        # cert.
        server_cert_pem, server_key_pem = cluster_ca.sign_server_cert(
            ca_cert_pem, ca_key_pem, [source_ip], []
        )
    finally:
        secure_zero(ca_key_pem)

    # Step 8 : wrap the private keys for the joiner, which replays the same
    # HKDF(ha_password, info="cluster-{node,server}-key-wrap:<uuid>") to recover
    # each. Separate HKDF info domains keep the two blobs non-interchangeable.
    # Follower-safe: master wraps locally, follower RPCs to master (only master
    # holds vault._ha_password_enc).
    wrapped_key = await ha_password.wrap_node_key_for_joiner_dispatch(
        node_key_pem, body.node_uuid
    )
    wrapped_server_key = await ha_password.wrap_server_key_for_joiner_dispatch(
        server_key_pem, body.node_uuid
    )

    # Step 9 : compute cert metadata for the membership row.
    parsed_cert = cluster_ca.parse_cert(node_cert_pem)
    cert_fingerprint = cluster_ca.compute_fingerprint(node_cert_pem)
    cert_not_after = parsed_cert.not_valid_after_utc

    # Step 10 : persist the membership row in joining state. Wrap the INSERT in a
    # SAVEPOINT (begin_nested) so a PK collision rolls back just the failed
    # INSERT, not the whole transaction -- the idempotent-retry UPDATE on the
    # catch path needs a usable session (else the parent tx is in
    # InFailedSQLTransactionError and any further query crashes).
    try:
        async with db.begin_nested():
            await cluster_nodes.insert_joining_node(
                db,
                node_uuid=body.node_uuid,
                source_ip=source_ip,
                cluster_version=settings.version,
                cert_fingerprint=cert_fingerprint,
                cert_not_after=cert_not_after,
                quarantine_secs=settings.cluster_join_quarantine_secs,
            )
        _retry_idempotent = False
    except cluster_nodes.SourceIpRebindError as exc:
        # Concurrent same-IP/different-uuid JOIN that raced past Step 5; the
        # partial unique caught it at INSERT. Mirror the 409.
        _metrics.cluster_uuid_ip_conflicts.inc()
        raise HTTPException(
            status_code=409,
            detail="source_ip already bound to a different active node",
        ) from exc
    except cluster_nodes.NodeUuidExistsError as exc:
        # Idempotent retry: the joiner walked JOIN again with the same (uuid, ip)
        # -- typically a transient 503 on a previous attempt that succeeded
        # server-side but the client never saw the reply. If the existing row is
        # still 'joining' (not integrated), refresh its cert metadata with the
        # fresh pair + reset quarantine and return the new payload. Any other
        # ha_state means the node already integrated -- 409 stands, operator REJOINs.
        refreshed = await cluster_nodes.refresh_joining_row(
            db,
            node_uuid=body.node_uuid,
            cert_fingerprint=cert_fingerprint,
            cert_not_after=cert_not_after,
            quarantine_secs=settings.cluster_join_quarantine_secs,
        )
        if not refreshed:
            raise HTTPException(
                status_code=409,
                detail="node_uuid already present -- use REJOIN flow",
            ) from exc
        # Idempotent retry succeeded ; mark for the audit log so the
        # operator can distinguish a first-JOIN from a retry-JOIN.
        _retry_idempotent = True

    # Step 11 : audit. Detail captures the public identifiers only --
    # no plaintext ha_password, no cert key material.
    primary_uuid_row = (
        await db.execute(
            text("SELECT value FROM vault_cluster_config WHERE key = 'primary_uuid'")
        )
    ).fetchone()
    primary_uuid = primary_uuid_row.value if primary_uuid_row else ""

    await log_action(
        db,
        actor=f"node:{body.node_uuid}",
        action="cluster_join_retry" if _retry_idempotent else "cluster_join",
        target=body.cluster_id,
        detail={
            "node_uuid": body.node_uuid,
            "source_ip": source_ip,
            "cert_fingerprint": cert_fingerprint,
            "cluster_version": settings.version,
            "ha_state": "joining",
            "idempotent_retry": _retry_idempotent,
        },
        ip_address=source_ip,
    )

    # Re-read the row so we return the canonical quarantine_until the
    # DB persisted (avoid clock drift between Python NOW and DB NOW).
    inserted = await cluster_nodes.get_node(db, body.node_uuid)

    response = ClusterJoinResponse(
        accepted=True,
        ha_state=inserted.ha_state,
        quarantine_until=inserted.quarantine_until.isoformat(),
        primary_uuid=primary_uuid,
        cluster_version=settings.version,
        node_cert_pem=node_cert_pem.decode("ascii"),
        node_cert_key_wrapped_hex=wrapped_key.hex(),
        ca_cert_pem=ca_cert_pem.decode("ascii"),
        server_cert_pem=server_cert_pem.decode("ascii"),
        server_cert_key_wrapped_hex=wrapped_server_key.hex(),
    )

    # Step 12 : persist the idempotency cache row so a retry of the same nonce
    # within TTL replays the identical payload. ON CONFLICT DO NOTHING guards the
    # rare race where two concurrent retries miss the cache, consume *different*
    # challenges, and both reach the INSERT: first INSERT wins, the loser's row
    # is dropped (its caller still gets a valid response, just uncached).
    await db.execute(
        text(
            "INSERT INTO vault_join_idempotency "
            "(nonce, node_uuid, source_ip, response_json, expires_at) "
            "VALUES (:n, :u, :ip, :r, "
            "        NOW() + (CAST(:ttl AS int) * INTERVAL '1 second')) "
            "ON CONFLICT (nonce) DO NOTHING"
        ),
        {
            "n": body.nonce,
            "u": body.node_uuid,
            "ip": source_ip,
            "r": response.model_dump_json(),
            "ttl": settings.cluster_join_idempotency_ttl_secs,
        },
    )

    await db.commit()

    log.info(
        "cluster_join: node=%s ip=%s cert_fpr=%s retry=%s",
        body.node_uuid,
        source_ip,
        cert_fingerprint,
        _retry_idempotent,
    )

    return response


# ---------------------------------------------------------------------------
# GET /cluster/ha visibility + GET /cluster/ha/self
# ---------------------------------------------------------------------------


class ClusterHaNode(BaseModel):
    node_uuid: str
    source_ip: str
    ha_state: str
    quarantine_until: str | None
    joined_at: str
    last_heartbeat: str | None
    cluster_version: str
    cert_fingerprint: str
    cert_not_after: str


class ClusterHaResponse(BaseModel):
    cluster_id: str
    cluster_version: str
    cluster_min_compatible_version: str
    primary_uuid: str | None
    ha_loaded: bool
    nodes: list[ClusterHaNode]
    uuid_ip_conflicts_total: int


class ClusterHaSelfResponse(BaseModel):
    node_uuid: str
    ha_state: str | None
    quarantine_until: str | None
    last_heartbeat: str | None
    ha_loaded: bool


class ClusterHaMembershipResponse(BaseModel):
    """Minimal public membership lookup payload.

    Carries only fields that are already exposed to anyone who can mTLS-
    handshake the node : the node_uuid (claimed in the handshake), the
    ha_state (observable from the cluster's behavior), the cert
    fingerprint (the SHA-256 of the cert PEM the node presents), and
    the cert expiry. No source_ip (LAN topology probe), no last_heartbeat
    (liveness fingerprinting), no joined_at / cluster_version (cluster-
    shape leak), no primary_uuid (separate decision surface).
    """

    node_uuid: str
    ha_state: str
    cert_fingerprint: str
    cert_not_after: str


def _iso_or_none(value) -> str | None:
    """ISO 8601 string for a TIMESTAMPTZ column, ``None`` if NULL."""
    if value is None:
        return None
    return value.isoformat()


@router.get(
    "/cluster/ha",
    response_model=ClusterHaResponse,
    dependencies=[Depends(require_permission("cluster", "r"))],
)
async def cluster_ha(db: AsyncSession = Depends(get_db)):
    """Cluster HA visibility -- members, states, timers, conflicts.

    Cluster-read endpoint that surfaces everything the
    operator needs to diagnose cluster health without a DB shell :

    - ``cluster_id`` + ``cluster_version`` -- bootstrap identity.
      ``cluster_id`` requires cluster:r (or the equivalent admin:r).
    - ``primary_uuid`` -- which node currently holds the primary role
      (resolved from ``vault_cluster_config``, not from
      ``vault_cluster_nodes`` -- failover races would briefly create
      two ``primary`` rows ; the config scalar is the tie-breaker).
    - ``ha_loaded`` -- whether the RAM cache for ha_password is hot
      on the worker handling this request. Failure mode mapped to
      ``False`` after an unseal means something went wrong
      silently. The counter ``ha_password_load_failures_total`` is the
      historical companion.
    - ``nodes`` -- every non-evicted membership row, ordered by
      ``joined_at``. ``ha_state``, ``quarantine_until``, and
      ``last_heartbeat`` let the operator watch a joining node move
      to secondary in real time.
    - ``uuid_ip_conflicts_total`` -- monotonic counter mirroring the
      Prometheus metric ; non-zero rate signals a (uuid, ip) conflict event
      (volume-wipe-rejoin attempt). A counter snapshot is kept
      over a row-level conflict list to keep the schema lean ; the
      audit chain captures the per-event detail.

    Errors :

    - ``409 cluster_not_initialised`` -- ``cluster_id`` row absent
      (the cluster has not been /cluster/init-ed yet). Surfaces a
      meaningful diagnostic ahead of letting the consumer figure out
      from an empty ``nodes`` list.
    """
    cluster_id_row = (
        await db.execute(
            text("SELECT value FROM vault_cluster_config WHERE key = 'cluster_id'")
        )
    ).fetchone()
    if cluster_id_row is None:
        raise HTTPException(
            status_code=409, detail="cluster not initialised -- call /cluster/init"
        )

    primary_uuid_row = (
        await db.execute(
            text("SELECT value FROM vault_cluster_config WHERE key = 'primary_uuid'")
        )
    ).fetchone()
    primary_uuid_val = primary_uuid_row.value if primary_uuid_row else None

    rows = await cluster_nodes.list_nodes(db)
    nodes = [
        ClusterHaNode(
            node_uuid=r.node_uuid,
            source_ip=r.source_ip,
            ha_state=r.ha_state,
            quarantine_until=_iso_or_none(r.quarantine_until),
            joined_at=r.joined_at.isoformat(),
            last_heartbeat=_iso_or_none(r.last_heartbeat),
            cluster_version=r.cluster_version,
            cert_fingerprint=r.cert_fingerprint,
            cert_not_after=r.cert_not_after.isoformat(),
        )
        for r in rows
    ]

    # Prometheus Counter -- the public `.inc()` API does not expose the
    # current value, so we reach into the internal sample. This is the
    # documented pattern (`Counter._value.get()` is the same accessor
    # `collect()` uses under the hood) and keeps this endpoint from growing a
    # parallel application-side counter just for the JSON response.
    uuid_ip_conflicts = int(_metrics.cluster_uuid_ip_conflicts._value.get())

    return ClusterHaResponse(
        cluster_id=cluster_id_row.value,
        cluster_version=settings.version,
        cluster_min_compatible_version=settings.cluster_min_compatible_version,
        primary_uuid=primary_uuid_val,
        ha_loaded=await ha_password.is_loaded_anywhere(),
        nodes=nodes,
        uuid_ip_conflicts_total=uuid_ip_conflicts,
    )


@router.get(
    "/cluster/ha/self",
    response_model=ClusterHaSelfResponse,
    dependencies=[Depends(require_vault_token)],
)
async def cluster_ha_self(db: AsyncSession = Depends(get_db)):
    """Local-node HA self-view -- intended for a joining node poll loop.

    Authentication is bearer-only (any valid vault
    token) -- a node holding admin credentials would just call
    /cluster/ha ; this endpoint exists so an operator can ship a
    minimal-scope token to a joining replica and let it observe its
    own ``quarantine_until`` countdown without granting visibility to
    its peers.

    ``node_uuid`` is resolved server-side from
    :func:`api.app.node_uuid.get_node_uuid` -- never trusted from the
    body or the token claims. A token cannot impersonate another
    node's row.

    The row is ``None`` until /cluster/join lands the joining INSERT.
    The endpoint returns ``ha_state=None`` rather than 404 in that
    window so a polling client sees a stable shape across the JOIN
    boundary.
    """
    my_uuid = get_node_uuid()
    row = await cluster_nodes.get_node(db, my_uuid)
    if row is None:
        return ClusterHaSelfResponse(
            node_uuid=my_uuid,
            ha_state=None,
            quarantine_until=None,
            last_heartbeat=None,
            ha_loaded=await ha_password.is_loaded_anywhere(),
        )
    return ClusterHaSelfResponse(
        node_uuid=my_uuid,
        ha_state=row.ha_state,
        quarantine_until=_iso_or_none(row.quarantine_until),
        last_heartbeat=_iso_or_none(row.last_heartbeat),
        ha_loaded=await ha_password.is_loaded_anywhere(),
    )


@router.get(
    "/cluster/ha/membership/{node_uuid}",
    response_model=ClusterHaMembershipResponse,
)
async def cluster_ha_membership(node_uuid: str, db: AsyncSession = Depends(get_db)):
    """Public minimal lookup of a cluster member by UUID.

    The auto-JOIN task uses this endpoint to discriminate a transient
    409 from /cluster/join (the row exists but
    :func:`cluster_nodes.refresh_joining_row` refused -- typically the
    quarantine elapsed and the state machine flipped 'joining' to
    'secondary' between the joiner's two attempts) from a permanent
    one (the row was never created, or the joiner truly has no path
    back to the wrapped key). The joiner has no bearer token at this
    point in its lifecycle -- /cluster/init owns the only
    ``ha_password`` it knows, not a vault token -- so making the
    endpoint public-but-minimal lets the discriminator work without
    growing a bootstrap token surface for one diagnostic call.

    Discoverability surface is deliberate :

    - ``ha_state`` is the membership state, no metadata. The values
      are stable cluster vocabulary documented in the runbook.
    - ``cert_fingerprint`` + ``cert_not_after`` are public material
      already shipped at JOIN time (the joiner persists them on disk)
      and re-presented at every mTLS handshake. Leaking them here is
      information already known to anyone who can reach the node's
      TLS endpoint -- the public-key infrastructure surface is
      identical with or without this endpoint.
    - No ``source_ip`` (would let a probe map UUIDs to LAN topology
      without auth -- a sealed cluster would still expose neighbor
      IPs).
    - No ``last_heartbeat`` (live-aliveness fingerprinting).
    - No ``joined_at`` / ``cluster_version`` (cluster-shape leak).
    - No ``primary_uuid`` (separate decision surface ; admin reads
      it from /cluster/ha, joiners do not need it for the 409 path).

    Errors :

    - ``404`` -- unknown uuid OR ``ha_state == 'evicted'``. The
      revoked list is private ; a 404 here is
      indistinguishable from never-existed.
    - ``503`` -- vault sealed. Even minimal data leaks would be
      surprising during a maintenance window ; the sealed gate also
      protects the diagnostic value (a sealed cluster cannot serve
      JOINs anyway, so the 409 -> membership-lookup chain has no
      reason to run during a seal).
    """
    if vault.sealed:
        raise HTTPException(
            status_code=503,
            detail="vault is sealed",
            headers={"Retry-After": "5"},
        )
    row = await cluster_nodes.get_node(db, node_uuid)
    if row is None or row.ha_state == "evicted":
        raise HTTPException(status_code=404, detail="node_uuid not found")
    return ClusterHaMembershipResponse(
        node_uuid=row.node_uuid,
        ha_state=row.ha_state,
        cert_fingerprint=row.cert_fingerprint,
        cert_not_after=row.cert_not_after.isoformat(),
    )


# ---------------------------------------------------------------------------
# Operator triggers : promote / demote / drain / evict + unrevoke
# ---------------------------------------------------------------------------
#
# All five are admin:w-gated and serialised on the cluster-wide advisory lock
# (with_cluster_lock / pg_try_advisory_xact_lock); on contention the route
# surfaces 409 cluster_op_in_flight. The election random-delay [0,1s] is kept so
# the manual path stays symmetric with the autonomous-election path.
#
# Drain is async (202 + reaper): the route poses ha_state='draining' +
# drain_deadline_at and returns; the reaper bascules draining -> evicted past the
# deadline and appends to revoked_node_uuids.
#
# Evict is definitive (append-only revoked_node_uuids) but reversible via
# /cluster/unrevoke -- an operator who clicked the wrong button recovers without
# a wipe-and-reinstall; every unrevoke emits a distinct audit row.


class ClusterNodeOpResponse(BaseModel):
    node_uuid: str
    ha_state: str
    primary_uuid: str | None = None
    drain_deadline_at: str | None = None


class ClusterUnrevokeResponse(BaseModel):
    node_uuid: str
    revoked: bool  # always False after a successful unrevoke


_CLUSTER_OP_IN_FLIGHT_DETAIL = "another cluster membership op is in flight -- retry"


# Non-promotable source states: a node in transit (joining/quarantined), on the
# way out (draining), or terminal (evicted) is ineligible for promote/demote/
# drain. Promote/demote add their own state-specific guards on top.
_NON_PROMOTABLE_STATES = frozenset({"joining", "quarantined", "draining", "evicted"})


async def _read_node_or_404(db: AsyncSession, node_uuid: str):
    row = await cluster_nodes.get_node(db, node_uuid)
    if row is None:
        raise HTTPException(status_code=404, detail=f"unknown node_uuid {node_uuid}")
    return row


def _version_compatible_with_floor(node_version: str) -> bool:
    """Promote-time version gate.

    A node whose ``cluster_version`` slipped below the configured floor
    cannot be promoted to primary -- the floor is a hard invariant of
    the cluster, not a polite suggestion. Demote/drain/evict do NOT
    apply the gate (the operator may need to evict an out-of-version
    node ; refusing to evict it would be a worse failure mode).
    """
    return _version_at_least(node_version, settings.cluster_min_compatible_version)


@router.post(
    "/cluster/promote/{node_uuid}",
    response_model=ClusterNodeOpResponse,
)
async def cluster_promote(
    node_uuid: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("cluster", "w")),
):
    """Promote ``node_uuid`` to primary, demote the previous primary.

    Targets a specific node rather than triggering a blind election --
    the operator carrying admin:w usually knows which node should hold
    primary (post-maintenance, region failover, planned hand-off).

    Atomic transaction :
      1. acquire the cluster-wide election lock ;
      2. random delay [0, 1s] (symmetry with autonomous election) ;
      3. validate target eligibility (state, version) ;
      4. flip target ``secondary`` -> ``primary`` ;
      5. flip ex-primary ``primary`` -> ``secondary`` (if any) ;
      6. update ``vault_cluster_config(primary_uuid)`` ;
      7. audit + counters.

    Returns 404 if the target does not exist, 409 if it is in a non-
    promotable state, or if its ``cluster_version`` is below the
    cluster floor, or if another cluster op holds the lock.
    """
    actor = token_info.get("name") or "admin"
    client_ip = get_client_ip(request)

    async def _body():
        # Random delay -- preserves the discipline of the autonomous
        # election path (no one can predict the claim ordering under
        # contention, even with admin credentials).
        await cluster_membership.election_random_delay()

        target = await _read_node_or_404(db, node_uuid)
        if target.ha_state == "primary":
            raise HTTPException(
                status_code=409,
                detail=f"node {node_uuid} is already primary",
            )
        if target.ha_state in _NON_PROMOTABLE_STATES:
            raise HTTPException(
                status_code=409,
                detail=(
                    f"node {node_uuid} is in state '{target.ha_state}' -- "
                    f"cannot promote"
                ),
            )
        if not _version_compatible_with_floor(target.cluster_version):
            raise HTTPException(
                status_code=409,
                detail=(
                    f"node {node_uuid} version {target.cluster_version} below "
                    f"cluster floor {settings.cluster_min_compatible_version}"
                ),
            )

        old_primary = await cluster_membership.read_primary_uuid(db)

        # Enforce the singleton in the election transaction.  Demoting all
        # stale primary rows (not only primary_uuid) also repairs a legacy
        # double-primary state in one operator action.
        flipped, demoted_primaries = await cluster_membership.promote_node_singleton(
            db, node_uuid, from_state="secondary"
        )
        if not flipped:
            raise HTTPException(
                status_code=409,
                detail=f"node {node_uuid} state changed during election -- retry",
            )

        await cluster_membership.set_primary_uuid(db, node_uuid)

        await log_action(
            db,
            actor=actor,
            action="cluster_node_promoted",
            target=node_uuid,
            detail={
                "previous_primary_uuid": old_primary,
                "demoted_primary_uuids": demoted_primaries,
                "target_version": target.cluster_version,
            },
            ip_address=client_ip,
        )
        await db.commit()

    acquired = await with_cluster_lock(
        db, cluster_membership.PRIMARY_ELECTION_LOCK, _body
    )
    if not acquired:
        raise HTTPException(status_code=409, detail=_CLUSTER_OP_IN_FLIGHT_DETAIL)

    fresh = await cluster_nodes.get_node(db, node_uuid)
    log.info("cluster_promote: node=%s by=%s", node_uuid, actor)
    return ClusterNodeOpResponse(
        node_uuid=node_uuid,
        ha_state=fresh.ha_state,
        primary_uuid=node_uuid,
    )


@router.post(
    "/cluster/demote/{node_uuid}",
    response_model=ClusterNodeOpResponse,
)
async def cluster_demote(
    node_uuid: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("cluster", "w")),
):
    """Demote the current primary back to secondary. Clears primary_uuid.

    The caller must target the *current* primary -- attempting to demote
    a secondary yields 409. Demote leaves the cluster temporarily
    without a primary ; the operator is expected to follow up with a
    POST /cluster/promote/{node_uuid} on the new primary, or to wait
    for the autonomous election path to fill the gap.
    """
    actor = token_info.get("name") or "admin"
    client_ip = get_client_ip(request)

    async def _body():
        await cluster_membership.election_random_delay()

        target = await _read_node_or_404(db, node_uuid)
        if target.ha_state != "primary":
            raise HTTPException(
                status_code=409,
                detail=(
                    f"node {node_uuid} is in state '{target.ha_state}' -- "
                    f"only the current primary can be demoted"
                ),
            )

        flipped = await cluster_membership.transition_node(
            db, node_uuid, from_state="primary", to_state="secondary"
        )
        if not flipped:
            raise HTTPException(
                status_code=409,
                detail=f"node {node_uuid} state changed during demote -- retry",
            )
        await cluster_membership.set_primary_uuid(db, None)

        await log_action(
            db,
            actor=actor,
            action="cluster_node_demoted",
            target=node_uuid,
            detail={},
            ip_address=client_ip,
        )
        await db.commit()

    acquired = await with_cluster_lock(
        db, cluster_membership.PRIMARY_ELECTION_LOCK, _body
    )
    if not acquired:
        raise HTTPException(status_code=409, detail=_CLUSTER_OP_IN_FLIGHT_DETAIL)

    fresh = await cluster_nodes.get_node(db, node_uuid)
    log.info("cluster_demote: node=%s by=%s", node_uuid, actor)
    return ClusterNodeOpResponse(
        node_uuid=node_uuid,
        ha_state=fresh.ha_state,
        primary_uuid=None,
    )


@router.post(
    "/cluster/drain/{node_uuid}",
    response_model=ClusterNodeOpResponse,
    status_code=202,
)
async def cluster_drain(
    node_uuid: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("cluster", "w")),
):
    """Mark ``node_uuid`` as draining, set its deadline, return 202.

    Async pattern : the route poses ``ha_state='draining'`` +
    ``drain_deadline_at = NOW() + cluster_drain_deadline_secs`` and
    returns immediately. The reaper
    later bascules ``draining`` -> ``evicted`` past the deadline and
    appends the uuid to ``revoked_node_uuids``.

    Idempotency : 409 on a node already draining/evicted. The operator
    must explicitly cancel a stale drain (a /cluster/drain/cancel
    may be added later).

    The current primary (master) cannot be drained directly -- the
    operator must POST /cluster/demote/{node_uuid} first, then drain
    the ex-primary. This makes the operator pause on the destructive
    side of the operation : losing a secondary degrades the cluster ;
    losing the primary blocks every cluster op until a successor is
    elected.
    """
    actor = token_info.get("name") or "admin"
    client_ip = get_client_ip(request)

    async def _body():
        target = await _read_node_or_404(db, node_uuid)
        if target.ha_state == "primary":
            raise HTTPException(
                status_code=409,
                detail=(
                    f"node {node_uuid} is the current primary -- demote "
                    f"it first via POST /cluster/demote/{{node_uuid}}"
                ),
            )
        if target.ha_state in {"draining", "evicted"}:
            raise HTTPException(
                status_code=409,
                detail=(
                    f"node {node_uuid} is in state '{target.ha_state}' -- cannot drain"
                ),
            )
        if target.ha_state in {"joining", "quarantined"}:
            raise HTTPException(
                status_code=409,
                detail=(
                    f"node {node_uuid} is in state '{target.ha_state}' -- "
                    f"evict it instead, drain expects a stable member"
                ),
            )

        flipped = await cluster_membership.transition_node(
            db,
            node_uuid,
            from_state=target.ha_state,
            to_state="draining",
            set_drain_deadline_secs=settings.cluster_drain_deadline_secs,
        )
        if not flipped:
            raise HTTPException(
                status_code=409,
                detail=f"node {node_uuid} state changed during drain -- retry",
            )

        await log_action(
            db,
            actor=actor,
            action="cluster_node_drained",
            target=node_uuid,
            detail={
                "previous_state": target.ha_state,
                "deadline_secs": settings.cluster_drain_deadline_secs,
            },
            ip_address=client_ip,
        )
        await db.commit()

    acquired = await with_cluster_lock(
        db, cluster_membership.PRIMARY_ELECTION_LOCK, _body
    )
    if not acquired:
        raise HTTPException(status_code=409, detail=_CLUSTER_OP_IN_FLIGHT_DETAIL)

    fresh = await cluster_nodes.get_node(db, node_uuid)
    primary_uuid_now = await cluster_membership.read_primary_uuid(db)
    log.info(
        "cluster_drain: node=%s by=%s deadline_secs=%d",
        node_uuid,
        actor,
        settings.cluster_drain_deadline_secs,
    )
    return ClusterNodeOpResponse(
        node_uuid=node_uuid,
        ha_state=fresh.ha_state,
        primary_uuid=primary_uuid_now,
        drain_deadline_at=_iso_or_none(fresh.drain_deadline_at),
    )


@router.post(
    "/cluster/evict/{node_uuid}",
    response_model=ClusterNodeOpResponse,
)
async def cluster_evict(
    node_uuid: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("cluster", "w")),
):
    """Immediately evict ``node_uuid`` + append to revoked_node_uuids.

    No grace : RPC ops in flight on the evicted node are not waited for.
    Use this for compromise / incident response. For planned removal,
    prefer drain.

    The current primary (master) cannot be evicted directly -- the
    operator must POST /cluster/demote/{node_uuid} first, then evict
    the ex-primary. Same rationale as drain : forces a pause before
    leaving the cluster headless.

    A subsequent JOIN with the same ``node_uuid`` is rejected with 403
    by /cluster/join.
    """
    actor = token_info.get("name") or "admin"
    client_ip = get_client_ip(request)

    async def _body():
        target = await _read_node_or_404(db, node_uuid)
        if target.ha_state == "primary":
            raise HTTPException(
                status_code=409,
                detail=(
                    f"node {node_uuid} is the current primary -- demote "
                    f"it first via POST /cluster/demote/{{node_uuid}}"
                ),
            )
        if target.ha_state == "evicted":
            raise HTTPException(
                status_code=409,
                detail=f"node {node_uuid} is already evicted",
            )

        flipped = await cluster_membership.transition_node(
            db,
            node_uuid,
            from_state=target.ha_state,
            to_state="evicted",
            clear_drain_deadline=True,
        )
        if not flipped:
            raise HTTPException(
                status_code=409,
                detail=f"node {node_uuid} state changed during evict -- retry",
            )

        await cluster_membership.add_revoked_uuid(
            db, node_uuid, actor=actor, ip_address=client_ip
        )

        await log_action(
            db,
            actor=actor,
            action="cluster_node_evicted",
            target=node_uuid,
            detail={"previous_state": target.ha_state},
            ip_address=client_ip,
        )
        await db.commit()

    acquired = await with_cluster_lock(
        db, cluster_membership.PRIMARY_ELECTION_LOCK, _body
    )
    if not acquired:
        raise HTTPException(status_code=409, detail=_CLUSTER_OP_IN_FLIGHT_DETAIL)

    fresh = await cluster_nodes.get_node(db, node_uuid)
    primary_uuid_now = await cluster_membership.read_primary_uuid(db)
    log.info("cluster_evict: node=%s by=%s", node_uuid, actor)
    return ClusterNodeOpResponse(
        node_uuid=node_uuid,
        ha_state=fresh.ha_state,
        primary_uuid=primary_uuid_now,
    )


@router.post(
    "/cluster/unrevoke/{node_uuid}",
    response_model=ClusterUnrevokeResponse,
)
async def cluster_unrevoke(
    node_uuid: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("cluster", "w")),
):
    """Remove ``node_uuid`` from revoked_node_uuids. Escape hatch.

    404 if the uuid is not currently revoked (nothing to undo).
    A successful unrevoke does NOT re-add the node to
    ``vault_cluster_nodes`` -- the operator must rejoin the node
    afterwards. The endpoint only lifts the JOIN-time 403 gate.
    """
    actor = token_info.get("name") or "admin"
    client_ip = get_client_ip(request)

    removed = await cluster_membership.remove_revoked_uuid(
        db, node_uuid, actor=actor, ip_address=client_ip
    )
    if not removed:
        raise HTTPException(
            status_code=404,
            detail=f"node_uuid {node_uuid} not in revoked list",
        )
    await db.commit()
    log.info("cluster_unrevoke: node=%s by=%s", node_uuid, actor)
    return ClusterUnrevokeResponse(node_uuid=node_uuid, revoked=False)
