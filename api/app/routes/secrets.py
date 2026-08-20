# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Secrets CRUD - encrypted at rest with double envelope + version history.

Author: shdw <horizon@resurgamus.com>
Project: Resurgamus Horizon - minimal AGPL-3.0 vault for infra automation.
License: AGPL-3.0-or-later - closed-source relicensing prohibited.
"""

import json
import logging
import uuid as _uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from rhorizon_crypto import secure_zero
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ..audit import log_action, log_read
from ..auth import (
    actor_display_name,
    check_namespace,
    check_namespace_membership,
    require_permission,
    resolve_namespace_names,
)
from ..client_ip import get_client_ip
from ..config import settings
from ..crypto import (
    SECRET_AAD_VERSION,
    dek_aad,
    secret_aad,
)
from ..database import get_db
from ..key_epoch import require_generation_current
from ..vault_state import vault

router = APIRouter(prefix="/api/v1/vault/secrets", tags=["secrets"])


def _decode_and_wipe(plaintext: bytearray) -> str:
    """Decode a Rust-returned secret buffer and wipe the mutable source."""
    try:
        return plaintext.decode()
    finally:
        secure_zero(plaintext)


def _require_namespace_mapping(row) -> str:
    """Return a secret row's namespace UUID or fail closed on corruption."""
    namespace_id = getattr(row, "namespace_id", None)
    if namespace_id is None:
        logging.getLogger("rhorizon.secrets").critical(
            "secret namespace mapping missing: secret=%s namespace=%s",
            getattr(row, "name", getattr(row, "id", "unknown")),
            getattr(row, "namespace", "unknown"),
        )
        raise HTTPException(503, "Secret namespace mapping unavailable")
    return str(namespace_id)


def _is_critical_secret_name(name: str) -> bool:
    """True when the secret name matches an ``audit_critical_secret_patterns``
    fnmatch glob -- flags writes on recovery handles for the critical audit
    marker + notification fan-out.
    """
    import fnmatch as _fnmatch

    patterns = [
        p.strip()
        for p in settings.audit_critical_secret_patterns.split(",")
        if p.strip()
    ]
    return any(_fnmatch.fnmatchcase(name, p) for p in patterns)


async def _save_version(
    db: AsyncSession,
    secret_id: str,
    version: int,
    ciphertext: bytes,
    nonce: bytes,
    dek_id: str,
    created_by: str,
):
    """Save a version snapshot and prune old versions if needed."""
    await db.execute(
        text("""
            INSERT INTO vault_secret_versions
                (secret_id, version, ciphertext, nonce, aad_version,
                 dek_id, created_by)
            VALUES
                (CAST(:sid AS uuid), :ver, :ct, :nonce, :aad_version,
                 CAST(:dek_id AS uuid), :actor)
            ON CONFLICT (secret_id, version) DO NOTHING
        """),
        {
            "sid": secret_id,
            "ver": version,
            "ct": ciphertext,
            "nonce": nonce,
            "aad_version": SECRET_AAD_VERSION,
            "dek_id": dek_id,
            "actor": created_by,
        },
    )
    # Prune oldest versions beyond limit + cleanup orphaned DEKs
    max_ver = settings.secret_max_versions
    if max_ver > 0:
        # Find versions to prune
        pruned = await db.execute(
            text("""
                DELETE FROM vault_secret_versions
                WHERE secret_id = CAST(:sid AS uuid)
                  AND version <= (
                    SELECT version FROM vault_secret_versions
                    WHERE secret_id = CAST(:sid AS uuid)
                    ORDER BY version DESC
                    OFFSET :keep LIMIT 1
                  )
                RETURNING dek_id
            """),
            {"sid": secret_id, "keep": max_ver},
        )
        # Delete orphaned DEKs (not used by current secret or other versions)
        for row in pruned.fetchall():
            await db.execute(
                text("""
                    DELETE FROM vault_dek WHERE id = CAST(:did AS uuid)
                    AND NOT EXISTS (
                        SELECT 1 FROM vault_secrets WHERE dek_id = CAST(:did AS uuid)
                    )
                    AND NOT EXISTS (
                        SELECT 1 FROM vault_secret_versions
                        WHERE dek_id = CAST(:did AS uuid)
                    )
                """),
                {"did": str(row.dek_id)},
            )


class SecretCreate(BaseModel):
    name: str = Field(..., max_length=256)
    value: str = Field(..., max_length=1_000_000)
    namespace: str = Field(default="default", max_length=255)
    metadata: dict | None = None
    expires_at: str | None = None
    is_honey: bool = Field(
        default=False,
        description=(
            "If true, the secret is a decoy. Any read fires a "
            "honey_access alert (CRITICAL log + audit + notification). "
            "Pick attractive names mirroring real ops naming "
            "(prod-pgsql-master, wg-server-private). The stored value "
            "should be plausible but fake - attackers may attempt to "
            "use it before realising."
        ),
    )


class SecretUpdate(BaseModel):
    value: str = Field(..., max_length=1_000_000)
    emergency: bool = Field(
        default=False,
        description=(
            "Suppress the rotation grace window. When false (default) and "
            "secret_grace_seconds > 0, the prior value stays readable via "
            "GET ?previous for the grace TTL during cutover. Set true when "
            "rotating because of a leak: no grace, the old value stops being "
            "served immediately."
        ),
    )


class SecretResponse(BaseModel):
    name: str
    value: str
    version: int


class SecretListItem(BaseModel):
    id: str
    name: str
    namespace: str
    version: int
    created_at: str
    updated_at: str
    dek_rotated_at: str | None = None


async def _resolve_or_create_namespace(db: AsyncSession, name: str):
    """Look up `vault_namespaces` by name, auto-creating it under `vault-admins`
    if absent (back-compat: secrets in arbitrary namespace strings keep working).
    Strict RBAC is opt-in via `POST /vault/namespaces/` with
    enforce_membership=true. Returns the row (id, name, owner_group_id,
    enforce_membership, delete_protection, archived_at).
    """
    row = (
        await db.execute(
            text(
                "SELECT id, name, owner_group_id, enforce_membership, "
                "       delete_protection, archived_at "
                "FROM vault_namespaces WHERE name = :name"
            ),
            {"name": name},
        )
    ).fetchone()
    if row is not None:
        return row
    admins_id = (
        await db.execute(
            text("SELECT id FROM vault_groups WHERE name = 'vault-admins'")
        )
    ).scalar()
    if admins_id is None:
        raise HTTPException(
            500,
            "vault-admins group missing - migration didn't run; "
            "cannot auto-create namespace",
        )
    return (
        await db.execute(
            text(
                """
                INSERT INTO vault_namespaces
                    (name, owner_group_id, created_by)
                VALUES (:name, CAST(:gid AS uuid), 'auto')
                ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
                RETURNING id, name, owner_group_id, enforce_membership,
                          delete_protection, archived_at
                """
            ),
            {"name": name, "gid": str(admins_id)},
        )
    ).fetchone()


# GET /namespaces, list namespaces with counts
@router.get("/namespaces")
async def list_namespaces(
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("secrets", "r")),
):
    vault.require_unsealed()

    result = await db.execute(
        text("""
            SELECT namespace, count(*) AS secret_count
            FROM vault_secrets
            WHERE deleted_at IS NULL
            GROUP BY namespace
            ORDER BY namespace
        """)
    )
    items = [
        {"namespace": r.namespace, "secret_count": r.secret_count}
        for r in result.fetchall()
    ]

    # A `namespaces` claim restricts the listing (wins even over admin).
    # Resolve names+UUIDs -> names (see resolve_namespace_names). None = no
    # claim = unrestricted; a resolved-empty claim filters to nothing, never
    # back to list-all.
    allowed_ns = await resolve_namespace_names(db, token_info)
    if allowed_ns is not None:
        items = [i for i in items if i["namespace"] in allowed_ns]

    return {"items": items}


class _DeleteBody(BaseModel):
    """Optional 2FA payload - required when the namespace is in 'protected'
    delete mode, or for the bulk namespace delete when 2FA is configured.
    Same duck-type as Mutation2FAEnvelope."""

    challenge: str | None = None
    yubikey_response: str | None = None
    totp_code: str | None = None
    webauthn_response: dict | None = None


# DELETE /namespaces/{namespace}, bulk-delete all secrets in a namespace.
# Admin break-glass : this is the only path that drops many secrets at once,
# so it carries the same controls as the per-secret protected delete
# (admin scope + 2FA) plus a refusal on any namespace whose delete_protection
# is not 'free'. For 'soft'/'protected' namespaces the operator deletes
# secrets individually so each follows the soft-delete / retention path.
# Previously this required only `secrets:w` with no 2FA and ignored
# delete_protection + enforce_membership, a full bypass of the namespace
# delete model (see archive_namespace in routes/namespaces.py).
@router.delete("/namespaces/{namespace}")
async def delete_namespace(
    namespace: str,
    request: Request,
    body: _DeleteBody | None = None,
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("admin", "w")),
):
    vault.require_unsealed()
    check_namespace(token_info, namespace)
    client_ip = get_client_ip(request)

    if namespace == "default":
        raise HTTPException(400, "Cannot delete the default namespace")

    # Resolve the namespace registry row : refuse bulk-delete on protected
    # namespaces and enforce membership when the namespace requires it. A
    # legacy namespace with no vault_namespaces row defaults to 'free'.
    ns_meta = (
        await db.execute(
            text(
                "SELECT id, enforce_membership, "
                "       COALESCE(delete_protection, 'free') AS dp "
                "FROM vault_namespaces WHERE name = :ns"
            ),
            {"ns": namespace},
        )
    ).fetchone()

    if ns_meta is not None:
        if ns_meta.dp != "free":
            raise HTTPException(
                409,
                f"Namespace '{namespace}' has delete_protection="
                f"'{ns_meta.dp}': bulk delete refused. Delete secrets "
                "individually so each follows the soft-delete path.",
            )
        if ns_meta.enforce_membership:
            await check_namespace_membership(
                db, token_info, str(ns_meta.id), write=True
            )

    # 2FA gate (admin scope already enforced by require_permission). Mirrors
    # the per-secret protected-delete and namespace-mutation gates.
    from .vault import _get_2fa_mode, _verify_2fa

    twofa_mode = await _get_2fa_mode(db)
    if twofa_mode != "none":
        await _verify_2fa(
            db,
            twofa_mode,
            body or _DeleteBody(),
            client_ip,
            aesgcm=None,  # delegate 2FA decrypt via RPC (follower-safe, B6)
            purpose="delete_namespace",
        )

    # Delete secrets and their DEKs
    result = await db.execute(
        text("DELETE FROM vault_secrets WHERE namespace = :ns RETURNING id, dek_id"),
        {"ns": namespace},
    )
    deleted = result.fetchall()
    if not deleted:
        raise HTTPException(404, f"Namespace '{namespace}' not found or empty")

    # Cleanup orphaned DEKs
    for row in deleted:
        await db.execute(
            text("DELETE FROM vault_dek WHERE id = CAST(:id AS uuid)"),
            {"id": str(row.dek_id)},
        )

    await log_action(
        db,
        actor=actor_display_name(token_info),
        action="delete_namespace",
        target=namespace,
        detail={"secrets_deleted": len(deleted)},
        ip_address=client_ip,
    )
    await db.commit()

    return {
        "status": "deleted",
        "namespace": namespace,
        "secrets_deleted": len(deleted),
    }


# POST /, create secret
@router.post("/", status_code=201)
async def create_secret(
    body: SecretCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("secrets", "w")),
):
    vault.require_unsealed()
    check_namespace(token_info, body.namespace)

    # Resolve / auto-create the vault_namespaces row for this name.
    # Resolve / auto-create the namespace row (back-compat); strict RBAC is
    # opt-in via POST /vault/namespaces/.
    ns_row = await _resolve_or_create_namespace(db, body.namespace)
    if ns_row.archived_at is not None:
        raise HTTPException(409, f"Namespace is archived: {body.namespace}")
    # Strict RBAC enforcement on write when the namespace requires it.
    if ns_row.enforce_membership:
        await check_namespace_membership(db, token_info, str(ns_row.id), write=True)

    # Check uniqueness on the (name, namespace) composite key.
    result = await db.execute(
        text("SELECT id FROM vault_secrets WHERE name = :name AND namespace = :ns"),
        {"name": body.name, "ns": body.namespace},
    )
    if result.fetchone():
        raise HTTPException(
            409, f"Secret '{body.name}' already exists in namespace '{body.namespace}'"
        )

    # Refuse the wrap if this host's master is mid-convergence: the DEK would
    # land under a stale dek_key (unreadable once the cluster converges). 503 +
    # Retry-After instead of silent corruption.
    await require_generation_current(db, vault)
    # Python-side UUID so the DEK AAD binds to the row id
    dek_id = str(_uuid.uuid4())
    encrypted_dek, dek_nonce, ciphertext, secret_nonce = await vault.secret_encrypt(
        body.value.encode(),
        dek_aad(dek_id),
        secret_aad(body.name, body.namespace),
    )
    await db.execute(
        text("""
            INSERT INTO vault_dek (id, encrypted_key, nonce)
            VALUES (CAST(:id AS uuid), :ekey, :nonce)
        """),
        {"id": dek_id, "ekey": encrypted_dek, "nonce": dek_nonce},
    )

    sid_result = await db.execute(
        text("""
            INSERT INTO vault_secrets
                (name, namespace, namespace_id, ciphertext, nonce, dek_id,
                 metadata, expires_at, created_by, is_honey)
            VALUES
                (:name, :ns, CAST(:ns_id AS uuid), :ct, :nonce,
                 CAST(:dek_id AS uuid), CAST(:meta AS jsonb),
                 CAST(:expires AS timestamptz), :actor, :is_honey)
            RETURNING id
        """),
        {
            "name": body.name,
            "ns": body.namespace,
            "ns_id": str(ns_row.id),
            "ct": ciphertext,
            "nonce": secret_nonce,
            "dek_id": dek_id,
            "meta": json.dumps(body.metadata or {}),
            "expires": body.expires_at,
            "actor": token_info["name"],
            "is_honey": body.is_honey,
        },
    )
    secret_id = str(sid_result.fetchone().id)

    await _save_version(
        db, secret_id, 1, ciphertext, secret_nonce, dek_id, token_info["name"]
    )

    await log_action(
        db,
        actor=actor_display_name(token_info),
        action="create_secret",
        target=body.name,
        detail={"namespace": body.namespace},
        ip_address=get_client_ip(request),
        critical=_is_critical_secret_name(body.name),
    )
    await db.commit()
    from .. import metrics as _m

    _m.secrets_write.labels(op="create").inc()

    return {"id": secret_id, "name": body.name, "version": 1}


# GET /{name}, read secret (decrypted)
@router.get("/{name}", response_model=SecretResponse)
async def get_secret(
    name: str,
    request: Request,
    namespace: str | None = Query(None),
    previous: bool = Query(
        False,
        description=(
            "Serve the prior value if it is still inside its rotation grace "
            "window (set by a non-emergency update). 404 when none is in grace."
        ),
    ),
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("secrets", "r")),
):
    vault.require_unsealed()

    result = await db.execute(
        text("""
            SELECT s.id, s.ciphertext, s.nonce, s.aad_version,
                   s.version, s.namespace,
                   s.namespace_id, s.dek_id, s.is_honey, n.enforce_membership,
                   d.encrypted_key, d.nonce AS dek_nonce
            FROM vault_secrets s
            JOIN vault_dek d ON d.id = s.dek_id
            LEFT JOIN vault_namespaces n ON n.id = s.namespace_id
            WHERE s.name = :name AND s.deleted_at IS NULL
              AND (CAST(:ns AS text) IS NULL OR s.namespace = :ns)
        """),
        {"name": name, "ns": namespace},
    )
    rows = result.fetchall()
    if not rows:
        raise HTTPException(404, f"Secret '{name}' not found")
    if len(rows) > 1:
        raise HTTPException(
            409,
            f"Secret name '{name}' is ambiguous across namespaces; "
            "specify ?namespace=<ns>",
        )
    row = rows[0]

    check_namespace(token_info, row.namespace)
    # Strict-RBAC: live owner-group membership on the read path too -- but ONLY
    # for enforce_membership namespaces. Agnostic namespaces keep the lenient
    # check_namespace model (no namespaces claim = unrestricted read) that a
    # plain secrets:r token relies on; calling check_namespace_membership there
    # 403s every no-claim read. The strict-read bypass this closes was
    # enforce_membership-only anyway.
    namespace_id = _require_namespace_mapping(row)
    if row.enforce_membership:
        await check_namespace_membership(db, token_info, namespace_id, write=False)

    # Rotation grace read: serve the prior value while it is still inside its
    # grace window. At most one version is ever in grace (update clears the
    # rest), so the newest grace-valid version is unambiguous. Audited under a
    # distinct action so stale-value reads stand out in the log.
    if previous:
        gv = await db.execute(
            text("""
                SELECT v.ciphertext, v.nonce, v.aad_version, v.version, v.dek_id,
                       d.encrypted_key, d.nonce AS dek_nonce
                FROM vault_secret_versions v
                JOIN vault_dek d ON d.id = v.dek_id
                WHERE v.secret_id = CAST(:sid AS uuid)
                  AND v.grace_until IS NOT NULL AND v.grace_until > NOW()
                ORDER BY v.version DESC
                LIMIT 1
            """),
            {"sid": str(row.id)},
        )
        gvr = gv.fetchone()
        if not gvr:
            raise HTTPException(
                404, f"No previous value of '{name}' within a grace window"
            )
        from .. import metrics as _m

        with _m.secret_decrypt_duration.time():
            gplain = await vault.secret_decrypt(
                bytes(gvr.encrypted_key),
                bytes(gvr.dek_nonce),
                dek_aad(str(gvr.dek_id)),
                bytes(gvr.ciphertext),
                bytes(gvr.nonce),
                secret_aad(name, row.namespace, version=gvr.aad_version),
            )
        value = _decode_and_wipe(gplain)
        await log_read(
            db,
            actor=actor_display_name(token_info),
            action="read_secret_previous",
            target=name,
            detail={"version": gvr.version},
            ip_address=get_client_ip(request),
        )
        await db.commit()
        _m.secrets_read.inc()
        return SecretResponse(
            name=name,
            value=value,
            version=gvr.version,
        )

    # Decrypt DEK + secret with AAD bound to the row identity. Timed: on a
    # follower the DEK unwrap is a master RPC, so this captures the per-read
    # crypto cost (secret_decrypt_duration had no observe() site before).
    from .. import metrics as _m

    with _m.secret_decrypt_duration.time():
        plaintext = await vault.secret_decrypt(
            bytes(row.encrypted_key),
            bytes(row.dek_nonce),
            dek_aad(str(row.dek_id)),
            bytes(row.ciphertext),
            bytes(row.nonce),
            secret_aad(name, row.namespace, version=row.aad_version),
        )
    value = _decode_and_wipe(plaintext)

    # Honeytoken IDS, fire alert if a decoy secret was read. Response is
    # unchanged so the attacker doesn't know we noticed.
    if row.is_honey:
        from ..honey import alert_honey_access

        await alert_honey_access(
            kind="secret",
            name=name,
            request=request,
            actor=actor_display_name(token_info),
        )

    # Reads go to vault_audit_lite (no advisory lock / HMAC chain / JSONL): a
    # tampered read log loses observability but can't mask a state mutation.
    # Same columns, queryable via the same /audit endpoints.
    await log_read(
        db,
        actor=actor_display_name(token_info),
        action="read_secret",
        target=name,
        ip_address=get_client_ip(request),
    )
    await db.commit()
    _m.secrets_read.inc()

    return SecretResponse(
        name=name,
        value=value,
        version=row.version,
    )


# GET /, list secrets (names only, never values)
@router.get("/")
async def list_secrets(
    namespace: str | None = Query(None),
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("secrets", "r")),
):
    vault.require_unsealed()

    # A `namespaces` claim restricts the listing (wins even over admin). The
    # claim may hold names OR UUIDs (newer tokens), so resolve it to
    # namespace NAMES and filter on `vault_secrets.namespace`. The response
    # also carries namespace_id so a broken namespace mapping fails closed.
    #   None      = no claim          -> unrestricted (admin / operator)
    #   empty set = claim resolved to nothing -> list NOTHING (never list-all)
    allowed_ns = await resolve_namespace_names(db, token_info)

    cols = (
        "SELECT id, name, namespace, namespace_id, version, created_at, updated_at, "
        "dek_rotated_at FROM vault_secrets"
    )

    if namespace:
        if allowed_ns is not None and namespace not in allowed_ns:
            raise HTTPException(403, f"Access denied for namespace: {namespace}")
        result = await db.execute(
            text(f"{cols} WHERE namespace = :ns AND deleted_at IS NULL ORDER BY name"),
            {"ns": namespace},
        )
    elif allowed_ns is not None:
        # Token restricted to its namespaces. An empty set lists nothing.
        if not allowed_ns:
            return {"items": []}
        ns_list = sorted(allowed_ns)
        placeholders = ", ".join(f":ns{i}" for i in range(len(ns_list)))
        params = {f"ns{i}": ns for i, ns in enumerate(ns_list)}
        result = await db.execute(
            text(
                f"{cols} WHERE namespace IN ({placeholders}) "
                "AND deleted_at IS NULL ORDER BY name"
            ),
            params,
        )
    else:
        result = await db.execute(
            text(f"{cols} WHERE deleted_at IS NULL ORDER BY name")
        )

    rows = result.fetchall()
    for row in rows:
        _require_namespace_mapping(row)
    items = [
        {
            "id": str(r.id),
            "name": r.name,
            "namespace": r.namespace,
            "version": r.version,
            "created_at": r.created_at.isoformat(),
            "updated_at": r.updated_at.isoformat(),
            "dek_rotated_at": r.dek_rotated_at.isoformat()
            if r.dek_rotated_at
            else None,
        }
        for r in rows
    ]
    return {"items": items}


# PUT /{name}, update secret value
@router.put("/{name}")
async def update_secret(
    name: str,
    body: SecretUpdate,
    request: Request,
    namespace: str | None = Query(None),
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("secrets", "w")),
):
    vault.require_unsealed()

    result = await db.execute(
        text(
            "SELECT id, dek_id, version, namespace, namespace_id "
            "FROM vault_secrets WHERE name = :name "
            "AND (CAST(:ns AS text) IS NULL OR namespace = :ns)"
        ),
        {"name": name, "ns": namespace},
    )
    rows = result.fetchall()
    if not rows:
        raise HTTPException(404, f"Secret '{name}' not found")
    if len(rows) > 1:
        raise HTTPException(
            409,
            f"Secret name '{name}' is ambiguous across namespaces; "
            "specify ?namespace=<ns>",
        )
    row = rows[0]

    check_namespace(token_info, row.namespace)
    await check_namespace_membership(
        db, token_info, _require_namespace_mapping(row), write=True
    )

    await require_generation_current(db, vault)  # skip if dek_key gen converging
    # New DEK for the updated value (AAD bound to the row id)
    new_dek_id = str(_uuid.uuid4())
    encrypted_dek, dek_nonce, ciphertext, secret_nonce = await vault.secret_encrypt(
        body.value.encode(),
        dek_aad(new_dek_id),
        secret_aad(name, row.namespace),
    )
    await db.execute(
        text("""
            INSERT INTO vault_dek (id, encrypted_key, nonce)
            VALUES (CAST(:id AS uuid), :ekey, :nonce)
        """),
        {"id": new_dek_id, "ekey": encrypted_dek, "nonce": dek_nonce},
    )

    new_version = row.version + 1

    await db.execute(
        text("""
            UPDATE vault_secrets
            SET ciphertext = :ct, nonce = :nonce,
                dek_id = CAST(:dek_id AS uuid),
                aad_version = :aad_version,
                version = :ver, updated_at = NOW()
            WHERE id = :id
        """),
        {
            "ct": ciphertext,
            "nonce": secret_nonce,
            "dek_id": new_dek_id,
            "aad_version": SECRET_AAD_VERSION,
            "ver": new_version,
            "id": str(row.id),
        },
    )

    await _save_version(
        db,
        str(row.id),
        new_version,
        ciphertext,
        secret_nonce,
        new_dek_id,
        token_info["name"],
    )

    # Rotation grace window. A non-emergency update lets the immediately-prior
    # version stay readable via GET ?previous for secret_grace_seconds, so a
    # consumer mid-cutover can still fetch the old value. An emergency update
    # suppresses it: the old (possibly leaked) value stops being served at once.
    # Mirrors the master-password emergency split. Always clear stale grace
    # first so at most one prior version is ever in grace.
    await db.execute(
        text(
            "UPDATE vault_secret_versions SET grace_until = NULL "
            "WHERE secret_id = CAST(:sid AS uuid)"
        ),
        {"sid": str(row.id)},
    )
    if not body.emergency and settings.secret_grace_seconds > 0:
        await db.execute(
            text(
                "UPDATE vault_secret_versions "
                "SET grace_until = NOW() + make_interval(secs => :secs) "
                "WHERE secret_id = CAST(:sid AS uuid) AND version = :prev"
            ),
            {
                "sid": str(row.id),
                "secs": settings.secret_grace_seconds,
                "prev": row.version,
            },
        )

    await log_action(
        db,
        actor=actor_display_name(token_info),
        action="update_secret",
        target=name,
        detail={"version": new_version, "emergency": body.emergency},
        ip_address=get_client_ip(request),
        critical=_is_critical_secret_name(name),
    )
    await db.commit()
    from .. import metrics as _m

    _m.secrets_write.labels(op="update").inc()

    return {"version": new_version}


# GET /{name}/versions, list version history
@router.get("/{name}/versions")
async def list_versions(
    name: str,
    namespace: str | None = Query(None),
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("secrets", "r")),
):
    vault.require_unsealed()

    result = await db.execute(
        text(
            "SELECT id, namespace, namespace_id FROM vault_secrets "
            "WHERE name = :name "
            "AND (CAST(:ns AS text) IS NULL OR namespace = :ns)"
        ),
        {"name": name, "ns": namespace},
    )
    rows = result.fetchall()
    if not rows:
        raise HTTPException(404, f"Secret '{name}' not found")
    if len(rows) > 1:
        raise HTTPException(
            409,
            f"Secret name '{name}' is ambiguous across namespaces; "
            "specify ?namespace=<ns>",
        )
    row = rows[0]
    check_namespace(token_info, row.namespace)
    await check_namespace_membership(
        db, token_info, _require_namespace_mapping(row), write=False
    )

    versions = await db.execute(
        text("""
            SELECT version, created_at, created_by
            FROM vault_secret_versions
            WHERE secret_id = CAST(:sid AS uuid)
            ORDER BY version DESC
        """),
        {"sid": str(row.id)},
    )
    items = [
        {
            "version": v.version,
            "created_at": v.created_at.isoformat(),
            "created_by": v.created_by,
        }
        for v in versions.fetchall()
    ]
    return {"name": name, "versions": items}


# GET /{name}/versions/{version}, read a specific version
@router.get("/{name}/versions/{version}")
async def get_version(
    name: str,
    version: int,
    request: Request,
    namespace: str | None = Query(None),
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("secrets", "r")),
):
    vault.require_unsealed()

    result = await db.execute(
        text(
            "SELECT id, namespace, namespace_id FROM vault_secrets "
            "WHERE name = :name "
            "AND (CAST(:ns AS text) IS NULL OR namespace = :ns)"
        ),
        {"name": name, "ns": namespace},
    )
    rows = result.fetchall()
    if not rows:
        raise HTTPException(404, f"Secret '{name}' not found")
    if len(rows) > 1:
        raise HTTPException(
            409,
            f"Secret name '{name}' is ambiguous across namespaces; "
            "specify ?namespace=<ns>",
        )
    secret_row = rows[0]
    check_namespace(token_info, secret_row.namespace)
    await check_namespace_membership(
        db, token_info, _require_namespace_mapping(secret_row), write=False
    )

    result = await db.execute(
        text("""
            SELECT v.ciphertext, v.nonce, v.aad_version, v.version, v.dek_id,
                   d.encrypted_key, d.nonce AS dek_nonce
            FROM vault_secret_versions v
            JOIN vault_dek d ON d.id = v.dek_id
            WHERE v.secret_id = CAST(:sid AS uuid)
              AND v.version = :ver
        """),
        {"sid": str(secret_row.id), "ver": version},
    )
    row = result.fetchone()
    if not row:
        raise HTTPException(404, f"Version {version} not found")

    from .. import metrics as _m

    with _m.secret_decrypt_duration.time():
        plaintext = await vault.secret_decrypt(
            bytes(row.encrypted_key),
            bytes(row.dek_nonce),
            dek_aad(str(row.dek_id)),
            bytes(row.ciphertext),
            bytes(row.nonce),
            secret_aad(name, secret_row.namespace, version=row.aad_version),
        )
    value = _decode_and_wipe(plaintext)

    # Read path goes to vault_audit_lite (non-chained).
    await log_read(
        db,
        actor=actor_display_name(token_info),
        action="read_secret_version",
        target=name,
        detail={"version": version},
        ip_address=get_client_ip(request),
    )
    await db.commit()

    return {
        "name": name,
        "value": value,
        "version": row.version,
    }


# POST /{name}/rollback/{version}, restore a previous version
@router.post("/{name}/rollback/{version}")
async def rollback_secret(
    name: str,
    version: int,
    request: Request,
    namespace: str | None = Query(None),
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("secrets", "w")),
):
    """Restore an old version as a new version (creates version N+1)."""
    vault.require_unsealed()

    result = await db.execute(
        text(
            "SELECT id, version AS current_version, namespace, namespace_id "
            "FROM vault_secrets WHERE name = :name "
            "AND (CAST(:ns AS text) IS NULL OR namespace = :ns)"
        ),
        {"name": name, "ns": namespace},
    )
    rows = result.fetchall()
    if not rows:
        raise HTTPException(404, f"Secret '{name}' not found")
    if len(rows) > 1:
        raise HTTPException(
            409,
            f"Secret name '{name}' is ambiguous across namespaces; "
            "specify ?namespace=<ns>",
        )
    secret_row = rows[0]
    check_namespace(token_info, secret_row.namespace)
    await check_namespace_membership(
        db, token_info, _require_namespace_mapping(secret_row), write=True
    )

    # Read old version
    result = await db.execute(
        text("""
            SELECT v.ciphertext, v.nonce, v.aad_version, v.dek_id,
                   d.encrypted_key, d.nonce AS dek_nonce
            FROM vault_secret_versions v
            JOIN vault_dek d ON d.id = v.dek_id
            WHERE v.secret_id = CAST(:sid AS uuid) AND v.version = :ver
        """),
        {"sid": str(secret_row.id), "ver": version},
    )
    old_row = result.fetchone()
    if not old_row:
        raise HTTPException(404, f"Version {version} not found")

    await require_generation_current(db, vault)  # skip if dek_key gen converging
    new_dek_id = str(_uuid.uuid4())
    encrypted_dek, dek_nonce, ciphertext, secret_nonce = await vault.secret_reencrypt(
        bytes(old_row.encrypted_key),
        bytes(old_row.dek_nonce),
        dek_aad(str(old_row.dek_id)),
        bytes(old_row.ciphertext),
        bytes(old_row.nonce),
        secret_aad(
            name,
            secret_row.namespace,
            version=old_row.aad_version,
        ),
        dek_aad(new_dek_id),
        secret_aad(name, secret_row.namespace),
    )
    await db.execute(
        text("""
            INSERT INTO vault_dek (id, encrypted_key, nonce)
            VALUES (CAST(:id AS uuid), :ekey, :nonce)
        """),
        {"id": new_dek_id, "ekey": encrypted_dek, "nonce": dek_nonce},
    )

    new_version = secret_row.current_version + 1

    await db.execute(
        text("""
            UPDATE vault_secrets
            SET ciphertext = :ct, nonce = :nonce,
                dek_id = CAST(:dek_id AS uuid),
                aad_version = :aad_version,
                version = :ver, updated_at = NOW()
            WHERE id = :id
        """),
        {
            "ct": ciphertext,
            "nonce": secret_nonce,
            "dek_id": new_dek_id,
            "aad_version": SECRET_AAD_VERSION,
            "ver": new_version,
            "id": str(secret_row.id),
        },
    )

    await _save_version(
        db,
        str(secret_row.id),
        new_version,
        ciphertext,
        secret_nonce,
        new_dek_id,
        token_info["name"],
    )

    await log_action(
        db,
        actor=actor_display_name(token_info),
        action="rollback_secret",
        target=name,
        detail={"from_version": version, "to_version": new_version},
        ip_address=get_client_ip(request),
        critical=_is_critical_secret_name(name),
    )
    await db.commit()

    return {
        "name": name,
        "restored_from": version,
        "new_version": new_version,
        "status": "rolled_back",
    }


# POST /{name}/rotate, rotate DEK without changing value
@router.post("/{name}/rotate")
async def rotate_secret(
    name: str,
    request: Request,
    namespace: str | None = Query(None),
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("secrets", "w")),
):
    """Re-encrypt secret with a new DEK. Value unchanged, version incremented."""
    vault.require_unsealed()

    result = await db.execute(
        text("""
            SELECT s.id, s.ciphertext, s.nonce, s.aad_version,
                   s.dek_id, s.version,
                   s.namespace, s.namespace_id,
                   d.encrypted_key, d.nonce AS dek_nonce
            FROM vault_secrets s
            JOIN vault_dek d ON d.id = s.dek_id
            WHERE s.name = :name
              AND (CAST(:ns AS text) IS NULL OR s.namespace = :ns)
        """),
        {"name": name, "ns": namespace},
    )
    rows = result.fetchall()
    if not rows:
        raise HTTPException(404, f"Secret '{name}' not found")
    if len(rows) > 1:
        raise HTTPException(
            409,
            f"Secret name '{name}' is ambiguous across namespaces; "
            "specify ?namespace=<ns>",
        )
    row = rows[0]

    check_namespace(token_info, row.namespace)
    await check_namespace_membership(
        db, token_info, _require_namespace_mapping(row), write=True
    )

    await require_generation_current(db, vault)  # skip if dek_key gen converging
    new_dek_id = str(_uuid.uuid4())
    encrypted_dek, dek_nonce, ciphertext, secret_nonce = await vault.secret_reencrypt(
        bytes(row.encrypted_key),
        bytes(row.dek_nonce),
        dek_aad(str(row.dek_id)),
        bytes(row.ciphertext),
        bytes(row.nonce),
        secret_aad(name, row.namespace, version=row.aad_version),
        dek_aad(new_dek_id),
        secret_aad(name, row.namespace),
    )
    await db.execute(
        text("""
            INSERT INTO vault_dek (id, encrypted_key, nonce)
            VALUES (CAST(:id AS uuid), :ekey, :nonce)
        """),
        {"id": new_dek_id, "ekey": encrypted_dek, "nonce": dek_nonce},
    )

    new_version = row.version + 1

    await db.execute(
        text("""
            UPDATE vault_secrets
            SET ciphertext = :ct, nonce = :nonce,
                dek_id = CAST(:dek_id AS uuid),
                aad_version = :aad_version,
                version = :ver, updated_at = NOW(),
                dek_rotated_at = NOW()
            WHERE id = :id
        """),
        {
            "ct": ciphertext,
            "nonce": secret_nonce,
            "dek_id": new_dek_id,
            "aad_version": SECRET_AAD_VERSION,
            "ver": new_version,
            "id": str(row.id),
        },
    )

    await _save_version(
        db,
        str(row.id),
        new_version,
        ciphertext,
        secret_nonce,
        new_dek_id,
        token_info["name"],
    )

    await log_action(
        db,
        actor=actor_display_name(token_info),
        action="rotate_secret",
        target=name,
        detail={"version": new_version},
        ip_address=get_client_ip(request),
        critical=_is_critical_secret_name(name),
    )
    await db.commit()

    return {"name": name, "version": new_version, "status": "rotated"}


# POST /rotate-all, bulk rotation
@router.post("/rotate-all")
async def rotate_all_secrets(
    request: Request,
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("admin", "w")),
):
    """Re-encrypt all secrets with new DEKs. Single batch query.

    Global maintenance op : it re-encrypts every secret in every namespace,
    so it requires admin:w (matching /audit/rotate-all). Previously a
    namespace-scoped `secrets:w` token could trigger a cluster-wide
    re-encryption of other tenants' secrets.
    """
    vault.require_unsealed()
    # Fence the whole batch: a bulk re-wrap under a stale dek_key would orphan
    # every secret it touches.
    await require_generation_current(db, vault)

    # Fetch all secrets + DEKs in one query
    result = await db.execute(
        text("""
            SELECT s.id, s.name, s.namespace, s.ciphertext, s.nonce,
                   s.aad_version,
                   s.dek_id, s.version,
                   d.encrypted_key, d.nonce AS dek_nonce
            FROM vault_secrets s
            JOIN vault_dek d ON d.id = s.dek_id
            ORDER BY s.name
        """)
    )
    rows = result.fetchall()

    rotated = 0
    for row in rows:
        new_dek_id = str(_uuid.uuid4())
        (
            encrypted_dek,
            dek_nonce,
            ciphertext,
            secret_nonce,
        ) = await vault.secret_reencrypt(
            bytes(row.encrypted_key),
            bytes(row.dek_nonce),
            dek_aad(str(row.dek_id)),
            bytes(row.ciphertext),
            bytes(row.nonce),
            secret_aad(
                row.name,
                row.namespace,
                version=row.aad_version,
            ),
            dek_aad(new_dek_id),
            secret_aad(row.name, row.namespace),
        )
        await db.execute(
            text("""
                INSERT INTO vault_dek (id, encrypted_key, nonce)
                VALUES (CAST(:id AS uuid), :ekey, :nonce)
            """),
            {"id": new_dek_id, "ekey": encrypted_dek, "nonce": dek_nonce},
        )

        new_version = row.version + 1

        await db.execute(
            text("""
                UPDATE vault_secrets
                SET ciphertext = :ct, nonce = :nonce,
                    dek_id = CAST(:dek_id AS uuid),
                    aad_version = :aad_version,
                    version = :ver, updated_at = NOW(),
                    dek_rotated_at = NOW()
                WHERE id = CAST(:sid AS uuid)
            """),
            {
                "ct": ciphertext,
                "nonce": secret_nonce,
                "dek_id": new_dek_id,
                "aad_version": SECRET_AAD_VERSION,
                "ver": new_version,
                "sid": str(row.id),
            },
        )

        await _save_version(
            db,
            str(row.id),
            new_version,
            ciphertext,
            secret_nonce,
            new_dek_id,
            "system",
        )
        rotated += 1

    await log_action(
        db,
        actor=actor_display_name(token_info),
        action="rotate_all_secrets",
        detail={"count": rotated},
        ip_address=get_client_ip(request),
    )
    await db.commit()

    return {"rotated": rotated}


async def _verify_protected_delete_2fa(
    db: AsyncSession,
    body: _DeleteBody,
    token_info: dict,
    client_ip: str | None,
) -> None:
    perms = token_info.get("permissions") or {}
    if "admin" not in perms:
        raise HTTPException(
            403,
            "Deletion in protected namespace requires admin scope",
        )

    from .vault import _get_2fa_mode, _verify_2fa

    twofa_mode = await _get_2fa_mode(db)
    if twofa_mode != "none":
        await _verify_2fa(
            db,
            twofa_mode,
            body,
            client_ip,
            aesgcm=None,  # delegate 2FA decrypt via RPC (follower-safe, B6)
            purpose="delete_protected_secret",
        )


@router.delete("/{name}")
async def delete_secret(
    name: str,
    request: Request,
    body: _DeleteBody | None = None,
    namespace: str | None = Query(None),
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("secrets", "w")),
):
    """Delete a secret. The behavior depends on the namespace's
    `delete_protection` mode :
      - 'free'      : hard delete (DROP row + orphaned DEK)
      - 'soft'      : soft delete (sets deleted_at + purge_after) ;
                      reaper purges after `soft_delete_retention_days`
      - 'protected' : same as soft + admin scope + 2FA challenge
                      (purpose='delete_protected_secret') ; longer
                      retention, no auto-purge if retention=0
    """
    vault.require_unsealed()
    client_ip = get_client_ip(request)

    # Lookup secret + the owning namespace's delete_protection mode in
    # one shot. The LEFT JOIN lets us detect a broken NULL mapping explicitly
    # below; it must never downgrade deletion to 'free' mode.
    ns_result = await db.execute(
        text(
            """
            SELECT s.id, s.dek_id, s.namespace, s.namespace_id, s.deleted_at,
                   COALESCE(n.delete_protection, 'free') AS dp
            FROM vault_secrets s
            LEFT JOIN vault_namespaces n ON s.namespace_id = n.id
            WHERE s.name = :name
              AND (CAST(:ns AS text) IS NULL OR s.namespace = :ns)
            """
        ),
        {"name": name, "ns": namespace},
    )
    ns_rows = ns_result.fetchall()
    if not ns_rows:
        raise HTTPException(404, f"Secret '{name}' not found")
    if len(ns_rows) > 1:
        raise HTTPException(
            409,
            f"Secret name '{name}' is ambiguous across namespaces; "
            "specify ?namespace=<ns>",
        )
    ns_row = ns_rows[0]
    if ns_row.deleted_at is not None:
        raise HTTPException(404, f"Secret '{name}' not found")
    check_namespace(token_info, ns_row.namespace)
    await check_namespace_membership(
        db, token_info, _require_namespace_mapping(ns_row), write=True
    )

    mode = ns_row.dp
    body = body or _DeleteBody()

    if mode == "free":
        result = await db.execute(
            text("DELETE FROM vault_secrets WHERE id = :id RETURNING dek_id"),
            {"id": str(ns_row.id)},
        )
        deleted = result.fetchone()
        await db.execute(
            text("DELETE FROM vault_dek WHERE id = CAST(:id AS uuid)"),
            {"id": str(deleted.dek_id)},
        )
        await log_action(
            db,
            actor=actor_display_name(token_info),
            action="delete_secret",
            target=name,
            detail={"mode": "free"},
            ip_address=client_ip,
            critical=_is_critical_secret_name(name),
        )
        status = "deleted"
        retention_days = None

    else:
        # 'protected' mode requires admin + fresh 2FA challenge.
        if mode == "protected":
            await _verify_protected_delete_2fa(db, body, token_info, client_ip)

        retention_days = (
            settings.soft_delete_retention_days
            if mode == "soft"
            else settings.protected_delete_retention_days
        )
        # purge_after = NULL means "never auto-purge" (operator must
        # restore or hard-delete via free mode).
        await db.execute(
            text(
                """
                UPDATE vault_secrets
                SET deleted_at = NOW(),
                    purge_after = CASE WHEN :days > 0
                                       THEN NOW() + make_interval(days => :days)
                                       ELSE NULL END
                WHERE id = :id
                """
            ),
            {"id": str(ns_row.id), "days": retention_days},
        )
        await log_action(
            db,
            actor=actor_display_name(token_info),
            action="soft_delete_secret",
            target=name,
            detail={
                "mode": mode,
                "retention_days": retention_days,
            },
            ip_address=client_ip,
            critical=_is_critical_secret_name(name),
        )
        status = "soft-deleted"

    from .. import metrics as _m

    _m.secrets_write.labels(op="delete").inc()
    await db.commit()

    out: dict = {"status": status, "name": name, "mode": mode}
    if retention_days is not None:
        out["retention_days"] = retention_days
    return out


# POST /{name}/restore, un-delete a soft-deleted secret within window.
@router.post("/{name}/restore")
async def restore_secret(
    name: str,
    request: Request,
    namespace: str | None = Query(None),
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("secrets", "w")),
):
    """Restore a soft-deleted secret. Works only if the secret is still
    in the retention window (deleted_at IS NOT NULL AND not purged yet).
    """
    vault.require_unsealed()
    rows = (
        await db.execute(
            text(
                """
                SELECT s.id, s.namespace, s.namespace_id
                FROM vault_secrets s
                WHERE s.name = :name AND s.deleted_at IS NOT NULL
                  AND (CAST(:ns AS text) IS NULL OR s.namespace = :ns)
                """
            ),
            {"name": name, "ns": namespace},
        )
    ).fetchall()
    if not rows:
        raise HTTPException(404, f"No soft-deleted secret named '{name}'")
    if len(rows) > 1:
        raise HTTPException(
            409,
            f"Secret name '{name}' is ambiguous across namespaces; "
            "specify ?namespace=<ns>",
        )
    row = rows[0]
    check_namespace(token_info, row.namespace)
    await check_namespace_membership(
        db, token_info, _require_namespace_mapping(row), write=True
    )
    await db.execute(
        text(
            "UPDATE vault_secrets "
            "SET deleted_at = NULL, purge_after = NULL "
            "WHERE id = :id"
        ),
        {"id": str(row.id)},
    )
    await log_action(
        db,
        actor=actor_display_name(token_info),
        action="restore_secret",
        target=name,
        detail={"secret_id": str(row.id)},
        ip_address=get_client_ip(request),
        critical=_is_critical_secret_name(name),
    )
    await db.commit()
    return {"restored": True, "name": name}
