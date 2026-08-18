# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Dynamic secrets - ephemeral credentials with TTL.

This route owns authorization, encrypted engine configuration and lease
bookkeeping. Backend protocol code lives in ``app.dynamic_engines`` and is
loaded from the closed catalog selected by ``dynamic-engines.ini``.
"""

import logging
import re
import secrets
import string
import uuid as _uuid
from datetime import timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    field_validator,
    model_validator,
)
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ..audit import log_action
from ..auth import (
    actor_display_name,
    check_namespace,
    require_permission,
    resolve_namespace_names,
)
from ..client_ip import get_client_ip
from ..config import settings
from ..crypto import (
    decrypt_secret,
    dek_aad,
    encrypt_secret,
    generate_dek,
)
from ..database import get_db
from ..dynamic_engines.base import (
    GENERATED_USERNAME_MAX_LENGTH,
    GENERATED_USERNAME_SUFFIX_BYTES,
    DynamicEngine,
    driver_available,
    engine_capability,
)
from ..dynamic_engines.loader import (
    BUILTIN_METADATA,
    BUILTIN_MODULES,
    configured_modules,
    load_engines,
)
from ..key_epoch import require_generation_current
from ..vault_state import vault

log = logging.getLogger("rhorizon.dynamic")

router = APIRouter(prefix="/api/v1/vault/dynamic", tags=["dynamic"])

_PASSWORD_CHARS = string.ascii_letters + string.digits + "!@#$%^&*"
_PASSWORD_LENGTH = 32
_MAX_DB_TTL_SECONDS = 2_147_483_647
_LEASE_REAPER_BATCH_SIZE = 250

# The INI is the hard operator boundary and is parsed without importing any
# backend. ``initialize_engine_registry`` imports only the cluster-enabled
# subset during lifespan, after the database is available.
CONFIGURED_MODULES = configured_modules(settings.dynamic_modules_file)
ENGINES: dict[str, DynamicEngine] = {}


class _DynamicRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")


class EngineCreate(_DynamicRequest):
    name: str = Field(..., min_length=1, max_length=128)
    namespace: str = Field("default", min_length=1, max_length=64)
    engine_type: str = Field(..., min_length=1, max_length=32)
    connection_url: SecretStr = Field(..., min_length=1, max_length=1024)
    max_ttl_seconds: int = Field(86400, ge=60, le=_MAX_DB_TTL_SECONDS)


class EngineConnectionTest(_DynamicRequest):
    namespace: str = Field("default", min_length=1, max_length=64)
    engine_type: str = Field(..., min_length=1, max_length=32)
    connection_url: SecretStr = Field(..., min_length=1, max_length=1024)


class ModuleStateUpdate(_DynamicRequest):
    enabled: bool = Field(strict=True)


class RoleCreate(_DynamicRequest):
    name: str = Field(..., min_length=1, max_length=128)
    creation_sql: str = Field(..., max_length=4096)
    revocation_sql: str = Field(..., max_length=4096)
    default_ttl_seconds: int = Field(
        3600,
        ge=60,
        le=_MAX_DB_TTL_SECONDS,
    )
    max_ttl_seconds: int = Field(
        86400,
        ge=60,
        le=_MAX_DB_TTL_SECONDS,
    )

    @field_validator("creation_sql", "revocation_sql")
    @classmethod
    def template_must_not_be_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("credential templates must not be blank")
        return value

    @model_validator(mode="after")
    def default_ttl_must_fit_maximum(self):
        if self.default_ttl_seconds > self.max_ttl_seconds:
            raise ValueError("default_ttl_seconds cannot exceed max_ttl_seconds")
        return self


class CredRequest(_DynamicRequest):
    ttl_seconds: int | None = Field(None, ge=60)  # Override default TTL


def _generate_password() -> str:
    return "".join(secrets.choice(_PASSWORD_CHARS) for _ in range(_PASSWORD_LENGTH))


def _generate_username(role_name: str) -> str:
    # Strict identifier charset: the username lands in the operator's {{name}}
    # template and runs on the target (SQL identifier / LDAP cn). Anything
    # outside [a-z0-9_] (quotes, spaces, ';') is collapsed to '_' so a hostile
    # role name can't shape the rendered statement. revoke reuses the stored
    # username, so the same value is dropped later -- no case/charset drift.
    suffix_length = GENERATED_USERNAME_SUFFIX_BYTES * 2
    prefix_length = GENERATED_USERNAME_MAX_LENGTH - len("rh__") - suffix_length
    safe_name = re.sub(r"[^a-z0-9_]", "_", role_name.lower())[:prefix_length]
    suffix = secrets.token_hex(GENERATED_USERNAME_SUFFIX_BYTES)
    return f"rh_{safe_name}_{suffix}"


def _integrity_constraint_name(exc: IntegrityError) -> str | None:
    driver_error = getattr(getattr(exc, "orig", None), "__cause__", None)
    return getattr(driver_error, "constraint_name", None)


def _normalize_uuid(value: str, not_found_detail: str) -> str:
    try:
        return str(_uuid.UUID(value))
    except (AttributeError, TypeError, ValueError):
        raise HTTPException(404, not_found_detail) from None


async def _engine_namespace(db: AsyncSession, engine_id: str) -> str:
    """Load an engine's namespace. Raises 404 if engine doesn't exist.

    Every endpoint that takes an engine_id must resolve the namespace through
    this helper before doing anything sensitive, then enforce check_namespace.
    """
    normalized_id = _normalize_uuid(engine_id, "Engine not found")

    result = await db.execute(
        text(
            "SELECT namespace FROM vault_dynamic_engines WHERE id = CAST(:id AS uuid)"
        ),
        {"id": normalized_id},
    )
    row = result.fetchone()
    if not row:
        raise HTTPException(404, "Engine not found")
    return row.namespace


async def _allowed_namespaces(
    db: AsyncSession,
    token_info: dict,
) -> list[str] | None:
    """Return the list of namespaces this token may access, or None if
    unrestricted. Name and UUID claims are normalized to namespace names.
    """
    allowed = await resolve_namespace_names(db, token_info)
    return None if allowed is None else sorted(allowed)


async def _check_dynamic_namespace(
    db: AsyncSession,
    token_info: dict,
    namespace: str,
) -> None:
    allowed = await _allowed_namespaces(db, token_info)
    if allowed is None:
        return
    check_namespace({"permissions": {"namespaces": allowed}}, namespace)


async def _require_active_namespace(
    db: AsyncSession,
    namespace: str,
) -> None:
    """Reject unknown and archived namespaces before creating remote state."""
    result = await db.execute(
        text("""
            SELECT 1
            FROM vault_namespaces
            WHERE name = :namespace AND archived_at IS NULL
        """),
        {"namespace": namespace},
    )
    if result.fetchone() is None:
        raise HTTPException(404, "Namespace not found")


async def _module_overrides(db: AsyncSession) -> dict[str, bool]:
    result = await db.execute(
        text("SELECT module_name, enabled FROM vault_dynamic_module_state")
    )
    return {row.module_name: row.enabled for row in result.fetchall()}


async def _module_inventory(db: AsyncSession) -> list[dict]:
    overrides = await _module_overrides(db)
    configured = set(CONFIGURED_MODULES)
    inventory = []
    for name in BUILTIN_MODULES:
        metadata = BUILTIN_METADATA[name]
        allowed = name in configured
        desired = allowed and overrides.get(name, True)
        loaded = name in ENGINES
        inventory.append(
            {
                "engine_type": name,
                "display_name": metadata["display_name"],
                "driver_module": metadata["driver_module"],
                "driver_installed": driver_available(metadata["driver_module"]),
                "configured": allowed,
                "enabled": desired,
                "loaded": loaded,
                "restart_required": desired != loaded,
            }
        )
    return inventory


async def _lock_module_transition(db: AsyncSession, engine_type: str) -> None:
    await db.execute(
        text(
            "SELECT pg_advisory_xact_lock("
            "hashtext('rhorizon.dynamic.module'), hashtext(:engine_type))"
        ),
        {"engine_type": engine_type},
    )


async def _lock_engine_mutation(db: AsyncSession, engine_id: str) -> None:
    """Serialize engine deletion with credential admission.

    Credential generation holds this transaction lock until its provisioning
    lease is durable. Deletion then either runs first or observes that lease.
    """
    await db.execute(
        text(
            "SELECT pg_advisory_xact_lock("
            "hashtext('rhorizon.dynamic.engine'), hashtext(:engine_id))"
        ),
        {"engine_id": engine_id},
    )


async def _require_module_accepts_new_work(
    db: AsyncSession,
    engine_type: str,
) -> None:
    """Block new engines/probes as soon as a disable is scheduled."""
    await _lock_module_transition(db, engine_type)
    overrides = await _module_overrides(db)
    if not overrides.get(engine_type, True):
        raise HTTPException(
            409,
            f"{engine_type} is disabled; restart API nodes to unload it",
        )


async def initialize_engine_registry(db: AsyncSession) -> None:
    """Load the INI-allowed, cluster-enabled backend subset exactly once/boot."""
    overrides = await _module_overrides(db)
    enabled = {name for name in CONFIGURED_MODULES if overrides.get(name, True)}
    loaded = load_engines(settings.dynamic_modules_file, enabled)
    ENGINES.clear()
    ENGINES.update(loaded)
    await enforce_enabled_module_invariant(db)


async def enforce_enabled_module_invariant(db: AsyncSession) -> None:
    """Fail boot if persisted engines depend on an unusable backend module.

    Silently starting would strand leases if the reaper could not import their
    revocation implementation or its protocol driver. Operators must revoke
    leases and delete engines before disabling a module or removing its driver.
    """
    result = await db.execute(
        text("""
            SELECT e.engine_type,
                   count(DISTINCT e.id) AS engine_count,
                   count(l.id) FILTER (
                       WHERE NOT l.revoked OR NOT l.revocation_verified
                   ) AS pending_leases
            FROM vault_dynamic_engines e
            LEFT JOIN vault_leases l ON l.engine_id = e.id
            GROUP BY e.engine_type
        """)
    )
    unavailable = []
    for row in result.fetchall():
        engine = ENGINES.get(row.engine_type)
        if engine is None or not driver_available(engine.support.driver_module):
            unavailable.append(row)
    if not unavailable:
        return
    summary = ", ".join(
        f"{row.engine_type} (engines={row.engine_count}, "
        f"pending_leases={row.pending_leases})"
        for row in unavailable
    )
    raise RuntimeError(
        "unavailable dynamic modules still have persisted state: "
        f"{summary}; restore the driver, or revoke leases and delete engines "
        "before disabling the module or removing its driver"
    )


# -- Engine CRUD -------------------------------------------------------------


@router.get("/engines")
async def list_engines(
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("admin", "r")),
):
    vault.require_unsealed()
    allowed_ns = await _allowed_namespaces(db, token_info)
    sql = """
        SELECT e.id, e.name, e.namespace, e.engine_type,
               e.max_ttl_seconds, e.created_at,
               (SELECT count(*) FROM vault_dynamic_roles
                WHERE engine_id = e.id) AS role_count,
               (SELECT count(*) FROM vault_leases
                WHERE engine_id = e.id AND NOT revoked
                AND expires_at > NOW()) AS active_leases
        FROM vault_dynamic_engines e
        {where}
        ORDER BY e.namespace, e.name
    """
    if allowed_ns is None:
        result = await db.execute(text(sql.format(where="")))
    else:
        result = await db.execute(
            text(sql.format(where="WHERE e.namespace = ANY(:ns)")),
            {"ns": allowed_ns},
        )
    return {
        "items": [
            {
                "id": str(r.id),
                "name": r.name,
                "namespace": r.namespace,
                "engine_type": r.engine_type,
                "max_ttl_seconds": r.max_ttl_seconds,
                "role_count": r.role_count,
                "active_leases": r.active_leases,
                "created_at": r.created_at.isoformat(),
            }
            for r in result.fetchall()
        ]
    }


@router.get("/engines/compatibility")
async def engine_compatibility(
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("admin", "r")),
):
    """Return the runtime engine registry and its validated targets.

    Unknown versions are not rejected: they remain usable but are reported as
    unvalidated until an integration run adds evidence to the matrix.
    """
    vault.require_unsealed()
    return {
        "unknown_version_policy": "allow_unvalidated",
        "available_modules": await _module_inventory(db),
        "engines": [
            _engine_capability(engine_type, engine)
            for engine_type, engine in ENGINES.items()
        ],
    }


@router.put("/modules/{engine_type}")
async def set_module_state(
    engine_type: str,
    body: ModuleStateUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("admin", "w")),
):
    """Schedule a cluster-wide module state for the next API restart."""
    vault.require_unsealed()
    if engine_type not in BUILTIN_MODULES:
        raise HTTPException(404, "Unknown dynamic module")
    if body.enabled and engine_type not in CONFIGURED_MODULES:
        raise HTTPException(
            409,
            "Module is disabled by dynamic-engines.ini and cannot be enabled "
            "from the UI",
        )
    metadata = BUILTIN_METADATA[engine_type]
    if body.enabled and not driver_available(metadata["driver_module"]):
        raise HTTPException(
            409,
            f"{metadata['driver_module']} is not installed in the API image",
        )
    await _lock_module_transition(db, engine_type)
    if not body.enabled:
        result = await db.execute(
            text(
                "SELECT count(*) AS engine_count "
                "FROM vault_dynamic_engines WHERE engine_type = :engine_type"
            ),
            {"engine_type": engine_type},
        )
        if result.one().engine_count:
            raise HTTPException(
                409,
                "Delete every engine of this type before disabling its module",
            )

    await db.execute(
        text("""
            INSERT INTO vault_dynamic_module_state
                (module_name, enabled, updated_at)
            VALUES (:module_name, :enabled, NOW())
            ON CONFLICT (module_name) DO UPDATE
            SET enabled = EXCLUDED.enabled, updated_at = NOW()
        """),
        {"module_name": engine_type, "enabled": body.enabled},
    )
    await log_action(
        db,
        actor=actor_display_name(token_info),
        action="set_dynamic_module_state",
        target=engine_type,
        detail={
            "enabled": body.enabled,
            "restart_required": body.enabled != (engine_type in ENGINES),
        },
        ip_address=get_client_ip(request),
    )
    await db.commit()
    return {
        "engine_type": engine_type,
        "enabled": body.enabled,
        "loaded": engine_type in ENGINES,
        "restart_required": body.enabled != (engine_type in ENGINES),
    }


@router.post("/engines/test-connection")
async def test_engine_connection(
    body: EngineConnectionTest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("admin", "w")),
):
    """Bind to an engine without changing it and report detected compatibility.

    This endpoint is deliberately privileged like engine creation: allowing an
    arbitrary caller to connect to a supplied URL would create an SSRF oracle.
    Credentials and target URLs are never included in the response or audit.
    """
    vault.require_unsealed()
    await _check_dynamic_namespace(db, token_info, body.namespace)
    await _require_active_namespace(db, body.namespace)
    engine = ENGINES.get(body.engine_type)
    if engine is None:
        raise HTTPException(400, f"engine_type must be one of: {', '.join(ENGINES)}")
    await _require_module_accepts_new_work(db, body.engine_type)

    conn_url = body.connection_url.get_secret_value()
    try:
        engine.validate_conn(conn_url)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from None

    if not driver_available(engine.support.driver_module):
        await log_action(
            db,
            actor=actor_display_name(token_info),
            action="test_dynamic_engine_connection",
            target=body.engine_type,
            detail={
                "connected": False,
                "namespace": body.namespace,
                "reason": "driver_unavailable",
            },
            ip_address=get_client_ip(request),
        )
        await db.commit()
        raise HTTPException(
            501,
            f"{engine.support.driver_module} is not installed for "
            f"{body.engine_type} support",
        ) from None

    try:
        probe = await engine.probe(conn_url)
    except Exception as exc:
        # Do not interpolate the driver exception: DSN parsers and connection
        # errors may echo usernames, passwords, hosts, or the complete URL.
        error_type = type(exc).__name__
        log.warning(
            "Dynamic engine connection probe failed: engine=%s error_type=%s",
            body.engine_type,
            error_type,
        )
        await log_action(
            db,
            actor=actor_display_name(token_info),
            action="test_dynamic_engine_connection",
            target=body.engine_type,
            detail={
                "connected": False,
                "namespace": body.namespace,
                "reason": "connection_failed",
                "error_type": error_type,
            },
            ip_address=get_client_ip(request),
        )
        await db.commit()
        raise HTTPException(
            502,
            f"{body.engine_type} connection failed ({error_type})",
        ) from None

    status = engine.compatibility_status(probe)
    await log_action(
        db,
        actor=actor_display_name(token_info),
        action="test_dynamic_engine_connection",
        target=body.engine_type,
        detail={
            "connected": True,
            "namespace": body.namespace,
            "product": probe.product,
            "server_version": probe.server_version,
            "compatibility": status,
        },
        ip_address=get_client_ip(request),
    )
    await db.commit()
    return {
        "engine_type": body.engine_type,
        "connected": True,
        "product": probe.product,
        "server_version": probe.server_version,
        "compatibility": status,
        "validated_targets": list(engine.support.validated_targets),
    }


@router.post("/engines", status_code=201)
async def create_engine(
    body: EngineCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("admin", "w")),
):
    vault.require_unsealed()
    await _check_dynamic_namespace(db, token_info, body.namespace)
    await _require_active_namespace(db, body.namespace)

    if body.engine_type not in ENGINES:
        raise HTTPException(400, f"engine_type must be one of: {', '.join(ENGINES)}")
    await _require_module_accepts_new_work(db, body.engine_type)
    backend = ENGINES[body.engine_type]
    if not driver_available(backend.support.driver_module):
        raise HTTPException(
            501,
            f"{backend.support.driver_module} is not installed for "
            f"{body.engine_type} support",
        )
    # Fail fast on a malformed connection_url (e.g. the LDAP JSON blob) rather
    # than at first credential generation.
    try:
        backend.validate_conn(body.connection_url.get_secret_value())
    except ValueError as exc:
        raise HTTPException(400, str(exc))

    # Encrypt connection URL with AAD bound to (engine name, dek id)
    await require_generation_current(db, vault)
    dek = generate_dek()
    dek_id = str(_uuid.uuid4())
    encrypted_dek, dek_nonce = await vault.aesgcm_encrypt(dek, dek_aad(dek_id))
    await db.execute(
        text("""
            INSERT INTO vault_dek (id, encrypted_key, nonce)
            VALUES (CAST(:id AS uuid), :ekey, :nonce)
        """),
        {"id": dek_id, "ekey": encrypted_dek, "nonce": dek_nonce},
    )

    engine_secret_aad = f"engine:{body.name}".encode()
    ct, nonce = encrypt_secret(
        body.connection_url.get_secret_value().encode(), dek, engine_secret_aad
    )

    try:
        result = await db.execute(
            text("""
                INSERT INTO vault_dynamic_engines
                    (name, namespace, engine_type,
                     connection_url, nonce, dek_id, max_ttl_seconds)
                VALUES (:name, :ns, :type, :ct, :nonce,
                        CAST(:dek_id AS uuid), :max_ttl)
                RETURNING id
            """),
            {
                "name": body.name,
                "ns": body.namespace,
                "type": body.engine_type,
                "ct": ct,
                "nonce": nonce,
                "dek_id": dek_id,
                "max_ttl": body.max_ttl_seconds,
            },
        )
    except IntegrityError as exc:
        if _integrity_constraint_name(exc) != "vault_dynamic_engines_name_key":
            raise
        # Clear the failed transaction and the newly inserted wrapped DEK.
        await db.rollback()
        raise HTTPException(409, "Dynamic engine name already exists") from None
    engine_id = str(result.fetchone().id)

    await log_action(
        db,
        actor=actor_display_name(token_info),
        action="create_dynamic_engine",
        target=body.name,
        detail={"engine_type": body.engine_type, "namespace": body.namespace},
        ip_address=get_client_ip(request),
    )
    await db.commit()

    return {"id": engine_id, "name": body.name, "namespace": body.namespace}


@router.delete("/engines/{engine_id}")
async def delete_engine(
    engine_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("admin", "w")),
):
    vault.require_unsealed()
    ns = await _engine_namespace(db, engine_id)
    await _check_dynamic_namespace(db, token_info, ns)
    await _lock_engine_mutation(db, engine_id)

    # A credential outlives its role template and possibly an earlier,
    # incorrectly-recorded revoke. Re-run every lease's snapshotted revocation
    # before deleting the engine; idempotent DROP/DELETE templates make this a
    # safe repair pass. Preflight first so a legacy row without a snapshot
    # blocks deletion before any external mutation occurs.
    lease_result = await db.execute(
        text(
            "SELECT l.id, l.username, l.revocation_sql, l.provisioning, "
            "       (l.expires_at <= NOW()) AS expired, "
            "       e.engine_type "
            "FROM vault_leases AS l "
            "JOIN vault_dynamic_engines AS e ON e.id = l.engine_id "
            "WHERE l.engine_id = CAST(:id AS uuid) "
            "AND (NOT l.revoked OR NOT l.revocation_verified)"
        ),
        {"id": engine_id},
    )
    engine_leases = lease_result.fetchall()
    if any(lease.provisioning and not lease.expired for lease in engine_leases):
        raise HTTPException(
            409,
            "Engine has a credential provisioning operation in progress",
        )
    if any(not lease.revocation_sql for lease in engine_leases):
        raise HTTPException(
            409,
            "Engine has a legacy lease without a revocation snapshot; "
            "revoke the target credential manually before deleting the engine",
        )
    if engine_leases:
        conn_url = await _get_connection_url(db, engine_id)
        for lease in engine_leases:
            try:
                await _revoke_credential(
                    lease.engine_type,
                    conn_url,
                    lease.revocation_sql,
                    lease.username,
                )
            except Exception as exc:
                log.warning(
                    "Engine deletion could not revoke credential %s "
                    "(engine=%s, error_type=%s)",
                    lease.username,
                    lease.engine_type,
                    type(exc).__name__,
                )
                raise HTTPException(
                    502,
                    "Engine deletion stopped because a target credential "
                    "could not be revoked",
                ) from None

    # Target credentials are gone; remove lease bookkeeping before the engine
    # because vault_leases deliberately has no ON DELETE CASCADE.
    await db.execute(
        text("DELETE FROM vault_leases WHERE engine_id = CAST(:id AS uuid)"),
        {"id": engine_id},
    )
    result = await db.execute(
        text(
            "DELETE FROM vault_dynamic_engines "
            "WHERE id = CAST(:id AS uuid) RETURNING name, dek_id"
        ),
        {"id": engine_id},
    )
    row = result.fetchone()
    if not row:
        raise HTTPException(404, "Engine not found")
    if row.dek_id is not None:
        await db.execute(
            text("DELETE FROM vault_dek WHERE id = CAST(:dek_id AS uuid)"),
            {"dek_id": str(row.dek_id)},
        )

    await log_action(
        db,
        actor=actor_display_name(token_info),
        action="delete_dynamic_engine",
        target=row.name,
        detail={"namespace": ns, "leases_revoked": len(engine_leases)},
        ip_address=get_client_ip(request),
    )
    await db.commit()
    return {"status": "deleted", "name": row.name}


# -- Role CRUD ---------------------------------------------------------------


@router.post("/engines/{engine_id}/roles", status_code=201)
async def create_role(
    engine_id: str,
    body: RoleCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("admin", "w")),
):
    vault.require_unsealed()
    ns = await _engine_namespace(db, engine_id)
    await _check_dynamic_namespace(db, token_info, ns)
    await _require_active_namespace(db, ns)
    await _lock_engine_mutation(db, engine_id)
    engine_state = (
        await db.execute(
            text(
                "SELECT max_ttl_seconds, engine_type FROM vault_dynamic_engines "
                "WHERE id = CAST(:id AS uuid)"
            ),
            {"id": engine_id},
        )
    ).one_or_none()
    if engine_state is None:
        raise HTTPException(404, "Engine not found")
    if body.max_ttl_seconds > engine_state.max_ttl_seconds:
        raise HTTPException(
            400,
            "Role max_ttl_seconds cannot exceed the engine maximum",
        )
    try:
        _engine(engine_state.engine_type).validate_role_templates(
            body.creation_sql,
            body.revocation_sql,
        )
    except ValueError:
        raise HTTPException(
            400,
            f"Invalid role templates for {engine_state.engine_type}",
        ) from None

    try:
        result = await db.execute(
            text("""
                INSERT INTO vault_dynamic_roles
                    (engine_id, name, creation_sql, revocation_sql,
                     default_ttl_seconds, max_ttl_seconds)
                VALUES
                    (CAST(:eid AS uuid), :name, :create_sql, :revoke_sql,
                     :default_ttl, :max_ttl)
                RETURNING id
            """),
            {
                "eid": engine_id,
                "name": body.name,
                "create_sql": body.creation_sql,
                "revoke_sql": body.revocation_sql,
                "default_ttl": body.default_ttl_seconds,
                "max_ttl": body.max_ttl_seconds,
            },
        )
    except IntegrityError as exc:
        if _integrity_constraint_name(exc) != "vault_dynamic_roles_engine_id_name_key":
            raise
        await db.rollback()
        raise HTTPException(
            409,
            "Dynamic role name already exists for this engine",
        ) from None
    role_id = str(result.fetchone().id)

    await log_action(
        db,
        actor=actor_display_name(token_info),
        action="create_dynamic_role",
        target=body.name,
        detail={"engine_id": engine_id},
        ip_address=get_client_ip(request),
    )
    await db.commit()
    return {"id": role_id, "name": body.name}


@router.get("/engines/{engine_id}/roles")
async def list_roles(
    engine_id: str,
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("admin", "r")),
):
    vault.require_unsealed()
    ns = await _engine_namespace(db, engine_id)
    await _check_dynamic_namespace(db, token_info, ns)
    result = await db.execute(
        text("""
            SELECT id, name, default_ttl_seconds, max_ttl_seconds
            FROM vault_dynamic_roles
            WHERE engine_id = CAST(:eid AS uuid)
            ORDER BY name
        """),
        {"eid": engine_id},
    )
    return {
        "items": [
            {
                "id": str(r.id),
                "name": r.name,
                "default_ttl_seconds": r.default_ttl_seconds,
                "max_ttl_seconds": r.max_ttl_seconds,
            }
            for r in result.fetchall()
        ]
    }


# -- Credential generation ---------------------------------------------------


async def _get_connection_url(db: AsyncSession, engine_id: str) -> str:
    """Decrypt the engine's connection URL."""
    result = await db.execute(
        text("""
            SELECT e.name, e.connection_url, e.nonce, e.dek_id,
                   d.encrypted_key, d.nonce AS dek_nonce
            FROM vault_dynamic_engines e
            LEFT JOIN vault_dek d ON d.id = e.dek_id
            WHERE e.id = CAST(:id AS uuid)
        """),
        {"id": engine_id},
    )
    row = result.fetchone()
    if not row:
        raise HTTPException(404, "Engine not found")
    if row.dek_id is None or row.encrypted_key is None or row.dek_nonce is None:
        log.critical(
            "Dynamic engine key material is unavailable: engine_id=%s",
            engine_id,
        )
        raise HTTPException(500, "Engine key material unavailable")

    dek = await vault.aesgcm_decrypt(
        bytes(row.encrypted_key),
        bytes(row.dek_nonce),
        dek_aad(str(row.dek_id)),
    )
    engine_secret_aad = f"engine:{row.name}".encode()
    return decrypt_secret(
        bytes(row.connection_url),
        bytes(row.nonce),
        dek,
        engine_secret_aad,
    ).decode()


def _engine_capability(engine_type: str, engine: DynamicEngine) -> dict:
    capability = engine_capability(engine)
    if capability["engine_type"] != engine_type:
        raise RuntimeError("dynamic engine registry key/type mismatch")
    return capability


def _engine(engine_type: str) -> DynamicEngine:
    try:
        return ENGINES[engine_type]
    except KeyError:
        raise ValueError(f"Unsupported engine_type: {engine_type}")


async def _provision_credential(
    engine_type: str, conn_url: str, rendered: str
) -> str | None:
    """Create a target credential from a fully rendered operator template."""
    return await _engine(engine_type).provision(conn_url, rendered)


async def _revoke_credential(
    engine_type: str, conn_url: str, revocation_sql: str, username: str
) -> None:
    """Revoke a leased target credential through its backend module."""
    rendered = revocation_sql.replace("{{name}}", username)
    await _engine(engine_type).revoke(conn_url, rendered)


async def _settle_failed_provision(
    db: AsyncSession,
    *,
    lease_id: str,
    engine_type: str,
    conn_url: str,
    revocation_sql: str,
    username: str,
) -> bool:
    """Compensate a partial target mutation and keep failures retryable."""
    try:
        await _revoke_credential(
            engine_type,
            conn_url,
            revocation_sql,
            username,
        )
    except Exception as exc:
        log.warning(
            "Provision compensation could not revoke credential %s "
            "(engine=%s, error_type=%s)",
            username,
            engine_type,
            type(exc).__name__,
        )
        await db.execute(
            text(
                "UPDATE vault_leases "
                "SET provisioning = false, expires_at = NOW() "
                "WHERE id = CAST(:id AS uuid)"
            ),
            {"id": lease_id},
        )
        await db.commit()
        return False

    await db.execute(
        text(
            "UPDATE vault_leases "
            "SET provisioning = false, revoked = true, "
            "    revocation_verified = true "
            "WHERE id = CAST(:id AS uuid)"
        ),
        {"id": lease_id},
    )
    await db.commit()
    return True


@router.post("/engines/{engine_id}/creds/{role_name}")
async def generate_credentials(
    engine_id: str,
    role_name: str,
    request: Request,
    response: Response,
    body: CredRequest | None = None,
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("secrets", "w")),
):
    """Generate ephemeral target credentials.

    Minting is the *consumption* action (an app/CI host requesting short-lived
    creds), so it needs only `secrets:w` -- not `admin:w`. The engine + role
    (creation_sql) are admin-provisioned; the consumer only picks among them,
    and `check_namespace` confines a namespace-scoped token to its own engines.
    Management (engine/role CRUD, lease revoke) stays admin.
    """
    vault.require_unsealed()
    ns = await _engine_namespace(db, engine_id)
    await _check_dynamic_namespace(db, token_info, ns)
    await _require_active_namespace(db, ns)
    await _lock_engine_mutation(db, engine_id)

    # Get role config
    role_result = await db.execute(
        text("""
            SELECT r.creation_sql, r.revocation_sql,
                   r.default_ttl_seconds, r.max_ttl_seconds,
                   e.max_ttl_seconds AS engine_max_ttl_seconds,
                   e.engine_type
            FROM vault_dynamic_roles AS r
            JOIN vault_dynamic_engines AS e ON e.id = r.engine_id
            WHERE r.engine_id = CAST(:eid AS uuid) AND r.name = :name
        """),
        {"eid": engine_id, "name": role_name},
    )
    role = role_result.fetchone()
    if not role:
        raise HTTPException(404, f"Role '{role_name}' not found")

    try:
        _engine(role.engine_type).validate_role_templates(
            role.creation_sql,
            role.revocation_sql,
        )
    except ValueError:
        raise HTTPException(
            409,
            f"Stored role templates are invalid for {role.engine_type}",
        ) from None

    effective_max_ttl = min(role.max_ttl_seconds, role.engine_max_ttl_seconds)
    if effective_max_ttl < 60 or role.default_ttl_seconds < 60:
        raise HTTPException(409, "Role has an invalid legacy TTL configuration")
    ttl = min(role.default_ttl_seconds, effective_max_ttl)
    if body and body.ttl_seconds is not None:
        ttl = min(body.ttl_seconds, effective_max_ttl)

    username = _generate_username(role_name)
    password = _generate_password()
    db_now = (await db.execute(text("SELECT NOW()"))).scalar_one()
    expires_at = db_now.astimezone(timezone.utc) + timedelta(seconds=ttl)

    # Render the operator-owned backend template.
    rendered_sql = (
        role.creation_sql.replace("{{name}}", username)
        .replace("{{password}}", password)
        .replace("{{expiration}}", expires_at.strftime("%Y-%m-%d %H:%M:%S UTC"))
    )

    # Execute through the enabled target module.
    conn_url = await _get_connection_url(db, engine_id)

    # Persist the immutable revocation snapshot before mutating the target.
    # If this worker dies after a partial or successful remote create, the
    # reaper still owns enough state to remove the credential by its TTL.
    lease_result = await db.execute(
        text("""
            INSERT INTO vault_leases
                (engine_id, role_name, username, revocation_sql, expires_at,
                 provisioning)
            VALUES
                (CAST(:eid AS uuid), :role, :user, :revoke_sql, :expires, true)
            RETURNING id
        """),
        {
            "eid": engine_id,
            "role": role_name,
            "user": username,
            "revoke_sql": role.revocation_sql,
            "expires": expires_at,
        },
    )
    lease_id = str(lease_result.fetchone().id)
    await db.commit()

    try:
        resource_dn = await _provision_credential(
            role.engine_type, conn_url, rendered_sql
        )
    except ImportError as exc:
        backend = _engine(role.engine_type)
        if driver_available(backend.support.driver_module):
            # An installed backend raised ImportError from inside its runtime
            # path. Treat it as a possible partial mutation and compensate.
            log.error(
                "Installed %s driver failed during provisioning (error_type=%s)",
                role.engine_type,
                type(exc).__name__,
            )
            await _settle_failed_provision(
                db,
                lease_id=lease_id,
                engine_type=role.engine_type,
                conn_url=conn_url,
                revocation_sql=role.revocation_sql,
                username=username,
            )
            raise HTTPException(502, "Failed to create target credentials") from None

        # A wholly absent optional driver is detected before any target
        # connection or mutation, so the persisted placeholder is safe to
        # close without a remote revocation.
        await db.execute(
            text(
                "UPDATE vault_leases "
                "SET provisioning = false, revoked = true, "
                "    revocation_verified = true "
                "WHERE id = CAST(:id AS uuid)"
            ),
            {"id": lease_id},
        )
        await db.commit()
        raise HTTPException(
            501,
            f"{backend.support.driver_module} is not installed for "
            f"{backend.support.display_name} support",
        ) from None
    except Exception as exc:
        # Driver errors can echo connection URLs or rendered templates. Log only
        # the backend and exception class; the API response is deliberately
        # generic for the same reason.
        log.error(
            "Failed to create %s credential (error_type=%s)",
            role.engine_type,
            type(exc).__name__,
        )
        cleanup_verified = await _settle_failed_provision(
            db,
            lease_id=lease_id,
            engine_type=role.engine_type,
            conn_url=conn_url,
            revocation_sql=role.revocation_sql,
            username=username,
        )
        log.error(
            "Failed %s credential compensation verified=%s",
            role.engine_type,
            cleanup_verified,
        )
        raise HTTPException(502, "Failed to create target credentials") from None

    settled = await db.execute(
        text(
            "UPDATE vault_leases SET provisioning = false "
            "WHERE id = CAST(:id AS uuid) "
            "  AND provisioning AND NOT revoked AND expires_at > NOW() "
            "RETURNING id"
        ),
        {"id": lease_id},
    )
    if settled.fetchone() is None:
        cleanup_verified = await _settle_failed_provision(
            db,
            lease_id=lease_id,
            engine_type=role.engine_type,
            conn_url=conn_url,
            revocation_sql=role.revocation_sql,
            username=username,
        )
        log.error(
            "Late %s credential was not delivered; compensation verified=%s",
            role.engine_type,
            cleanup_verified,
        )
        raise HTTPException(502, "Failed to create target credentials") from None
    await log_action(
        db,
        actor=actor_display_name(token_info),
        action="generate_credentials",
        target=username,
        detail={
            "engine_id": engine_id,
            "role": role_name,
            "ttl": ttl,
            "lease_id": lease_id,
        },
        ip_address=get_client_ip(request),
    )
    await db.commit()

    resp = {
        "username": username,
        "password": password,
        "lease_id": lease_id,
        "ttl_seconds": ttl,
        "expires_at": expires_at.isoformat(),
    }
    # ldap: the bind DN (cn alone can't bind). Omitted for SQL backends where
    # the username is the login.
    if resource_dn:
        resp["dn"] = resource_dn
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return resp


# -- Lease management --------------------------------------------------------


@router.get("/leases")
async def list_leases(
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("admin", "r")),
):
    vault.require_unsealed()
    allowed_ns = await _allowed_namespaces(db, token_info)
    sql = """
        SELECT l.id, l.role_name, l.username, l.expires_at,
               l.revoked, l.revocation_verified, l.provisioning,
               (l.expires_at <= NOW()) AS expired,
               l.created_at, e.name AS engine_name,
               e.namespace AS engine_namespace
        FROM vault_leases l
        JOIN vault_dynamic_engines e ON e.id = l.engine_id
        WHERE (NOT l.revoked OR NOT l.revocation_verified)
        {ns_filter}
        ORDER BY l.expires_at
    """
    if allowed_ns is None:
        result = await db.execute(text(sql.format(ns_filter="")))
    else:
        result = await db.execute(
            text(sql.format(ns_filter="AND e.namespace = ANY(:ns)")),
            {"ns": allowed_ns},
        )
    return {
        "items": [
            {
                "id": str(r.id),
                "engine": r.engine_name,
                "namespace": r.engine_namespace,
                "role": r.role_name,
                "username": r.username,
                "provisioning": r.provisioning,
                "expired": r.expired,
                "revoked": r.revoked,
                "revocation_verified": r.revocation_verified,
                "expires_at": r.expires_at.isoformat(),
                "created_at": r.created_at.isoformat(),
            }
            for r in result.fetchall()
        ]
    }


@router.post("/leases/{lease_id}/revoke")
async def revoke_lease(
    lease_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("admin", "w")),
):
    """Revoke a lease and verify target-side deletion immediately."""
    vault.require_unsealed()
    lease_id = _normalize_uuid(lease_id, "Lease not found or already revoked")
    result = await db.execute(
        text("""
            SELECT l.username, l.engine_id, l.role_name,
                   l.revocation_sql, l.provisioning,
                   (l.expires_at <= NOW()) AS expired,
                   e.engine_type, e.namespace
            FROM vault_leases l
            JOIN vault_dynamic_engines e ON e.id = l.engine_id
            WHERE l.id = CAST(:id AS uuid)
              AND (NOT l.revoked OR NOT l.revocation_verified)
        """),
        {"id": lease_id},
    )
    row = result.fetchone()
    if not row:
        raise HTTPException(404, "Lease not found or already revoked")
    await _check_dynamic_namespace(db, token_info, row.namespace)
    if row.provisioning and not row.expired:
        raise HTTPException(409, "Credential provisioning is still in progress")

    if not row.revocation_sql:
        raise HTTPException(
            409,
            "Lease has no revocation snapshot; target credential was not changed",
        )
    try:
        conn_url = await _get_connection_url(db, str(row.engine_id))
        await _revoke_credential(
            row.engine_type, conn_url, row.revocation_sql, row.username
        )
    except Exception as exc:
        log.warning(
            "Failed to revoke target credential %s (engine=%s, error_type=%s)",
            row.username,
            row.engine_type,
            type(exc).__name__,
        )
        raise HTTPException(
            502,
            "Target credential revocation failed; lease remains active for retry",
        ) from None

    await db.execute(
        text(
            "UPDATE vault_leases "
            "SET provisioning = false, revoked = true, "
            "    revocation_verified = true "
            "WHERE id = CAST(:id AS uuid)"
        ),
        {"id": lease_id},
    )

    await log_action(
        db,
        actor=actor_display_name(token_info),
        action="revoke_lease",
        target=row.username,
        detail={"lease_id": lease_id, "role": row.role_name},
        ip_address=get_client_ip(request),
    )
    await db.commit()

    return {"status": "revoked", "username": row.username}


class LeaseRenewRequest(_DynamicRequest):
    ttl_seconds: int = Field(3600, ge=60, le=86400)


@router.post("/leases/{lease_id}/renew")
async def renew_lease(
    lease_id: str,
    request: Request,
    body: LeaseRenewRequest | None = None,
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("secrets", "w")),
):
    """Extend a lease: push expires_at to NOW()+ttl, capped at the role's
    absolute lifetime (created_at + max_ttl_seconds).

    Same TTL-extension model as token renewal (tokens.renew_token): it only
    moves expires_at, and the reaper simply will not drop the credential until
    the new time. That is sufficient because the canonical creation template
    enforces expiry through the reaper (DROP at expiry), not a DB-native clause.
    If an operator's creation_sql sets a backend-native expiry (e.g. PG
    `VALID UNTIL '{{expiration}}'`), renewing the lease alone does not move that
    clause -- rely on the reaper default, or re-mint.

    The max_ttl cap is the one thing a lease needs that a token does not: it is
    the dynamic-secrets invariant that a credential cannot be renewed past its
    absolute lifetime. Consumption action (secrets:w, like minting);
    check_namespace confines a namespace-scoped token to its own engines.
    """
    vault.require_unsealed()
    lease_id = _normalize_uuid(
        lease_id,
        "Lease not found, revoked, or already expired",
    )
    ttl = body.ttl_seconds if body else 3600
    result = await db.execute(
        text("""
            SELECT l.username, l.role_name, l.created_at, l.expires_at,
                   NOW() AS db_now,
                   l.provisioning, e.namespace,
                   e.max_ttl_seconds AS engine_max_ttl_seconds,
                   r.max_ttl_seconds AS role_max_ttl_seconds
            FROM vault_leases l
            JOIN vault_dynamic_engines e ON e.id = l.engine_id
            LEFT JOIN vault_dynamic_roles r
                   ON r.engine_id = l.engine_id AND r.name = l.role_name
            WHERE l.id = CAST(:id AS uuid)
              AND NOT l.revoked AND l.expires_at > NOW()
        """),
        {"id": lease_id},
    )
    row = result.fetchone()
    if not row:
        raise HTTPException(404, "Lease not found, revoked, or already expired")
    await _check_dynamic_namespace(db, token_info, row.namespace)
    await _require_active_namespace(db, row.namespace)
    if row.provisioning:
        raise HTTPException(409, "Credential provisioning is still in progress")

    now = row.db_now.astimezone(timezone.utc)
    new_expires = now + timedelta(seconds=ttl)
    # The engine cap survives role deletion. A live role may only tighten it.
    absolute_max_ttl = row.engine_max_ttl_seconds
    if row.role_max_ttl_seconds is not None:
        absolute_max_ttl = min(absolute_max_ttl, row.role_max_ttl_seconds)
    if absolute_max_ttl < 60:
        raise HTTPException(409, "Lease has an invalid legacy TTL configuration")
    hard_cap = row.created_at + timedelta(seconds=absolute_max_ttl)
    new_expires = min(new_expires, hard_cap)
    if new_expires <= row.expires_at:
        raise HTTPException(409, "Lease already at its maximum lifetime")

    renewed = await db.execute(
        text("""
            UPDATE vault_leases
            SET expires_at = :new_expires
            WHERE id = CAST(:id AS uuid)
              AND NOT revoked
              AND NOT provisioning
              AND expires_at > statement_timestamp()
              AND expires_at = :observed_expires
            RETURNING id
        """),
        {
            "id": lease_id,
            "new_expires": new_expires,
            "observed_expires": row.expires_at,
        },
    )
    if renewed.fetchone() is None:
        raise HTTPException(409, "Lease changed during renewal; reload and retry")
    await log_action(
        db,
        actor=actor_display_name(token_info),
        action="renew_lease",
        target=row.username,
        detail={
            "lease_id": lease_id,
            "role": row.role_name,
            "new_expires_at": new_expires.isoformat(),
        },
        ip_address=get_client_ip(request),
    )
    await db.commit()
    return {
        "status": "renewed",
        "username": row.username,
        "lease_id": lease_id,
        "expires_at": new_expires.isoformat(),
        "ttl_seconds": int((new_expires - now).total_seconds()),
    }


async def expire_due_leases(db: AsyncSession) -> list[dict]:
    """Reaper hook: revoke a bounded batch of expired target credentials, then
    mark their leases revoked.

    This is what makes dynamic credentials actually ephemeral: the lease TTL is
    enforced on the *target*, not just recorded here. Without it a credential
    whose creation template lacks a target-native expiry clause (e.g. PG
    `VALID UNTIL`) would keep working forever after its lease "expired".

    Only leases whose target credential was actually revoked are marked. Failed
    attempts remain eligible, but are moved behind never-attempted and
    older-attempted leases so one unavailable engine cannot starve the queue.
    No-op while the vault is sealed (decrypting the engine connection URL needs
    the master key). Caller owns the commit.
    """
    if vault.sealed:
        return []

    result = await db.execute(
        text("""
            SELECT l.id, l.username, l.engine_id, l.role_name,
                   e.engine_type, l.revocation_sql
            FROM vault_leases l
            JOIN vault_dynamic_engines e ON e.id = l.engine_id
            WHERE (NOT l.revoked OR NOT l.revocation_verified)
              AND l.expires_at < NOW()
            ORDER BY l.revocation_attempted_at NULLS FIRST,
                     l.expires_at, l.id
            LIMIT :batch_size
            FOR UPDATE OF l SKIP LOCKED
        """),
        {"batch_size": _LEASE_REAPER_BATCH_SIZE},
    )
    leases = result.fetchall()
    if not leases:
        return []

    # Persist queue progress even when loading the engine or revoking the
    # target credential fails. This prevents a permanently broken oldest batch
    # from starving every newer expired lease.
    await db.execute(
        text(
            "UPDATE vault_leases SET revocation_attempted_at = NOW() "
            "WHERE id = ANY(:lease_ids)"
        ),
        {"lease_ids": [ls.id for ls in leases]},
    )

    # Group by engine so the engine connection URL is decrypted once per engine
    # (an RPC round-trip to the master), not once per lease.
    by_engine: dict = {}
    for ls in leases:
        by_engine.setdefault(ls.engine_id, []).append(ls)

    dropped: list[dict] = []
    for engine_id, eng_leases in by_engine.items():
        try:
            conn_url = await _get_connection_url(db, str(engine_id))
        except Exception as exc:
            log.warning(
                "Reaper: cannot load engine %s (error_type=%s)",
                engine_id,
                type(exc).__name__,
            )
            continue
        for ls in eng_leases:
            if ls.revocation_sql:
                try:
                    await _revoke_credential(
                        ls.engine_type, conn_url, ls.revocation_sql, ls.username
                    )
                except Exception as exc:
                    # Engine unreachable / drop failed -> leave un-revoked, retry.
                    log.warning(
                        "Reaper: failed to revoke %s on engine %s (error_type=%s)",
                        ls.username,
                        engine_id,
                        type(exc).__name__,
                    )
                    continue
            else:
                # A legacy/corrupt lease without a snapshot cannot prove target
                # revocation. Keep its revocation unverified so monitoring and
                # later reaper cycles continue surfacing the operator repair.
                log.error(
                    "Reaper: lease %s has no revocation snapshot (role=%s); "
                    "target credential may still be active",
                    ls.id,
                    ls.role_name,
                )
                continue
            await db.execute(
                text(
                    "UPDATE vault_leases "
                    "SET provisioning = false, revoked = true, "
                    "    revocation_verified = true "
                    "WHERE id = CAST(:id AS uuid)"
                ),
                {"id": str(ls.id)},
            )
            await log_action(
                db,
                actor="reaper",
                action="expire_lease",
                target=ls.username,
                detail={"lease_id": str(ls.id), "role": ls.role_name},
            )
            dropped.append({"id": str(ls.id), "username": ls.username})

    return dropped
