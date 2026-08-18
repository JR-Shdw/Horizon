# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Vault tokens CRUD - HMAC-SHA512 hashed, shown once at creation."""

import json
import uuid as _uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ..audit import log_action
from ..auth import (
    actor_display_name,
    check_namespace,
    is_external_session,
    is_reserved_token_name,
    require_permission,
    require_vault_token,
)
from ..client_ip import get_client_ip
from ..config import settings
from ..crypto import generate_token
from ..database import get_db
from ..ip_acl import normalize_allowed_ips
from ..vault_state import vault


def _validate_uuid(val: str):
    try:
        _uuid.UUID(val)
    except (ValueError, AttributeError):
        raise HTTPException(400, "Invalid UUID")


router = APIRouter(prefix="/api/v1/vault/tokens", tags=["tokens"])


def _is_ephemeral_token(name: str | None, expires_at: datetime | None) -> bool:
    """True only for tokens minted by the dedicated ephemeral endpoint."""
    return bool(name and name.startswith("eph-") and expires_at is not None)


def _check_grant_permissions(caller_perms: dict, requested_perms: dict):
    """POLA grant gate: a caller cannot grant what it doesn't hold.

    Scope: each requested scope mode must be held explicitly or through the
    caller's matching admin mode.
    Namespace: a namespace-restricted caller may only grant a namespaces subset,
    else it could mint a token reaching another namespace (escalation).
    """
    caller_perms = caller_perms if isinstance(caller_perms, dict) else {}
    caller_admin = caller_perms.get("admin")
    admin_modes = set(caller_admin) if isinstance(caller_admin, str) else set()
    for scope, level in requested_perms.items():
        if scope == "namespaces":
            continue
        if not isinstance(level, str) or level not in {"r", "w", "rw"}:
            raise HTTPException(403, f"Invalid permission level for '{scope}'")
        caller_level = caller_perms.get(scope)
        caller_modes = set(caller_level) if isinstance(caller_level, str) else set()
        effective_modes = caller_modes | admin_modes
        requested_modes = set(level)
        if not requested_modes.issubset(effective_modes):
            raise HTTPException(
                403,
                f"Cannot grant '{level}' on '{scope}' "
                f"(caller has '{caller_level or ''}', admin '{caller_admin or ''}')",
            )

    # Namespace subset, applies even to admin: a namespace-restricted caller
    # must not mint an unrestricted token.
    caller_ns = caller_perms.get("namespaces")
    if caller_ns:
        requested_ns = requested_perms.get("namespaces")
        if requested_ns is None:
            raise HTTPException(
                403,
                "Caller is namespace-restricted; new token must specify "
                f"a 'namespaces' subset of {caller_ns}",
            )
        if not set(requested_ns).issubset(set(caller_ns)):
            raise HTTPException(
                403,
                f"Cannot grant namespaces {requested_ns} - caller "
                f"restricted to {caller_ns}",
            )


def _check_namespace_subset(caller_perms: dict, target_perms: dict):
    """Namespace-only confinement for revoke/delete/renew: the target's
    namespaces must be within the caller's; a root/unrestricted token is
    off-limits to a restricted caller. No scope check -- removing/extending
    access isn't granting it, so a pure token-admin manages its namespace
    regardless of the target's scopes.
    """
    caller_ns = caller_perms.get("namespaces")
    if not caller_ns:
        return  # unrestricted caller
    target_ns = target_perms.get("namespaces")
    if target_ns is None:
        raise HTTPException(
            403, "Namespace-restricted caller cannot manage an unrestricted token"
        )
    if not set(target_ns).issubset(set(caller_ns)):
        raise HTTPException(
            403,
            f"Cannot manage namespaces {target_ns} - caller restricted to {caller_ns}",
        )


async def _authorize_token_mutation(
    db: AsyncSession,
    token_id: str,
    token_info: dict,
    *,
    active_only: bool = True,
    scope_check: bool = True,
):
    """Load a token and confine the caller to ones it may act on.

    scope_check=True (rotate / set-allowed-ips, which re-issue/widen) -> full
    grant gate. scope_check=False (revoke/delete/renew, which remove/extend) ->
    namespace-only gate. Either way a restricted caller can't touch a root /
    cross-namespace token. active_only=False (delete) also loads revoked rows.
    404 if absent.
    """
    where = "WHERE id = CAST(:id AS uuid)" + (
        " AND active = true" if active_only else ""
    )
    row = (
        await db.execute(
            text(
                "SELECT id, name, permissions, allowed_ips, expires_at, active "
                f"FROM vault_tokens {where}"
            ),
            {"id": token_id},
        )
    ).fetchone()
    if not row:
        raise HTTPException(
            404, "Token not found" + (" or revoked" if active_only else "")
        )
    target_perms = row.permissions if isinstance(row.permissions, dict) else {}
    caller_perms = token_info.get("permissions", {})
    if scope_check:
        _check_grant_permissions(caller_perms, target_perms)
    else:
        _check_namespace_subset(caller_perms, target_perms)
    return row


class TokenCreate(BaseModel):
    name: str = Field(..., max_length=128)
    permissions: dict  # {"secrets": "rw", "audit": "r", ...}
    expires_at: str | None = None
    allowed_ips: str | None = Field(
        default=None,
        max_length=2048,
        description=(
            "Comma-separated CIDRs/IPs the token may authenticate from "
            "(IPv4+IPv6, bare IP = /32 or /128). NULL/empty = unrestricted. "
            "Narrower limits leaked-token replay (lateral movement)."
        ),
    )
    is_honey: bool = Field(
        default=False,
        description=(
            "Decoy token: any auth using it fires a honey_access alert "
            "(CRITICAL log + audit + notify). Name it like real ops creds."
        ),
    )


# POST /, create token (returns plaintext once)
@router.post("/", status_code=201)
async def create_token(
    body: TokenCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("tokens", "w")),
):
    """Mint a long-lived token. Plaintext is returned once.

    `name` doubles as the audit actor. `permissions` is POLA-gated
    (_check_grant_permissions). `allowed_ips` is enforced in require_vault_token
    (wrong IP -> 403 before scope/namespace). Returns {token, name, allowed_ips}
    with allowed_ips canonicalized.
    """
    vault.require_unsealed()
    # Reserved prefixes mark a human session (ldap:/proxy:); a minted API token
    # must not forge one (audit-actor spoofing + strict-RBAC membership bypass).
    if is_reserved_token_name(body.name):
        raise HTTPException(
            400, "Token name may not start with a reserved prefix (ldap:/proxy:)"
        )
    _check_grant_permissions(token_info.get("permissions", {}), body.permissions)

    try:
        allowed_ips = normalize_allowed_ips(body.allowed_ips)
    except ValueError as e:
        raise HTTPException(400, f"Invalid allowed_ips entry: {e}")

    # Check name uniqueness
    result = await db.execute(
        text("SELECT id FROM vault_tokens WHERE name = :name AND active = true"),
        {"name": body.name},
    )
    if result.fetchone():
        raise HTTPException(409, f"Active token '{body.name}' already exists")

    raw_token = generate_token()
    token_hash = await vault.hmac_sha512_hex(raw_token)

    # Parse expires_at string to datetime (asyncpg needs native datetime)
    expires = None
    if body.expires_at:
        from datetime import datetime as _dt

        expires = _dt.fromisoformat(body.expires_at)

    await db.execute(
        text("""
            INSERT INTO vault_tokens
                (name, token_hash, permissions, created_by,
                 expires_at, allowed_ips, is_honey)
            VALUES
                (:name, :hash, CAST(:perms AS jsonb), :actor,
                 :expires, :ips, :is_honey)
        """),
        {
            "name": body.name,
            "hash": token_hash,
            "perms": json.dumps(body.permissions),
            "actor": token_info["name"],
            "expires": expires,
            "ips": allowed_ips,
            "is_honey": body.is_honey,
        },
    )

    await log_action(
        db,
        actor=actor_display_name(token_info),
        action="create_token",
        target=body.name,
        detail={"permissions": body.permissions, "allowed_ips": allowed_ips},
        ip_address=get_client_ip(request),
    )
    await db.commit()
    from .. import metrics as _m

    _m.tokens_created.labels(kind="standard").inc()

    return {"token": raw_token, "name": body.name, "allowed_ips": allowed_ips}


# POST /ephemeral, short-lived scoped token for agents/automation


class EphemeralTokenCreate(BaseModel):
    permissions: dict  # {"secrets": "r", "namespaces": ["prod"]}
    ttl_seconds: int = Field(default=3600, ge=60, le=86400)
    label: str = Field(default="", max_length=128)
    allowed_ips: str | None = Field(
        default=None,
        max_length=2048,
        description=(
            "Comma-separated CIDRs/IPs the token may authenticate from (same "
            "format as /tokens/). NULL/empty = unrestricted; for a CI runner, "
            "its host or pool subnet."
        ),
    )
    inherit_group_membership: bool = Field(
        default=False,
        description=(
            "Copy the caller's group memberships onto the ephemeral so it works "
            "in strict-RBAC namespaces without pre-declaring its name. Reaper "
            "cleans the rows on expiry."
        ),
    )


@router.post("/ephemeral", status_code=201)
async def create_ephemeral_token(
    body: EphemeralTokenCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("tokens", "w")),
):
    """Short-lived scoped token for agents/automation: TTL 60s-24h (capped by
    RHORIZON_EPHEMERAL_MAX_TTL), auto-named eph-<hex>, reaper-purged on expiry.
    Bind `allowed_ips` to the runner host/subnet to limit leaked-token replay.
    """
    vault.require_unsealed()

    ttl = min(body.ttl_seconds, settings.ephemeral_max_ttl)
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl)

    # Prevent ephemeral root tokens (stricter than POLA, admin is never ephemeral)
    if "admin" in body.permissions:
        raise HTTPException(403, "Ephemeral tokens cannot have admin scope")
    _check_grant_permissions(token_info.get("permissions", {}), body.permissions)

    try:
        allowed_ips = normalize_allowed_ips(body.allowed_ips)
    except ValueError as e:
        raise HTTPException(400, f"Invalid allowed_ips entry: {e}")

    raw_token = generate_token()
    token_hash = await vault.hmac_sha512_hex(raw_token)
    name = f"eph-{_uuid.uuid4().hex[:8]}"

    token_row = await db.execute(
        text("""
            INSERT INTO vault_tokens
                (name, token_hash, permissions, created_by, expires_at, allowed_ips)
            VALUES
                (:name, :hash, CAST(:perms AS jsonb), :actor, :expires, :ips)
            RETURNING id
        """),
        {
            "name": name,
            "hash": token_hash,
            "perms": json.dumps(body.permissions),
            "actor": token_info["name"],
            "expires": expires_at,
            "ips": allowed_ips,
        },
    )
    ephemeral_id = str(token_row.fetchone().id)

    inherited_groups: list[str] = []
    if body.inherit_group_membership:
        # Replicate the caller's typed memberships onto the new token UUID.
        # External sessions match their full source-qualified identity; native
        # tokens match their stable UUID. Display names never enter authz.
        if is_external_session(token_info):
            principal = token_info["name"]
            membership_query = text("""
                SELECT group_id FROM vault_group_members
                WHERE principal_type = 'external'
                  AND external_id = :principal
            """)
        else:
            principal = token_info["id"]
            membership_query = text("""
                SELECT group_id FROM vault_group_members
                WHERE principal_type = 'token'
                  AND token_id = CAST(:principal AS uuid)
            """)
        rows = (
            await db.execute(
                membership_query,
                {"principal": principal},
            )
        ).fetchall()
        for r in rows:
            await db.execute(
                text(
                    """
                    INSERT INTO vault_group_members
                        (group_id, principal_type, token_id)
                    VALUES (:gid, 'token', CAST(:token_id AS uuid))
                    ON CONFLICT DO NOTHING
                    """
                ),
                {"gid": str(r.group_id), "token_id": ephemeral_id},
            )
            inherited_groups.append(str(r.group_id))

    await log_action(
        db,
        actor=actor_display_name(token_info),
        action="create_ephemeral_token",
        target=name,
        detail={
            "permissions": body.permissions,
            "ttl": ttl,
            "label": body.label,
            "allowed_ips": allowed_ips,
            "inherited_groups": inherited_groups or None,
        },
        ip_address=get_client_ip(request),
    )
    await db.commit()
    from .. import metrics as _m

    _m.tokens_created.labels(kind="ephemeral").inc()

    return {
        "token": raw_token,
        "name": name,
        "expires_at": expires_at.isoformat(),
        "ttl_seconds": ttl,
        "allowed_ips": allowed_ips,
    }


# GET /, list tokens (never shows hash)
@router.get("/")
async def list_tokens(
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("tokens", "r")),
):
    vault.require_unsealed()

    # A namespace-restricted caller only sees tokens it could manage: those whose
    # namespaces claim is a subset of its own. Tokens with no namespaces claim
    # (root / unrestricted) are hidden from restricted callers, mirroring the
    # _check_grant_permissions gate (you can't grant what you can't see).
    allowed_ns = token_info.get("permissions", {}).get("namespaces")

    def _visible(perms) -> bool:
        if not allowed_ns:
            return True
        tns = perms.get("namespaces") if isinstance(perms, dict) else None
        return bool(tns) and set(tns).issubset(set(allowed_ns))

    result = await db.execute(
        text("""
            SELECT id, name, permissions, active, created_by,
                   created_at, last_used_at, expires_at, revoked_at,
                   allowed_ips, rotated_at
            FROM vault_tokens
            ORDER BY created_at DESC
        """)
    )
    items = [
        {
            "id": str(r.id),
            "name": r.name,
            "permissions": r.permissions,
            "active": r.active,
            "created_by": r.created_by,
            "created_at": r.created_at.isoformat(),
            "last_used_at": r.last_used_at.isoformat() if r.last_used_at else None,
            "expires_at": r.expires_at.isoformat() if r.expires_at else None,
            "revoked_at": r.revoked_at.isoformat() if r.revoked_at else None,
            "allowed_ips": r.allowed_ips,
            "rotated_at": r.rotated_at.isoformat() if r.rotated_at else None,
            # Mirror /whoami : ephemeral = name minted by /tokens/ephemeral
            # (always prefixed `eph-` and always has expires_at set).
            "is_ephemeral": _is_ephemeral_token(r.name, r.expires_at),
        }
        for r in result.fetchall()
        if _visible(r.permissions)
    ]
    return {"items": items}


# POST /{id}/revoke, deactivate token
@router.post("/{token_id}/revoke")
async def revoke_token(
    token_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("tokens", "w")),
):
    vault.require_unsealed()
    _validate_uuid(token_id)
    target = await _authorize_token_mutation(
        db, token_id, token_info, scope_check=False
    )
    await db.execute(
        text("""
            UPDATE vault_tokens SET active = false, revoked_at = NOW()
            WHERE id = CAST(:id AS uuid) AND active = true
        """),
        {"id": token_id},
    )

    await log_action(
        db,
        actor=actor_display_name(token_info),
        action="revoke_token",
        target=target.name,
        ip_address=get_client_ip(request),
    )
    from .. import metrics as _m

    _m.tokens_revoked.inc()
    await db.commit()

    return {"status": "revoked", "name": target.name}


# DELETE /{id}, delete token permanently
@router.delete("/{token_id}")
async def delete_token(
    token_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("tokens", "w")),
):
    vault.require_unsealed()
    _validate_uuid(token_id)
    target = await _authorize_token_mutation(
        db, token_id, token_info, active_only=False, scope_check=False
    )
    await db.execute(
        text("DELETE FROM vault_tokens WHERE id = CAST(:id AS uuid)"),
        {"id": token_id},
    )

    await log_action(
        db,
        actor=actor_display_name(token_info),
        action="delete_token",
        target=target.name,
        ip_address=get_client_ip(request),
    )
    await db.commit()

    return {"status": "deleted", "name": target.name}


# GET /whoami, introspect the calling token; any valid token, no scope.
@router.get("/whoami")
async def whoami(
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_vault_token),
):
    vault.require_unsealed()
    # Look up full token record for richer fields not in token_info
    r = await db.execute(
        text(
            "SELECT id, name, permissions, active, created_by, created_at, "
            "last_used_at, expires_at, allowed_ips FROM vault_tokens WHERE id = :id"
        ),
        {"id": token_info["id"]},
    )
    row = r.fetchone()
    if not row:
        raise HTTPException(404, "Token vanished mid-flight")

    perms = row.permissions if isinstance(row.permissions, dict) else {}
    return {
        "id": str(row.id),
        "name": row.name,
        "permissions": perms,
        "scopes": [k for k in perms if k != "namespaces"],
        "namespaces": perms.get("namespaces") or None,
        "allowed_ips": row.allowed_ips,
        "active": row.active,
        "created_by": row.created_by,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "last_used_at": row.last_used_at.isoformat() if row.last_used_at else None,
        "expires_at": row.expires_at.isoformat() if row.expires_at else None,
        "is_ephemeral": _is_ephemeral_token(row.name, row.expires_at),
    }


# POST /{id}/renew, extend an ephemeral token's expires_at
class RenewRequest(BaseModel):
    ttl_seconds: int = Field(..., ge=60, le=86400)


@router.post("/{token_id}/renew")
async def renew_token(
    token_id: str,
    body: RenewRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("tokens", "w")),
):
    """Extend an ephemeral token's TTL by `ttl_seconds` from now.

    Refuses to renew non-ephemeral (no expires_at) tokens - they don't
    have a TTL to extend. Capped at the same 60s..86400s window as
    ephemeral creation.
    """
    vault.require_unsealed()
    _validate_uuid(token_id)
    target = await _authorize_token_mutation(
        db, token_id, token_info, scope_check=False
    )
    if target.expires_at is None:
        raise HTTPException(404, "Token is not ephemeral (cannot renew)")

    new_expires = datetime.now(timezone.utc) + timedelta(seconds=body.ttl_seconds)
    await db.execute(
        text(
            "UPDATE vault_tokens SET expires_at = :exp "
            "WHERE id = CAST(:id AS uuid) AND active = true"
        ),
        {"id": token_id, "exp": new_expires},
    )

    await log_action(
        db,
        actor=actor_display_name(token_info),
        action="renew_token",
        target=target.name,
        detail={"new_ttl_seconds": body.ttl_seconds},
        ip_address=get_client_ip(request),
    )
    await db.commit()
    return {
        "status": "renewed",
        "name": target.name,
        "expires_at": new_expires.isoformat(),
        "ttl_seconds": body.ttl_seconds,
    }


# POST /{id}/rotate, re-mint a live token's secret in place
@router.post("/{token_id}/rotate")
async def rotate_token(
    token_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("tokens", "w")),
):
    """Rotate a live token's secret in place: same id/name/permissions/
    allowed_ips/expires_at, fresh plaintext. The old value stops authenticating
    on commit, so every consumer must take the new one. Preserves audit lineage
    (vs delete+recreate). last_used_at -> NULL so the new value reads as unused.

    Rotating = re-issuing, so it takes the full grant gate on the stored
    permissions: a namespace-restricted caller can only rotate a namespaces-
    subset token, never a root/unrestricted one.
    """
    vault.require_unsealed()
    _validate_uuid(token_id)
    existing = await _authorize_token_mutation(db, token_id, token_info)

    raw_token = generate_token()
    token_hash = await vault.hmac_sha512_hex(raw_token)

    await db.execute(
        text("""
            UPDATE vault_tokens
               SET token_hash = :hash, rotated_at = NOW(), last_used_at = NULL
             WHERE id = CAST(:id AS uuid) AND active = true
        """),
        {"hash": token_hash, "id": token_id},
    )

    await log_action(
        db,
        actor=actor_display_name(token_info),
        action="rotate_token",
        target=existing.name,
        ip_address=get_client_ip(request),
    )
    await db.commit()
    from .. import metrics as _m

    _m.tokens_rotated.inc()

    return {
        "token": raw_token,
        "name": existing.name,
        "warning": "Save this token - shown once only",
    }


class TokenAllowedIps(BaseModel):
    allowed_ips: str | None = Field(
        default=None,
        max_length=2048,
        description=(
            "Comma-separated CIDRs / IPs the token may authenticate from. "
            "Empty / null clears the restriction (any IP). Same format as create."
        ),
    )


@router.post("/{token_id}/allowed-ips")
async def set_token_allowed_ips(
    token_id: str,
    body: TokenAllowedIps,
    request: Request,
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("tokens", "w")),
):
    """Replace a live token's IP allowlist in place (nothing else changes).
    Widening it changes the token's reach, so it's gated like rotate (full grant
    gate on the stored permissions). Takes effect on the next request; logged as
    a critical audit event.
    """
    vault.require_unsealed()
    _validate_uuid(token_id)

    try:
        new_allowed_ips = normalize_allowed_ips(body.allowed_ips)
    except ValueError as e:
        raise HTTPException(400, f"Invalid allowed_ips entry: {e}")

    existing = await _authorize_token_mutation(db, token_id, token_info)

    await db.execute(
        text("""
            UPDATE vault_tokens
               SET allowed_ips = :ips
             WHERE id = CAST(:id AS uuid) AND active = true
        """),
        {"ips": new_allowed_ips, "id": token_id},
    )

    await log_action(
        db,
        actor=actor_display_name(token_info),
        action="update_token_allowed_ips",
        target=existing.name,
        detail={"old": existing.allowed_ips, "new": new_allowed_ips},
        ip_address=get_client_ip(request),
        critical=True,
    )
    await db.commit()

    return {"id": token_id, "name": existing.name, "allowed_ips": new_allowed_ips}


# -- Pending token rotations (post backup/restore) --------------------------
# Backup-carried tokens land as stubs (their hmac_key-bound hash can't survive
# the restore). An admin rotates each stub to mint a fresh plaintext, or revokes
# it; the reaper purges stubs older than restore_rotation_grace_days.


@router.get("/pending/")
async def list_pending_token_rotations(
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("tokens", "r")),
):
    """List token stubs waiting for an admin to rotate or revoke them.

    A caller with a `namespaces` claim only sees the stubs whose namespace
    is in their claim.
    """
    vault.require_unsealed()

    rows = await db.execute(
        text("""
            SELECT id, name, namespace, permissions, allowed_ips,
                   expires_at, is_honey, group_names, backup_origin, created_at
            FROM vault_pending_token_rotations
            ORDER BY created_at DESC
        """)
    )
    perms = token_info.get("permissions", {})
    allowed_ns = perms.get("namespaces")
    items = []
    for r in rows.fetchall():
        if allowed_ns and r.namespace not in allowed_ns:
            continue
        items.append(
            {
                "id": str(r.id),
                "name": r.name,
                "namespace": r.namespace,
                "permissions": r.permissions,
                "allowed_ips": r.allowed_ips,
                "expires_at": r.expires_at.isoformat() if r.expires_at else None,
                "is_honey": bool(r.is_honey),
                "group_names": r.group_names,
                "backup_origin": r.backup_origin,
                "created_at": r.created_at.isoformat(),
            }
        )
    return {"items": items}


@router.post("/pending/{pending_id}/rotate")
async def rotate_pending_token(
    pending_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("tokens", "w")),
):
    """Mint a fresh plaintext for a pending stub: INSERT an active vault_tokens
    row from the stub's metadata, DELETE the stub. Plaintext shown once.
    """
    vault.require_unsealed()
    _validate_uuid(pending_id)

    row = await db.execute(
        text("""
            SELECT id, name, namespace, permissions, allowed_ips, expires_at,
                   is_honey, group_names
            FROM vault_pending_token_rotations
            WHERE id = CAST(:id AS uuid)
        """),
        {"id": pending_id},
    )
    stub = row.fetchone()
    if not stub:
        raise HTTPException(404, "Pending rotation not found")

    check_namespace(token_info, stub.namespace)

    plaintext = generate_token()
    token_hash = await vault.hmac_sha512_hex(plaintext)

    # Supersede any still-active row with this name (restore over a non-wiped
    # vault): its pre-restore hash can't be reproduced client-side anyway.
    await db.execute(
        text("""
            UPDATE vault_tokens
               SET active = false, revoked_at = NOW()
             WHERE name = :name AND active
        """),
        {"name": stub.name},
    )

    inserted = await db.execute(
        text("""
            INSERT INTO vault_tokens
                (name, token_hash, permissions, allowed_ips, expires_at,
                 is_honey, active, created_by, rotated_at)
            VALUES
                (:name, :hash, CAST(:perms AS jsonb), :allowed_ips,
                 :expires_at, CAST(:is_honey AS boolean), true,
                 'restore-rotation', NOW())
            RETURNING id
        """),
        {
            "name": stub.name,
            "hash": token_hash,
            "perms": json.dumps(stub.permissions or {}),
            "allowed_ips": normalize_allowed_ips(stub.allowed_ips),
            "expires_at": stub.expires_at,
            "is_honey": bool(stub.is_honey),
        },
    )
    new_token_id = str(inserted.fetchone().id)

    for group_name in stub.group_names or []:
        membership = await db.execute(
            text("""
                INSERT INTO vault_group_members
                    (group_id, principal_type, token_id)
                SELECT id, 'token', CAST(:token_id AS uuid)
                FROM vault_groups
                WHERE name = :group_name
                ON CONFLICT DO NOTHING
                RETURNING id
            """),
            {"token_id": new_token_id, "group_name": group_name},
        )
        if membership.fetchone() is None:
            raise HTTPException(
                409,
                f"Cannot restore token membership: group '{group_name}' is missing",
            )

    await db.execute(
        text("DELETE FROM vault_pending_token_rotations WHERE id = CAST(:id AS uuid)"),
        {"id": pending_id},
    )

    await log_action(
        db,
        actor=actor_display_name(token_info),
        action="restore_token_rotated",
        target=stub.name,
        detail={"namespace": stub.namespace, "groups": stub.group_names or None},
        ip_address=get_client_ip(request),
    )
    await db.commit()

    return {
        "token": plaintext,
        "name": stub.name,
        "namespace": stub.namespace,
        "is_honey": bool(stub.is_honey),
        "warning": "Save this token - shown once only",
    }


@router.delete("/pending/{pending_id}")
async def revoke_pending_token(
    pending_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("tokens", "w")),
):
    """Drop a pending stub without minting a token -- revocation before any
    plaintext exists, for a legacy token the admin no longer needs.
    """
    vault.require_unsealed()
    _validate_uuid(pending_id)

    row = await db.execute(
        text("""
            SELECT name, namespace FROM vault_pending_token_rotations
            WHERE id = CAST(:id AS uuid)
        """),
        {"id": pending_id},
    )
    stub = row.fetchone()
    if not stub:
        raise HTTPException(404, "Pending rotation not found")

    check_namespace(token_info, stub.namespace)

    await db.execute(
        text("DELETE FROM vault_pending_token_rotations WHERE id = CAST(:id AS uuid)"),
        {"id": pending_id},
    )

    await log_action(
        db,
        actor=actor_display_name(token_info),
        action="restore_token_revoked",
        target=stub.name,
        detail={"namespace": stub.namespace},
        ip_address=get_client_ip(request),
    )
    await db.commit()

    return {"status": "revoked", "name": stub.name, "namespace": stub.namespace}
