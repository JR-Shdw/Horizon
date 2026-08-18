# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Namespaces - RBAC-owned containers for secrets.

A namespace is an explicit row in `vault_namespaces` owned by
exactly one vault_groups entry. Two security flags, both one-way
ratchets at the DB level :
  - `enforce_membership` : if true, secrets-CRUD inside this namespace
    requires live `vault_group_members` check (not just a token claim).
  - `delete_protection`  : 'free' (default, hard delete), 'soft' (DELETE
    becomes soft-delete with retention window + restore), or 'protected'
    (admin + 2FA + extended retention + no auto-purge).

ALL mutations (POST / PUT / DELETE) require :
  - admin:w scope
  - fresh 2FA challenge tagged `namespace_mutation` (only when the
    vault has 2FA configured ; mode='none' relaxes this to just admin)
  - per-actor rate-limit (default 10 mutations / 60 min, config:
    `namespace_mutation_rate_per_hour`)

GET endpoints are claim-/membership-filtered : a token sees only the
namespaces it has access to via its `permissions.namespaces` claim or
group membership. Admin without claim sees everything.
"""

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ..audit import log_action
from ..auth import actor_display_name, require_permission
from ..client_ip import get_client_ip
from ..config import settings
from ..database import get_db
from ..vault_state import vault

router = APIRouter(prefix="/api/v1/vault/namespaces", tags=["namespaces"])


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class _Mutation2FAEnvelope(BaseModel):
    """Common 2FA fields for namespace mutation bodies. Duck-typed against
    `_verify_2fa(body=...)` in vault.py - same field names as UnsealRequest."""

    challenge: str | None = None
    yubikey_response: str | None = None
    totp_code: str | None = None
    webauthn_response: dict | None = None


_DELETE_PROTECTION_VALUES = {"free", "soft", "protected"}
_DELETE_PROTECTION_RANK = {"free": 0, "soft": 1, "protected": 2}


class NamespaceCreate(_Mutation2FAEnvelope):
    name: str = Field(..., min_length=1, max_length=128)
    owner_group_id: str
    enforce_membership: bool = False
    delete_protection: str = Field(
        default="free",
        description=(
            "Deletion mode for secrets in this namespace. 'free' = hard "
            "delete (default). 'soft' = soft-delete + retention window + "
            "restore. 'protected' = admin + 2FA + extended retention. "
            "One-way ratchet : free -> soft -> protected, never backwards."
        ),
    )


class NamespaceUpdate(_Mutation2FAEnvelope):
    # `name` is intentionally absent : namespace names are IMMUTABLE
    # post-creation. Renaming would invalidate the AEAD AAD on every
    # secret in the namespace and the security implications of the
    # re-encrypt loop need design review before exposing it. To
    # "rename" today : create a fresh namespace with the new name,
    # migrate secrets manually, archive the old one.
    owner_group_id: str | None = None
    enforce_membership: bool | None = None
    delete_protection: str | None = None


class NamespaceDeleteBody(_Mutation2FAEnvelope):
    pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _gate_mutation(
    db: AsyncSession,
    body: _Mutation2FAEnvelope,
    token_info: dict,
    client_ip: str,
) -> None:
    """Enforce admin + 2FA + per-actor rate-limit on namespace mutations.

    `require_permission("admin", "w")` was already enforced by the route
    dependency before this is called. Here we add the 2FA challenge
    verification and the rate-limit check.
    """
    # 1. Rate-limit per actor : count mutation entries in the last hour.
    actor = actor_display_name(token_info)
    cap = getattr(settings, "namespace_mutation_rate_per_hour", 10)
    recent = (
        await db.execute(
            text(
                "SELECT count(*) FROM vault_audit "
                "WHERE actor = :actor "
                "  AND action IN ('create_namespace', 'update_namespace', "
                "                 'archive_namespace') "
                "  AND timestamp > NOW() - INTERVAL '1 hour'"
            ),
            {"actor": actor},
        )
    ).scalar()
    if recent and recent >= cap:
        await log_action(
            db,
            actor=actor,
            action="namespace_rate_limit_exceeded",
            detail={"recent_count": recent, "cap": cap},
            ip_address=client_ip,
        )
        await db.commit()
        raise HTTPException(
            429,
            f"Too many namespace mutations ({recent}/{cap} in last hour)",
        )

    # 2. 2FA challenge, required when the vault has 2FA configured.
    #    Reuses _verify_2fa from vault.py with purpose='namespace_mutation'.
    from .vault import _get_2fa_mode, _verify_2fa

    mode = await _get_2fa_mode(db)
    if mode == "none":
        return  # admin scope is enough when no 2FA is configured

    # aesgcm=None -> _verify_2fa delegates the 2FA decrypt via RPC (follower-safe;
    # a follower holds no dek_key). The local-key form is unseal-only.
    await _verify_2fa(
        db, mode, body, client_ip, aesgcm=None, purpose="namespace_mutation"
    )


def _row_to_dict(row) -> dict[str, Any]:
    """Serialize a vault_namespaces row for API responses."""
    return {
        "id": str(row.id),
        "name": row.name,
        "owner_group_id": str(row.owner_group_id),
        "enforce_membership": bool(row.enforce_membership),
        "delete_protection": row.delete_protection,
        "archived_at": row.archived_at.isoformat() if row.archived_at else None,
        "created_by": row.created_by,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/", status_code=201)
async def create_namespace(
    body: NamespaceCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("admin", "w")),
):
    """Create a new namespace owned by `owner_group_id`. Admin + 2FA + rate-limit.

    `enforce_membership` defaults to false (agnostic mode), `delete_protection`
    to 'free'. Both are one-way ratchets at the DB level - once raised,
    the API + the trigger refuse to relax them. To "downgrade" : create a
    fresh namespace in the desired mode and migrate secrets.
    """
    vault.require_unsealed()
    client_ip = get_client_ip(request)

    if body.delete_protection not in _DELETE_PROTECTION_VALUES:
        raise HTTPException(
            400, f"delete_protection must be one of {sorted(_DELETE_PROTECTION_VALUES)}"
        )

    await _gate_mutation(db, body, token_info, client_ip)

    # Verify the owner group exists.
    owner = (
        await db.execute(
            text("SELECT id FROM vault_groups WHERE id = CAST(:gid AS uuid)"),
            {"gid": body.owner_group_id},
        )
    ).fetchone()
    if owner is None:
        raise HTTPException(404, f"Owner group not found: {body.owner_group_id}")

    try:
        result = await db.execute(
            text(
                """
                INSERT INTO vault_namespaces
                    (name, owner_group_id, enforce_membership,
                     delete_protection, created_by)
                VALUES (:name, CAST(:gid AS uuid), :enforce, :dp, :actor)
                RETURNING id, name, owner_group_id, enforce_membership,
                          delete_protection, archived_at, created_by, created_at
                """
            ),
            {
                "name": body.name,
                "gid": body.owner_group_id,
                "enforce": body.enforce_membership,
                "dp": body.delete_protection,
                "actor": actor_display_name(token_info),
            },
        )
    except Exception as e:
        if "duplicate" in str(e).lower() or "unique" in str(e).lower():
            raise HTTPException(409, f"Namespace already exists: {body.name}")
        raise

    row = result.fetchone()
    await log_action(
        db,
        actor=actor_display_name(token_info),
        action="create_namespace",
        target=body.name,
        detail={
            "namespace_id": str(row.id),
            "owner_group_id": body.owner_group_id,
            "enforce_membership": body.enforce_membership,
            "delete_protection": body.delete_protection,
        },
        ip_address=client_ip,
    )
    await db.commit()
    return _row_to_dict(row)


@router.get("/")
async def list_namespaces(
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("admin", "r")),
):
    """List namespaces visible to the caller.

    For now : admin scope returns all. Filtering by token claim and group
    membership for non-root tokens is implemented at the secret-access
    layer (`check_namespace_membership`) ; the namespace-list endpoint
    is admin-only because it's a discovery surface.
    """
    rows = (
        await db.execute(
            text(
                "SELECT id, name, owner_group_id, enforce_membership, "
                "       delete_protection, archived_at, created_by, created_at "
                "FROM vault_namespaces ORDER BY name"
            )
        )
    ).fetchall()
    return {"items": [_row_to_dict(r) for r in rows]}


@router.get("/{name}")
async def get_namespace(
    name: str,
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("admin", "r")),
):
    """Return details of one namespace : owner, RBAC mode, lock state, secret count."""
    row = (
        await db.execute(
            text(
                "SELECT id, name, owner_group_id, enforce_membership, "
                "       delete_protection, archived_at, created_by, created_at "
                "FROM vault_namespaces WHERE name = :name"
            ),
            {"name": name},
        )
    ).fetchone()
    if row is None:
        raise HTTPException(404, f"Namespace not found: {name}")
    secret_count = (
        await db.execute(
            text("SELECT count(*) FROM vault_secrets WHERE namespace_id = :nid"),
            {"nid": str(row.id)},
        )
    ).scalar() or 0
    out = _row_to_dict(row)
    out["secret_count"] = int(secret_count)
    return out


@router.put("/{name}")
async def update_namespace(
    name: str,
    body: NamespaceUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("admin", "w")),
):
    """Change owner_group or upgrade enforce_membership.

    The namespace `name` is IMMUTABLE post-creation. Renaming would
    invalidate the AEAD AAD on every secret in the namespace ; the
    re-encrypt loop has security implications still under review, so
    the API doesn't expose rename today. To "rename" : create a new
    namespace with the desired name, migrate secrets manually,
    archive the old one.

    Set-once flag : `enforce_membership` true->false rejected by the DB
    trigger (one-way ratchet) - the API surfaces that as 423 Locked
    rather than the raw DB error.
    """
    vault.require_unsealed()
    client_ip = get_client_ip(request)

    await _gate_mutation(db, body, token_info, client_ip)

    current = (
        await db.execute(
            text(
                "SELECT id, name, owner_group_id, enforce_membership, "
                "       delete_protection, archived_at, created_by, created_at "
                "FROM vault_namespaces WHERE name = :name"
            ),
            {"name": name},
        )
    ).fetchone()
    if current is None:
        raise HTTPException(404, f"Namespace not found: {name}")
    if current.archived_at is not None:
        raise HTTPException(409, "Cannot update archived namespace")

    new_owner = (
        body.owner_group_id
        if body.owner_group_id is not None
        else str(current.owner_group_id)
    )
    new_enforce = (
        body.enforce_membership
        if body.enforce_membership is not None
        else current.enforce_membership
    )
    new_dp = (
        body.delete_protection
        if body.delete_protection is not None
        else current.delete_protection
    )

    # Set-once: enforce_membership true->false rejected at API too (matches DB trigger).
    if current.enforce_membership and not new_enforce:
        raise HTTPException(
            423,
            "enforce_membership is set-once: cannot relax. To recover, "
            "create a new namespace in agnostic mode and migrate secrets.",
        )

    # delete_protection one-way ratchet : same idea, free->soft->protected.
    if new_dp not in _DELETE_PROTECTION_VALUES:
        raise HTTPException(
            400,
            f"delete_protection must be one of {sorted(_DELETE_PROTECTION_VALUES)}",
        )
    old_rank = _DELETE_PROTECTION_RANK[current.delete_protection]
    new_rank = _DELETE_PROTECTION_RANK[new_dp]
    if new_rank < old_rank:
        raise HTTPException(
            423,
            f"delete_protection is one-way (free->soft->protected): cannot "
            f"relax from '{current.delete_protection}' to '{new_dp}'. Create "
            "a new namespace in the desired mode and migrate secrets.",
        )

    # Owner change : verify new owner exists.
    if new_owner != str(current.owner_group_id):
        owner_row = (
            await db.execute(
                text("SELECT id FROM vault_groups WHERE id = CAST(:gid AS uuid)"),
                {"gid": new_owner},
            )
        ).fetchone()
        if owner_row is None:
            raise HTTPException(404, f"Owner group not found: {new_owner}")

    try:
        await db.execute(
            text(
                """
                UPDATE vault_namespaces
                SET owner_group_id = CAST(:new_owner AS uuid),
                    enforce_membership = :new_enforce,
                    delete_protection = :new_dp
                WHERE id = :nid
                """
            ),
            {
                "new_owner": new_owner,
                "new_enforce": new_enforce,
                "new_dp": new_dp,
                "nid": str(current.id),
            },
        )
    except Exception as e:
        s = str(e)
        if "set-once" in s or "ratchet" in s:
            raise HTTPException(423, str(e))
        raise

    await log_action(
        db,
        actor=actor_display_name(token_info),
        action="update_namespace",
        target=name,
        detail={
            "namespace_id": str(current.id),
            "new_owner_group_id": (
                new_owner if new_owner != str(current.owner_group_id) else None
            ),
            "new_enforce_membership": (
                new_enforce if new_enforce != current.enforce_membership else None
            ),
            "new_delete_protection": (
                new_dp if new_dp != current.delete_protection else None
            ),
        },
        ip_address=client_ip,
    )
    await db.commit()

    refreshed = (
        await db.execute(
            text(
                "SELECT id, name, owner_group_id, enforce_membership, "
                "       delete_protection, archived_at, created_by, created_at "
                "FROM vault_namespaces WHERE id = :nid"
            ),
            {"nid": str(current.id)},
        )
    ).fetchone()
    return _row_to_dict(refreshed)


@router.delete("/{name}")
async def archive_namespace(
    name: str,
    body: NamespaceDeleteBody,
    request: Request,
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("admin", "w")),
):
    """Soft-delete : sets `archived_at` to NOW(). Refuses if there are
    still non-archived secrets in the namespace - the operator must
    delete or migrate them first.
    """
    vault.require_unsealed()
    client_ip = get_client_ip(request)

    await _gate_mutation(db, body, token_info, client_ip)

    row = (
        await db.execute(
            text("SELECT id, archived_at FROM vault_namespaces WHERE name = :name"),
            {"name": name},
        )
    ).fetchone()
    if row is None:
        raise HTTPException(404, f"Namespace not found: {name}")
    if row.archived_at is not None:
        raise HTTPException(409, "Namespace already archived")

    n_secrets = (
        await db.execute(
            text("SELECT count(*) FROM vault_secrets WHERE namespace_id = :nid"),
            {"nid": str(row.id)},
        )
    ).scalar() or 0
    if n_secrets > 0:
        raise HTTPException(
            409,
            f"Cannot archive - {n_secrets} secret(s) still reference this "
            "namespace. Delete or transfer them first.",
        )

    await db.execute(
        text("UPDATE vault_namespaces SET archived_at = NOW() WHERE id = :nid"),
        {"nid": str(row.id)},
    )
    await log_action(
        db,
        actor=actor_display_name(token_info),
        action="archive_namespace",
        target=name,
        detail={"namespace_id": str(row.id)},
        ip_address=client_ip,
    )
    await db.commit()
    return {"archived": True, "namespace": name}
