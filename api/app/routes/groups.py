# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Groups / RBAC - team-level permission management."""

import json
import uuid as _uuid
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ..audit import log_action
from ..auth import actor_display_name, is_reserved_token_name, require_permission
from ..client_ip import get_client_ip
from ..database import get_db
from ..vault_state import vault

router = APIRouter(prefix="/api/v1/vault/groups", tags=["groups"])


def _validate_uuid(val: str):
    try:
        _uuid.UUID(val)
    except (ValueError, AttributeError):
        raise HTTPException(400, "Invalid UUID")


class GroupCreate(BaseModel):
    name: str = Field(..., max_length=128)
    permissions: dict  # {"secrets": "rw", "namespaces": ["prod"]}
    source: str = Field(default="local", max_length=32)
    ldap_dn: str | None = Field(default=None, max_length=512)


class GroupUpdate(BaseModel):
    permissions: dict


class MemberAdd(BaseModel):
    principal_type: Literal["external", "token"]
    principal_id: str = Field(..., min_length=1, max_length=256)


@router.get("/")
async def list_groups(
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("admin", "r")),
):
    vault.require_unsealed()
    result = await db.execute(
        text("""
            SELECT g.id, g.name, g.permissions, g.source, g.ldap_dn,
                   g.created_at,
                   (SELECT count(*) FROM vault_group_members
                    WHERE group_id = g.id) AS member_count
            FROM vault_groups g ORDER BY g.name
        """)
    )
    return {
        "items": [
            {
                "id": str(r.id),
                "name": r.name,
                "permissions": r.permissions,
                "source": r.source,
                "ldap_dn": r.ldap_dn,
                "member_count": r.member_count,
                "created_at": r.created_at.isoformat(),
            }
            for r in result.fetchall()
        ]
    }


@router.post("/", status_code=201)
async def create_group(
    body: GroupCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("admin", "w")),
):
    vault.require_unsealed()

    existing = await db.execute(
        text("SELECT id FROM vault_groups WHERE name = :name"),
        {"name": body.name},
    )
    if existing.fetchone():
        raise HTTPException(409, f"Group '{body.name}' already exists")

    result = await db.execute(
        text("""
            INSERT INTO vault_groups (name, permissions, source, ldap_dn)
            VALUES (:name, CAST(:perms AS jsonb), :source, :ldap_dn)
            RETURNING id
        """),
        {
            "name": body.name,
            "perms": json.dumps(body.permissions),
            "source": body.source,
            "ldap_dn": body.ldap_dn,
        },
    )
    group_id = str(result.fetchone().id)

    await log_action(
        db,
        actor=actor_display_name(token_info),
        action="create_group",
        target=body.name,
        detail={"permissions": body.permissions, "source": body.source},
        ip_address=get_client_ip(request),
    )
    await db.commit()

    return {"id": group_id, "name": body.name}


@router.put("/{group_id}")
async def update_group(
    group_id: str,
    body: GroupUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("admin", "w")),
):
    vault.require_unsealed()
    _validate_uuid(group_id)
    result = await db.execute(
        text("""
            UPDATE vault_groups
            SET permissions = CAST(:perms AS jsonb)
            WHERE id = CAST(:id AS uuid)
            RETURNING name
        """),
        {"id": group_id, "perms": json.dumps(body.permissions)},
    )
    row = result.fetchone()
    if not row:
        raise HTTPException(404, "Group not found")

    await log_action(
        db,
        actor=actor_display_name(token_info),
        action="update_group",
        target=row.name,
        detail={"permissions": body.permissions},
        ip_address=get_client_ip(request),
    )
    await db.commit()
    return {"status": "updated", "name": row.name}


@router.delete("/{group_id}")
async def delete_group(
    group_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("admin", "w")),
):
    vault.require_unsealed()
    _validate_uuid(group_id)
    result = await db.execute(
        text("DELETE FROM vault_groups WHERE id = CAST(:id AS uuid) RETURNING name"),
        {"id": group_id},
    )
    row = result.fetchone()
    if not row:
        raise HTTPException(404, "Group not found")

    await log_action(
        db,
        actor=actor_display_name(token_info),
        action="delete_group",
        target=row.name,
        ip_address=get_client_ip(request),
    )
    await db.commit()
    return {"status": "deleted", "name": row.name}


@router.get("/{group_id}/members")
async def list_members(
    group_id: str,
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("admin", "r")),
):
    vault.require_unsealed()
    _validate_uuid(group_id)
    result = await db.execute(
        text("""
            SELECT m.id, m.principal_type, m.external_id, m.token_id,
                   t.name AS token_name, m.added_at
            FROM vault_group_members AS m
            LEFT JOIN vault_tokens AS t ON t.id = m.token_id
            WHERE m.group_id = CAST(:id AS uuid)
            ORDER BY m.principal_type,
                     COALESCE(m.external_id, t.name, m.token_id::text)
        """),
        {"id": group_id},
    )
    return {
        "items": [
            {
                "member_id": str(r.id),
                "principal_type": r.principal_type,
                "principal_id": (
                    r.external_id if r.principal_type == "external" else str(r.token_id)
                ),
                "display_name": (
                    r.external_id.split(":", 1)[-1]
                    if r.principal_type == "external"
                    else r.token_name
                ),
                "added_at": r.added_at.isoformat(),
            }
            for r in result.fetchall()
        ]
    }


@router.post("/{group_id}/members", status_code=201)
async def add_member(
    group_id: str,
    body: MemberAdd,
    request: Request,
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("admin", "w")),
):
    vault.require_unsealed()
    _validate_uuid(group_id)
    # Verify group exists
    grp = await db.execute(
        text("SELECT name FROM vault_groups WHERE id = CAST(:id AS uuid)"),
        {"id": group_id},
    )
    if not grp.fetchone():
        raise HTTPException(404, "Group not found")

    if body.principal_type == "external":
        principal_id = body.principal_id
        if (
            not is_reserved_token_name(principal_id)
            or not principal_id.split(":", 1)[1]
        ):
            raise HTTPException(
                400,
                "External principal must be source-qualified "
                "('ldap:<subject>' or 'proxy:<subject>')",
            )
        display_name = principal_id.split(":", 1)[1]
        membership = await db.execute(
            text("""
                INSERT INTO vault_group_members
                    (group_id, principal_type, external_id)
                VALUES (CAST(:gid AS uuid), 'external', :principal)
                ON CONFLICT (group_id, external_id)
                    WHERE principal_type = 'external'
                DO UPDATE SET added_at = vault_group_members.added_at
                RETURNING id
            """),
            {"gid": group_id, "principal": principal_id},
        )
    else:
        _validate_uuid(body.principal_id)
        token = (
            await db.execute(
                text(
                    "SELECT id, name FROM vault_tokens "
                    "WHERE id = CAST(:id AS uuid) AND active "
                    "AND (expires_at IS NULL OR expires_at > NOW())"
                ),
                {"id": body.principal_id},
            )
        ).fetchone()
        if token is None:
            raise HTTPException(404, "Active, unexpired token principal not found")
        if is_reserved_token_name(token.name):
            raise HTTPException(
                400,
                "LDAP/login-provider sessions must be added as an "
                f"external principal using '{token.name}'",
            )
        principal_id = str(token.id)
        display_name = token.name
        membership = await db.execute(
            text("""
                INSERT INTO vault_group_members
                    (group_id, principal_type, token_id)
                VALUES (CAST(:gid AS uuid), 'token', CAST(:principal AS uuid))
                ON CONFLICT (group_id, token_id)
                    WHERE principal_type = 'token'
                DO UPDATE SET added_at = vault_group_members.added_at
                RETURNING id
            """),
            {"gid": group_id, "principal": principal_id},
        )
    member_id = str(membership.fetchone().id)

    await log_action(
        db,
        actor=actor_display_name(token_info),
        action="add_group_member",
        target=f"{body.principal_type}:{principal_id}",
        detail={
            "group_id": group_id,
            "member_id": member_id,
            "display_name": display_name,
        },
        ip_address=get_client_ip(request),
    )
    await db.commit()
    return {
        "status": "added",
        "member_id": member_id,
        "principal_type": body.principal_type,
        "principal_id": principal_id,
        "display_name": display_name,
    }


@router.delete("/{group_id}/members/{member_id}")
async def remove_member(
    group_id: str,
    member_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("admin", "w")),
):
    vault.require_unsealed()
    _validate_uuid(group_id)
    _validate_uuid(member_id)
    result = await db.execute(
        text("""
            DELETE FROM vault_group_members
            WHERE group_id = CAST(:gid AS uuid)
              AND id = CAST(:member_id AS uuid)
            RETURNING principal_type, external_id, token_id
        """),
        {"gid": group_id, "member_id": member_id},
    )
    member = result.fetchone()
    if not member:
        raise HTTPException(404, "Member not found in group")
    principal_id = (
        member.external_id
        if member.principal_type == "external"
        else str(member.token_id)
    )

    await log_action(
        db,
        actor=actor_display_name(token_info),
        action="remove_group_member",
        target=f"{member.principal_type}:{principal_id}",
        detail={"group_id": group_id, "member_id": member_id},
        ip_address=get_client_ip(request),
    )
    await db.commit()
    return {
        "status": "removed",
        "member_id": member_id,
        "principal_type": member.principal_type,
        "principal_id": principal_id,
    }
