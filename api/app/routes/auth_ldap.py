# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""LDAP / Active Directory authentication.

Flow:
  1. User sends username + password to POST /api/v1/vault/auth/ldap
  2. rhorizon binds to LDAP with the user's credentials (verify password)
  3. Searches for the user's groups
  4. Maps groups -> rhorizon permissions via configurable mapping
  5. Creates a session token (short-lived, stored in DB)

Uses bonsai (native async LDAP client, C extension).
Supports: Active Directory, OpenLDAP, FreeIPA, Authentik LDAP.
"""

import json
import logging
import re
import uuid as _uuid
from datetime import datetime, timedelta, timezone

import bonsai
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, SecretStr
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ..audit import log_action
from ..auth import actor_display_name, require_permission
from ..client_ip import get_client_ip
from ..crypto import (
    decrypt_secret,
    dek_aad,
    encrypt_secret,
    generate_dek,
    generate_token,
)
from ..database import get_db
from ..key_epoch import require_generation_current
from ..vault_state import vault

log = logging.getLogger("rhorizon.ldap")

router = APIRouter(prefix="/api/v1/vault/auth", tags=["auth"])

_SESSION_TTL_HOURS = 8

_BUILTIN_MAPPINGS = {
    "vault-admins": {"admin": "rw"},
    "vault-ops": {"secrets": "rw", "audit": "r", "tokens": "r"},
    "vault-readers": {"secrets": "r"},
}

# LDAP special chars that must be escaped in filters (RFC 4515)
_LDAP_ESCAPE_RE = re.compile(r"[\\*\(\)\x00]")


def _ldap_escape(value: str) -> str:
    """Escape LDAP filter special characters (RFC 4515 sect. 3)."""
    return _LDAP_ESCAPE_RE.sub(lambda m: "\\%02x" % ord(m.group(0)), value)


def _build_group_filter(template: str, user_dn: str) -> str:
    """Substitute the (escaped) user DN into the group-search filter template.
    The DN is RFC-4515-escaped like the username -- a DN carrying filter
    metacharacters would otherwise inject into the group query."""
    return template.replace("{user_dn}", _ldap_escape(user_dn))


class LdapLoginRequest(BaseModel):
    username: str = Field(..., max_length=256)
    password: SecretStr = Field(..., max_length=8192)


class LdapConfigUpdate(BaseModel):
    url: str = Field(..., max_length=512)
    bind_dn: str = Field(..., max_length=512)
    bind_password: SecretStr
    user_base: str = Field(..., max_length=512)
    user_filter: str = Field(default="(sAMAccountName={username})", max_length=512)
    group_base: str = Field(..., max_length=512)
    group_filter: str = Field(default="(member={user_dn})", max_length=512)
    group_attr: str = Field(default="cn", max_length=64)
    tls_verify: bool = True
    session_ttl_hours: int = 8


async def _get_ldap_config(db: AsyncSession) -> dict | None:
    result = await db.execute(
        text("SELECT value FROM vault_config WHERE key = 'ldap_config'")
    )
    row = result.fetchone()
    if not row:
        return None
    cfg = json.loads(row.value)

    # Decrypt bind password if encrypted (AAD bound to row identity)
    if "bind_password_dek_id" in cfg:
        dek_result = await db.execute(
            text("""
                SELECT encrypted_key, nonce
                FROM vault_dek WHERE id = CAST(:id AS uuid)
            """),
            {"id": cfg["bind_password_dek_id"]},
        )
        dek_row = dek_result.fetchone()
        if dek_row:
            dek = await vault.aesgcm_decrypt(
                bytes(dek_row.encrypted_key),
                bytes(dek_row.nonce),
                dek_aad(cfg["bind_password_dek_id"]),
            )
            cfg["bind_password"] = decrypt_secret(
                bytes.fromhex(cfg["bind_password_ct"]),
                bytes.fromhex(cfg["bind_password_nonce"]),
                dek,
                b"ldap:bind_password",
            ).decode()

    return cfg


async def _get_group_mappings(db: AsyncSession) -> dict:
    result = await db.execute(
        text("SELECT value FROM vault_config WHERE key = 'ldap_group_mappings'")
    )
    row = result.fetchone()
    if row:
        return json.loads(row.value)
    return _BUILTIN_MAPPINGS


async def _ldap_authenticate(
    config: dict, username: str, password: str
) -> tuple[str, list[str]]:
    """Bind to LDAP, verify credentials, return (user_dn, groups)."""
    client = bonsai.LDAPClient(config["url"])
    client.set_credentials(
        "SIMPLE",
        user=config["bind_dn"],
        password=config["bind_password"],
    )
    if not config.get("tls_verify", True):
        client.set_cert_policy("allow")
        log.warning("LDAP TLS verification disabled")

    # Escape username to prevent LDAP injection (RFC 4515)
    safe_username = _ldap_escape(username)

    # Step 1: service account bind -> find user DN
    try:
        async with client.connect(is_async=True) as conn:
            user_filter = config["user_filter"].replace("{username}", safe_username)
            results = await conn.search(
                config["user_base"],
                bonsai.LDAPSearchScope.SUB,
                user_filter,
            )
            if not results:
                raise HTTPException(401, "Invalid credentials")
            user_dn = str(results[0].dn)
    except bonsai.AuthenticationError:
        raise HTTPException(401, "LDAP bind failed (bad service account)")
    except bonsai.LDAPError as e:
        log.error("LDAP connection error: %s", e)
        raise HTTPException(502, "LDAP server unreachable")

    # Step 2: bind as user -> verify password + get groups
    user_client = bonsai.LDAPClient(config["url"])
    user_client.set_credentials("SIMPLE", user=user_dn, password=password)
    if not config.get("tls_verify", True):
        user_client.set_cert_policy("allow")

    try:
        async with user_client.connect(is_async=True) as user_conn:
            group_filter = _build_group_filter(
                config.get("group_filter", "(member={user_dn})"), user_dn
            )
            group_attr = config.get("group_attr", "cn")
            group_results = await user_conn.search(
                config["group_base"],
                bonsai.LDAPSearchScope.SUB,
                group_filter,
            )
            groups = []
            for entry in group_results:
                if group_attr in entry:
                    val = entry[group_attr]
                    groups.append(val[0] if isinstance(val, list) else str(val))
    except bonsai.AuthenticationError:
        raise HTTPException(401, "Invalid credentials")
    except bonsai.LDAPError as e:
        log.error("LDAP error during user bind: %s", e)
        raise HTTPException(502, "LDAP error")

    return user_dn, groups


def _resolve_permissions(groups: list[str], mappings: dict) -> dict:
    """Merge permissions from all matching groups."""
    merged: dict = {}
    for group in groups:
        perms = mappings.get(group, {})
        for scope, mode in perms.items():
            if scope == "namespaces":
                existing = merged.get("namespaces", [])
                merged["namespaces"] = list(set(existing + mode))
            elif scope not in merged or mode == "rw":
                merged[scope] = mode
    return merged


@router.post("/ldap")
async def ldap_login(
    body: LdapLoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Authenticate via LDAP and receive a session token."""
    vault.require_unsealed()

    # Rate limiting (shared DB-backed counter per IP)
    client_ip = get_client_ip(request)
    from ..authfail import log_authfail
    from ..rate_limit import check_rate_limit, clear_failures, record_failure

    await check_rate_limit(db, client_ip)

    config = await _get_ldap_config(db)
    if not config:
        raise HTTPException(501, "LDAP not configured")

    try:
        user_dn, groups = await _ldap_authenticate(
            config, body.username, body.password.get_secret_value()
        )
    except HTTPException as e:
        if e.status_code == 401:
            await record_failure(db, client_ip)
            log_authfail(client_ip, "ldap_invalid_credentials")
        raise
    await clear_failures(db, client_ip)
    log.info("LDAP auth OK: %s (groups: %s)", body.username, groups)

    mappings = await _get_group_mappings(db)
    permissions = _resolve_permissions(groups, mappings)

    if not permissions:
        raise HTTPException(
            403,
            "User has no matching group mappings",
        )

    raw_token = generate_token()
    token_hash = await vault.hmac_sha512_hex(raw_token)
    ttl = config.get("session_ttl_hours", _SESSION_TTL_HOURS)
    expires_at = datetime.now(timezone.utc) + timedelta(hours=ttl)

    # Upsert: replace existing session token for this user
    await db.execute(
        text("""
            INSERT INTO vault_tokens
                (name, token_hash, permissions, created_by, expires_at)
            VALUES
                (:name, :hash, CAST(:perms AS jsonb), :actor, :expires)
            ON CONFLICT (name) WHERE active DO UPDATE SET
                token_hash = :hash,
                permissions = CAST(:perms AS jsonb),
                expires_at = :expires,
                active = true,
                last_used_at = NULL
        """),
        {
            "name": f"ldap:{body.username}",
            "hash": token_hash,
            "perms": json.dumps(permissions),
            # `actor` here is the SQL bind for `created_by`, record the
            # actual LDAP user, not the literal "ldap". The auth source
            # is already encoded in the `name` prefix.
            "actor": body.username,
            "expires": expires_at,
        },
    )

    await log_action(
        db,
        actor=body.username,
        action="ldap_login",
        detail={
            "user_dn": user_dn,
            "groups": groups,
            "permissions": permissions,
            "ttl_hours": ttl,
        },
        ip_address=get_client_ip(request),
    )
    await db.commit()

    return {
        "token": raw_token,
        "username": body.username,
        "groups": groups,
        "permissions": permissions,
        "expires_at": expires_at.isoformat(),
    }


@router.post("/ldap/config")
async def configure_ldap(
    body: LdapConfigUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("admin", "w")),
):
    """Configure LDAP connection (admin only). Bind password encrypted."""
    vault.require_unsealed()

    # Encrypt bind password with a DEK (AAD bound to row identity)
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

    ct, nonce = encrypt_secret(
        body.bind_password.get_secret_value().encode(),
        dek,
        b"ldap:bind_password",
    )

    config = body.model_dump(exclude={"bind_password"})
    config["bind_password_ct"] = ct.hex()
    config["bind_password_nonce"] = nonce.hex()
    config["bind_password_dek_id"] = dek_id

    await db.execute(
        text(
            "INSERT INTO vault_config (key, value) "
            "VALUES ('ldap_config', :val) "
            "ON CONFLICT (key) DO UPDATE SET value = :val"
        ),
        {"val": json.dumps(config)},
    )

    await log_action(
        db,
        actor=actor_display_name(token_info),
        action="ldap_configure",
        detail={"url": body.url, "user_base": body.user_base},
        ip_address=get_client_ip(request),
    )
    await db.commit()

    return {"status": "configured", "url": body.url}


@router.get("/ldap/config")
async def get_ldap_config(
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("admin", "r")),
):
    """Get LDAP configuration (bind password never exposed)."""
    vault.require_unsealed()
    config = await _get_ldap_config(db)
    if not config:
        return {"configured": False}

    # Never expose bind password or encrypted material
    safe = {}
    for k, v in config.items():
        if k.startswith("bind_password"):
            continue
        safe[k] = v
    safe["bind_password"] = "********"
    return {"configured": True, **safe}


@router.put("/ldap/mappings")
async def update_group_mappings(
    mappings: dict,
    request: Request,
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("admin", "w")),
):
    """Update LDAP group -> permission mappings."""
    vault.require_unsealed()
    await db.execute(
        text(
            "INSERT INTO vault_config (key, value) "
            "VALUES ('ldap_group_mappings', :val) "
            "ON CONFLICT (key) DO UPDATE SET value = :val"
        ),
        {"val": json.dumps(mappings)},
    )

    await log_action(
        db,
        actor=actor_display_name(token_info),
        action="ldap_update_mappings",
        detail={"groups": list(mappings.keys())},
        ip_address=get_client_ip(request),
    )
    await db.commit()

    return {"status": "updated", "groups": list(mappings.keys())}


@router.get("/ldap/mappings")
async def get_group_mappings(
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("admin", "r")),
):
    """Get current group -> permission mappings."""
    vault.require_unsealed()
    return {"mappings": await _get_group_mappings(db)}
