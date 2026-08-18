# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""SSO reverse proxy authentication (Authelia / Authentik / Keycloak).

When a trusted reverse proxy authenticates a user, it forwards identity
headers to the backend:

  Remote-User: jdoe
  Remote-Groups: vault-admins,vault-ops

This module reads those headers, validates the request comes from a
trusted proxy IP, maps groups to rhorizon permissions, and issues a
session token.

Configuration is **DB-backed** (vault_config key = 'proxy_config'),
overriding the `RHORIZON_PROXY_*` env defaults at runtime. Operators
can edit the config via the UI / API. A trusted-IP change requires a
coordinated API restart so every worker changes its XFF trust boundary
at the same time. The env values bootstrap fresh installs.
"""

import ipaddress
import json
import logging
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator, model_validator
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ..audit import log_action
from ..auth import actor_display_name, require_permission
from ..client_ip import get_identity_trusted_proxies
from ..config import settings
from ..crypto import generate_token
from ..database import get_db
from ..vault_state import vault

log = logging.getLogger("rhorizon.proxy_auth")

router = APIRouter(prefix="/api/v1/vault/auth", tags=["auth"])


# ---------------------------------------------------------------------------
# Effective configuration, DB takes precedence over env vars
# ---------------------------------------------------------------------------


async def _get_proxy_config(db: AsyncSession) -> dict:
    """Return the effective proxy auth config.

    DB-stored values (vault_config key='proxy_config') override the env
    defaults. The env values seed a fresh install. Operators edit the DB
    config via POST /proxy/config.
    """
    row = await db.execute(
        text("SELECT value FROM vault_config WHERE key = 'proxy_config'")
    )
    r = row.fetchone()
    db_cfg = json.loads(r.value) if r else {}
    return {
        "enabled": db_cfg.get("enabled", settings.proxy_auth_enabled),
        "user_header": db_cfg.get("user_header", settings.proxy_user_header),
        "groups_header": db_cfg.get("groups_header", settings.proxy_groups_header),
        "trusted_ips": db_cfg.get("trusted_ips", settings.proxy_trusted_ips),
        "session_ttl_hours": db_cfg.get(
            "session_ttl_hours", settings.proxy_session_ttl_hours
        ),
    }


def _parse_trusted_networks(
    trusted_ips: str | None = None,
) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """Parse a comma-separated list of CIDR / IP entries into networks.

    If `trusted_ips` is None, falls back to `settings.proxy_trusted_ips`
    (the env-var default). Tests monkeypatching the env can keep using
    the no-arg form; runtime callers pass the DB-resolved value.
    """
    raw = trusted_ips if trusted_ips is not None else settings.proxy_trusted_ips
    raw = (raw or "").strip()
    if not raw:
        return []
    nets = []
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry:
            continue
        try:
            nets.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            log.warning("Invalid trusted proxy IP/network: %s", entry)
    return nets


def _is_trusted(client_ip: str, trusted_ips: str | None = None) -> bool:
    """Check if client IP is in the trusted proxy list.

    If `trusted_ips` is None, falls back to `settings.proxy_trusted_ips`.
    """
    networks = _parse_trusted_networks(trusted_ips)
    if not networks:
        return False
    try:
        addr = ipaddress.ip_address(client_ip)
    except ValueError:
        return False
    return any(addr in net for net in networks)


# ---------------------------------------------------------------------------
# Mappings: proxy-specific (separate from LDAP)
# ---------------------------------------------------------------------------


async def _get_proxy_mappings(db: AsyncSession) -> dict:
    """Return the proxy group -> permissions mappings.

    Resolution order:
      1. `proxy_group_mappings` - explicit proxy-specific mappings
      2. `ldap_group_mappings` - same shape, single-identity-source case
      3. `_BUILTIN_MAPPINGS` from auth_ldap (vault-admins / vault-ops /
         vault-readers default mappings) - convenient for testing and
         small deployments.

    Operators who want strict separation between LDAP and proxy
    identities should configure (1) explicitly.
    """
    from .auth_ldap import _BUILTIN_MAPPINGS

    r = await db.execute(
        text("SELECT value FROM vault_config WHERE key = 'proxy_group_mappings'")
    )
    row = r.fetchone()
    if row:
        return json.loads(row.value)
    r = await db.execute(
        text("SELECT value FROM vault_config WHERE key = 'ldap_group_mappings'")
    )
    row = r.fetchone()
    if row:
        return json.loads(row.value)
    return _BUILTIN_MAPPINGS


def _merge_permissions(groups: list[str], mappings: dict) -> dict:
    """Combine the permissions of every matching group into one perms dict.

    For each scope (secrets/tokens/audit/admin), keep the strongest mode
    (`rw` > `r`). Namespaces are unioned.
    """
    out: dict = {}
    ns_set: set[str] = set()
    has_ns_restriction = False
    for g in groups:
        perms = mappings.get(g)
        if not perms:
            continue
        for k, v in perms.items():
            if k == "namespaces":
                has_ns_restriction = True
                if isinstance(v, list):
                    ns_set.update(v)
                continue
            cur = out.get(k)
            if cur == "rw":
                continue
            out[k] = v if (v == "rw" or cur is None) else cur
    if has_ns_restriction and ns_set:
        out["namespaces"] = sorted(ns_set)
    return out


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class ProxyAuthConfigUpdate(BaseModel):
    enabled: bool = True
    user_header: str = Field(default="Remote-User", max_length=128)
    groups_header: str = Field(default="Remote-Groups", max_length=128)
    trusted_ips: str = Field(default="", max_length=2048)
    session_ttl_hours: int = Field(default=8, ge=1, le=168)

    @field_validator("trusted_ips")
    @classmethod
    def validate_trusted_ips(cls, value: str) -> str:
        for entry in value.split(","):
            entry = entry.strip()
            if not entry:
                continue
            try:
                ipaddress.ip_network(entry, strict=False)
            except ValueError as exc:
                raise ValueError(f"invalid trusted proxy IP/network: {entry}") from exc
        return value

    @model_validator(mode="after")
    def require_trusted_ips_when_enabled(self) -> "ProxyAuthConfigUpdate":
        if self.enabled and not self.trusted_ips.strip():
            raise ValueError("trusted_ips is required when proxy auth is enabled")
        return self


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post("/proxy")
async def proxy_login(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Authenticate via trusted reverse proxy headers."""
    vault.require_unsealed()

    cfg = await _get_proxy_config(db)
    if not cfg["enabled"]:
        raise HTTPException(501, "Proxy authentication not enabled")

    client_ip = request.client.host if request.client else "unknown"

    if not _is_trusted(client_ip, cfg["trusted_ips"]):
        log.warning("Proxy auth rejected - untrusted IP: %s", client_ip)
        from ..authfail import log_authfail

        log_authfail(client_ip, "proxy_untrusted_ip")
        raise HTTPException(403, "Request not from a trusted proxy")

    username = request.headers.get(cfg["user_header"])
    if not username or not username.strip():
        raise HTTPException(400, f"Missing header: {cfg['user_header']}")
    username = username.strip()[:256]

    # Parse groups (comma or space separated)
    groups_raw = request.headers.get(cfg["groups_header"], "")
    groups = [g.strip() for g in groups_raw.replace(",", " ").split() if g.strip()]

    mappings = await _get_proxy_mappings(db)
    permissions = _merge_permissions(groups, mappings)

    if not permissions:
        log.info("Proxy auth: %s has no matching groups (%s)", username, groups)
        raise HTTPException(403, "No matching group mappings for this user")

    raw_token = generate_token()
    token_hash = await vault.hmac_sha512_hex(raw_token)
    ttl = cfg["session_ttl_hours"]
    expires_at = datetime.now(timezone.utc) + timedelta(hours=ttl)

    # Upsert: one active session per proxy user
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
            "name": f"proxy:{username}",
            "hash": token_hash,
            "perms": json.dumps(permissions),
            # `actor` here is the SQL bind for `created_by`, record the
            # actual SSO user, not the literal string "proxy". The auth
            # source is already encoded in the `name` prefix.
            "actor": username,
            "expires": expires_at,
        },
    )

    await log_action(
        db,
        actor=username,
        action="proxy_login",
        detail={
            "groups": groups,
            "permissions": permissions,
            "proxy_ip": client_ip,
            "ttl_hours": ttl,
        },
        ip_address=client_ip,
    )
    await db.commit()

    log.info("Proxy auth OK: %s (groups: %s, perms: %s)", username, groups, permissions)

    return {
        "token": raw_token,
        "username": username,
        "groups": groups,
        "permissions": permissions,
        "expires_at": expires_at.isoformat(),
    }


@router.get("/proxy/config")
async def get_proxy_config(
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("admin", "r")),
):
    """Get the effective proxy auth configuration (admin:r).

    Returns the merged DB+env config along with the env defaults so the
    UI can show "currently effective" vs "env fallback".
    """
    cfg = await _get_proxy_config(db)
    return {
        **cfg,
        "env_defaults": {
            "enabled": settings.proxy_auth_enabled,
            "user_header": settings.proxy_user_header,
            "groups_header": settings.proxy_groups_header,
            "trusted_ips": settings.proxy_trusted_ips,
            "session_ttl_hours": settings.proxy_session_ttl_hours,
        },
    }


@router.post("/proxy/config")
async def set_proxy_config(
    body: ProxyAuthConfigUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("admin", "w")),
):
    """Write proxy auth config to the DB (admin:w).

    Authentication settings take effect on the next login request.
    A trusted-IP change requires a coordinated API restart before the
    X-Forwarded-For resolver uses it in every worker.
    """
    vault.require_unsealed()

    cfg = body.model_dump()
    requested_proxies = _parse_trusted_networks(cfg["trusted_ips"])
    restart_required = requested_proxies != get_identity_trusted_proxies()
    await db.execute(
        text(
            "INSERT INTO vault_config (key, value) "
            "VALUES ('proxy_config', :v) "
            "ON CONFLICT (key) DO UPDATE SET value = :v"
        ),
        {"v": json.dumps(cfg)},
    )
    client_ip = request.client.host if request.client else "unknown"
    await log_action(
        db,
        actor=actor_display_name(token_info),
        action="proxy_configure",
        detail={
            "enabled": cfg["enabled"],
            "trusted_ips": cfg["trusted_ips"],
            "session_ttl_hours": cfg["session_ttl_hours"],
            "restart_required": restart_required,
        },
        ip_address=client_ip,
    )
    await db.commit()
    return {
        "status": "configured",
        "restart_required": restart_required,
        **cfg,
    }


@router.get("/proxy/mappings")
async def get_proxy_mappings(
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("admin", "r")),
):
    """Get current proxy-group -> permissions mappings."""
    vault.require_unsealed()
    return {"mappings": await _get_proxy_mappings(db)}


@router.put("/proxy/mappings")
async def update_proxy_mappings(
    mappings: dict,
    request: Request,
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("admin", "w")),
):
    """Replace the entire proxy group -> permissions mapping table."""
    vault.require_unsealed()
    await db.execute(
        text(
            "INSERT INTO vault_config (key, value) "
            "VALUES ('proxy_group_mappings', :v) "
            "ON CONFLICT (key) DO UPDATE SET value = :v"
        ),
        {"v": json.dumps(mappings)},
    )
    client_ip = request.client.host if request.client else "unknown"
    await log_action(
        db,
        actor=actor_display_name(token_info),
        action="proxy_update_mappings",
        detail={"groups": list(mappings.keys())},
        ip_address=client_ip,
    )
    await db.commit()
    return {"status": "updated", "groups": list(mappings.keys())}
