# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Notification channels - Matrix, webhook, email alerts on vault events."""

import asyncio
import json
import logging
import smtplib
from email.message import EmailMessage

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ..audit import log_action
from ..auth import actor_display_name, require_permission
from ..client_ip import get_client_ip
from ..database import get_db
from ..vault_state import vault

log = logging.getLogger("rhorizon.notify")

router = APIRouter(prefix="/api/v1/vault/notifications", tags=["notifications"])


class ChannelCreate(BaseModel):
    name: str = Field(..., max_length=128)
    channel_type: str = Field(..., max_length=32)
    config: dict  # {homeserver, room_id, token} / {url} / {smtp_host...}
    events: list[str] = Field(default=[], max_length=50)
    enabled: bool = True


class ChannelUpdate(BaseModel):
    config: dict | None = None
    events: list[str] | None = None
    enabled: bool | None = None


# Valid event types, reference list. Not enforced server-side (any
# event name passes), but kept aligned with frontend/js/views/pulsar.js
# PULSAR_EVENTS so the UI checklist matches what actually fires.
EVENTS = {
    "honey_access",  # decoy token/secret accessed (CRITICAL)
    "unseal",
    "seal",
    "unseal_failed",
    "rate_limit_triggered",
    "master_password_rotated",
    "token_created",
    "token_revoked",
    "secret_created",
    "secret_updated",
    "secret_deleted",
    "shamir_init",
    "2fa_mode_changed",
    "ldap_login",
    "chain_broken",  # audit chain integrity violation
}


@router.get("/")
async def list_channels(
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("admin", "r")),
):
    vault.require_unsealed()
    result = await db.execute(
        text("""
            SELECT id, name, channel_type, config, events, enabled, created_at
            FROM vault_notification_channels ORDER BY name
        """)
    )
    items = []
    for r in result.fetchall():
        cfg = r.config if isinstance(r.config, dict) else {}
        # Mask sensitive fields
        sensitive = ("token", "password")
        safe_cfg = {k: ("********" if k in sensitive else v) for k, v in cfg.items()}
        items.append(
            {
                "id": str(r.id),
                "name": r.name,
                "channel_type": r.channel_type,
                "config": safe_cfg,
                "events": r.events if isinstance(r.events, list) else [],
                "enabled": r.enabled,
                "created_at": r.created_at.isoformat(),
            }
        )
    return {"items": items}


@router.post("/", status_code=201)
async def create_channel(
    body: ChannelCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("admin", "w")),
):
    vault.require_unsealed()

    if body.channel_type not in ("matrix", "webhook", "email"):
        raise HTTPException(400, "channel_type must be: matrix, webhook, email")

    result = await db.execute(
        text("""
            INSERT INTO vault_notification_channels
                (name, channel_type, config, events, enabled)
            VALUES
                (:name, :type, CAST(:config AS jsonb),
                 CAST(:events AS jsonb), :enabled)
            RETURNING id
        """),
        {
            "name": body.name,
            "type": body.channel_type,
            "config": json.dumps(body.config),
            "events": json.dumps(body.events),
            "enabled": body.enabled,
        },
    )
    channel_id = str(result.fetchone().id)

    await log_action(
        db,
        actor=actor_display_name(token_info),
        action="create_notification_channel",
        target=body.name,
        detail={"channel_type": body.channel_type},
        ip_address=get_client_ip(request),
    )
    await db.commit()

    return {"id": channel_id, "name": body.name}


@router.put("/{channel_id}")
async def update_channel(
    channel_id: str,
    body: ChannelUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("admin", "w")),
):
    vault.require_unsealed()
    params: dict = {"id": channel_id}
    has_config = body.config is not None
    has_events = body.events is not None
    has_enabled = body.enabled is not None

    if not (has_config or has_events or has_enabled):
        raise HTTPException(400, "No fields to update")

    if has_config:
        params["config"] = json.dumps(body.config)
    if has_events:
        params["events"] = json.dumps(body.events)
    if has_enabled:
        params["enabled"] = body.enabled

    # Static SQL branches, no dynamic column interpolation
    _QUERIES = {
        (True, True, True): (
            "UPDATE vault_notification_channels "
            "SET config = CAST(:config AS jsonb), "
            "events = CAST(:events AS jsonb), enabled = :enabled "
            "WHERE id = CAST(:id AS uuid) RETURNING name"
        ),
        (True, True, False): (
            "UPDATE vault_notification_channels "
            "SET config = CAST(:config AS jsonb), "
            "events = CAST(:events AS jsonb) "
            "WHERE id = CAST(:id AS uuid) RETURNING name"
        ),
        (True, False, True): (
            "UPDATE vault_notification_channels "
            "SET config = CAST(:config AS jsonb), enabled = :enabled "
            "WHERE id = CAST(:id AS uuid) RETURNING name"
        ),
        (True, False, False): (
            "UPDATE vault_notification_channels "
            "SET config = CAST(:config AS jsonb) "
            "WHERE id = CAST(:id AS uuid) RETURNING name"
        ),
        (False, True, True): (
            "UPDATE vault_notification_channels "
            "SET events = CAST(:events AS jsonb), enabled = :enabled "
            "WHERE id = CAST(:id AS uuid) RETURNING name"
        ),
        (False, True, False): (
            "UPDATE vault_notification_channels "
            "SET events = CAST(:events AS jsonb) "
            "WHERE id = CAST(:id AS uuid) RETURNING name"
        ),
        (False, False, True): (
            "UPDATE vault_notification_channels "
            "SET enabled = :enabled "
            "WHERE id = CAST(:id AS uuid) RETURNING name"
        ),
    }

    result = await db.execute(
        text(_QUERIES[(has_config, has_events, has_enabled)]),
        params,
    )
    row = result.fetchone()
    if not row:
        raise HTTPException(404, "Channel not found")

    await log_action(
        db,
        actor=actor_display_name(token_info),
        action="update_notification_channel",
        target=row.name,
        ip_address=get_client_ip(request),
    )
    await db.commit()
    return {"status": "updated", "name": row.name}


@router.delete("/{channel_id}")
async def delete_channel(
    channel_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("admin", "w")),
):
    vault.require_unsealed()
    result = await db.execute(
        text(
            "DELETE FROM vault_notification_channels "
            "WHERE id = CAST(:id AS uuid) RETURNING name"
        ),
        {"id": channel_id},
    )
    row = result.fetchone()
    if not row:
        raise HTTPException(404, "Channel not found")

    await log_action(
        db,
        actor=actor_display_name(token_info),
        action="delete_notification_channel",
        target=row.name,
        ip_address=get_client_ip(request),
    )
    await db.commit()
    return {"status": "deleted", "name": row.name}


@router.post("/{channel_id}/test")
async def test_channel(
    channel_id: str,
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("admin", "w")),
):
    """Send a test notification."""
    vault.require_unsealed()
    result = await db.execute(
        text(
            "SELECT name, channel_type, config "
            "FROM vault_notification_channels "
            "WHERE id = CAST(:id AS uuid)"
        ),
        {"id": channel_id},
    )
    row = result.fetchone()
    if not row:
        raise HTTPException(404, "Channel not found")

    cfg = row.config if isinstance(row.config, dict) else {}
    message = "rhorizon test notification"

    try:
        await _send_notification(row.channel_type, cfg, "test", message)
    except Exception as e:
        log.error("Notification test failed for %s: %s", row.name, e)
        raise HTTPException(502, "Notification delivery failed")

    return {"status": "sent", "channel": row.name}


async def dispatch_event(db: AsyncSession, event: str, message: str):
    """Send notification to all enabled channels subscribed to this event."""
    result = await db.execute(
        text(
            "SELECT channel_type, config, events FROM vault_notification_channels "
            "WHERE enabled = true"
        )
    )
    for row in result.fetchall():
        cfg = row.config if isinstance(row.config, dict) else {}
        # Subscription is the `events` COLUMN, not config. Empty = subscribe-all.
        events = row.events if isinstance(row.events, list) else []
        if events and event not in events:
            continue
        try:
            await _send_notification(row.channel_type, cfg, event, message)
        except Exception:
            log.warning("Notification failed for %s", row.channel_type, exc_info=True)


async def _send_notification(channel_type: str, config: dict, event: str, message: str):
    """Send a single notification."""
    if channel_type == "matrix":
        await _send_matrix(config, event, message)
    elif channel_type == "webhook":
        await _send_webhook(config, event, message)
    elif channel_type == "email":
        await _send_email(config, event, message)
    else:
        log.warning("Unknown channel type: %s", channel_type)


def _smtp_send_sync(
    host: str,
    port: int,
    use_ssl: bool,
    use_starttls: bool,
    user: str,
    password: str,
    msg: EmailMessage,
) -> None:
    if use_ssl:
        client = smtplib.SMTP_SSL(host, port, timeout=15)
    else:
        client = smtplib.SMTP(host, port, timeout=15)
    try:
        client.ehlo()
        if use_starttls and not use_ssl:
            client.starttls()
            client.ehlo()
        if user and password:
            client.login(user, password)
        client.send_message(msg)
    finally:
        try:
            client.quit()
        except Exception:
            client.close()


async def _send_email(config: dict, event: str, message: str):
    host = config.get("smtp_host", "")
    port = int(config.get("smtp_port", 587) or 587)
    use_ssl = bool(config.get("smtp_use_ssl", False))
    use_starttls = bool(config.get("smtp_use_starttls", True))
    user = config.get("smtp_user", "")
    password = config.get("smtp_password", "")
    sender = config.get("from", user or "rhorizon@localhost")
    recipients = config.get("to", [])
    if isinstance(recipients, str):
        recipients = [r.strip() for r in recipients.split(",") if r.strip()]

    if not host or not recipients:
        raise ValueError(
            "Email config requires: smtp_host and at least one 'to' address"
        )

    _guard_ssrf(host)  # reject an SMTP host that resolves to an internal target

    msg = EmailMessage()
    msg["Subject"] = f"[rhorizon] {event}"
    msg["From"] = sender
    msg["To"] = ", ".join(recipients)
    msg.set_content(message)

    await asyncio.to_thread(
        _smtp_send_sync,
        host,
        port,
        use_ssl,
        use_starttls,
        user,
        password,
        msg,
    )


async def _send_matrix(config: dict, event: str, message: str):
    homeserver = config.get("homeserver", "")
    room_id = config.get("room_id", "")
    token = config.get("token", "")

    if not all([homeserver, room_id, token]):
        raise ValueError("Matrix config requires: homeserver, room_id, token")

    from urllib.parse import urlparse

    # SSRF guard: the vault makes the request, so reject internal/metadata hosts.
    _guard_ssrf(urlparse(homeserver).hostname or homeserver)

    url = f"{homeserver}/_matrix/client/r0/rooms/{room_id}/send/m.room.message"
    async with httpx.AsyncClient() as client:
        r = await client.put(
            f"{url}/{event}_{id(message)}",
            json={
                "msgtype": "m.text",
                "body": f"[rhorizon] {event}: {message}",
            },
            headers={"Authorization": f"Bearer {token}"},
            timeout=10,
        )
        r.raise_for_status()


_CLOUD_METADATA_HOSTS = frozenset(
    {
        # AWS / Alibaba / GCP / Hetzner / DigitalOcean / OpenStack / Oracle
        "169.254.169.254",
        "fd00:ec2::254",
        # Google
        "metadata.google.internal",
        "metadata",
        # Azure (IMDS)
        "169.254.169.254",
        # Alibaba
        "100.100.100.200",
    }
)
_HEADERS_DENYLIST = frozenset(
    h.lower()
    for h in (
        # hop-by-hop / proxy smuggling
        "host",
        "transfer-encoding",
        "te",
        "trailer",
        "upgrade",
        "connection",
        "proxy-authenticate",
        "proxy-authorization",
        # session smuggling
        "cookie",
        "set-cookie",
        # IP spoofing
        "x-forwarded-for",
        "x-forwarded-host",
        "x-forwarded-proto",
        "x-real-ip",
        "forwarded",
    )
)


def _is_disallowed_host(hostname: str) -> tuple[bool, str]:
    """Return (blocked, reason) - resolve hostname and reject any IP that is
    loopback/private/link-local/multicast/reserved, plus literal cloud
    metadata hostnames. Catches SSRF tricks like `127.1`, `2130706433`
    (decimal), `[::ffff:127.0.0.1]`, `metadata.google.internal`.

    Validation-time only: the HTTP/SMTP client re-resolves at connect time, so a
    DNS-rebinding attacker is NOT fully blocked (would need connect-IP pinning --
    backlog). Solid against static internal/metadata targets.
    """
    import ipaddress
    import socket

    if not hostname:
        return True, "empty hostname"
    if hostname.lower() in _CLOUD_METADATA_HOSTS:
        return True, f"cloud metadata host: {hostname}"
    try:
        infos = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        # Hostname doesn't resolve, let httpx fail at request time. We
        # do not have an internal IP to leak data to ; an unresolvable
        # name is not an SSRF surface, just a misconfiguration. The
        # subsequent http call will raise a connection error.
        return False, ""
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if (
            ip.is_loopback
            or ip.is_private
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            return True, f"private/internal IP: {ip} (hostname={hostname})"
    return False, ""


def _guard_ssrf(hostname: str) -> None:
    """Raise ValueError if `hostname` resolves to an internal/metadata target.
    Applied uniformly to every outbound destination (webhook/Matrix/SMTP)."""
    blocked, reason = _is_disallowed_host(hostname)
    if blocked:
        log.warning("Outbound SSRF blocked: host=%s - %s", hostname, reason)
        raise ValueError(f"Destination rejected (SSRF mitigation): {reason}")


async def _send_webhook(config: dict, event: str, message: str):
    url = config.get("url", "")
    if not url:
        raise ValueError("Webhook config requires: url")

    from urllib.parse import urlparse

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Webhook URL must be http(s): {parsed.scheme}")

    _guard_ssrf(parsed.hostname or "")
    log.info("Sending webhook to %s for event %s", parsed.hostname, event)
    raw_headers = config.get("headers", {}) or {}
    # Drop hop-by-hop, session, and IP-spoofing headers, admin caller
    # cannot smuggle Cookie/X-Forwarded-* into outbound requests.
    headers = {
        k: v for k, v in raw_headers.items() if k.lower() not in _HEADERS_DENYLIST
    }
    async with httpx.AsyncClient() as client:
        r = await client.post(
            url,
            json={"event": event, "message": message, "source": "rhorizon"},
            headers=headers,
            timeout=10,
        )
        r.raise_for_status()
