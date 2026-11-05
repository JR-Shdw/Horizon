# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Notification channels - Matrix, webhook, email alerts on vault events."""

import asyncio
import contextlib
import dataclasses
import errno
import ipaddress
import json
import logging
import smtplib
import socket
import ssl
import uuid
from email.message import EmailMessage
from urllib.parse import urlparse

import httpcore
import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ..audit import log_action
from ..auth import actor_display_name, require_permission
from ..client_ip import get_client_ip
from ..config import parse_notify_internal_allow, settings
from ..crypto import decrypt_secret, dek_aad, encrypt_secret, generate_dek
from ..database import get_db
from ..key_epoch import is_generation_current, require_generation_current
from ..metrics import notification_failures, notification_undelivered
from ..vault_state import vault

log = logging.getLogger("rhorizon.notify")

router = APIRouter(prefix="/api/v1/vault/notifications", tags=["notifications"])

_MAX_ERROR_LENGTH = 500
_MASK = "********"
# A webhook URL can itself be a credential, so it is stored like one.
_SECRET_FIELDS = ("token", "password", "smtp_password", "url", "headers")
# Delivered to every enabled channel, whatever it subscribed to.
_ALWAYS_DELIVERED = frozenset({"critical", "chain_broken"})
_CHANNEL_COLUMNS = (
    "id, name, channel_type, config, events, consecutive_failures, "
    "secrets_ct, secrets_nonce, dek_id"
)


class DestinationRejected(ValueError):
    """The destination is internal, a metadata host, or missing."""


class DestinationUnresolved(ValueError):
    """The destination name does not resolve from the vault."""


class ChannelUnreadable(ValueError):
    """The channel's stored credentials cannot be decrypted."""


def _secret_aad(channel_id: str) -> bytes:
    return f"notification:{channel_id}".encode()


async def _store_secrets(
    db: AsyncSession, channel_id: str, config: dict
) -> tuple[dict, bytes | None, bytes | None, str | None]:
    """Return the public config and the encrypted remainder.

    Same envelope as a secret: a fresh DEK in vault_dek, so key rotation
    re-wraps it, with the AAD bound to the channel row.
    """
    public = {k: v for k, v in config.items() if k not in _SECRET_FIELDS}
    secrets = {k: v for k, v in config.items() if k in _SECRET_FIELDS}
    if not secrets:
        return public, None, None, None
    dek = generate_dek()
    dek_id = str(uuid.uuid4())
    encrypted_dek, dek_nonce = await vault.aesgcm_encrypt(dek, dek_aad(dek_id))
    await db.execute(
        text(
            "INSERT INTO vault_dek (id, encrypted_key, nonce) "
            "VALUES (CAST(:id AS uuid), :ekey, :nonce)"
        ),
        {"id": dek_id, "ekey": encrypted_dek, "nonce": dek_nonce},
    )
    ciphertext, nonce = encrypt_secret(
        json.dumps(secrets).encode(), dek, _secret_aad(channel_id)
    )
    return public, ciphertext, nonce, dek_id


async def _load_config(db: AsyncSession, row) -> dict:
    """Return the full config. A sealed vault can only read secret-free rows."""
    config = row.config if isinstance(row.config, dict) else {}
    if row.secrets_ct is None:
        return config
    try:
        dek_row = (
            await db.execute(
                text(
                    "SELECT encrypted_key, nonce FROM vault_dek "
                    "WHERE id = CAST(:id AS uuid)"
                ),
                {"id": str(row.dek_id)},
            )
        ).fetchone()
        dek = await vault.aesgcm_decrypt(
            bytes(dek_row.encrypted_key),
            bytes(dek_row.nonce),
            dek_aad(str(row.dek_id)),
        )
        plaintext = decrypt_secret(
            bytes(row.secrets_ct),
            bytes(row.secrets_nonce),
            dek,
            _secret_aad(str(row.id)),
        )
    except Exception as exc:
        raise ChannelUnreadable(
            "Stored credentials cannot be decrypted: reconfigure this channel"
        ) from exc
    return {**config, **json.loads(plaintext)}


async def _delete_dek(db: AsyncSession, dek_id) -> None:
    if dek_id:
        await db.execute(
            text("DELETE FROM vault_dek WHERE id = CAST(:id AS uuid)"),
            {"id": str(dek_id)},
        )


async def encrypt_plaintext_channels(db: AsyncSession) -> None:
    """Move credentials of channels written before encryption out of `config`.

    Runs with notification dispatch, which every unseal triggers. Best effort:
    a standby cannot write, and the next dispatch tries again.
    """
    if vault.sealed:
        return
    try:
        result = await db.execute(
            text(
                "SELECT id, config FROM vault_notification_channels "
                "WHERE config ?| CAST(:fields AS text[]) "
                "FOR UPDATE SKIP LOCKED"
            ),
            {"fields": list(_SECRET_FIELDS)},
        )
        rows = result.fetchall()
        if rows and await is_generation_current(db, vault):
            for row in rows:
                public, ct, nonce, dek_id = await _store_secrets(
                    db, str(row.id), row.config
                )
                await db.execute(
                    text(
                        "UPDATE vault_notification_channels "
                        "SET config = CAST(:config AS jsonb), secrets_ct = :ct, "
                        "secrets_nonce = :nonce, dek_id = CAST(:dek_id AS uuid) "
                        "WHERE id = CAST(:id AS uuid)"
                    ),
                    {
                        "id": str(row.id),
                        "config": json.dumps(public),
                        "ct": ct,
                        "nonce": nonce,
                        "dek_id": dek_id,
                    },
                )
            log.info("Encrypted the credentials of %d channels", len(rows))
        await db.commit()
    except Exception as exc:
        with contextlib.suppress(Exception):
            await db.rollback()
        log.warning("Channel credentials not encrypted: %s", type(exc).__name__)


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
    "notification_channel_failed",  # sent to every other enabled channel
    "critical",  # always delivered, see _ALWAYS_DELIVERED
}


def _iso(value) -> str | None:
    return value.isoformat() if value else None


def _channel_status(row) -> str:
    if row.consecutive_failures:
        return "failing"
    return "ok" if row.last_success_at else "untested"


@router.get("/")
async def list_channels(
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("admin", "r")),
):
    vault.require_unsealed()
    result = await db.execute(
        text("""
            SELECT id, name, channel_type, config, events, enabled, created_at,
                   secrets_ct IS NOT NULL AS has_secrets,
                   last_success_at, last_failure_at, last_error,
                   consecutive_failures
            FROM vault_notification_channels ORDER BY name
        """)
    )
    items = []
    for r in result.fetchall():
        cfg = r.config if isinstance(r.config, dict) else {}
        # Rows not yet encrypted still hold secrets here.
        safe_cfg = {k: _MASK if k in _SECRET_FIELDS else v for k, v in cfg.items()}
        items.append(
            {
                "id": str(r.id),
                "name": r.name,
                "channel_type": r.channel_type,
                "config": safe_cfg,
                "has_secrets": r.has_secrets,
                "events": r.events if isinstance(r.events, list) else [],
                "enabled": r.enabled,
                "created_at": r.created_at.isoformat(),
                "status": _channel_status(r),
                "last_success_at": _iso(r.last_success_at),
                "last_failure_at": _iso(r.last_failure_at),
                "last_error": r.last_error,
                "consecutive_failures": r.consecutive_failures,
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

    await require_generation_current(db, vault)
    channel_id = str(uuid.uuid4())
    public, ciphertext, nonce, dek_id = await _store_secrets(
        db, channel_id, body.config
    )
    await db.execute(
        text("""
            INSERT INTO vault_notification_channels
                (id, name, channel_type, config, events, enabled,
                 secrets_ct, secrets_nonce, dek_id)
            VALUES
                (CAST(:id AS uuid), :name, :type, CAST(:config AS jsonb),
                 CAST(:events AS jsonb), :enabled, :ct, :nonce,
                 CAST(:dek_id AS uuid))
        """),
        {
            "id": channel_id,
            "name": body.name,
            "type": body.channel_type,
            "config": json.dumps(public),
            "events": json.dumps(body.events),
            "enabled": body.enabled,
            "ct": ciphertext,
            "nonce": nonce,
            "dek_id": dek_id,
        },
    )

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


async def _replace_config(db: AsyncSession, row, config: dict) -> None:
    """Replace a channel's config.

    Listing never returns secrets, so a secret left out or sent masked keeps
    its value. An explicit null removes it.
    """
    await require_generation_current(db, vault)
    try:
        current = await _load_config(db, row)
    except ChannelUnreadable:
        current = {}
    merged = {k: v for k, v in current.items() if k in _SECRET_FIELDS}
    for key, value in config.items():
        if key in _SECRET_FIELDS and value == _MASK:
            continue
        merged[key] = value
    merged = {
        k: v for k, v in merged.items() if v is not None or k not in _SECRET_FIELDS
    }
    public, ciphertext, nonce, dek_id = await _store_secrets(db, str(row.id), merged)
    # Failure state is reset: it described the previous configuration.
    await db.execute(
        text(
            "UPDATE vault_notification_channels "
            "SET config = CAST(:config AS jsonb), secrets_ct = :ct, "
            "secrets_nonce = :nonce, dek_id = CAST(:dek_id AS uuid), "
            "last_error = NULL, consecutive_failures = 0 "
            "WHERE id = CAST(:id AS uuid)"
        ),
        {
            "id": str(row.id),
            "config": json.dumps(public),
            "ct": ciphertext,
            "nonce": nonce,
            "dek_id": dek_id,
        },
    )
    await _delete_dek(db, row.dek_id)


@router.put("/{channel_id}")
async def update_channel(
    channel_id: str,
    body: ChannelUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    token_info: dict = Depends(require_permission("admin", "w")),
):
    vault.require_unsealed()
    if body.config is None and body.events is None and body.enabled is None:
        raise HTTPException(400, "No fields to update")

    result = await db.execute(
        text(
            f"SELECT {_CHANNEL_COLUMNS} FROM vault_notification_channels "
            "WHERE id = CAST(:id AS uuid) FOR UPDATE"
        ),
        {"id": channel_id},
    )
    row = result.fetchone()
    if not row:
        raise HTTPException(404, "Channel not found")

    if body.config is not None:
        await _replace_config(db, row, body.config)
    if body.events is not None:
        await db.execute(
            text(
                "UPDATE vault_notification_channels "
                "SET events = CAST(:events AS jsonb) WHERE id = CAST(:id AS uuid)"
            ),
            {"id": channel_id, "events": json.dumps(body.events)},
        )
    if body.enabled is not None:
        await db.execute(
            text(
                "UPDATE vault_notification_channels "
                "SET enabled = :enabled WHERE id = CAST(:id AS uuid)"
            ),
            {"id": channel_id, "enabled": body.enabled},
        )

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
            "WHERE id = CAST(:id AS uuid) RETURNING name, dek_id"
        ),
        {"id": channel_id},
    )
    row = result.fetchone()
    if not row:
        raise HTTPException(404, "Channel not found")
    await _delete_dek(db, row.dek_id)

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
            f"SELECT {_CHANNEL_COLUMNS} FROM vault_notification_channels "
            "WHERE id = CAST(:id AS uuid)"
        ),
        {"id": channel_id},
    )
    row = result.fetchone()
    if not row:
        raise HTTPException(404, "Channel not found")

    outcome = await _deliver(db, row, "test", "rhorizon test notification")
    if outcome.error:
        raise HTTPException(502, outcome.error)

    return {"status": "sent", "channel": row.name}


@dataclasses.dataclass(frozen=True)
class _Outcome:
    error: str | None = None
    first_failure: bool = False


async def _record_outcome(db: AsyncSession, query: str, params: dict) -> int | None:
    """Best effort: a standby cannot write, and delivery must not depend on it."""
    try:
        result = await db.execute(text(query), params)
        count = result.scalar_one_or_none()
        await db.commit()
        return count
    except Exception as exc:
        with contextlib.suppress(Exception):
            await db.rollback()
        log.warning("Notification status not recorded: %s", type(exc).__name__)
        return None


async def _deliver(db: AsyncSession, row, event: str, message: str) -> _Outcome:
    """Send to one channel, then record and report the result."""
    config = row.config if isinstance(row.config, dict) else {}
    try:
        config = await _load_config(db, row)
        await _send_notification(row.channel_type, config, event, message)
    except Exception as exc:
        reason, error = _describe_failure(row.channel_type, config, exc)
        notification_failures.labels(channel_type=row.channel_type, reason=reason).inc()
        log.error(
            "Notification failed: channel=%s type=%s event=%s reason=%s: %s",
            row.name,
            row.channel_type,
            event,
            reason,
            error,
        )
        failures = await _record_outcome(
            db,
            "UPDATE vault_notification_channels "
            "SET last_failure_at = NOW(), last_error = :error, "
            "consecutive_failures = consecutive_failures + 1 "
            "WHERE id = CAST(:id AS uuid) RETURNING consecutive_failures",
            {"id": str(row.id), "error": error[:_MAX_ERROR_LENGTH]},
        )
        return _Outcome(error=error, first_failure=failures == 1)

    if row.consecutive_failures:
        log.info(
            "Notification channel recovered: channel=%s type=%s after %d failures",
            row.name,
            row.channel_type,
            row.consecutive_failures,
        )
    await _record_outcome(
        db,
        "UPDATE vault_notification_channels "
        "SET last_success_at = NOW(), last_error = NULL, consecutive_failures = 0 "
        "WHERE id = CAST(:id AS uuid) RETURNING consecutive_failures",
        {"id": str(row.id)},
    )
    return _Outcome()


def _locked(row) -> bool:
    """Its credentials need keys that a sealed vault does not hold."""
    return vault.sealed and row.secrets_ct is not None


async def dispatch_event(db: AsyncSession, event: str, message: str):
    """Send notification to all enabled channels subscribed to this event."""
    await encrypt_plaintext_channels(db)
    result = await db.execute(
        text(
            f"SELECT {_CHANNEL_COLUMNS} FROM vault_notification_channels "
            "WHERE enabled = true"
        )
    )
    rows = result.fetchall()
    targets = 0
    delivered = 0
    failed = {}
    for row in rows:
        # Subscription is the `events` COLUMN, not config. Empty = subscribe-all.
        events = row.events if isinstance(row.events, list) else []
        if events and event not in events and event not in _ALWAYS_DELIVERED:
            continue
        targets += 1
        if _locked(row):
            log.warning(
                "Notification skipped: channel=%s event=%s: vault is sealed and "
                "this channel's credentials are encrypted",
                row.name,
                event,
            )
            continue
        outcome = await _deliver(db, row, event, message)
        if outcome.error:
            failed[row.id] = (row, outcome)
        else:
            delivered += 1

    if targets and not delivered:
        notification_undelivered.labels(event=event).inc()
        log.critical(
            "Alert not delivered: event=%s reached none of %d channels", event, targets
        )
    await _announce_failures(db, rows, failed)


async def _announce_failures(db: AsyncSession, rows, failed: dict) -> None:
    """Warn through the other channels the first time a channel breaks."""
    notices = [
        f"Channel '{row.name}' ({row.channel_type}) failed: {outcome.error}"
        for row, outcome in failed.values()
        if outcome.first_failure
    ]
    if not notices:
        return
    message = "\n".join(notices)
    for row in rows:
        if row.id not in failed and not _locked(row):
            await _deliver(db, row, "notification_channel_failed", message)


def _channel_target(channel_type: str, config: dict) -> str:
    """Host only: webhook paths and queries can carry secrets."""
    if channel_type == "email":
        return f"{config.get('smtp_host', '')}:{config.get('smtp_port', 587) or 587}"
    url = config.get("homeserver" if channel_type == "matrix" else "url", "")
    return urlparse(str(url)).hostname or "the destination"


def _exception_chain(exc: BaseException) -> list[BaseException]:
    """Innermost first: httpx wraps the error that names the real cause."""
    chain = []
    current = exc
    while current is not None and current not in chain:
        chain.append(current)
        current = current.__cause__ or current.__context__
    return chain[::-1]


def _describe_smtp(target: str, exc: smtplib.SMTPException) -> tuple[str, str]:
    if isinstance(exc, smtplib.SMTPAuthenticationError):
        return "auth", f"{target} rejected the login: check smtp_user and smtp_password"
    if isinstance(exc, smtplib.SMTPNotSupportedError):
        if "STARTTLS" in str(exc):
            return "tls", (
                f"{target} does not offer STARTTLS: enable smtp_use_ssl, or turn "
                "STARTTLS off for a relay listed in RH_NOTIFY_INTERNAL_ALLOW"
            )
        return "auth", f"{target} does not accept a login on this connection"
    if isinstance(exc, smtplib.SMTPRecipientsRefused):
        return "rejected", f"{target} refused every recipient: check 'to'"
    if isinstance(exc, smtplib.SMTPSenderRefused):
        return "rejected", f"{target} refused the sender: check 'from'"
    if isinstance(exc, smtplib.SMTPResponseException):
        return "rejected", f"{target} answered SMTP {exc.smtp_code}"
    return "connection", f"{target} closed the SMTP connection"


def _describe_http(
    channel_type: str, target: str, exc: httpx.HTTPStatusError
) -> tuple[str, str]:
    status = exc.response.status_code
    if status in (401, 403):
        credential = "access token" if channel_type == "matrix" else "credentials"
        return "auth", f"{target} rejected the {credential} (HTTP {status})"
    return "http_status", f"{target} answered HTTP {status}"


def _describe_failure(
    channel_type: str, config: dict, exc: Exception
) -> tuple[str, str]:
    """Return (metric reason, operator message).

    Built from known fields, never str(exc): httpx messages hold the full URL,
    and a Matrix or webhook URL can be a credential.
    """
    target = _channel_target(channel_type, config)
    for err in _exception_chain(exc):
        if isinstance(err, DestinationRejected):
            return "blocked_destination", (
                f"{target} is refused: notification channels only reach public "
                "addresses, and this one is private, internal or missing. List an "
                "internal relay in RH_NOTIFY_INTERNAL_ALLOW"
            )
        if isinstance(err, (DestinationUnresolved, socket.gaierror)):
            return "dns", f"{target} does not resolve from the vault"
        if isinstance(err, ssl.SSLCertVerificationError):
            return "tls_certificate", (
                f"TLS certificate of {target} was rejected: {err.verify_message}"
            )
        if isinstance(err, ssl.SSLError):
            return "tls", f"TLS handshake with {target} failed: {err.reason}"
        if isinstance(err, smtplib.SMTPException):
            return _describe_smtp(target, err)
        if isinstance(err, httpx.HTTPStatusError):
            return _describe_http(channel_type, target, err)
        if isinstance(err, (TimeoutError, httpx.TimeoutException)):
            return "timeout", f"{target} did not answer in time"
        if isinstance(err, OSError) and err.errno == errno.ECONNREFUSED:
            return "connection", f"{target} refused the connection"
        if isinstance(err, (OSError, httpx.TransportError)):
            return "connection", f"Could not connect to {target}"
        if isinstance(err, ValueError):
            return "config", str(err)
    return "unknown", f"Delivery to {target} failed: {type(exc).__name__}"


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
    if user and password and not (use_ssl or use_starttls):
        if not _is_listed_relay(host, port):
            raise ValueError(
                "SMTP credentials require TLS: enable SSL or STARTTLS, or list "
                "this relay in RH_NOTIFY_INTERNAL_ALLOW"
            )
    context = ssl.create_default_context()
    if use_ssl:
        client = _PinnedSMTPSSL(host, port, timeout=15, context=context)
    else:
        client = _PinnedSMTP(host, port, timeout=15)
    try:
        client.ehlo()
        if use_starttls and not use_ssl:
            client.starttls(context=context)
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

    _guard_ssrf(host, port)  # reject an SMTP host that resolves to an internal target

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

    # SSRF guard: the vault makes the request, so reject internal/metadata hosts.
    parsed = urlparse(homeserver)
    _guard_ssrf(parsed.hostname or homeserver, _url_port(parsed))

    url = f"{homeserver}/_matrix/client/r0/rooms/{room_id}/send/m.room.message"
    async with _outbound_client() as client:
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


def _internal_allowed(address: str, port: int | None) -> bool:
    """True when the operator listed this internal address and port."""
    ip = ipaddress.ip_address(address)
    ip = getattr(ip, "ipv4_mapped", None) or ip
    if str(ip) in _CLOUD_METADATA_HOSTS or ip.version != 4:
        return False
    return any(
        ip in network and allowed_port in (None, port)
        for network, allowed_port in parse_notify_internal_allow(
            settings.notify_internal_allow
        )
    )


def _refused(address: str, port: int | None) -> bool:
    return _is_internal_ip(address) and not _internal_allowed(address, port)


def _is_listed_relay(hostname: str, port: int) -> bool:
    """Every address of the destination is on the operator's internal list."""
    try:
        infos = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return False
    return bool(infos) and all(_internal_allowed(i[4][0], port) for i in infos)


def _url_port(parsed) -> int:
    return parsed.port or (443 if parsed.scheme == "https" else 80)


def _is_disallowed_host(hostname: str, port: int | None = None) -> tuple[bool, str]:
    """Return (blocked, reason) - resolve hostname and reject any IP that is
    loopback/private/link-local/multicast/reserved, plus literal cloud
    metadata hostnames. Catches SSRF tricks like `127.1`, `2130706433`
    (decimal), `[::ffff:127.0.0.1]`, `metadata.google.internal`.

    This is the early check. The clients re-validate at connect time through
    :func:`_pinned_address`, so a name cannot rebind between the two.
    """
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
        if _refused(info[4][0], port):
            return True, f"private/internal IP: {info[4][0]} (hostname={hostname})"
    return False, ""


def _is_internal_ip(address: str) -> bool:
    ip = ipaddress.ip_address(address)
    ip = getattr(ip, "ipv4_mapped", None) or ip
    return (
        ip.is_loopback
        or ip.is_private
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def _pinned_address(hostname: str, port: int) -> str:
    """Resolve and validate the address the client will actually connect to."""
    if hostname.lower() in _CLOUD_METADATA_HOSTS:
        raise DestinationRejected(f"Destination rejected (SSRF mitigation): {hostname}")
    try:
        infos = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise DestinationUnresolved(
            f"Destination does not resolve: {hostname}"
        ) from exc
    addresses = [info[4][0] for info in infos]
    if not addresses or any(_refused(address, port) for address in addresses):
        log.warning("Outbound SSRF blocked at connect: host=%s", hostname)
        raise DestinationRejected(f"Destination rejected (SSRF mitigation): {hostname}")
    return addresses[0]


class _PinnedBackend(httpcore.AsyncNetworkBackend):
    """Connect to the validated address. TLS still verifies the hostname."""

    def __init__(self) -> None:
        self._backend = httpcore.AnyIOBackend()

    async def connect_tcp(
        self, host, port, timeout=None, local_address=None, socket_options=None
    ):
        address = await asyncio.to_thread(_pinned_address, host, port)
        return await self._backend.connect_tcp(
            address,
            port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )

    async def sleep(self, seconds: float) -> None:
        await self._backend.sleep(seconds)


def _outbound_client() -> httpx.AsyncClient:
    transport = httpx.AsyncHTTPTransport()
    transport._pool = httpcore.AsyncConnectionPool(
        ssl_context=httpx.create_ssl_context(),
        network_backend=_PinnedBackend(),
    )
    # trust_env=False: a proxy would resolve the name outside this check.
    return httpx.AsyncClient(transport=transport, trust_env=False)


class _PinnedSocket:
    def _get_socket(self, host, port, timeout):
        return super()._get_socket(_pinned_address(host, port), port, timeout)


class _PinnedSMTP(_PinnedSocket, smtplib.SMTP):
    pass


class _PinnedSMTPSSL(_PinnedSocket, smtplib.SMTP_SSL):
    pass


def _guard_ssrf(hostname: str, port: int | None = None) -> None:
    """Raise ValueError if `hostname` resolves to an internal/metadata target.
    Applied uniformly to every outbound destination (webhook/Matrix/SMTP)."""
    blocked, reason = _is_disallowed_host(hostname, port)
    if blocked:
        log.warning("Outbound SSRF blocked: host=%s - %s", hostname, reason)
        raise DestinationRejected(f"Destination rejected (SSRF mitigation): {reason}")


async def _send_webhook(config: dict, event: str, message: str):
    url = config.get("url", "")
    if not url:
        raise ValueError("Webhook config requires: url")

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Webhook URL must be http(s): {parsed.scheme}")

    _guard_ssrf(parsed.hostname or "", _url_port(parsed))
    log.info("Sending webhook to %s for event %s", parsed.hostname, event)
    raw_headers = config.get("headers", {}) or {}
    # Drop hop-by-hop, session, and IP-spoofing headers, admin caller
    # cannot smuggle Cookie/X-Forwarded-* into outbound requests.
    headers = {
        k: v for k, v in raw_headers.items() if k.lower() not in _HEADERS_DENYLIST
    }
    async with _outbound_client() as client:
        r = await client.post(
            url,
            json={"event": event, "message": message, "source": "rhorizon"},
            headers=headers,
            timeout=10,
        )
        r.raise_for_status()
