# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Honeytoken intrusion detection.

Honey secrets and honey tokens are decoy entries seeded in the vault
that legitimate users and applications never touch. Any access is
strong evidence of an active intrusion or insider misuse.

The detection path is intentionally non-disruptive: a honey access returns
the same response as a legitimate one (never tip off the attacker). The
alarm fires out-of-band via:
  1. CRITICAL log line (picked up by SIEM if forwarded)
  2. Tamper-evident audit chain entry (action="honey_access")
  3. Notification dispatch to channels subscribed to "honey_access"

Seeding is manual: honeytokens lose value if they look default, so the
operator picks attractive names mirroring the real scheme
(prod-pgsql-master, wg-server-private) and sets is_honey=true on the row.
"""

import asyncio
import logging

from fastapi import Request

from .audit import log_action
from .client_ip import get_client_ip
from .metrics import honey_access

log = logging.getLogger("rhorizon.honey")
_notification_tasks: set[asyncio.Task[None]] = set()


async def _dispatch_honey_notification(message: str) -> None:
    """Deliver a honey alert without borrowing the request's DB session."""
    try:
        from .database import async_session
        from .routes.notifications import dispatch_event

        async with async_session() as notification_db:
            await dispatch_event(notification_db, "honey_access", message)
    except Exception:
        log.exception("[honey] notification dispatch failed")


async def alert_honey_access(
    kind: str,
    name: str,
    request: Request,
    actor: str = "unknown",
) -> None:
    """Fire all alert paths for a honey access. Never raises."""
    client_ip = get_client_ip(request) if request else "unknown"
    user_agent = request.headers.get("user-agent", "") if request else ""

    log.critical(
        "[honey] %s access detected - name=%r actor=%r ip=%s ua=%r",
        kind,
        name,
        actor,
        client_ip,
        user_agent[:200],
    )
    # Bound the label set : we only seed honey of these two flavours.
    # Anything else gets bucketed to "other" so an unforeseen kind
    # never explodes the cardinality.
    honey_access.labels(kind=kind if kind in ("secret", "token") else "other").inc()

    detail = {
        "kind": kind,
        "name": name,
        "ip": client_ip,
        "user_agent": user_agent[:200],
    }

    # Dedicated session + immediate commit: the audit trail must persist
    # even if the calling endpoint rollbacks or never commits (an attacker
    # must not be able to erase their trace by triggering a rollback).
    try:
        from .database import async_session

        async with async_session() as audit_db:
            await log_action(
                audit_db,
                actor=actor,
                action="honey_access",
                target=name,
                detail=detail,
                ip_address=client_ip,
            )
            await audit_db.commit()
    except Exception:
        log.exception("[honey] audit log failed")

    # Best-effort external delivery is genuinely out-of-band: the audit above
    # is the durable trail of record, while a slow Matrix/webhook/SMTP endpoint
    # must not delay the decoy response and reveal that the token is monitored.
    try:
        msg = (
            f"HONEY ACCESS - {kind}={name!r} from {client_ip} "
            f"actor={actor!r} ua={user_agent[:80]!r}"
        )
        task = asyncio.create_task(_dispatch_honey_notification(msg))
        _notification_tasks.add(task)
        task.add_done_callback(_notification_tasks.discard)
    except Exception:
        log.exception("[honey] notification dispatch could not be scheduled")
