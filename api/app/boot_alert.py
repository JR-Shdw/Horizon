# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Alert when a node is still sealed some time after it started.

Channel credentials are encrypted under the vault keys, so a sealed node cannot
use them. The destination comes from a deployment file instead, typically an
internal alert relay that holds its own Matrix token.
"""

import asyncio
import fcntl
import logging
import os
from pathlib import Path

from .config import settings
from .vault_state import vault

log = logging.getLogger("rhorizon.boot_alert")

EVENT = "started_sealed"
ATTEMPTS = 3
RETRY_SECS = 10


def _take_node_lock() -> tuple[bool, int | None]:
    """Return (owner, fd). One worker per node owns the alert until shutdown."""
    path = Path(settings.node_uuid_path).parent / ".boot-alert.lock"
    try:
        fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    except OSError as exc:
        # A duplicate alert beats a missing one.
        log.warning("boot alert: no node lock at %s (%s)", path, exc)
        return True, None
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(fd)
        return False, None
    return True, fd


def _read_url() -> str:
    try:
        return Path(settings.notify_boot_url_file).read_text().strip()
    except OSError as exc:
        log.error("boot alert: cannot read RH_NOTIFY_BOOT_URL_FILE (%s)", exc)
        return ""


async def alert_if_sealed() -> bool:
    """Wait the grace period, then alert if this node is still sealed."""
    await asyncio.sleep(settings.notify_boot_grace_secs)
    if not vault.sealed:
        return False
    url = _read_url()
    if not url:
        log.error("boot alert: node still sealed, but no alert URL is configured")
        return False

    from .cluster import get_hostname
    from .metrics import notification_undelivered
    from .routes.notifications import _send_webhook

    message = (
        f"Horizon {settings.version} on {get_hostname()} is still sealed "
        f"{settings.notify_boot_grace_secs}s after start"
    )
    for attempt in range(1, ATTEMPTS + 1):
        if not vault.sealed:
            return False
        try:
            await _send_webhook({"url": url}, EVENT, message)
        except Exception as exc:
            # The error text can carry the URL.
            log.warning(
                "boot alert: attempt %d/%d failed (%s)",
                attempt,
                ATTEMPTS,
                type(exc).__name__,
            )
            if attempt < ATTEMPTS:
                await asyncio.sleep(RETRY_SECS)
            continue
        log.warning("boot alert sent: node still sealed after start")
        return True
    notification_undelivered.labels(event=EVENT).inc()
    log.critical("Alert not delivered: event=%s", EVENT)
    return False


async def boot_sealed_alert_task() -> None:
    owner, fd = _take_node_lock()
    if not owner:
        return
    try:
        await alert_if_sealed()
        # Keep the lock so sibling workers stay quiet for this start.
        await asyncio.Event().wait()
    finally:
        if fd is not None:
            os.close(fd)
