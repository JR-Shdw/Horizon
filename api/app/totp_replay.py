# SPDX-License-Identifier: AGPL-3.0-or-later
"""Cluster-wide, single-use consumption of validated TOTP counters."""

import logging

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from .crypto import totp_counter_for_code

_COUNTER_KEY = "totp_last_counter"
_log = logging.getLogger("rhorizon.totp")


async def verify_and_consume_totp(
    db: AsyncSession,
    secret: str,
    code: str,
) -> bool:
    """Validate a TOTP and atomically consume its counter in ``vault_config``."""
    counter = totp_counter_for_code(secret, code)
    if counter is None:
        return False

    result = await db.execute(
        text("SELECT value FROM vault_config WHERE key = :key FOR UPDATE"),
        {"key": _COUNTER_KEY},
    )
    row = result.fetchone()
    if row is not None:
        try:
            last_counter = int(row.value)
        except (TypeError, ValueError):
            _log.critical("invalid persisted TOTP replay counter; denying code")
            return False
        if counter <= last_counter:
            return False
        await db.execute(
            text("UPDATE vault_config SET value = :value WHERE key = :key"),
            {"key": _COUNTER_KEY, "value": str(counter)},
        )
        return True

    # Two first uses can both observe an absent row. The primary-key conflict
    # serializes them; only the transaction that inserts the counter succeeds.
    inserted = await db.execute(
        text(
            "INSERT INTO vault_config (key, value) VALUES (:key, :value) "
            "ON CONFLICT (key) DO NOTHING RETURNING value"
        ),
        {"key": _COUNTER_KEY, "value": str(counter)},
    )
    return inserted.fetchone() is not None
