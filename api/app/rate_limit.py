# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Rate limiting - DB-backed, multi-worker safe.

Shared by vault unseal, token auth, and LDAP login.
Same table (vault_rate_limits), same escalation per IP.
Whitelisted CIDRs (RHORIZON_RATE_LIMIT_WHITELIST) bypass all checks.
Thresholds are intentionally permissive - combined with whitelist + admin
unblock endpoint, they protect against runaway bots without blocking
legitimate trial-and-error work.
"""

import ipaddress
import logging

from fastapi import HTTPException
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from .authfail import log_authfail
from .config import settings

log = logging.getLogger("rhorizon.rate_limit")

# (failure_count, lockout_seconds), escalating. Deliberately permissive: a
# 256-bit token is infeasible to brute-force and Argon2id (256MB/~500ms per
# attempt) already throttles the master password. Second line, not first.
RATE_LIMITS = [(20, 30), (50, 300), (200, 3600)]


def _parse_whitelist(csv: str) -> list:
    """Parse RHORIZON_RATE_LIMIT_WHITELIST into ip_network objects.

    Accepts plain IPs (treated as /32 for IPv4 or /128 for IPv6) and CIDRs.
    Malformed entries are silently skipped.
    """
    networks = []
    for token in csv.split(","):
        token = token.strip()
        if not token:
            continue
        try:
            networks.append(ipaddress.ip_network(token, strict=False))
        except ValueError:
            continue
    return networks


_WHITELIST_CIDRS = _parse_whitelist(settings.rate_limit_whitelist)


def _is_whitelisted(ip_str: str) -> bool:
    """True if ip_str belongs to any whitelisted CIDR."""
    if not _WHITELIST_CIDRS:
        return False
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any(ip in net for net in _WHITELIST_CIDRS)


async def check_rate_limit(db: AsyncSession, ip: str):
    """Raise 429 if IP is locked out. Whitelisted IPs skip."""
    if _is_whitelisted(ip):
        return
    result = await db.execute(
        text(
            "SELECT EXTRACT(EPOCH FROM locked_until - NOW())::int AS wait "
            "FROM vault_rate_limits "
            "WHERE ip_address = :ip AND locked_until > NOW()"
        ),
        {"ip": ip},
    )
    row = result.fetchone()
    if row:
        log_authfail(ip, "rate_limited")
        raise HTTPException(429, f"Too many attempts. Retry in {max(1, row.wait)}s")


async def record_failure(db: AsyncSession, ip: str):
    """Record a failed attempt, apply lockout if threshold reached.

    Windowed counting: if the IP's last failure is older than
    ``rate_limit_findtime`` seconds, the counter RESETS to 1 instead of
    incrementing. The count is otherwise cumulative-for-life and token auth
    never clears it on success, so without this an IP that ever crossed a
    threshold relocks forever every few requests. Old failures age out; an
    actively-failing IP keeps incrementing within the window and still locks.
    No per-success hot-path write - the reset rides the next failure's upsert.
    """
    if _is_whitelisted(ip):
        return
    result = await db.execute(
        text(
            "INSERT INTO vault_rate_limits (ip_address, fail_count, updated_at) "
            "VALUES (:ip, 1, NOW()) "
            "ON CONFLICT (ip_address) DO UPDATE "
            "SET fail_count = CASE "
            "      WHEN vault_rate_limits.updated_at "
            "           < NOW() - make_interval(secs => :window) THEN 1 "
            "      ELSE vault_rate_limits.fail_count + 1 END, "
            "    updated_at = NOW() "
            "RETURNING fail_count"
        ),
        {"ip": ip, "window": settings.rate_limit_findtime},
    )
    count = result.scalar()
    lockout_seconds = 0
    threshold_hit = 0
    for threshold, seconds in reversed(RATE_LIMITS):
        if count >= threshold:
            lockout_seconds = seconds
            threshold_hit = threshold
            break
    if lockout_seconds:
        await db.execute(
            text(
                "UPDATE vault_rate_limits "
                "SET locked_until = NOW() + make_interval(secs => :secs) "
                "WHERE ip_address = :ip"
            ),
            {"ip": ip, "secs": lockout_seconds},
        )
        log.warning(
            "Rate limit lockout: ip=%s count=%d threshold=%d duration=%ds",
            ip,
            count,
            threshold_hit,
            lockout_seconds,
        )
    await db.commit()


async def clear_failures(db: AsyncSession, ip: str):
    """Reset failures for an IP."""
    await db.execute(
        text("DELETE FROM vault_rate_limits WHERE ip_address = :ip"),
        {"ip": ip},
    )
    await db.commit()
