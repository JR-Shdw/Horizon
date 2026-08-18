# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
import os
import socket
import ssl as _ssl

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from .config import settings


def _pg_ssl_context():
    """asyncpg SSL context for settings.database_ssl.

    verify-full : keep the secure create_default_context() baseline
                  (CERT_REQUIRED + hostname check); pin database_ca_cert
                  when set, else fall back to the system trust store.
    require     : encrypt only, server cert NOT verified (no MITM
                  protection -- only safe same-host / loopback).
    'disable' never reaches here; the caller skips TLS entirely.
    """
    ctx = _ssl.create_default_context()
    if settings.database_ssl == "verify-full":
        if settings.database_ca_cert:
            ctx.load_verify_locations(cafile=settings.database_ca_cert)
        return ctx
    ctx.check_hostname = False
    ctx.verify_mode = _ssl.CERT_NONE
    return ctx


# application_name "rhorizon:{host}" lets /cluster join pg_locks with
# pg_stat_activity to identify which host holds an advisory lock.
_HOSTNAME = os.environ.get("HOSTNAME") or socket.gethostname() or "default"

_connect_args = {"ssl": _pg_ssl_context()} if settings.database_ssl != "disable" else {}
# asyncpg honors `server_settings` to set per-connection PG GUCs at startup.
_connect_args["server_settings"] = {
    "application_name": f"rhorizon:{_HOSTNAME}",
}


# Pool sizing is a CLUSTER-WIDE budget:
#
#   nodes * workers_per_node * (pool_size + max_overflow)
#
# must stay below PostgreSQL max_connections after reserving capacity for
# migrations, health probes, autovacuum and operators.  The defaults deliberately
# cap each worker at 16 connections.  In the reference three-node / five-worker
# HA deployment that is 3 * 5 * 16 = 240 application connections against
# max_connections=300, leaving 60 (20%) outside the application pools.
# Env overrides for sizing experiments; invalid/negative fall back to defaults.
def _pool_int(name: str, default: int) -> int:
    v = os.environ.get(name)
    if not v:
        return default
    try:
        n = int(v)
        return n if n >= 0 else default
    except ValueError:
        return default


_POOL_SIZE = _pool_int("RHORIZON_POOL_SIZE", 8)
_POOL_OVERFLOW = _pool_int("RHORIZON_POOL_OVERFLOW", 8)

engine = create_async_engine(
    settings.database_url,
    pool_size=_POOL_SIZE,
    max_overflow=_POOL_OVERFLOW,
    pool_recycle=1800,  # recycle connections after 30 min
    pool_pre_ping=True,  # verify connection is alive before use
    pool_timeout=10,  # wait max 10s for a connection
    connect_args=_connect_args,
)
async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def get_db():
    async with async_session() as session:
        yield session
