# SPDX-License-Identifier: AGPL-3.0-or-later
"""PostgreSQL dynamic roles."""

import re

import asyncpg

from ..base import (
    ENGINE_CONNECT_TIMEOUT,
    DynamicEngine,
    EngineProbe,
    EngineSupport,
    first_version_number,
    is_generated_username,
)

_REVOCATION_TEMPLATE = re.compile(
    r'DROP\s+(?:ROLE|USER)\s+IF\s+EXISTS\s+(?:"\{\{name\}\}"|\{\{name\}\})\s*;?',
    re.IGNORECASE,
)
_RENDERED_REVOCATION = re.compile(
    r'DROP\s+(?:ROLE|USER)\s+IF\s+EXISTS\s+(?:"(?P<quoted>[a-z0-9_]+)"'
    r"|(?P<plain>[a-z0-9_]+))\s*;?",
    re.IGNORECASE,
)


def _validate_revocation_template(revocation: str) -> None:
    if _REVOCATION_TEMPLATE.fullmatch(revocation.strip()) is None:
        raise ValueError(
            "PostgreSQL revocation must idempotently drop exactly {{name}} "
            "with IF EXISTS"
        )


def _validate_rendered_revocation(rendered: str) -> None:
    match = _RENDERED_REVOCATION.fullmatch(rendered.strip())
    username = (match.group("quoted") or match.group("plain")) if match else ""
    if not is_generated_username(username, allow_legacy=True):
        raise ValueError(
            "PostgreSQL revocation must idempotently drop the generated role"
        )


async def _execute(conn_url: str, sql: str) -> None:
    conn = await asyncpg.connect(
        conn_url,
        timeout=ENGINE_CONNECT_TIMEOUT,
        command_timeout=ENGINE_CONNECT_TIMEOUT,
    )
    try:
        await conn.execute(sql)
    finally:
        await conn.close(timeout=ENGINE_CONNECT_TIMEOUT)


class PostgresEngine(DynamicEngine):
    engine_type = "postgresql"
    support = EngineSupport(
        display_name="PostgreSQL",
        driver_module="asyncpg",
        validated_targets=("PostgreSQL 18",),
        implementation_targets=("PostgreSQL",),
        creation_example=("CREATE ROLE \"{{name}}\" LOGIN PASSWORD '{{password}}'"),
        revocation_example='DROP ROLE IF EXISTS "{{name}}"',
    )

    async def provision(self, conn_url: str, rendered: str) -> None:
        await _execute(conn_url, rendered)

    def validate_role_templates(self, creation: str, revocation: str) -> None:
        _validate_revocation_template(revocation)

    async def revoke(self, conn_url: str, rendered: str) -> None:
        _validate_rendered_revocation(rendered)
        await _execute(conn_url, rendered)

    async def probe(self, conn_url: str) -> EngineProbe:
        conn = await asyncpg.connect(
            conn_url,
            timeout=ENGINE_CONNECT_TIMEOUT,
            command_timeout=ENGINE_CONNECT_TIMEOUT,
        )
        try:
            version = await conn.fetchval("SHOW server_version")
            return EngineProbe("PostgreSQL", str(version))
        finally:
            await conn.close(timeout=ENGINE_CONNECT_TIMEOUT)

    def compatibility_status(self, probe: EngineProbe) -> str:
        major = first_version_number(probe.server_version)
        return "validated" if major == 18 else "connected_unvalidated"


ENGINE = PostgresEngine()
