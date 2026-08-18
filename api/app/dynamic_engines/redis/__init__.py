# SPDX-License-Identifier: AGPL-3.0-or-later
"""Redis ACL-backed dynamic users."""

import re
import shlex
from urllib.parse import urlparse

from ..base import (
    ENGINE_CONNECT_TIMEOUT,
    DynamicEngine,
    EngineProbe,
    EngineSupport,
    is_generated_username,
)

_DATABASE_PATH = re.compile(r"/[0-9]+")


def _validate_connection_url(conn_url: str) -> None:
    try:
        parsed = urlparse(conn_url)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise ValueError("malformed Redis connection_url") from exc

    if parsed.scheme not in {"redis", "rediss"} or not hostname:
        raise ValueError("redis connection_url must use redis:// or rediss://")
    if port == 0:
        raise ValueError("Redis connection_url port must be greater than zero")
    if parsed.query or parsed.fragment:
        raise ValueError("Redis connection_url does not accept query parameters")
    if parsed.path not in {"", "/"} and _DATABASE_PATH.fullmatch(parsed.path) is None:
        raise ValueError("Redis connection_url database must be a numeric path")


def _command(rendered: str, expected: tuple[str, str]) -> list[str]:
    try:
        parts = shlex.split(rendered, posix=True)
    except ValueError as exc:
        raise ValueError("malformed Redis ACL template") from exc
    if len(parts) < 3 or tuple(part.upper() for part in parts[:2]) != expected:
        raise ValueError(f"Redis template must start with {' '.join(expected)}")
    allow_legacy = expected == ("ACL", "DELUSER")
    if not is_generated_username(parts[2], allow_legacy=allow_legacy):
        raise ValueError("Redis ACL template must target the generated rh_ user")
    return parts


def _template_command(template: str, expected: tuple[str, str]) -> list[str]:
    try:
        parts = shlex.split(template, posix=True)
    except ValueError as exc:
        raise ValueError("malformed Redis ACL template") from exc
    if len(parts) < 3 or tuple(part.upper() for part in parts[:2]) != expected:
        raise ValueError(f"Redis template must start with {' '.join(expected)}")
    if parts[2] != "{{name}}":
        raise ValueError("Redis ACL template must target the {{name}} placeholder")
    return parts


async def _client(conn_url: str):
    from redis.asyncio import Redis

    _validate_connection_url(conn_url)
    return Redis.from_url(
        conn_url,
        decode_responses=True,
        socket_connect_timeout=ENGINE_CONNECT_TIMEOUT,
        socket_timeout=ENGINE_CONNECT_TIMEOUT,
    )


class RedisEngine(DynamicEngine):
    engine_type = "redis"
    support = EngineSupport(
        display_name="Redis",
        driver_module="redis.asyncio",
        validated_targets=(),
        implementation_targets=("Redis 6+ ACL",),
        creation_example=(
            "ACL SETUSER {{name}} reset on >{{password}} ~app:* resetchannels +@read"
        ),
        revocation_example="ACL DELUSER {{name}}",
    )

    def validate_conn(self, conn_url: str) -> None:
        _validate_connection_url(conn_url)

    def validate_role_templates(self, creation: str, revocation: str) -> None:
        create_parts = _template_command(creation, ("ACL", "SETUSER"))
        modifiers = [
            part
            for part in create_parts[3:]
            if part.startswith((">", "<", "#", "!")) or part.lower() == "nopass"
        ]
        options = {part.lower() for part in create_parts[3:]}
        if (
            modifiers != [">{{password}}"]
            or "reset" not in options
            or "on" not in options
        ):
            raise ValueError(
                "Redis creation must reset and enable the user with only >{{password}}"
            )

        revoke_parts = _template_command(revocation, ("ACL", "DELUSER"))
        if len(revoke_parts) != 3:
            raise ValueError("Redis revocation must delete exactly {{name}}")

    async def provision(self, conn_url: str, rendered: str) -> None:
        parts = _command(rendered, ("ACL", "SETUSER"))
        client = await _client(conn_url)
        try:
            await client.execute_command(*parts)
        finally:
            await client.aclose()

    async def revoke(self, conn_url: str, rendered: str) -> None:
        parts = _command(rendered, ("ACL", "DELUSER"))
        if len(parts) != 3:
            raise ValueError("Redis revoke template must delete exactly one user")
        client = await _client(conn_url)
        try:
            await client.execute_command(*parts)
        finally:
            await client.aclose()

    async def probe(self, conn_url: str) -> EngineProbe:
        client = await _client(conn_url)
        try:
            info = await client.info(section="server")
            return EngineProbe("Redis", str(info.get("redis_version") or "") or None)
        finally:
            await client.aclose()


ENGINE = RedisEngine()
