# SPDX-License-Identifier: AGPL-3.0-or-later
"""MySQL and MariaDB dynamic users."""

import asyncio
import re
import ssl
from urllib.parse import ParseResult, parse_qs, unquote, urlparse

from ..base import (
    ENGINE_CONNECT_TIMEOUT,
    DynamicEngine,
    EngineProbe,
    EngineSupport,
    first_version_number,
    is_generated_username,
    mariadb_major_version,
)

_TLS_OPTIONS = {"ssl_ca", "ssl_cert", "ssl_key"}
_ACCOUNT_HOST_PATTERN = r"[a-z0-9._%:/-]+"
_REVOCATION_TEMPLATE = re.compile(
    r"DROP\s+USER\s+IF\s+EXISTS\s+'\{\{name\}\}'@'" + _ACCOUNT_HOST_PATTERN + r"'\s*;?",
    re.IGNORECASE,
)
_RENDERED_REVOCATION = re.compile(
    r"DROP\s+USER\s+IF\s+EXISTS\s+'(?P<username>[a-z0-9_]+)'@'"
    + _ACCOUNT_HOST_PATTERN
    + r"'\s*;?",
    re.IGNORECASE,
)


def _validate_revocation_template(revocation: str) -> None:
    if _REVOCATION_TEMPLATE.fullmatch(revocation.strip()) is None:
        raise ValueError(
            "MySQL revocation must idempotently drop exactly {{name}} with IF EXISTS"
        )


def _validate_rendered_revocation(rendered: str) -> None:
    match = _RENDERED_REVOCATION.fullmatch(rendered.strip())
    username = match.group("username") if match else ""
    if not is_generated_username(username, allow_legacy=True):
        raise ValueError("MySQL revocation must idempotently drop the generated user")


def _parse_connection(conn_url: str) -> tuple[ParseResult, dict[str, str]]:
    """Validate the DSN structure without reading files or connecting."""
    parsed = urlparse(conn_url)
    if parsed.scheme not in {"mysql", "mysqls"}:
        raise ValueError("mysql connection_url must use mysql:// or mysqls://")
    if not parsed.hostname or not parsed.username:
        raise ValueError("mysql connection_url must include a host and username")
    if parsed.params or ";" in parsed.path or parsed.fragment:
        raise ValueError(
            "mysql connection_url must not contain path parameters or a fragment"
        )
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("mysql connection_url contains an invalid port") from exc
    if port == 0:
        raise ValueError("mysql connection_url contains an invalid port")

    raw_options = parse_qs(parsed.query, keep_blank_values=True, strict_parsing=True)
    unknown = set(raw_options) - _TLS_OPTIONS
    if unknown:
        raise ValueError("unsupported mysql connection options")
    if any(len(values) != 1 or not values[0] for values in raw_options.values()):
        raise ValueError("mysql connection options must have one non-empty value")
    options = {name: values[0] for name, values in raw_options.items()}

    if parsed.scheme == "mysql" and options:
        raise ValueError("TLS options require a mysqls:// connection_url")
    if bool(options.get("ssl_cert")) != bool(options.get("ssl_key")):
        raise ValueError("ssl_cert and ssl_key must be provided together")
    return parsed, options


def _ssl_context(options: dict[str, str]) -> ssl.SSLContext:
    context = ssl.create_default_context(cafile=options.get("ssl_ca"))
    if cert := options.get("ssl_cert"):
        context.load_cert_chain(certfile=cert, keyfile=options["ssl_key"])
    return context


async def _connect(conn_url: str):
    import aiomysql

    parsed, options = _parse_connection(conn_url)
    kwargs = {
        "host": parsed.hostname,
        "port": parsed.port if parsed.port is not None else 3306,
        "user": unquote(parsed.username) if parsed.username is not None else None,
        "password": unquote(parsed.password) if parsed.password is not None else None,
        "db": unquote(parsed.path.lstrip("/")),
        "connect_timeout": ENGINE_CONNECT_TIMEOUT,
    }
    if parsed.scheme == "mysqls":
        kwargs["ssl"] = _ssl_context(options)
    return await aiomysql.connect(
        **kwargs,
    )


async def _execute(conn_url: str, sql: str) -> None:
    async with asyncio.timeout(ENGINE_CONNECT_TIMEOUT):
        conn = await _connect(conn_url)
        try:
            async with conn.cursor() as cur:
                for statement in sql.split(";"):
                    if statement := statement.strip():
                        await cur.execute(statement)
            await conn.commit()
        finally:
            await conn.ensure_closed()


def _product_name(version: str | None, version_comment: str | None) -> str:
    fingerprint = f"{version or ''} {version_comment or ''}".casefold()
    if "mariadb" in fingerprint:
        return "MariaDB"
    if "percona" in fingerprint:
        return "Percona Server"
    if "aurora" in fingerprint:
        return "Amazon Aurora MySQL"
    if version_comment is not None and "mysql" in version_comment.casefold():
        return "MySQL"
    return "MySQL-compatible"


class MysqlEngine(DynamicEngine):
    engine_type = "mysql"
    support = EngineSupport(
        display_name="MySQL / MariaDB",
        driver_module="aiomysql",
        validated_targets=("MySQL 8.x", "MariaDB 11"),
        implementation_targets=("MySQL", "MariaDB"),
        creation_example=(
            "CREATE USER '{{name}}'@'%' IDENTIFIED BY '{{password}}'; "
            "GRANT SELECT ON app.* TO '{{name}}'@'%'"
        ),
        revocation_example="DROP USER IF EXISTS '{{name}}'@'%'",
    )

    def validate_conn(self, conn_url: str) -> None:
        _parse_connection(conn_url)

    async def provision(self, conn_url: str, rendered: str) -> None:
        await _execute(conn_url, rendered)

    def validate_role_templates(self, creation: str, revocation: str) -> None:
        _validate_revocation_template(revocation)

    async def revoke(self, conn_url: str, rendered: str) -> None:
        _validate_rendered_revocation(rendered)
        await _execute(conn_url, rendered)

    async def probe(self, conn_url: str) -> EngineProbe:
        async with asyncio.timeout(ENGINE_CONNECT_TIMEOUT):
            conn = await _connect(conn_url)
            try:
                async with conn.cursor() as cur:
                    await cur.execute("SELECT VERSION(), @@version_comment")
                    row = await cur.fetchone()
                version = (
                    str(row[0]) if row is not None and row[0] is not None else None
                )
                version_comment = (
                    str(row[1]) if row is not None and row[1] is not None else None
                )
                product = _product_name(version, version_comment)
                return EngineProbe(product, version)
            finally:
                await conn.ensure_closed()

    def compatibility_status(self, probe: EngineProbe) -> str:
        if probe.product == "MariaDB":
            validated = mariadb_major_version(probe.server_version) == 11
        else:
            validated = (
                probe.product == "MySQL"
                and first_version_number(probe.server_version) == 8
            )
        return "validated" if validated else "connected_unvalidated"


ENGINE = MysqlEngine()
