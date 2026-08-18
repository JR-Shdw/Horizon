# SPDX-License-Identifier: AGPL-3.0-or-later
"""Apache Cassandra dynamic roles."""

import asyncio
import json
import re
import ssl
from dataclasses import dataclass, field

from ..base import (
    ENGINE_CONNECT_TIMEOUT,
    DynamicEngine,
    EngineProbe,
    EngineSupport,
    is_generated_username,
)

_CONNECTION_FIELDS = {
    "hosts",
    "port",
    "username",
    "password",
    "keyspace",
    "tls",
    "ca_cert",
    "server_name",
}
_REQUIRED_CONNECTION_FIELDS = {"hosts", "username", "password"}
_TEMPLATE_CREATE = re.compile(
    r"CREATE\s+ROLE\s+\{\{name\}\}\s+WITH\s+LOGIN\s*=\s*true\s+"
    r"AND\s+PASSWORD\s*=\s*'\{\{password\}\}'",
    re.IGNORECASE,
)
_TEMPLATE_GRANT = re.compile(
    r"GRANT\s+.+\s+TO\s+\{\{name\}\}",
    re.IGNORECASE | re.DOTALL,
)
_TEMPLATE_REVOKE = re.compile(
    r"DROP\s+ROLE\s+IF\s+EXISTS\s+\{\{name\}\}",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class CassandraConnection:
    hosts: tuple[str, ...]
    port: int
    username: str
    password: str = field(repr=False)
    keyspace: str | None
    tls: bool
    ca_cert: str | None
    server_name: str | None


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("cassandra connection JSON contains duplicate keys")
        result[key] = value
    return result


def parse_connection(conn_url: str) -> CassandraConnection:
    try:
        cfg = json.loads(conn_url, object_pairs_hook=_unique_json_object)
        if (
            not isinstance(cfg, dict)
            or not _REQUIRED_CONNECTION_FIELDS <= set(cfg)
            or not set(cfg) <= _CONNECTION_FIELDS
        ):
            raise TypeError
        hosts = cfg["hosts"]
        username = cfg["username"]
        password = cfg["password"]
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise ValueError(
            "cassandra connection_url must be JSON with hosts, username and password"
        ) from exc
    if (
        not isinstance(hosts, list)
        or not hosts
        or not all(isinstance(host, str) and host for host in hosts)
    ):
        raise ValueError("cassandra hosts must be a non-empty string array")
    if not all(isinstance(value, str) and value for value in (username, password)):
        raise ValueError("cassandra username and password must be non-empty strings")
    port = cfg.get("port", 9042)
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("cassandra port must be between 1 and 65535")
    keyspace = cfg.get("keyspace")
    if keyspace is not None and (not isinstance(keyspace, str) or not keyspace):
        raise ValueError("cassandra keyspace must be a non-empty string")
    tls = cfg.get("tls", True)
    if not isinstance(tls, bool):
        raise ValueError("cassandra tls must be a boolean")
    ca_cert = cfg.get("ca_cert")
    if ca_cert is not None and (not isinstance(ca_cert, str) or not ca_cert):
        raise ValueError("cassandra ca_cert must be a non-empty path")
    if ca_cert is not None and not tls:
        raise ValueError("cassandra ca_cert requires tls")
    server_name = cfg.get("server_name")
    if tls and (
        not isinstance(server_name, str)
        or not server_name
        or any(character.isspace() for character in server_name)
    ):
        raise ValueError("cassandra server_name is required with tls")
    if not tls and server_name is not None:
        raise ValueError("cassandra server_name requires tls")
    return CassandraConnection(
        hosts=tuple(hosts),
        port=port,
        username=username,
        password=password,
        keyspace=keyspace,
        tls=tls,
        ca_cert=ca_cert,
        server_name=server_name,
    )


def _connect(cfg: CassandraConnection):
    from cassandra.auth import PlainTextAuthProvider
    from cassandra.cluster import Cluster

    context = None
    if cfg.tls:
        context = ssl.create_default_context(cafile=cfg.ca_cert)
    auth = PlainTextAuthProvider(username=cfg.username, password=cfg.password)
    cluster = Cluster(
        contact_points=list(cfg.hosts),
        port=cfg.port,
        auth_provider=auth,
        ssl_context=context,
        ssl_options={"server_hostname": cfg.server_name} if context else None,
        connect_timeout=ENGINE_CONNECT_TIMEOUT,
        control_connection_timeout=ENGINE_CONNECT_TIMEOUT,
    )
    try:
        session = cluster.connect(cfg.keyspace)
    except Exception:
        cluster.shutdown()
        raise
    return cluster, session


def _split_cql(cql: str) -> list[str]:
    statements = []
    current = []
    state = "normal"
    index = 0
    while index < len(cql):
        character = cql[index]
        following = cql[index : index + 2]

        if state == "normal":
            if character == "'":
                state = "string"
            elif character == '"':
                state = "identifier"
            elif following in {"--", "//"}:
                state = "line_comment"
                current.append(following)
                index += 2
                continue
            elif following == "/*":
                state = "block_comment"
                current.append(following)
                index += 2
                continue
            elif character == ";":
                if statement := "".join(current).strip():
                    statements.append(statement)
                current = []
                index += 1
                continue
        elif state in {"string", "identifier"}:
            delimiter = "'" if state == "string" else '"'
            if character == delimiter:
                if index + 1 < len(cql) and cql[index + 1] == delimiter:
                    current.append(delimiter * 2)
                    index += 2
                    continue
                state = "normal"
        elif state == "line_comment":
            if character in "\r\n":
                state = "normal"
        elif state == "block_comment" and following == "*/":
            current.append(following)
            state = "normal"
            index += 2
            continue

        current.append(character)
        index += 1

    if state in {"string", "identifier", "block_comment"}:
        raise ValueError("CQL contains an unterminated quoted value or comment")
    if statement := "".join(current).strip():
        statements.append(statement)
    if not statements:
        raise ValueError("CQL must contain at least one statement")
    return statements


def _reject_template_comments(cql: str) -> None:
    if any(marker in cql for marker in ("--", "//", "/*")):
        raise ValueError("Cassandra dynamic role templates must not contain comments")


def _validate_creation_template(creation: str) -> None:
    _reject_template_comments(creation)
    statements = _split_cql(creation)
    if _TEMPLATE_CREATE.fullmatch(statements[0]) is None:
        raise ValueError(
            "Cassandra creation must create {{name}} with the generated password"
        )
    if any(
        _TEMPLATE_GRANT.fullmatch(statement) is None for statement in statements[1:]
    ):
        raise ValueError("Cassandra creation may only grant privileges to {{name}}")
    if (
        creation.count("{{name}}") != len(statements)
        or creation.count("{{password}}") != 1
    ):
        raise ValueError("Cassandra creation contains invalid placeholders")
    remaining = creation.replace("{{name}}", "").replace("{{password}}", "")
    if "{{" in remaining or "}}" in remaining:
        raise ValueError("Cassandra creation contains unknown placeholders")


def _validate_revocation_template(revocation: str) -> None:
    _reject_template_comments(revocation)
    statements = _split_cql(revocation)
    if len(statements) != 1 or _TEMPLATE_REVOKE.fullmatch(statements[0]) is None:
        raise ValueError("Cassandra revocation must drop exactly {{name}}")


def _validate_rendered_creation(rendered: str) -> None:
    _reject_template_comments(rendered)
    statements = _split_cql(rendered)
    match = re.fullmatch(
        r"CREATE\s+ROLE\s+(rh_[a-z0-9_]*_[0-9a-f]{16})\s+WITH\s+"
        r"LOGIN\s*=\s*true\s+AND\s+PASSWORD\s*=\s*'[^']+'",
        statements[0],
        re.IGNORECASE,
    )
    if match is None:
        raise ValueError("Cassandra creation must target the generated role")
    username = match.group(1)
    if not is_generated_username(username):
        raise ValueError("Cassandra creation must target the generated role")
    grant = re.compile(
        rf"GRANT\s+.+\s+TO\s+{re.escape(username)}",
        re.IGNORECASE | re.DOTALL,
    )
    if any(grant.fullmatch(statement) is None for statement in statements[1:]):
        raise ValueError("Cassandra grants must target the generated role")


def _validate_rendered_revocation(rendered: str) -> None:
    _reject_template_comments(rendered)
    statements = _split_cql(rendered)
    if len(statements) != 1:
        raise ValueError("Cassandra revocation must drop exactly one role")
    match = re.fullmatch(
        r"DROP\s+ROLE\s+IF\s+EXISTS\s+(rh_[a-z0-9_]*_[0-9a-f]{8,16})",
        statements[0],
        re.IGNORECASE,
    )
    if match is None or not is_generated_username(match.group(1), allow_legacy=True):
        raise ValueError("Cassandra revocation must target the generated role")


def _execute_sync(cfg: CassandraConnection, cql: str) -> None:
    statements = _split_cql(cql)
    cluster, session = _connect(cfg)
    try:
        for statement in statements:
            session.execute(statement, timeout=ENGINE_CONNECT_TIMEOUT)
    finally:
        cluster.shutdown()


def _probe_sync(cfg: CassandraConnection) -> EngineProbe:
    cluster, session = _connect(cfg)
    try:
        row = session.execute(
            "SELECT release_version FROM system.local",
            timeout=ENGINE_CONNECT_TIMEOUT,
        ).one()
        version = str(row.release_version) if row is not None else None
        return EngineProbe("Apache Cassandra", version)
    finally:
        cluster.shutdown()


class CassandraEngine(DynamicEngine):
    engine_type = "cassandra"
    support = EngineSupport(
        display_name="Apache Cassandra",
        driver_module="cassandra",
        validated_targets=(),
        implementation_targets=("Apache Cassandra role authentication",),
        creation_example=(
            "CREATE ROLE {{name}} WITH LOGIN = true "
            "AND PASSWORD = '{{password}}'; "
            "GRANT SELECT ON KEYSPACE app TO {{name}}"
        ),
        revocation_example="DROP ROLE IF EXISTS {{name}}",
    )

    def validate_conn(self, conn_url: str) -> None:
        parse_connection(conn_url)

    def validate_role_templates(self, creation: str, revocation: str) -> None:
        _validate_creation_template(creation)
        _validate_revocation_template(revocation)

    async def provision(self, conn_url: str, rendered: str) -> None:
        _validate_rendered_creation(rendered)
        cfg = parse_connection(conn_url)
        await asyncio.to_thread(_execute_sync, cfg, rendered)

    async def revoke(self, conn_url: str, rendered: str) -> None:
        _validate_rendered_revocation(rendered)
        cfg = parse_connection(conn_url)
        await asyncio.to_thread(_execute_sync, cfg, rendered)

    async def probe(self, conn_url: str) -> EngineProbe:
        cfg = parse_connection(conn_url)
        return await asyncio.to_thread(_probe_sync, cfg)


ENGINE = CassandraEngine()
