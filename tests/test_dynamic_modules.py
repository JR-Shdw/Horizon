# SPDX-License-Identifier: AGPL-3.0-or-later
"""Closed dynamic-module loader and native Redis/Cassandra backends."""

import asyncio
import re
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest
from api.app.dynamic_engines import cassandra as cassandra_engine
from api.app.dynamic_engines import ldap as ldap_engine
from api.app.dynamic_engines import mysql as mysql_engine
from api.app.dynamic_engines import postgresql as postgresql_engine
from api.app.dynamic_engines import redis as redis_engine
from api.app.dynamic_engines.base import (
    ENGINE_CONNECT_TIMEOUT,
    DynamicEngine,
    driver_available,
    is_generated_username,
)
from api.app.dynamic_engines.loader import (
    BUILTIN_METADATA,
    BUILTIN_MODULES,
    load_engines,
)
from api.app.routes import dynamic
from fastapi import HTTPException


def _config(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "dynamic-engines.ini"
    path.write_text(f"[modules]\n{body}", encoding="utf-8")
    return path


def test_loader_imports_only_enabled_closed_catalog_modules(tmp_path, monkeypatch):
    from api.app.dynamic_engines import loader

    imported = []
    real_import = loader.import_module

    def tracked_import(name, package):
        imported.append(name)
        return real_import(name, package)

    monkeypatch.setattr(loader, "import_module", tracked_import)
    engines = load_engines(
        str(
            _config(
                tmp_path,
                "postgresql = enabled\nredis = disabled\n# cassandra = enabled\n",
            )
        ),
        {"postgresql"},
    )

    assert set(engines) == {"postgresql"}
    assert imported == [".postgresql"]


@pytest.mark.parametrize(
    "body",
    [
        "arbitrary.module = enabled\n",
        "redis = maybe\n",
    ],
)
def test_loader_rejects_arbitrary_modules_and_invalid_states(tmp_path, body):
    with pytest.raises(RuntimeError):
        load_engines(str(_config(tmp_path, body)), set())


def test_loader_rejects_inherited_default_module_states(tmp_path):
    config = tmp_path / "dynamic-engines.ini"
    config.write_text(
        "[DEFAULT]\nredis = enabled\n[modules]\npostgresql = enabled\n",
        encoding="utf-8",
    )

    with pytest.raises(RuntimeError, match="explicit"):
        load_engines(str(config), set())


def test_dynamic_engine_contract_rejects_incomplete_backends():
    class IncompleteEngine(DynamicEngine):
        pass

    with pytest.raises(TypeError, match="abstract"):
        IncompleteEngine()


@pytest.mark.parametrize(
    ("model", "payload"),
    [
        (
            dynamic.EngineCreate,
            {"name": "", "engine_type": "postgresql", "connection_url": "dsn"},
        ),
        (
            dynamic.EngineCreate,
            {
                "name": "db",
                "namespace": "",
                "engine_type": "postgresql",
                "connection_url": "dsn",
            },
        ),
        (
            dynamic.EngineConnectionTest,
            {"engine_type": "", "connection_url": "dsn"},
        ),
        (
            dynamic.EngineConnectionTest,
            {"engine_type": "postgresql", "connection_url": ""},
        ),
        (
            dynamic.EngineCreate,
            {
                "name": "db",
                "engine_type": "postgresql",
                "connection_url": "dsn",
                "max_ttl_seconds": 2_147_483_648,
            },
        ),
        (
            dynamic.RoleCreate,
            {
                "name": "role",
                "creation_sql": "create",
                "revocation_sql": "revoke",
                "max_ttl_seconds": 2_147_483_648,
            },
        ),
    ],
)
def test_dynamic_models_reject_empty_identifiers_and_oversized_ttls(model, payload):
    with pytest.raises(ValueError):
        model(**payload)


@pytest.mark.parametrize(
    ("model", "payload"),
    [
        (dynamic.ModuleStateUpdate, {"enabled": "yes"}),
        (
            dynamic.EngineCreate,
            {
                "name": "db",
                "engine_type": "postgresql",
                "connection_url": "dsn",
                "max_ttl": 60,
            },
        ),
        (dynamic.CredRequest, {"ttl_seconds": 60, "unexpected": True}),
    ],
)
def test_dynamic_models_reject_coerced_state_and_unknown_fields(model, payload):
    with pytest.raises(ValueError):
        model(**payload)


def test_driver_detection_resolves_only_the_top_level_package(monkeypatch):
    looked_up = []

    def passive_find_spec(module_name):
        looked_up.append(module_name)
        return object()

    monkeypatch.setattr(
        "api.app.dynamic_engines.base.find_spec",
        passive_find_spec,
    )

    assert driver_available("redis.asyncio") is True
    assert looked_up == ["redis"]


def test_generated_username_format_keeps_legacy_acceptance_revocation_only():
    current = "rh_app_deadbeefcafebabe"
    legacy = "rh_app_deadbeef"

    assert is_generated_username(current)
    assert not is_generated_username(legacy)
    assert is_generated_username(legacy, allow_legacy=True)


@pytest.mark.parametrize(
    "value",
    [
        "rh__deadbeefcafebabe",
        "rh__deadbeef",
        f"rh_{'a' * 32}_deadbeefcafebabe",
        None,
    ],
)
def test_generated_username_rejects_corrupt_shape_or_length(value):
    assert not is_generated_username(value, allow_legacy=True)


@pytest.mark.asyncio
async def test_engine_namespace_rejects_invalid_uuid_before_database_access():
    class DatabaseMustNotRun:
        async def execute(self, *_args, **_kwargs):
            raise AssertionError("invalid UUID reached PostgreSQL")

    with pytest.raises(HTTPException) as exc_info:
        await dynamic._engine_namespace(DatabaseMustNotRun(), "not-a-uuid")

    assert exc_info.value.status_code == 404
    assert exc_info.value.detail == "Engine not found"


@pytest.mark.asyncio
async def test_dynamic_namespace_filter_resolves_names_and_uuids():
    namespace_id = "11111111-1111-4111-8111-111111111111"

    class Result:
        def fetchall(self):
            return [SimpleNamespace(name="prod")]

    class NamespaceDb:
        async def execute(self, *_args, **_kwargs):
            return Result()

    db = NamespaceDb()
    assert await dynamic._allowed_namespaces(db, {"permissions": {}}) is None
    assert (
        await dynamic._allowed_namespaces(
            db,
            {"permissions": {"namespaces": []}},
        )
        == []
    )
    assert (
        await dynamic._allowed_namespaces(
            db,
            {"permissions": {"namespaces": "prod"}},
        )
        == []
    )
    assert await dynamic._allowed_namespaces(
        db,
        {"permissions": {"namespaces": [namespace_id]}},
    ) == ["prod"]
    await dynamic._check_dynamic_namespace(
        db,
        {"permissions": {"namespaces": [namespace_id]}},
        "prod",
    )
    with pytest.raises(HTTPException) as exc_info:
        await dynamic._check_dynamic_namespace(
            db,
            {"permissions": {"admin": "rw", "namespaces": []}},
            "prod",
        )
    assert exc_info.value.status_code == 403


def test_every_builtin_has_an_isolated_folder_and_dependency_manifest():
    root = Path(__file__).parents[1] / "api" / "app" / "dynamic_engines"
    for name in BUILTIN_MODULES:
        module = root / name
        assert (module / "__init__.py").is_file()
        assert (module / "requirements.in").is_file()
        assert (module / "requirements.txt").is_file()


def test_builtin_catalog_metadata_matches_every_engine():
    engines = {
        "postgresql": postgresql_engine.ENGINE,
        "mysql": mysql_engine.ENGINE,
        "ldap": ldap_engine.ENGINE,
        "redis": redis_engine.ENGINE,
        "cassandra": cassandra_engine.ENGINE,
    }

    for engine_type, engine in engines.items():
        assert (
            engine.support.display_name == BUILTIN_METADATA[engine_type]["display_name"]
        )
        assert (
            engine.support.driver_module
            == BUILTIN_METADATA[engine_type]["driver_module"]
        )


def test_optional_drivers_are_not_in_the_core_dependency_manifest():
    root = Path(__file__).parents[1]
    core = (root / "api" / "requirements.in").read_text()
    assert "aiomysql" not in core
    assert "\nredis==" not in core
    assert "cassandra-driver" not in core

    dockerfile = (root / "api" / "Dockerfile").read_text()
    for name in ("mysql", "redis", "cassandra"):
        assert f"dynamic_engines/{name}/requirements.txt" in dockerfile


def test_module_locks_match_core_versions_for_shared_dependencies():
    root = Path(__file__).parents[1]

    def pins(path):
        return dict(
            re.findall(
                r"^([a-zA-Z0-9_.-]+)==([^ \\\n]+)",
                path.read_text(),
                flags=re.MULTILINE,
            )
        )

    core = pins(root / "api" / "requirements.txt")
    modules = root / "api" / "app" / "dynamic_engines"
    for name in BUILTIN_MODULES:
        module = pins(modules / name / "requirements.txt")
        for package in set(core) & set(module):
            assert module[package] == core[package], (name, package)


@pytest.mark.asyncio
async def test_postgresql_commands_have_connection_and_execution_timeouts(monkeypatch):
    calls = {}

    class Connection:
        async def execute(self, sql):
            calls["sql"] = sql

        async def close(self, *, timeout):
            calls["close_timeout"] = timeout

    async def connect(conn_url, **kwargs):
        calls["conn_url"] = conn_url
        calls["kwargs"] = kwargs
        return Connection()

    monkeypatch.setattr(postgresql_engine.asyncpg, "connect", connect)

    await postgresql_engine._execute("postgresql://target/db", "SELECT 1")

    assert calls == {
        "conn_url": "postgresql://target/db",
        "kwargs": {
            "timeout": ENGINE_CONNECT_TIMEOUT,
            "command_timeout": ENGINE_CONNECT_TIMEOUT,
        },
        "sql": "SELECT 1",
        "close_timeout": ENGINE_CONNECT_TIMEOUT,
    }


@pytest.mark.asyncio
async def test_postgresql_probe_has_connection_and_execution_timeouts(monkeypatch):
    calls = {}

    class Connection:
        async def fetchval(self, sql):
            calls["sql"] = sql
            return "18.1"

        async def close(self, *, timeout):
            calls["close_timeout"] = timeout

    async def connect(conn_url, **kwargs):
        calls["conn_url"] = conn_url
        calls["kwargs"] = kwargs
        return Connection()

    monkeypatch.setattr(postgresql_engine.asyncpg, "connect", connect)

    probe = await postgresql_engine.ENGINE.probe("postgresql://target/db")

    assert probe.server_version == "18.1"
    assert calls == {
        "conn_url": "postgresql://target/db",
        "kwargs": {
            "timeout": ENGINE_CONNECT_TIMEOUT,
            "command_timeout": ENGINE_CONNECT_TIMEOUT,
        },
        "sql": "SHOW server_version",
        "close_timeout": ENGINE_CONNECT_TIMEOUT,
    }


@pytest.mark.asyncio
async def test_mysql_connection_decodes_uri_credentials(monkeypatch):
    calls = {}

    async def connect(**kwargs):
        calls.update(kwargs)
        return object()

    monkeypatch.setitem(sys.modules, "aiomysql", SimpleNamespace(connect=connect))

    await mysql_engine._connect(
        "mysql://admin%40example:p%23ss%2Fword@db.example:3307/app%2Fdata"
    )

    assert calls == {
        "host": "db.example",
        "port": 3307,
        "user": "admin@example",
        "password": "p#ss/word",
        "db": "app/data",
        "connect_timeout": ENGINE_CONNECT_TIMEOUT,
    }


@pytest.mark.asyncio
async def test_mysqls_builds_a_verified_tls_context(monkeypatch):
    calls = {}

    class Context:
        def load_cert_chain(self, **kwargs):
            calls["cert_chain"] = kwargs

    context = Context()

    def create_default_context(**kwargs):
        calls["context"] = kwargs
        return context

    async def connect(**kwargs):
        calls["connect"] = kwargs
        return object()

    monkeypatch.setattr(
        mysql_engine.ssl,
        "create_default_context",
        create_default_context,
    )
    monkeypatch.setitem(sys.modules, "aiomysql", SimpleNamespace(connect=connect))

    await mysql_engine._connect(
        "mysqls://admin:pw@db.example/app"
        "?ssl_ca=%2Fetc%2Fca.pem"
        "&ssl_cert=%2Fetc%2Fclient.pem"
        "&ssl_key=%2Fetc%2Fclient.key"
    )

    assert calls["context"] == {"cafile": "/etc/ca.pem"}
    assert calls["cert_chain"] == {
        "certfile": "/etc/client.pem",
        "keyfile": "/etc/client.key",
    }
    assert calls["connect"]["ssl"] is context


@pytest.mark.parametrize(
    "conn_url",
    [
        "postgresql://admin:pw@db.example/app",
        "mysql://admin:pw@db.example/app?ssl_ca=/etc/ca.pem",
        "mysqls://admin:pw@db.example/app?unknown=value",
        "mysqls://admin:pw@db.example/app?ssl_cert=/etc/client.pem",
        "mysqls://admin:pw@db.example/app?ssl_ca=one&ssl_ca=two",
        "mysqls://admin:pw@db.example:0/app",
        "mysqls://admin:pw@db.example:invalid/app",
        "mysql://admin:pw@db.example/app;ignored",
        "mysql://admin:pw@db.example/app#ignored",
    ],
)
def test_mysql_rejects_ambiguous_or_invalid_connection_urls(conn_url):
    with pytest.raises(ValueError):
        mysql_engine.ENGINE.validate_conn(conn_url)


def test_mysql_validation_does_not_read_tls_files(monkeypatch):
    def unexpected_io(**_kwargs):
        raise AssertionError("validation attempted TLS file I/O")

    monkeypatch.setattr(mysql_engine.ssl, "create_default_context", unexpected_io)
    mysql_engine.ENGINE.validate_conn(
        "mysqls://admin:pw@db.example/app?ssl_ca=/not/read/during/validation"
    )


@pytest.mark.parametrize(
    ("engine", "creation", "revocation"),
    [
        (
            postgresql_engine.ENGINE,
            "CREATE ROLE {{name}} LOGIN PASSWORD '{{password}}'",
            'DROP ROLE IF EXISTS "{{name}}"',
        ),
        (
            mysql_engine.ENGINE,
            "CREATE USER '{{name}}'@'%' IDENTIFIED BY '{{password}}'",
            "DROP USER IF EXISTS '{{name}}'@'%'",
        ),
    ],
)
def test_sql_revocation_templates_require_idempotent_generated_identity(
    engine, creation, revocation
):
    engine.validate_role_templates(creation, revocation)


@pytest.mark.parametrize(
    ("engine", "creation", "revocation"),
    [
        (
            postgresql_engine.ENGINE,
            "CREATE ROLE {{name}} LOGIN PASSWORD '{{password}}'",
            'DROP ROLE "{{name}}"',
        ),
        (
            postgresql_engine.ENGINE,
            "CREATE ROLE {{name}} LOGIN PASSWORD '{{password}}'",
            'DROP ROLE IF EXISTS "{{name}}"; DROP ROLE operator',
        ),
        (
            mysql_engine.ENGINE,
            "CREATE USER '{{name}}'@'%' IDENTIFIED BY '{{password}}'",
            "DROP USER '{{name}}'@'%'",
        ),
        (
            mysql_engine.ENGINE,
            "CREATE USER '{{name}}'@'%' IDENTIFIED BY '{{password}}'",
            "DROP USER IF EXISTS 'fixed'@'%'",
        ),
    ],
)
def test_sql_revocation_templates_reject_non_idempotent_or_fixed_targets(
    engine, creation, revocation
):
    with pytest.raises(ValueError):
        engine.validate_role_templates(creation, revocation)


@pytest.mark.parametrize(
    "host",
    [
        "%",
        "localhost",
        "db.internal",
        "2001:db8::1",
        "198.51.100.0/255.255.255.0",
    ],
)
def test_mysql_revocation_accepts_closed_account_host_profile(host):
    mysql_engine.ENGINE.validate_role_templates(
        "CREATE USER '{{name}}'@'%' IDENTIFIED BY '{{password}}'",
        f"DROP USER IF EXISTS '{{{{name}}}}'@'{host}'",
    )


@pytest.mark.parametrize("host", ["host name", "host\\", "host\tname", "host;name"])
def test_mysql_revocation_rejects_ambiguous_account_hosts(host):
    with pytest.raises(ValueError):
        mysql_engine.ENGINE.validate_role_templates(
            "CREATE USER '{{name}}'@'%' IDENTIFIED BY '{{password}}'",
            f"DROP USER IF EXISTS '{{{{name}}}}'@'{host}'",
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("engine", "rendered"),
    [
        (postgresql_engine.ENGINE, 'DROP ROLE IF EXISTS "operator"'),
        (mysql_engine.ENGINE, "DROP USER IF EXISTS 'operator'@'%'"),
    ],
)
async def test_sql_revocation_revalidates_legacy_snapshots_before_io(
    engine, rendered, monkeypatch
):
    async def must_not_execute(*_args):
        raise AssertionError("invalid legacy revocation reached the target")

    module = postgresql_engine if engine is postgresql_engine.ENGINE else mysql_engine
    monkeypatch.setattr(module, "_execute", must_not_execute)

    with pytest.raises(ValueError):
        await engine.revoke("unused", rendered)


@pytest.mark.asyncio
async def test_mysql_execution_timeout_closes_connection(monkeypatch):
    class Cursor:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def execute(self, _statement):
            await asyncio.sleep(1)

    class Connection:
        closed = False

        def cursor(self):
            return Cursor()

        async def commit(self):
            pass

        async def ensure_closed(self):
            self.closed = True

    connection = Connection()

    async def connect(_conn_url):
        return connection

    monkeypatch.setattr(mysql_engine, "_connect", connect)
    monkeypatch.setattr(mysql_engine, "ENGINE_CONNECT_TIMEOUT", 0.01)

    with pytest.raises(TimeoutError):
        await mysql_engine._execute("mysql://target/db", "SELECT 1")

    assert connection.closed is True


@pytest.mark.asyncio
async def test_mysql_probe_timeout_closes_connection(monkeypatch):
    class Cursor:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def execute(self, _statement):
            await asyncio.sleep(1)

    class Connection:
        closed = False

        def cursor(self):
            return Cursor()

        async def ensure_closed(self):
            self.closed = True

    connection = Connection()

    async def connect(_conn_url):
        return connection

    monkeypatch.setattr(mysql_engine, "_connect", connect)
    monkeypatch.setattr(mysql_engine, "ENGINE_CONNECT_TIMEOUT", 0.01)

    with pytest.raises(TimeoutError):
        await mysql_engine.ENGINE.probe("mysql://target/db")

    assert connection.closed is True


@pytest.mark.asyncio
async def test_mysql_probe_uses_vendor_comment_and_closes_connection(monkeypatch):
    calls = {}

    class Cursor:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def execute(self, statement):
            calls["statement"] = statement

        async def fetchone(self):
            return ("8.0.36-28", "Percona Server (GPL)")

    class Connection:
        def cursor(self):
            return Cursor()

        async def ensure_closed(self):
            calls["closed"] = True

    async def connect(_conn_url):
        return Connection()

    monkeypatch.setattr(mysql_engine, "_connect", connect)

    probe = await mysql_engine.ENGINE.probe("mysql://target/db")

    assert probe.product == "Percona Server"
    assert probe.server_version == "8.0.36-28"
    assert calls == {
        "statement": "SELECT VERSION(), @@version_comment",
        "closed": True,
    }


@pytest.mark.parametrize(
    ("version", "comment", "expected"),
    [
        ("8.4.0", "MySQL Community Server - GPL", "MySQL"),
        ("11.4.2-MariaDB", "mariadb.org binary distribution", "MariaDB"),
        ("8.0.36-28", "Percona Server (GPL)", "Percona Server"),
        ("8.0.mysql_aurora.3.08.2", "Amazon Aurora", "Amazon Aurora MySQL"),
        ("8.0.36", "Source distribution", "MySQL-compatible"),
        (None, None, "MySQL-compatible"),
    ],
)
def test_mysql_product_name_does_not_mislabel_compatible_forks(
    version, comment, expected
):
    assert mysql_engine._product_name(version, comment) == expected


class _RecordingDb:
    def __init__(self):
        self.statements = []
        self.commits = 0

    async def execute(self, statement, params):
        self.statements.append((str(statement), params))

    async def commit(self):
        self.commits += 1


@pytest.mark.asyncio
async def test_failed_provision_marks_verified_after_compensation(monkeypatch):
    db = _RecordingDb()

    async def revoke(*_args):
        return None

    monkeypatch.setattr(dynamic, "_revoke_credential", revoke)

    verified = await dynamic._settle_failed_provision(
        db,
        lease_id="00000000-0000-0000-0000-000000000001",
        engine_type="mysql",
        conn_url="mysql://admin:pw@target/db",
        revocation_sql="DROP USER IF EXISTS '{{name}}'@'%'",
        username="rh_app_deadbeef",
    )

    assert verified is True
    assert "revocation_verified = true" in db.statements[0][0]
    assert "provisioning = false" in db.statements[0][0]
    assert db.commits == 1


@pytest.mark.asyncio
async def test_failed_provision_expires_lease_when_compensation_fails(monkeypatch):
    db = _RecordingDb()

    async def revoke(*_args):
        raise RuntimeError("target unavailable")

    monkeypatch.setattr(dynamic, "_revoke_credential", revoke)

    verified = await dynamic._settle_failed_provision(
        db,
        lease_id="00000000-0000-0000-0000-000000000001",
        engine_type="mysql",
        conn_url="mysql://admin:pw@target/db",
        revocation_sql="DROP USER IF EXISTS '{{name}}'@'%'",
        username="rh_app_deadbeef",
    )

    assert verified is False
    assert "expires_at = NOW()" in db.statements[0][0]
    assert "provisioning = false" in db.statements[0][0]
    assert db.commits == 1


class _RedisClient:
    def __init__(self):
        self.commands = []
        self.closed = False

    async def execute_command(self, *parts):
        self.commands.append(parts)

    async def info(self, section):
        assert section == "server"
        return {"redis_version": "8.0.1"}

    async def aclose(self):
        self.closed = True


@pytest.mark.asyncio
async def test_redis_acl_lifecycle_is_command_scoped(monkeypatch):
    client = _RedisClient()

    async def get_client(_url):
        return client

    monkeypatch.setattr(redis_engine, "_client", get_client)
    engine = redis_engine.ENGINE
    engine.validate_conn("rediss://admin:secret@redis.example:6379/0")
    engine.validate_role_templates(
        "ACL SETUSER {{name}} reset on >{{password}} ~app:* +@read",
        "ACL DELUSER {{name}}",
    )

    await engine.provision(
        "rediss://admin:secret@redis.example:6379/0",
        "ACL SETUSER rh_app_deadbeefcafebabe reset on >secret ~app:* +@read",
    )
    await engine.revoke(
        "rediss://admin:secret@redis.example:6379/0",
        "ACL DELUSER rh_app_deadbeefcafebabe",
    )
    probe = await engine.probe("rediss://admin:secret@redis.example:6379/0")

    assert client.commands == [
        (
            "ACL",
            "SETUSER",
            "rh_app_deadbeefcafebabe",
            "reset",
            "on",
            ">secret",
            "~app:*",
            "+@read",
        ),
        ("ACL", "DELUSER", "rh_app_deadbeefcafebabe"),
    ]
    assert probe.product == "Redis"
    assert probe.server_version == "8.0.1"
    assert client.closed


@pytest.mark.parametrize(
    "connection_url",
    [
        "redis://localhost:6379?socket_timeout=0",
        "rediss://localhost:6379/0?ssl_cert_reqs=none",
        "rediss://localhost:6379/0#ignored",
        "redis://localhost:0/0",
        "redis://localhost/not-a-database",
        "redis://[broken",
    ],
)
def test_redis_rejects_connection_options_outside_closed_profile(connection_url):
    with pytest.raises(ValueError):
        redis_engine.ENGINE.validate_conn(connection_url)


@pytest.mark.parametrize(
    "connection_url",
    [
        "redis://localhost",
        "rediss://admin:secret@redis.example:6379/",
        "rediss://admin:secret@redis.example:6379/0",
        "redis://[2001:db8::1]:6379/12",
    ],
)
def test_redis_accepts_closed_connection_profile(connection_url):
    redis_engine.ENGINE.validate_conn(connection_url)


@pytest.mark.parametrize(
    "template",
    [
        "FLUSHALL rh_app_deadbeef",
        "ACL SETUSER administrator on >secret",
        "ACL DELUSER rh_one rh_two",
    ],
)
@pytest.mark.asyncio
async def test_redis_rejects_templates_outside_generated_user_scope(
    monkeypatch, template
):
    async def should_not_connect(_url):
        raise AssertionError("unsafe template must fail before connecting")

    monkeypatch.setattr(redis_engine, "_client", should_not_connect)
    if template.startswith("ACL DELUSER"):
        operation = redis_engine.ENGINE.revoke
    else:
        operation = redis_engine.ENGINE.provision
    with pytest.raises(ValueError):
        await operation("redis://localhost", template)


@pytest.mark.parametrize(
    ("creation", "revocation"),
    [
        (
            "ACL SETUSER rh_fixed_deadbeef reset on >{{password}} +@read",
            "ACL DELUSER {{name}}",
        ),
        (
            "ACL SETUSER {{name}} reset on >{{password}} >static +@read",
            "ACL DELUSER {{name}}",
        ),
        (
            "ACL SETUSER {{name}} reset on nopass +@read",
            "ACL DELUSER {{name}}",
        ),
        (
            "ACL SETUSER {{name}} on >{{password}} +@read",
            "ACL DELUSER {{name}}",
        ),
        (
            "ACL SETUSER {{name}} reset on >{{password}} +@read",
            "ACL DELUSER {{name}} rh_other_deadbeef",
        ),
    ],
)
def test_redis_role_templates_require_generated_identity_and_one_password(
    creation,
    revocation,
):
    with pytest.raises(ValueError):
        redis_engine.ENGINE.validate_role_templates(creation, revocation)


@pytest.mark.asyncio
async def test_redis_revocation_accepts_legacy_generated_username(monkeypatch):
    client = _RedisClient()

    async def get_client(_url):
        return client

    monkeypatch.setattr(redis_engine, "_client", get_client)
    await redis_engine.ENGINE.revoke(
        "redis://localhost",
        "ACL DELUSER rh_legacy_deadbeef",
    )

    assert client.commands == [("ACL", "DELUSER", "rh_legacy_deadbeef")]


def test_cassandra_connection_requires_tls_by_default():
    cfg = cassandra_engine.parse_connection(
        '{"hosts":["cassandra-1","cassandra-2"],"username":"admin",'
        '"password":"secret","server_name":"cassandra.internal"}'
    )
    assert cfg.hosts == ("cassandra-1", "cassandra-2")
    assert cfg.port == 9042
    assert cfg.tls is True
    assert "secret" not in repr(cfg)


@pytest.mark.parametrize(
    "description",
    [
        "{}",
        '{"hosts":[],"username":"admin","password":"secret"}',
        '{"hosts":["db"],"username":"admin","password":"secret","tls":"yes"}',
        '{"hosts":["db"],"username":"admin","password":"secret","port":70000}',
        '{"hosts":["db"],"username":"admin","password":"secret","port":true}',
        (
            '{"hosts":["db"],"username":"admin","password":"secret",'
            '"tls":false,"ca_cert":"/etc/cassandra/ca.pem"}'
        ),
        '{"hosts":["db"],"username":"admin","password":"secret"}',
        (
            '{"hosts":["db"],"username":"admin","password":"secret",'
            '"tls":false,"server_name":"cassandra.internal"}'
        ),
        ('{"hosts":["db"],"username":"admin","password":"first","password":"second"}'),
        ('{"hosts":["db"],"username":"admin","password":"secret","tls_verify":false}'),
    ],
)
def test_cassandra_rejects_malformed_connection_descriptions(description):
    with pytest.raises(ValueError):
        cassandra_engine.parse_connection(description)


@pytest.mark.asyncio
async def test_cassandra_driver_runs_off_the_event_loop(monkeypatch):
    calls = []

    async def fake_to_thread(function, *args):
        calls.append((function, args))
        if function is cassandra_engine._probe_sync:
            return cassandra_engine.EngineProbe("Apache Cassandra", "5.0.4")
        return None

    monkeypatch.setattr(cassandra_engine.asyncio, "to_thread", fake_to_thread)
    engine = cassandra_engine.ENGINE
    description = (
        '{"hosts":["db"],"username":"admin","password":"secret",'
        '"server_name":"cassandra.internal"}'
    )

    await engine.provision(
        description,
        "CREATE ROLE rh_app_deadbeefcafebabe "
        "WITH LOGIN = true AND PASSWORD = 'secret'; "
        "GRANT SELECT ON KEYSPACE app TO rh_app_deadbeefcafebabe",
    )
    await engine.revoke(description, "DROP ROLE IF EXISTS rh_app_deadbeefcafebabe")
    probe = await engine.probe(description)

    assert [call[0] for call in calls] == [
        cassandra_engine._execute_sync,
        cassandra_engine._execute_sync,
        cassandra_engine._probe_sync,
    ]
    assert probe.server_version == "5.0.4"


def test_cassandra_tls_passes_server_identity_to_driver(monkeypatch):
    captured = {}

    class AuthProvider:
        def __init__(self, username, password):
            self.username = username
            self.password = password

    class Cluster:
        def __init__(self, **options):
            captured.update(options)

        def connect(self, keyspace):
            captured["keyspace"] = keyspace
            return object()

        def shutdown(self):
            captured["shutdown"] = True

    cassandra_package = ModuleType("cassandra")
    cassandra_package.__path__ = []
    auth_module = ModuleType("cassandra.auth")
    auth_module.PlainTextAuthProvider = AuthProvider
    cluster_module = ModuleType("cassandra.cluster")
    cluster_module.Cluster = Cluster
    monkeypatch.setitem(sys.modules, "cassandra", cassandra_package)
    monkeypatch.setitem(sys.modules, "cassandra.auth", auth_module)
    monkeypatch.setitem(sys.modules, "cassandra.cluster", cluster_module)

    cfg = cassandra_engine.parse_connection(
        '{"hosts":["db1","db2"],"username":"admin","password":"secret",'
        '"server_name":"cassandra.internal"}'
    )
    cluster, _session = cassandra_engine._connect(cfg)

    assert captured["ssl_context"].verify_mode == cassandra_engine.ssl.CERT_REQUIRED
    assert captured["ssl_context"].check_hostname is True
    assert captured["ssl_options"] == {"server_hostname": "cassandra.internal"}
    cluster.shutdown()


def test_cassandra_cql_splitter_preserves_quoted_and_commented_semicolons():
    assert cassandra_engine._split_cql(
        "CREATE ROLE rh WITH OPTIONS = {'note': 'one;two'}; "
        'GRANT SELECT ON KEYSPACE "app;archive" TO rh; '
        "-- keep ; inside this comment\nDROP ROLE rh"
    ) == [
        "CREATE ROLE rh WITH OPTIONS = {'note': 'one;two'}",
        'GRANT SELECT ON KEYSPACE "app;archive" TO rh',
        "-- keep ; inside this comment\nDROP ROLE rh",
    ]


@pytest.mark.parametrize(
    "cql",
    [
        "",
        " ; ",
        "CREATE ROLE 'unterminated",
        'GRANT SELECT ON KEYSPACE "unterminated',
        "CREATE ROLE rh /* unterminated",
    ],
)
def test_cassandra_cql_splitter_rejects_incomplete_input(cql):
    with pytest.raises(ValueError):
        cassandra_engine._split_cql(cql)


def test_cassandra_dynamic_role_templates_are_scoped_to_generated_role():
    engine = cassandra_engine.ENGINE
    engine.validate_role_templates(
        "CREATE ROLE {{name}} WITH LOGIN = true "
        "AND PASSWORD = '{{password}}'; "
        "GRANT SELECT ON KEYSPACE app TO {{name}}",
        "DROP ROLE IF EXISTS {{name}}",
    )


@pytest.mark.parametrize(
    ("creation", "revocation"),
    [
        (
            "CREATE ROLE admin WITH LOGIN = true AND PASSWORD = '{{password}}'",
            "DROP ROLE IF EXISTS {{name}}",
        ),
        (
            "CREATE ROLE {{name}} WITH LOGIN = true "
            "AND PASSWORD = '{{password}}' AND SUPERUSER = true",
            "DROP ROLE IF EXISTS {{name}}",
        ),
        (
            "CREATE ROLE {{name}} WITH LOGIN = true "
            "AND PASSWORD = '{{password}}'; "
            "GRANT ALL PERMISSIONS ON ALL KEYSPACES TO admin",
            "DROP ROLE IF EXISTS {{name}}",
        ),
        (
            "CREATE ROLE {{name}} WITH LOGIN = true AND PASSWORD = '{{password}}'",
            "DROP ROLE IF EXISTS admin",
        ),
        (
            "CREATE ROLE {{name}} WITH LOGIN = true "
            "AND PASSWORD = '{{password}}' /* trusted */",
            "DROP ROLE IF EXISTS {{name}}",
        ),
        (
            "CREATE ROLE {{name}} WITH LOGIN = true "
            "AND PASSWORD = '{{password}}'; "
            "GRANT SELECT ON KEYSPACE {{keyspace}} TO {{name}}",
            "DROP ROLE IF EXISTS {{name}}",
        ),
    ],
)
def test_cassandra_rejects_role_templates_outside_generated_scope(
    creation,
    revocation,
):
    with pytest.raises(ValueError):
        cassandra_engine.ENGINE.validate_role_templates(creation, revocation)


@pytest.mark.asyncio
async def test_cassandra_rejects_rendered_commands_before_connecting(monkeypatch):
    async def must_not_run(*_args):
        raise AssertionError("unsafe CQL must fail before opening a connection")

    monkeypatch.setattr(cassandra_engine.asyncio, "to_thread", must_not_run)
    with pytest.raises(ValueError):
        await cassandra_engine.ENGINE.provision(
            "not parsed",
            "CREATE ROLE admin WITH LOGIN = true AND PASSWORD = 'secret'",
        )
    with pytest.raises(ValueError):
        await cassandra_engine.ENGINE.revoke(
            "not parsed",
            "DROP ROLE IF EXISTS admin",
        )


def test_cassandra_revocation_accepts_only_current_or_legacy_generated_names():
    cassandra_engine._validate_rendered_revocation(
        "DROP ROLE IF EXISTS rh_legacy_deadbeef"
    )
    cassandra_engine._validate_rendered_revocation(
        "DROP ROLE IF EXISTS rh_current_deadbeefcafebabe"
    )
    with pytest.raises(ValueError):
        cassandra_engine._validate_rendered_revocation(
            "DROP ROLE IF EXISTS rh_invalid_deadbeef00"
        )


class _InvariantResult:
    def __init__(self, rows):
        self._rows = rows

    def fetchall(self):
        return self._rows


class _InvariantDb:
    def __init__(self, rows):
        self.rows = rows

    async def execute(self, _query):
        return _InvariantResult(self.rows)


class _SequenceDb:
    def __init__(self, row_sets):
        self.row_sets = iter(row_sets)

    async def execute(self, _query):
        return _InvariantResult(next(self.row_sets))


@pytest.mark.asyncio
async def test_disabled_module_with_persisted_state_fails_closed(monkeypatch):
    monkeypatch.setattr(dynamic, "ENGINES", {"postgresql": object()})
    row = SimpleNamespace(engine_type="redis", engine_count=1, pending_leases=2)

    with pytest.raises(RuntimeError, match="redis.*pending_leases=2"):
        await dynamic.enforce_enabled_module_invariant(_InvariantDb([row]))


@pytest.mark.asyncio
async def test_missing_driver_with_persisted_state_fails_closed(monkeypatch):
    monkeypatch.setattr(dynamic, "ENGINES", {"redis": redis_engine.ENGINE})
    monkeypatch.setattr(dynamic, "driver_available", lambda _module: False)
    row = SimpleNamespace(engine_type="redis", engine_count=1, pending_leases=2)

    with pytest.raises(RuntimeError, match="redis.*pending_leases=2"):
        await dynamic.enforce_enabled_module_invariant(_InvariantDb([row]))


@pytest.mark.asyncio
async def test_new_module_work_acquires_cluster_transition_lock_first(monkeypatch):
    events = []

    async def lock(_db, engine_type):
        events.append(("lock", engine_type))

    async def overrides(_db):
        events.append(("overrides", None))
        return {}

    monkeypatch.setattr(dynamic, "_lock_module_transition", lock)
    monkeypatch.setattr(dynamic, "_module_overrides", overrides)

    await dynamic._require_module_accepts_new_work(object(), "redis")

    assert events == [("lock", "redis"), ("overrides", None)]


@pytest.mark.asyncio
async def test_boot_imports_only_cluster_enabled_modules(monkeypatch):
    loaded_with = {}
    registry = {}

    def fake_load(_path, enabled):
        loaded_with["enabled"] = enabled
        return {"postgresql": object()}

    monkeypatch.setattr(dynamic, "CONFIGURED_MODULES", ("postgresql", "redis"))
    monkeypatch.setattr(dynamic, "ENGINES", registry)
    monkeypatch.setattr(dynamic, "load_engines", fake_load)
    db = _SequenceDb(
        [
            [SimpleNamespace(module_name="redis", enabled=False)],
            [],
        ]
    )

    await dynamic.initialize_engine_registry(db)

    assert loaded_with["enabled"] == {"postgresql"}
    assert set(registry) == {"postgresql"}
