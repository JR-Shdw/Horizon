# SPDX-License-Identifier: AGPL-3.0-or-later
"""Focused edge coverage for the closed dynamic-engine boundary."""

import sys
from types import ModuleType, SimpleNamespace

import pytest
from api.app.dynamic_engines import cassandra as cassandra_engine
from api.app.dynamic_engines import loader
from api.app.dynamic_engines import redis as redis_engine
from api.app.dynamic_engines.base import (
    DynamicEngine,
    EngineProbe,
    EngineSupport,
    driver_available,
    engine_capability,
    first_version_number,
    mariadb_major_version,
)


class _ContractEngine(DynamicEngine):
    engine_type = "contract"
    support = EngineSupport("Contract", "missing.driver", (), (), "create", "drop")

    async def provision(self, conn_url, rendered):
        return await super().provision(conn_url, rendered)

    async def revoke(self, conn_url, rendered):
        return await super().revoke(conn_url, rendered)

    async def probe(self, conn_url):
        return await super().probe(conn_url)


@pytest.mark.parametrize(
    ("product", "version", "match"),
    [
        (None, "1", "product must not be empty"),
        (42, "1", "product must be a string"),
        (" ", "1", "product must not be empty"),
        ("x" * 129, "1", "product is too long"),
        ("bad\nproduct", "1", "control characters"),
        ("Redis", " ", None),
    ],
)
def test_engine_probe_normalizes_untrusted_driver_metadata(product, version, match):
    if match:
        with pytest.raises(ValueError, match=match):
            EngineProbe(product, version)
    else:
        assert EngineProbe(product, version).server_version is None


@pytest.mark.asyncio
async def test_dynamic_engine_contract_defaults_and_abstract_guards():
    engine = _ContractEngine()
    assert engine.validate_conn("anything") is None
    assert engine.validate_role_templates("create", "revoke") is None
    assert engine.compatibility_status(EngineProbe("Unknown", None)) == (
        "connected_unvalidated"
    )
    with pytest.raises(NotImplementedError):
        await engine.provision("url", "create")
    with pytest.raises(NotImplementedError):
        await engine.revoke("url", "drop")
    with pytest.raises(NotImplementedError):
        await engine.probe("url")


def test_base_version_and_capability_edge_paths(monkeypatch):
    monkeypatch.setattr(
        "api.app.dynamic_engines.base.find_spec",
        lambda _name: (_ for _ in ()).throw(ValueError("bad spec")),
    )
    assert driver_available("broken.module") is False
    assert first_version_number(None) is None
    assert first_version_number("release") is None
    assert mariadb_major_version(None) is None
    assert mariadb_major_version("5.5.5-11.4.2-MariaDB") == 11

    capability = engine_capability(_ContractEngine())
    assert capability["engine_type"] == "contract"
    assert capability["driver_installed"] is False


def test_loader_rejects_missing_and_unreadable_config(tmp_path, monkeypatch):
    with pytest.raises(RuntimeError, match="not found"):
        loader.configured_modules(str(tmp_path / "missing.ini"))

    path = tmp_path / "dynamic.ini"
    path.write_text("[modules]\nredis=enabled\n")
    monkeypatch.setattr(
        loader.Path,
        "open",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("denied")),
    )
    with pytest.raises(RuntimeError, match="cannot read"):
        loader.configured_modules(str(path))


def test_loader_rejects_cluster_state_outside_ini(tmp_path):
    path = tmp_path / "dynamic.ini"
    path.write_text("[modules]\nredis=disabled\n")
    with pytest.raises(RuntimeError, match="not allowed"):
        loader.load_engines(str(path), {"redis"})


def test_loader_skips_disabled_cluster_module(tmp_path):
    path = tmp_path / "dynamic.ini"
    path.write_text("[modules]\nredis=enabled\n")
    assert loader.load_engines(str(path), set()) == {}


@pytest.mark.parametrize("failure", ["engine", "metadata"])
def test_loader_validates_export_and_fixed_metadata(tmp_path, monkeypatch, failure):
    path = tmp_path / "dynamic.ini"
    path.write_text("[modules]\nredis=enabled\n")
    if failure == "engine":
        module = SimpleNamespace(ENGINE=object())
        match = "invalid ENGINE"
    else:
        engine = redis_engine.RedisEngine()
        engine.support = EngineSupport("Forged", "redis.asyncio", (), (), "", "")
        module = SimpleNamespace(ENGINE=engine)
        match = "metadata"
    monkeypatch.setattr(loader, "import_module", lambda *_args, **_kwargs: module)
    with pytest.raises(RuntimeError, match=match):
        loader.load_engines(str(path), {"redis"})


def test_redis_malformed_quotes_and_scheme_are_rejected():
    with pytest.raises(ValueError, match="redis://"):
        redis_engine._validate_connection_url("http://redis.example")
    with pytest.raises(ValueError, match="malformed Redis ACL"):
        redis_engine._command("ACL SETUSER 'unterminated", ("ACL", "SETUSER"))
    with pytest.raises(ValueError, match="malformed Redis ACL"):
        redis_engine._template_command("ACL SETUSER 'unterminated", ("ACL", "SETUSER"))


@pytest.mark.asyncio
async def test_redis_client_uses_bounded_timeouts(monkeypatch):
    calls = {}

    class Redis:
        @staticmethod
        def from_url(url, **kwargs):
            calls.update(url=url, **kwargs)
            return object()

    package = ModuleType("redis")
    package.__path__ = []
    module = ModuleType("redis.asyncio")
    module.Redis = Redis
    monkeypatch.setitem(sys.modules, "redis", package)
    monkeypatch.setitem(sys.modules, "redis.asyncio", module)

    await redis_engine._client("redis://localhost/0")
    assert calls["socket_connect_timeout"] == redis_engine.ENGINE_CONNECT_TIMEOUT
    assert calls["socket_timeout"] == redis_engine.ENGINE_CONNECT_TIMEOUT


@pytest.mark.asyncio
async def test_redis_revoke_rejects_multiple_generated_targets():
    with pytest.raises(ValueError, match="exactly one"):
        await redis_engine.ENGINE.revoke(
            "redis://localhost",
            "ACL DELUSER rh_app_deadbeefcafebabe extra",
        )


@pytest.mark.parametrize(
    "description",
    [
        '{"hosts":["db"],"username":"","password":"secret","tls":false}',
        '{"hosts":["db"],"username":"admin","password":"secret","keyspace":"","tls":false}',
        '{"hosts":["db"],"username":"admin","password":"secret","ca_cert":"","server_name":"db"}',
    ],
)
def test_cassandra_rejects_empty_sensitive_connection_fields(description):
    with pytest.raises(ValueError):
        cassandra_engine.parse_connection(description)


def test_cassandra_connect_cleans_up_partial_connection(monkeypatch):
    calls = []

    class AuthProvider:
        def __init__(self, **_kwargs):
            pass

    class Cluster:
        def __init__(self, **_kwargs):
            pass

        def connect(self, _keyspace):
            raise RuntimeError("target refused")

        def shutdown(self):
            calls.append("shutdown")

    package = ModuleType("cassandra")
    package.__path__ = []
    auth = ModuleType("cassandra.auth")
    auth.PlainTextAuthProvider = AuthProvider
    cluster = ModuleType("cassandra.cluster")
    cluster.Cluster = Cluster
    monkeypatch.setitem(sys.modules, "cassandra", package)
    monkeypatch.setitem(sys.modules, "cassandra.auth", auth)
    monkeypatch.setitem(sys.modules, "cassandra.cluster", cluster)
    cfg = cassandra_engine.parse_connection(
        '{"hosts":["db"],"username":"admin","password":"secret","tls":false}'
    )
    with pytest.raises(RuntimeError, match="refused"):
        cassandra_engine._connect(cfg)
    assert calls == ["shutdown"]


def test_cassandra_splitter_handles_escaped_quotes_and_block_comment():
    assert cassandra_engine._split_cql(
        "CREATE ROLE 'it''s'; /* internal; comment */ DROP ROLE role"
    ) == ["CREATE ROLE 'it''s'", "/* internal; comment */ DROP ROLE role"]


def test_cassandra_rendered_scope_guards(monkeypatch):
    with pytest.raises(ValueError, match="grants must target"):
        cassandra_engine._validate_rendered_creation(
            "CREATE ROLE rh_app_deadbeefcafebabe WITH LOGIN = true "
            "AND PASSWORD = 'secret'; GRANT SELECT ON KEYSPACE app "
            "TO rh_other_deadbeefcafebabe"
        )
    with pytest.raises(ValueError, match="exactly one"):
        cassandra_engine._validate_rendered_revocation(
            "DROP ROLE IF EXISTS rh_app_deadbeefcafebabe; "
            "DROP ROLE IF EXISTS rh_other_deadbeefcafebabe"
        )
    monkeypatch.setattr(
        cassandra_engine, "is_generated_username", lambda *_a, **_k: False
    )
    with pytest.raises(ValueError, match="generated role"):
        cassandra_engine._validate_rendered_creation(
            "CREATE ROLE rh_app_deadbeefcafebabe WITH LOGIN = true "
            "AND PASSWORD = 'secret'"
        )


def test_cassandra_sync_execution_and_probe_always_close(monkeypatch):
    calls = []

    class Cluster:
        def shutdown(self):
            calls.append("shutdown")

    class Query:
        def __init__(self, one=None):
            self._one = one

        def one(self):
            return self._one

    class Session:
        def execute(self, statement, timeout):
            calls.append((statement, timeout))
            if statement.startswith("SELECT release_version"):
                return Query(SimpleNamespace(release_version="5.0.4"))
            return Query()

    cfg = cassandra_engine.parse_connection(
        '{"hosts":["db"],"username":"admin","password":"secret","tls":false}'
    )
    monkeypatch.setattr(
        cassandra_engine, "_connect", lambda _cfg: (Cluster(), Session())
    )
    cassandra_engine._execute_sync(cfg, "CREATE ROLE one; GRANT SELECT TO one")
    probe = cassandra_engine._probe_sync(cfg)
    assert probe.server_version == "5.0.4"
    assert calls.count("shutdown") == 2


def test_cassandra_validate_conn_exercises_public_boundary():
    cassandra_engine.ENGINE.validate_conn(
        '{"hosts":["db"],"username":"admin","password":"secret","tls":false}'
    )
