# SPDX-License-Identifier: AGPL-3.0-or-later
"""Dynamic-engine compatibility registry and probe API."""

import re
from pathlib import Path

import pytest
from api.app.dynamic_engines.base import EngineProbe
from api.app.dynamic_engines.loader import BUILTIN_MODULES
from api.app.routes import dynamic

PFX = "/api/v1/vault/dynamic"


def test_engine_registry_matches_every_schema_constraint():
    schema = (Path(__file__).parent.parent / "schema.sql").read_text()
    clauses = re.findall(
        r"CHECK\s*\(\s*engine_type\s+IN\s*\(([^)]*)\)\s*\)",
        schema,
        flags=re.IGNORECASE,
    )
    assert clauses, "schema.sql has no engine_type CHECK constraint"
    # The database accepts the compiled built-in catalog. Runtime enablement is
    # narrower and controlled independently by dynamic-engines.ini.
    expected = set(BUILTIN_MODULES)
    for clause in clauses:
        assert set(re.findall(r"'([^']+)'", clause)) == expected


@pytest.mark.parametrize(
    ("engine_type", "product", "version", "expected"),
    [
        ("postgresql", "PostgreSQL", "18.1", "validated"),
        ("postgresql", "PostgreSQL", "19beta1", "connected_unvalidated"),
        ("mysql", "MySQL", "8.4.0", "validated"),
        ("mysql", "MySQL", "9.0.1", "connected_unvalidated"),
        ("mysql", "MariaDB", "11.4.2-MariaDB", "validated"),
        ("mysql", "MariaDB", "5.5.5-11.4.2-MariaDB", "validated"),
        ("mysql", "MariaDB", "12.0.0-MariaDB", "connected_unvalidated"),
        ("mysql", "Percona Server", "8.0.36-28", "connected_unvalidated"),
        (
            "mysql",
            "Amazon Aurora MySQL",
            "8.0.mysql_aurora.3.08.2",
            "connected_unvalidated",
        ),
        ("mysql", "MySQL-compatible", "8.0.36", "connected_unvalidated"),
        ("ldap", "lldap", "0.6.2", "validated"),
        ("ldap", "not-lldap", "0.6.2", "connected_unvalidated"),
        ("ldap", "LDAP", "lldap-compatible", "connected_unvalidated"),
        ("ldap", "OpenLDAP", "2.6.8", "connected_unvalidated"),
        ("ldap", "LDAP", None, "connected_unvalidated"),
    ],
)
def test_compatibility_status_is_evidence_based(
    engine_type, product, version, expected
):
    probe = EngineProbe(product=product, server_version=version)
    assert dynamic.ENGINES[engine_type].compatibility_status(probe) == expected


def test_engine_probe_normalizes_bounded_remote_metadata():
    probe = EngineProbe("  LDAP  ", "  2.6.8  ")
    empty_version = EngineProbe("Redis", "   ")

    assert probe.product == "LDAP"
    assert probe.server_version == "2.6.8"
    assert empty_version.server_version is None


@pytest.mark.parametrize(
    ("product", "version"),
    [
        ("", "1"),
        ("x" * 129, "1"),
        ("LDAP\u202e", "1"),
        ("LDAP", "x" * 257),
        ("LDAP", "1\nforged"),
        ("LDAP", "1\u2028forged"),
        ("LDAP", "1\u2029forged"),
    ],
)
def test_engine_probe_rejects_untrusted_remote_metadata(product, version):
    with pytest.raises(ValueError):
        EngineProbe(product, version)


@pytest.mark.asyncio
async def test_compatibility_endpoint_exposes_registry(
    client, master_password, admin_token
):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    response = await client.get(f"{PFX}/engines/compatibility", headers=headers)

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["unknown_version_policy"] == "allow_unvalidated"
    assert {item["engine_type"] for item in body["engines"]} == set(dynamic.ENGINES)
    assert {item["engine_type"] for item in body["available_modules"]} == set(
        BUILTIN_MODULES
    )
    for module in body["available_modules"]:
        assert isinstance(module["configured"], bool)
        assert isinstance(module["enabled"], bool)
        assert isinstance(module["loaded"], bool)
        assert isinstance(module["restart_required"], bool)
    for item in body["engines"]:
        assert isinstance(item["validated_targets"], list)
        assert item["implementation_targets"]
        assert isinstance(item["driver_installed"], bool)


@pytest.mark.asyncio
async def test_connection_probe_reports_validated_target(
    client, master_password, admin_token, monkeypatch
):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    async def probe(conn_url):
        assert conn_url == "postgresql://probe-secret@db.example/test"
        return EngineProbe("PostgreSQL", "18.4")

    monkeypatch.setattr(dynamic.ENGINES["postgresql"], "probe", probe)
    response = await client.post(
        f"{PFX}/engines/test-connection",
        json={
            "engine_type": "postgresql",
            "connection_url": "postgresql://probe-secret@db.example/test",
        },
        headers=headers,
    )

    assert response.status_code == 200, response.text
    assert response.json() == {
        "engine_type": "postgresql",
        "connected": True,
        "product": "PostgreSQL",
        "server_version": "18.4",
        "compatibility": "validated",
        "validated_targets": ["PostgreSQL 18"],
    }


@pytest.mark.asyncio
async def test_connection_probe_failure_does_not_echo_credentials(
    client, master_password, admin_token, monkeypatch
):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}
    leaked = "postgresql://admin:never-return-me@db.example/test"

    async def probe(_conn_url):
        raise RuntimeError(f"driver echoed {leaked}")

    monkeypatch.setattr(dynamic.ENGINES["postgresql"], "probe", probe)
    response = await client.post(
        f"{PFX}/engines/test-connection",
        json={"engine_type": "postgresql", "connection_url": leaked},
        headers=headers,
    )

    assert response.status_code == 502
    assert "never-return-me" not in response.text
    assert response.json()["detail"] == "postgresql connection failed (RuntimeError)"


@pytest.mark.asyncio
async def test_connection_probe_distinguishes_absent_and_broken_driver(
    client,
    master_password,
    admin_token,
    monkeypatch,
):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}
    payload = {
        "engine_type": "postgresql",
        "connection_url": "postgresql://probe@db.example/test",
    }

    async def must_not_probe(_conn_url):
        raise AssertionError("absent driver reached probe")

    monkeypatch.setattr(dynamic.ENGINES["postgresql"], "probe", must_not_probe)
    monkeypatch.setattr(dynamic, "driver_available", lambda _module: False)
    absent = await client.post(
        f"{PFX}/engines/test-connection",
        json=payload,
        headers=headers,
    )

    async def broken_probe(_conn_url):
        raise ImportError("installed driver lost an internal dependency")

    monkeypatch.setattr(dynamic.ENGINES["postgresql"], "probe", broken_probe)
    monkeypatch.setattr(dynamic, "driver_available", lambda _module: True)
    broken = await client.post(
        f"{PFX}/engines/test-connection",
        json=payload,
        headers=headers,
    )

    assert absent.status_code == 501
    assert broken.status_code == 502
    assert broken.json()["detail"] == "postgresql connection failed (ImportError)"


@pytest.mark.asyncio
async def test_connection_probe_reports_engine_timeout(
    client, master_password, admin_token, monkeypatch
):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    async def probe(_conn_url):
        raise TimeoutError

    monkeypatch.setattr(dynamic.ENGINES["postgresql"], "probe", probe)
    response = await client.post(
        f"{PFX}/engines/test-connection",
        json={
            "engine_type": "postgresql",
            "connection_url": "postgresql://probe@db.example/test",
        },
        headers=headers,
    )

    assert response.status_code == 502
    assert response.json()["detail"] == "postgresql connection failed (TimeoutError)"


@pytest.mark.asyncio
async def test_connection_probe_rejects_unknown_engine(
    client, master_password, admin_token
):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = await client.post(
        f"{PFX}/engines/test-connection",
        json={"engine_type": "oracle", "connection_url": "secret"},
        headers=headers,
    )

    assert response.status_code == 400
    for engine_type in dynamic.ENGINES:
        assert engine_type in response.json()["detail"]


@pytest.mark.asyncio
async def test_module_state_is_cluster_wide_and_requires_restart(
    client, master_password, admin_token
):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    disabled = await client.put(
        f"{PFX}/modules/postgresql",
        json={"enabled": False},
        headers=headers,
    )
    assert disabled.status_code == 200, disabled.text
    assert disabled.json() == {
        "engine_type": "postgresql",
        "enabled": False,
        "loaded": True,
        "restart_required": True,
    }

    inventory = await client.get(
        f"{PFX}/engines/compatibility",
        headers=headers,
    )
    postgres = next(
        item
        for item in inventory.json()["available_modules"]
        if item["engine_type"] == "postgresql"
    )
    assert postgres["enabled"] is False
    assert postgres["loaded"] is True
    assert postgres["restart_required"] is True

    blocked = await client.post(
        f"{PFX}/engines",
        json={
            "name": "must-not-start-after-module-disable",
            "engine_type": "postgresql",
            "connection_url": "postgresql://admin:secret@db.example/app",
        },
        headers=headers,
    )
    assert blocked.status_code == 409
    assert "is disabled" in blocked.json()["detail"]

    restored = await client.put(
        f"{PFX}/modules/postgresql",
        json={"enabled": True},
        headers=headers,
    )
    assert restored.status_code == 200, restored.text
    assert restored.json()["restart_required"] is False


@pytest.mark.asyncio
async def test_module_cannot_be_disabled_while_an_engine_uses_it(
    client, master_password, admin_token
):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}
    created = await client.post(
        f"{PFX}/engines",
        json={
            "name": "module-disable-guard",
            "engine_type": "postgresql",
            "connection_url": "postgresql://admin:secret@db.example/app",
        },
        headers=headers,
    )
    assert created.status_code == 201, created.text

    disabled = await client.put(
        f"{PFX}/modules/postgresql",
        json={"enabled": False},
        headers=headers,
    )
    assert disabled.status_code == 409
    assert "Delete every engine" in disabled.json()["detail"]

    deleted = await client.delete(
        f"{PFX}/engines/{created.json()['id']}",
        headers=headers,
    )
    assert deleted.status_code == 200, deleted.text
