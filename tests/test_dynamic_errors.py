# SPDX-License-Identifier: AGPL-3.0-or-later
"""dynamic-secrets error paths reachable without a live target engine.

The bulk of dynamic.py is exercised only against a real PostgreSQL/MySQL/LDAP
target (integration suites). These cover the cheap, real branches that need no
backend: engine-not-found 404s and the abstract-engine contract.
"""

import asyncio
import uuid
from types import SimpleNamespace

import pytest
from api.app.database import async_session
from api.app.dynamic_engines.base import DynamicEngine
from api.app.routes import dynamic
from fastapi import HTTPException
from sqlalchemy import text

PFX = "/api/v1/vault/dynamic"


@pytest.mark.asyncio
async def test_dynamic_engine_not_found_404s(client, master_password, admin_token):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    h = {"Authorization": f"Bearer {admin_token}"}
    bogus = str(uuid.uuid4())
    # roles listing + credential issuance against a non-existent engine -> 404
    r_roles = await client.get(f"{PFX}/engines/{bogus}/roles", headers=h)
    r_creds = await client.post(f"{PFX}/engines/{bogus}/creds/somerole", headers=h)
    assert r_roles.status_code == 404
    assert r_creds.status_code == 404


def test_dynamic_engine_abstract_contract():
    with pytest.raises(TypeError, match="abstract"):
        DynamicEngine()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("endpoint", "detail"),
    [
        ("revoke", "Lease not found or already revoked"),
        ("renew", "Lease not found, revoked, or already expired"),
    ],
)
async def test_invalid_lease_uuid_returns_404_before_database_cast(
    client,
    master_password,
    admin_token,
    endpoint,
    detail,
):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    response = await client.post(
        f"{PFX}/leases/not-a-uuid/{endpoint}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert response.status_code == 404
    assert response.json()["detail"] == detail


@pytest.mark.asyncio
async def test_lease_renew_rejects_unknown_fields(
    client,
    master_password,
    admin_token,
):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    response = await client.post(
        f"{PFX}/leases/{uuid.uuid4()}/renew",
        json={"ttl_seconds": 3600, "max_ttl_seconds": 999999},
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert response.status_code == 422
    assert response.json()["detail"][0]["type"] == "extra_forbidden"


@pytest.mark.asyncio
async def test_connection_url_reports_missing_engine_key_material(client, caplog):
    class MissingKeyResult:
        @staticmethod
        def fetchone():
            return SimpleNamespace(
                name="broken-engine",
                connection_url=b"ciphertext",
                nonce=b"nonce",
                dek_id=None,
                encrypted_key=None,
                dek_nonce=None,
            )

    class MissingKeySession:
        @staticmethod
        async def execute(*_args, **_kwargs):
            return MissingKeyResult()

    with caplog.at_level("CRITICAL", logger="rhorizon.dynamic"):
        with pytest.raises(HTTPException) as error:
            await dynamic._get_connection_url(MissingKeySession(), str(uuid.uuid4()))

    assert error.value.status_code == 500
    assert error.value.detail == "Engine key material unavailable"
    assert "broken-engine" not in caplog.text
    async with async_session() as db:
        nullable = (
            await db.execute(
                text("""
                    SELECT is_nullable
                    FROM information_schema.columns
                    WHERE table_name = 'vault_dynamic_engines'
                      AND column_name = 'dek_id'
                """)
            )
        ).scalar_one()
    assert nullable == "NO"


@pytest.mark.asyncio
@pytest.mark.parametrize("endpoint", ["probe", "create"])
async def test_dynamic_engine_rejects_unknown_namespace_before_remote_work(
    client,
    master_password,
    admin_token,
    monkeypatch,
    endpoint,
):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    async def must_not_probe(_conn_url):
        raise AssertionError("unknown namespace reached the target engine")

    monkeypatch.setattr(dynamic.ENGINES["postgresql"], "probe", must_not_probe)
    payload = {
        "namespace": "missing-dynamic-namespace",
        "engine_type": "postgresql",
        "connection_url": "postgresql://admin:pw@target/db",
    }
    if endpoint == "probe":
        response = await client.post(
            f"{PFX}/engines/test-connection",
            json=payload,
            headers=headers,
        )
    else:
        response = await client.post(
            f"{PFX}/engines",
            json={"name": "orphan-engine", **payload},
            headers=headers,
        )

    assert response.status_code == 404
    assert response.json()["detail"] == "Namespace not found"

    async with async_session() as db:
        orphan_count = (
            await db.execute(
                text("""
                    SELECT COUNT(*)
                    FROM vault_dynamic_engines
                    WHERE namespace = 'missing-dynamic-namespace'
                """)
            )
        ).scalar_one()
    assert orphan_count == 0


@pytest.mark.asyncio
async def test_dynamic_engine_rejects_archived_namespace(
    client,
    master_password,
    admin_token,
    monkeypatch,
):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}
    namespace = f"archived-dynamic-{uuid.uuid4().hex}"

    async with async_session() as db:
        await db.execute(
            text("""
                INSERT INTO vault_namespaces
                    (name, owner_group_id, archived_at)
                SELECT :namespace, owner_group_id, NOW()
                FROM vault_namespaces
                WHERE name = 'default'
            """),
            {"namespace": namespace},
        )
        await db.commit()

    async def must_not_probe(_conn_url):
        raise AssertionError("archived namespace reached the target engine")

    monkeypatch.setattr(dynamic.ENGINES["postgresql"], "probe", must_not_probe)
    response = await client.post(
        f"{PFX}/engines/test-connection",
        json={
            "namespace": namespace,
            "engine_type": "postgresql",
            "connection_url": "postgresql://admin:pw@target/db",
        },
        headers=headers,
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Namespace not found"

    async with async_session() as db:
        await db.execute(
            text("DELETE FROM vault_namespaces WHERE name = :namespace"),
            {"namespace": namespace},
        )
        await db.commit()


@pytest.mark.asyncio
async def test_duplicate_dynamic_engine_returns_409_without_orphan_dek(
    client,
    master_password,
    admin_token,
):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}
    payload = {
        "name": f"duplicate-engine-{uuid.uuid4().hex}",
        "engine_type": "postgresql",
        "connection_url": "postgresql://admin:pw@target/db",
    }

    created = await client.post(f"{PFX}/engines", json=payload, headers=headers)
    assert created.status_code == 201

    async with async_session() as db:
        engine_dek_id = (
            await db.execute(
                text("""
                    SELECT dek_id
                    FROM vault_dynamic_engines
                    WHERE id = CAST(:id AS uuid)
                """),
                {"id": created.json()["id"]},
            )
        ).scalar_one()
        dek_count_before = (
            await db.execute(text("SELECT COUNT(*) FROM vault_dek"))
        ).scalar_one()

    duplicate = await client.post(f"{PFX}/engines", json=payload, headers=headers)

    assert duplicate.status_code == 409
    assert duplicate.json()["detail"] == "Dynamic engine name already exists"
    async with async_session() as db:
        dek_count_after = (
            await db.execute(text("SELECT COUNT(*) FROM vault_dek"))
        ).scalar_one()
    assert dek_count_after == dek_count_before

    cleanup = await client.delete(
        f"{PFX}/engines/{created.json()['id']}",
        headers=headers,
    )
    assert cleanup.status_code == 200
    async with async_session() as db:
        deleted_dek_exists = (
            await db.execute(
                text(
                    "SELECT EXISTS ("
                    "SELECT 1 FROM vault_dek WHERE id = CAST(:dek_id AS uuid)"
                    ")"
                ),
                {"dek_id": str(engine_dek_id)},
            )
        ).scalar_one()
    assert deleted_dek_exists is False


@pytest.mark.asyncio
@pytest.mark.parametrize("cleanup_fails", [False, True])
@pytest.mark.parametrize("provision_error", [RuntimeError, ImportError])
async def test_partial_provision_is_tracked_and_compensated(
    client,
    master_password,
    admin_token,
    monkeypatch,
    cleanup_fails,
    provision_error,
):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}
    engine_response = await client.post(
        f"{PFX}/engines",
        json={
            "name": f"partial-{provision_error.__name__}-{cleanup_fails}",
            "engine_type": "postgresql",
            "connection_url": "postgresql://admin:pw@target/db",
        },
        headers=headers,
    )
    engine_id = engine_response.json()["id"]
    await client.post(
        f"{PFX}/engines/{engine_id}/roles",
        json={
            "name": "reader",
            "creation_sql": "CREATE ROLE {{name}}",
            "revocation_sql": "DROP ROLE IF EXISTS {{name}}",
        },
        headers=headers,
    )

    async def fail_after_possible_mutation(*_args):
        raise provision_error("target rejected a later statement")

    async def compensate(*_args):
        if cleanup_fails:
            raise RuntimeError("target unavailable during cleanup")

    monkeypatch.setattr(dynamic, "_provision_credential", fail_after_possible_mutation)
    monkeypatch.setattr(dynamic, "_revoke_credential", compensate)
    if provision_error is ImportError:
        monkeypatch.setattr(dynamic, "driver_available", lambda _module: True)

    response = await client.post(
        f"{PFX}/engines/{engine_id}/creds/reader",
        headers=headers,
    )
    assert response.status_code == 502

    async with async_session() as db:
        state = (
            await db.execute(
                text("""
                    SELECT provisioning, revoked, revocation_verified,
                           expires_at <= NOW() AS expired
                    FROM vault_leases
                    WHERE engine_id = CAST(:id AS uuid)
                """),
                {"id": engine_id},
            )
        ).one()

    assert state.provisioning is False
    assert state.revoked is (not cleanup_fails)
    assert state.revocation_verified is (not cleanup_fails)
    assert state.expired is cleanup_fails

    async def cleanup(*_args):
        return None

    monkeypatch.setattr(dynamic, "_revoke_credential", cleanup)
    delete_response = await client.delete(
        f"{PFX}/engines/{engine_id}",
        headers=headers,
    )
    assert delete_response.status_code == 200


@pytest.mark.asyncio
async def test_provisioning_lease_blocks_concurrent_mutations(
    client,
    master_password,
    admin_token,
):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}
    engine_response = await client.post(
        f"{PFX}/engines",
        json={
            "name": "provisioning-race",
            "engine_type": "postgresql",
            "connection_url": "postgresql://admin:pw@target/db",
        },
        headers=headers,
    )
    engine_id = engine_response.json()["id"]

    async with async_session() as db:
        lease_id = str(
            (
                await db.execute(
                    text("""
                        INSERT INTO vault_leases
                            (engine_id, role_name, username, revocation_sql,
                             expires_at, provisioning)
                        VALUES
                            (CAST(:engine_id AS uuid), 'reader', 'rh_pending',
                             'DROP ROLE IF EXISTS {{name}}',
                             NOW() + INTERVAL '1 hour', true)
                        RETURNING id
                    """),
                    {"engine_id": engine_id},
                )
            )
            .one()
            .id
        )
        await db.commit()

    leases = await client.get(f"{PFX}/leases", headers=headers)
    pending = next(item for item in leases.json()["items"] if item["id"] == lease_id)
    assert pending["provisioning"] is True

    revoke = await client.post(f"{PFX}/leases/{lease_id}/revoke", headers=headers)
    renew = await client.post(
        f"{PFX}/leases/{lease_id}/renew",
        json={"ttl_seconds": 3600},
        headers=headers,
    )
    delete = await client.delete(f"{PFX}/engines/{engine_id}", headers=headers)

    assert revoke.status_code == 409
    assert renew.status_code == 409
    assert delete.status_code == 409

    async with async_session() as db:
        await db.execute(
            text("DELETE FROM vault_leases WHERE id = CAST(:id AS uuid)"),
            {"id": lease_id},
        )
        await db.commit()
    cleanup = await client.delete(f"{PFX}/engines/{engine_id}", headers=headers)
    assert cleanup.status_code == 200


@pytest.mark.asyncio
async def test_expired_unrevoked_lease_remains_visible(
    client,
    master_password,
    admin_token,
):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}
    created = await client.post(
        f"{PFX}/engines",
        json={
            "name": f"visible-expired-{uuid.uuid4().hex}",
            "engine_type": "postgresql",
            "connection_url": "postgresql://admin:pw@target/db",
        },
        headers=headers,
    )
    assert created.status_code == 201
    engine_id = created.json()["id"]
    async with async_session() as db:
        lease_id = str(
            (
                await db.execute(
                    text("""
                        INSERT INTO vault_leases
                            (engine_id, role_name, username, revocation_sql,
                             expires_at)
                        VALUES
                            (CAST(:engine_id AS uuid), 'reader',
                             'rh_expired_visible',
                             'DROP ROLE IF EXISTS {{name}}',
                             NOW() - INTERVAL '1 minute')
                        RETURNING id
                    """),
                    {"engine_id": engine_id},
                )
            )
            .one()
            .id
        )
        await db.commit()

    leases = await client.get(f"{PFX}/leases", headers=headers)
    visible = next(item for item in leases.json()["items"] if item["id"] == lease_id)
    assert visible["expired"] is True
    assert visible["revoked"] is False
    assert visible["revocation_verified"] is False
    assert visible["provisioning"] is False

    async with async_session() as db:
        await db.execute(
            text("DELETE FROM vault_leases WHERE id = CAST(:id AS uuid)"),
            {"id": lease_id},
        )
        await db.commit()
    cleanup = await client.delete(f"{PFX}/engines/{engine_id}", headers=headers)
    assert cleanup.status_code == 200


@pytest.mark.asyncio
async def test_expired_provisioning_lease_is_operator_recoverable(
    client,
    master_password,
    admin_token,
    monkeypatch,
):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}
    created = await client.post(
        f"{PFX}/engines",
        json={
            "name": f"stale-provisioning-{uuid.uuid4().hex}",
            "engine_type": "postgresql",
            "connection_url": "postgresql://admin:pw@target/db",
        },
        headers=headers,
    )
    assert created.status_code == 201
    engine_id = created.json()["id"]

    async def insert_stale_lease(username):
        async with async_session() as db:
            lease_id = str(
                (
                    await db.execute(
                        text("""
                            INSERT INTO vault_leases
                                (engine_id, role_name, username, revocation_sql,
                                 expires_at, provisioning)
                            VALUES
                                (CAST(:engine_id AS uuid), 'reader', :username,
                                 'DROP ROLE IF EXISTS {{name}}',
                                 NOW() - INTERVAL '1 minute', true)
                            RETURNING id
                        """),
                        {"engine_id": engine_id, "username": username},
                    )
                )
                .one()
                .id
            )
            await db.commit()
        return lease_id

    revoked_usernames = []

    async def revoke_ok(_engine_type, _url, _template, username):
        revoked_usernames.append(username)

    monkeypatch.setattr(dynamic, "_revoke_credential", revoke_ok)
    manual_lease_id = await insert_stale_lease("rh_stale_manual")
    manual = await client.post(
        f"{PFX}/leases/{manual_lease_id}/revoke",
        headers=headers,
    )
    assert manual.status_code == 200

    delete_lease_id = await insert_stale_lease("rh_stale_delete")
    deleted = await client.delete(f"{PFX}/engines/{engine_id}", headers=headers)
    assert deleted.status_code == 200
    assert revoked_usernames == ["rh_stale_manual", "rh_stale_delete"]

    async with async_session() as db:
        remaining = (
            await db.execute(
                text(
                    "SELECT COUNT(*) FROM vault_leases "
                    "WHERE id IN (CAST(:manual AS uuid), CAST(:deleted AS uuid))"
                ),
                {"manual": manual_lease_id, "deleted": delete_lease_id},
            )
        ).scalar_one()
    assert remaining == 0


@pytest.mark.asyncio
async def test_engine_delete_waits_for_provisioning_lease_admission(
    client,
    master_password,
    admin_token,
    monkeypatch,
):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}
    engine_response = await client.post(
        f"{PFX}/engines",
        json={
            "name": f"admission-race-{uuid.uuid4().hex}",
            "engine_type": "postgresql",
            "connection_url": "postgresql://admin:pw@target/db",
        },
        headers=headers,
    )
    engine_id = engine_response.json()["id"]
    role_response = await client.post(
        f"{PFX}/engines/{engine_id}/roles",
        json={
            "name": "reader",
            "creation_sql": "CREATE ROLE {{name}}",
            "revocation_sql": "DROP ROLE IF EXISTS {{name}}",
        },
        headers=headers,
    )
    assert role_response.status_code == 201

    connection_read_started = asyncio.Event()
    allow_connection_read = asyncio.Event()
    remote_provision_started = asyncio.Event()
    allow_remote_provision = asyncio.Event()
    original_get_connection_url = dynamic._get_connection_url

    async def gated_get_connection_url(db, requested_engine_id):
        connection_read_started.set()
        await allow_connection_read.wait()
        return await original_get_connection_url(db, requested_engine_id)

    async def gated_provision(*_args):
        remote_provision_started.set()
        await allow_remote_provision.wait()
        return None

    async def revoke_ok(*_args):
        return None

    monkeypatch.setattr(dynamic, "_get_connection_url", gated_get_connection_url)
    monkeypatch.setattr(dynamic, "_provision_credential", gated_provision)
    monkeypatch.setattr(dynamic, "_revoke_credential", revoke_ok)

    credential_task = asyncio.create_task(
        client.post(
            f"{PFX}/engines/{engine_id}/creds/reader",
            headers=headers,
        )
    )
    await asyncio.wait_for(connection_read_started.wait(), timeout=2)

    delete_task = asyncio.create_task(
        client.delete(f"{PFX}/engines/{engine_id}", headers=headers)
    )
    with pytest.raises(asyncio.TimeoutError):
        await asyncio.wait_for(asyncio.shield(delete_task), timeout=0.1)

    allow_connection_read.set()
    await asyncio.wait_for(remote_provision_started.wait(), timeout=2)
    delete_response = await asyncio.wait_for(delete_task, timeout=2)
    assert delete_response.status_code == 409
    assert "provisioning operation in progress" in delete_response.text

    allow_remote_provision.set()
    credential_response = await asyncio.wait_for(credential_task, timeout=2)
    assert credential_response.status_code == 200

    cleanup = await client.delete(
        f"{PFX}/engines/{engine_id}",
        headers=headers,
    )
    assert cleanup.status_code == 200


@pytest.mark.asyncio
async def test_role_creation_rejects_archived_engine_namespace(
    client,
    master_password,
    admin_token,
    monkeypatch,
):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}
    namespace = f"archived-role-{uuid.uuid4().hex}"
    async with async_session() as db:
        await db.execute(
            text("""
                INSERT INTO vault_namespaces (name, owner_group_id)
                SELECT :namespace, owner_group_id
                FROM vault_namespaces
                WHERE name = 'default'
            """),
            {"namespace": namespace},
        )
        await db.commit()

    created = await client.post(
        f"{PFX}/engines",
        json={
            "name": f"archived-role-engine-{uuid.uuid4().hex}",
            "namespace": namespace,
            "engine_type": "postgresql",
            "connection_url": "postgresql://admin:pw@target/db",
        },
        headers=headers,
    )
    assert created.status_code == 201
    engine_id = created.json()["id"]
    initial_role = await client.post(
        f"{PFX}/engines/{engine_id}/roles",
        json={
            "name": "reader",
            "creation_sql": "CREATE ROLE {{name}}",
            "revocation_sql": "DROP ROLE IF EXISTS {{name}}",
        },
        headers=headers,
    )
    assert initial_role.status_code == 201
    async with async_session() as db:
        renew_lease_id = str(
            (
                await db.execute(
                    text("""
                        INSERT INTO vault_leases
                            (engine_id, role_name, username, revocation_sql,
                             expires_at)
                        VALUES
                            (CAST(:engine_id AS uuid), 'reader',
                             'rh_archived_renew',
                             'DROP ROLE IF EXISTS {{name}}',
                             NOW() + INTERVAL '1 hour')
                        RETURNING id
                    """),
                    {"engine_id": engine_id},
                )
            )
            .one()
            .id
        )
        await db.execute(
            text(
                "UPDATE vault_namespaces SET archived_at = NOW() "
                "WHERE name = :namespace"
            ),
            {"namespace": namespace},
        )
        await db.commit()

    role = await client.post(
        f"{PFX}/engines/{engine_id}/roles",
        json={
            "name": "writer",
            "creation_sql": "CREATE ROLE {{name}}",
            "revocation_sql": "DROP ROLE IF EXISTS {{name}}",
        },
        headers=headers,
    )
    assert role.status_code == 404
    assert role.json()["detail"] == "Namespace not found"

    async def must_not_provision(*_args):
        raise AssertionError("archived namespace reached remote provisioning")

    monkeypatch.setattr(dynamic, "_provision_credential", must_not_provision)
    credentials = await client.post(
        f"{PFX}/engines/{engine_id}/creds/reader",
        headers=headers,
    )
    assert credentials.status_code == 404
    assert credentials.json()["detail"] == "Namespace not found"

    renewal = await client.post(
        f"{PFX}/leases/{renew_lease_id}/renew",
        json={"ttl_seconds": 3600},
        headers=headers,
    )
    assert renewal.status_code == 404
    assert renewal.json()["detail"] == "Namespace not found"

    async with async_session() as db:
        await db.execute(
            text("DELETE FROM vault_leases WHERE id = CAST(:id AS uuid)"),
            {"id": renew_lease_id},
        )
        await db.commit()
    cleanup = await client.delete(f"{PFX}/engines/{engine_id}", headers=headers)
    assert cleanup.status_code == 200
    async with async_session() as db:
        await db.execute(
            text("DELETE FROM vault_namespaces WHERE name = :namespace"),
            {"namespace": namespace},
        )
        await db.commit()


@pytest.mark.asyncio
async def test_role_creation_waits_for_engine_mutation_lock(
    client,
    master_password,
    admin_token,
):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}
    created = await client.post(
        f"{PFX}/engines",
        json={
            "name": f"role-lock-{uuid.uuid4().hex}",
            "engine_type": "postgresql",
            "connection_url": "postgresql://admin:pw@target/db",
        },
        headers=headers,
    )
    assert created.status_code == 201
    engine_id = created.json()["id"]

    async with async_session() as lock_db:
        await dynamic._lock_engine_mutation(lock_db, engine_id)
        role_task = asyncio.create_task(
            client.post(
                f"{PFX}/engines/{engine_id}/roles",
                json={
                    "name": "reader",
                    "creation_sql": "CREATE ROLE {{name}}",
                    "revocation_sql": "DROP ROLE IF EXISTS {{name}}",
                },
                headers=headers,
            )
        )
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(asyncio.shield(role_task), timeout=0.1)
        await lock_db.commit()

    role_response = await asyncio.wait_for(role_task, timeout=2)
    assert role_response.status_code == 201
    cleanup = await client.delete(f"{PFX}/engines/{engine_id}", headers=headers)
    assert cleanup.status_code == 200


@pytest.mark.asyncio
async def test_duplicate_dynamic_role_returns_409(
    client,
    master_password,
    admin_token,
):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}
    created = await client.post(
        f"{PFX}/engines",
        json={
            "name": f"duplicate-role-engine-{uuid.uuid4().hex}",
            "engine_type": "postgresql",
            "connection_url": "postgresql://admin:pw@target/db",
        },
        headers=headers,
    )
    assert created.status_code == 201
    engine_id = created.json()["id"]
    role_payload = {
        "name": "reader",
        "creation_sql": "CREATE ROLE {{name}}",
        "revocation_sql": "DROP ROLE IF EXISTS {{name}}",
    }
    first = await client.post(
        f"{PFX}/engines/{engine_id}/roles",
        json=role_payload,
        headers=headers,
    )
    duplicate = await client.post(
        f"{PFX}/engines/{engine_id}/roles",
        json=role_payload,
        headers=headers,
    )

    assert first.status_code == 201
    assert duplicate.status_code == 409
    assert (
        duplicate.json()["detail"] == "Dynamic role name already exists for this engine"
    )
    async with async_session() as db:
        role_count = (
            await db.execute(
                text("""
                    SELECT COUNT(*)
                    FROM vault_dynamic_roles
                    WHERE engine_id = CAST(:engine_id AS uuid)
                      AND name = 'reader'
                """),
                {"engine_id": engine_id},
            )
        ).scalar_one()
    assert role_count == 1

    cleanup = await client.delete(f"{PFX}/engines/{engine_id}", headers=headers)
    assert cleanup.status_code == 200


@pytest.mark.asyncio
async def test_credential_expiry_uses_database_clock(
    client,
    master_password,
    admin_token,
    monkeypatch,
):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}
    created = await client.post(
        f"{PFX}/engines",
        json={
            "name": f"database-clock-{uuid.uuid4().hex}",
            "engine_type": "postgresql",
            "connection_url": "postgresql://admin:pw@target/db",
        },
        headers=headers,
    )
    assert created.status_code == 201
    engine_id = created.json()["id"]
    role = await client.post(
        f"{PFX}/engines/{engine_id}/roles",
        json={
            "name": "reader",
            "creation_sql": "CREATE ROLE {{name}}",
            "revocation_sql": "DROP ROLE IF EXISTS {{name}}",
            "default_ttl_seconds": 60,
            "max_ttl_seconds": 60,
        },
        headers=headers,
    )
    assert role.status_code == 201

    class ForbiddenLocalClock:
        @staticmethod
        def now(*_args, **_kwargs):
            raise AssertionError("credential generation read the API host clock")

    async def provision_ok(*_args):
        return None

    async def revoke_ok(*_args):
        return None

    monkeypatch.setattr(dynamic, "datetime", ForbiddenLocalClock, raising=False)
    monkeypatch.setattr(dynamic, "_provision_credential", provision_ok)
    monkeypatch.setattr(dynamic, "_revoke_credential", revoke_ok)
    credentials = await client.post(
        f"{PFX}/engines/{engine_id}/creds/reader",
        headers=headers,
    )
    assert credentials.status_code == 200
    assert credentials.headers["cache-control"] == "no-store"
    assert credentials.headers["pragma"] == "no-cache"
    renewal = await client.post(
        f"{PFX}/leases/{credentials.json()['lease_id']}/renew",
        json={"ttl_seconds": 60},
        headers=headers,
    )
    assert renewal.status_code == 409

    async with async_session() as db:
        lifetime = (
            await db.execute(
                text("""
                    SELECT EXTRACT(EPOCH FROM (expires_at - created_at))
                    FROM vault_leases
                    WHERE id = CAST(:lease_id AS uuid)
                """),
                {"lease_id": credentials.json()["lease_id"]},
            )
        ).scalar_one()
    assert 59 <= float(lifetime) <= 60

    cleanup = await client.delete(f"{PFX}/engines/{engine_id}", headers=headers)
    assert cleanup.status_code == 200


@pytest.mark.asyncio
async def test_late_provision_cannot_resurrect_reaped_lease(
    client,
    master_password,
    admin_token,
    monkeypatch,
):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}
    created = await client.post(
        f"{PFX}/engines",
        json={
            "name": f"late-provision-{uuid.uuid4().hex}",
            "engine_type": "postgresql",
            "connection_url": "postgresql://admin:pw@target/db",
        },
        headers=headers,
    )
    assert created.status_code == 201
    engine_id = created.json()["id"]
    role = await client.post(
        f"{PFX}/engines/{engine_id}/roles",
        json={
            "name": "reader",
            "creation_sql": "CREATE ROLE {{name}}",
            "revocation_sql": "DROP ROLE IF EXISTS {{name}}",
            "default_ttl_seconds": 60,
            "max_ttl_seconds": 60,
        },
        headers=headers,
    )
    assert role.status_code == 201

    async def provision_after_reaper(*_args):
        async with async_session() as reaper_db:
            await reaper_db.execute(
                text("""
                    UPDATE vault_leases
                    SET provisioning = false,
                        revoked = true,
                        revocation_verified = true,
                        expires_at = NOW() - INTERVAL '1 second'
                    WHERE engine_id = CAST(:engine_id AS uuid)
                      AND provisioning
                """),
                {"engine_id": engine_id},
            )
            await reaper_db.commit()
        return None

    revoked_usernames = []

    async def revoke_late_credential(_engine_type, _url, _template, username):
        revoked_usernames.append(username)

    monkeypatch.setattr(dynamic, "_provision_credential", provision_after_reaper)
    monkeypatch.setattr(dynamic, "_revoke_credential", revoke_late_credential)
    credentials = await client.post(
        f"{PFX}/engines/{engine_id}/creds/reader",
        headers=headers,
    )

    assert credentials.status_code == 502
    assert credentials.json()["detail"] == "Failed to create target credentials"
    assert len(revoked_usernames) == 1
    async with async_session() as db:
        lease_state = (
            await db.execute(
                text("""
                    SELECT provisioning, revoked, revocation_verified
                    FROM vault_leases
                    WHERE engine_id = CAST(:engine_id AS uuid)
                """),
                {"engine_id": engine_id},
            )
        ).one()
    assert lease_state.provisioning is False
    assert lease_state.revoked is True
    assert lease_state.revocation_verified is True

    cleanup = await client.delete(f"{PFX}/engines/{engine_id}", headers=headers)
    assert cleanup.status_code == 200


@pytest.mark.asyncio
async def test_renew_does_not_resurrect_concurrently_revoked_lease(
    client,
    master_password,
    admin_token,
    monkeypatch,
):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}
    created = await client.post(
        f"{PFX}/engines",
        json={
            "name": f"renew-race-{uuid.uuid4().hex}",
            "engine_type": "postgresql",
            "connection_url": "postgresql://admin:pw@target/db",
        },
        headers=headers,
    )
    assert created.status_code == 201
    engine_id = created.json()["id"]
    async with async_session() as db:
        lease = (
            await db.execute(
                text("""
                    INSERT INTO vault_leases
                        (engine_id, role_name, username, revocation_sql,
                         expires_at)
                    VALUES
                        (CAST(:engine_id AS uuid), 'reader', 'rh_renew_race',
                         'DROP ROLE IF EXISTS {{name}}',
                         NOW() + INTERVAL '5 minutes')
                    RETURNING id, expires_at
                """),
                {"engine_id": engine_id},
            )
        ).one()
        lease_id = str(lease.id)
        original_expiry = lease.expires_at
        await db.commit()

    namespace_checked = asyncio.Event()
    allow_renewal = asyncio.Event()
    original_require_active = dynamic._require_active_namespace

    async def gated_require_active(db, namespace):
        await original_require_active(db, namespace)
        namespace_checked.set()
        await allow_renewal.wait()

    monkeypatch.setattr(dynamic, "_require_active_namespace", gated_require_active)
    renew_task = asyncio.create_task(
        client.post(
            f"{PFX}/leases/{lease_id}/renew",
            json={"ttl_seconds": 3600},
            headers=headers,
        )
    )
    await asyncio.wait_for(namespace_checked.wait(), timeout=2)
    async with async_session() as db:
        await db.execute(
            text("""
                UPDATE vault_leases
                SET revoked = true, revocation_verified = true
                WHERE id = CAST(:id AS uuid)
            """),
            {"id": lease_id},
        )
        await db.commit()
    allow_renewal.set()

    renewal = await asyncio.wait_for(renew_task, timeout=2)
    assert renewal.status_code == 409
    assert renewal.json()["detail"] == (
        "Lease changed during renewal; reload and retry"
    )
    async with async_session() as db:
        state = (
            await db.execute(
                text("""
                    SELECT revoked, revocation_verified, expires_at
                    FROM vault_leases
                    WHERE id = CAST(:id AS uuid)
                """),
                {"id": lease_id},
            )
        ).one()
    assert state.revoked is True
    assert state.revocation_verified is True
    assert state.expires_at == original_expiry

    cleanup = await client.delete(f"{PFX}/engines/{engine_id}", headers=headers)
    assert cleanup.status_code == 200


@pytest.mark.asyncio
async def test_dynamic_ttl_invariants_are_enforced(
    client,
    master_password,
    admin_token,
):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    invalid_engine = await client.post(
        f"{PFX}/engines",
        json={
            "name": "invalid-engine-ttl",
            "engine_type": "postgresql",
            "connection_url": "postgresql://admin:pw@target/db",
            "max_ttl_seconds": 0,
        },
        headers=headers,
    )
    assert invalid_engine.status_code == 422

    engine_response = await client.post(
        f"{PFX}/engines",
        json={
            "name": "engine-ttl-cap",
            "engine_type": "postgresql",
            "connection_url": "postgresql://admin:pw@target/db",
            "max_ttl_seconds": 120,
        },
        headers=headers,
    )
    engine_id = engine_response.json()["id"]
    over_engine_cap = await client.post(
        f"{PFX}/engines/{engine_id}/roles",
        json={
            "name": "too-long",
            "creation_sql": "CREATE ROLE {{name}}",
            "revocation_sql": "DROP ROLE IF EXISTS {{name}}",
            "default_ttl_seconds": 60,
            "max_ttl_seconds": 300,
        },
        headers=headers,
    )
    inverted_role_ttl = await client.post(
        f"{PFX}/engines/{engine_id}/roles",
        json={
            "name": "inverted",
            "creation_sql": "CREATE ROLE {{name}}",
            "revocation_sql": "DROP ROLE IF EXISTS {{name}}",
            "default_ttl_seconds": 120,
            "max_ttl_seconds": 60,
        },
        headers=headers,
    )

    assert over_engine_cap.status_code == 400
    assert inverted_role_ttl.status_code == 422

    cleanup = await client.delete(f"{PFX}/engines/{engine_id}", headers=headers)
    assert cleanup.status_code == 200


@pytest.mark.asyncio
async def test_missing_driver_cannot_create_persisted_engine(
    client,
    master_password,
    admin_token,
    monkeypatch,
):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}
    monkeypatch.setattr(dynamic, "driver_available", lambda _module: False)

    response = await client.post(
        f"{PFX}/engines",
        json={
            "name": "missing-driver-engine",
            "engine_type": "redis",
            "connection_url": "rediss://admin:pw@redis.example/0",
        },
        headers=headers,
    )

    assert response.status_code == 501
    async with async_session() as db:
        count = (
            await db.execute(
                text(
                    "SELECT count(*) FROM vault_dynamic_engines "
                    "WHERE name = 'missing-driver-engine'"
                )
            )
        ).scalar_one()
    assert count == 0


@pytest.mark.asyncio
async def test_redis_role_rejects_fixed_or_additional_credentials(
    client,
    master_password,
    admin_token,
    monkeypatch,
):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}
    monkeypatch.setattr(dynamic, "driver_available", lambda _module: True)
    engine_response = await client.post(
        f"{PFX}/engines",
        json={
            "name": "redis-template-scope",
            "engine_type": "redis",
            "connection_url": "rediss://admin:pw@redis.example/0",
        },
        headers=headers,
    )
    engine_id = engine_response.json()["id"]

    fixed_user = await client.post(
        f"{PFX}/engines/{engine_id}/roles",
        json={
            "name": "fixed-user",
            "creation_sql": (
                "ACL SETUSER rh_fixed_deadbeef reset on >{{password}} +@read"
            ),
            "revocation_sql": "ACL DELUSER {{name}}",
        },
        headers=headers,
    )
    extra_password = await client.post(
        f"{PFX}/engines/{engine_id}/roles",
        json={
            "name": "extra-password",
            "creation_sql": (
                "ACL SETUSER {{name}} reset on >{{password}} >static +@read"
            ),
            "revocation_sql": "ACL DELUSER {{name}}",
        },
        headers=headers,
    )
    valid = await client.post(
        f"{PFX}/engines/{engine_id}/roles",
        json={
            "name": "valid",
            "creation_sql": (
                "ACL SETUSER {{name}} reset on >{{password}} ~app:* +@read"
            ),
            "revocation_sql": "ACL DELUSER {{name}}",
        },
        headers=headers,
    )

    assert fixed_user.status_code == 400
    assert extra_password.status_code == 400
    assert valid.status_code == 201

    cleanup = await client.delete(f"{PFX}/engines/{engine_id}", headers=headers)
    assert cleanup.status_code == 200
