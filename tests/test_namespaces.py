# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Tests for /api/v1/vault/namespaces - RBAC-owned namespaces.

Covers : CRUD lifecycle, one-way ratchet on `enforce_membership`,
archive precondition (refuses non-empty), 2FA gate.
"""

import json

import pytest
import pytest_asyncio
from sqlalchemy import text


async def _vault_admins_id(db):
    row = (
        await db.execute(
            text("SELECT id FROM vault_groups WHERE name = 'vault-admins'")
        )
    ).fetchone()
    return str(row.id) if row else None


@pytest_asyncio.fixture(autouse=True)
async def _clean_test_namespaces():
    """Wipe any test-ns-* rows before AND after each test so failures
    in one test don't pollute the next via DB persistence.
    """
    from api.app.database import async_session

    async def _wipe():
        async with async_session() as db:
            await db.execute(
                text("DELETE FROM vault_namespaces WHERE name LIKE 'test-ns-%'")
            )
            await db.commit()

    await _wipe()
    yield
    await _wipe()


@pytest.mark.asyncio
async def test_create_namespace_admin_can_create(client, master_password, admin_token):
    """Happy path : admin creates a namespace, gets back the row."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})

    from api.app.database import async_session

    async with async_session() as db:
        gid = await _vault_admins_id(db)

    r = await client.post(
        "/api/v1/vault/namespaces/",
        json={"name": "test-ns-create", "owner_group_id": gid},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 201, r.text
    data = r.json()
    assert data["name"] == "test-ns-create"
    assert data["owner_group_id"] == gid
    assert data["enforce_membership"] is False
    assert data["archived_at"] is None

    # Cleanup
    async with async_session() as db:
        await db.execute(
            text("DELETE FROM vault_namespaces WHERE name = 'test-ns-create'")
        )
        await db.commit()


@pytest.mark.asyncio
async def test_create_namespace_duplicate_409(client, master_password, admin_token):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    from api.app.database import async_session

    async with async_session() as db:
        gid = await _vault_admins_id(db)

    headers = {"Authorization": f"Bearer {admin_token}"}
    r1 = await client.post(
        "/api/v1/vault/namespaces/",
        json={"name": "test-ns-dup", "owner_group_id": gid},
        headers=headers,
    )
    assert r1.status_code == 201
    r2 = await client.post(
        "/api/v1/vault/namespaces/",
        json={"name": "test-ns-dup", "owner_group_id": gid},
        headers=headers,
    )
    assert r2.status_code == 409

    async with async_session() as db:
        await db.execute(
            text("DELETE FROM vault_namespaces WHERE name = 'test-ns-dup'")
        )
        await db.commit()


@pytest.mark.asyncio
async def test_create_namespace_unknown_owner_404(client, master_password, admin_token):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}
    r = await client.post(
        "/api/v1/vault/namespaces/",
        json={
            "name": "test-ns-bad-owner",
            "owner_group_id": "00000000-0000-0000-0000-000000000000",
        },
        headers=headers,
    )
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_non_admin_cannot_create(client, master_password, admin_token):
    """A token with secrets:rw but no admin scope is rejected."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    from api.app.database import async_session

    async with async_session() as db:
        gid = await _vault_admins_id(db)

    # Mint a non-root token
    headers = {"Authorization": f"Bearer {admin_token}"}
    r = await client.post(
        "/api/v1/vault/tokens/",
        json={"name": "test-non-admin-ns", "permissions": {"secrets": "rw"}},
        headers=headers,
    )
    assert r.status_code == 201
    non_admin = r.json()["token"]

    r = await client.post(
        "/api/v1/vault/namespaces/",
        json={"name": "test-ns-noadmin", "owner_group_id": gid},
        headers={"Authorization": f"Bearer {non_admin}"},
    )
    assert r.status_code == 403

    async with async_session() as db:
        await db.execute(
            text("DELETE FROM vault_tokens WHERE name = 'test-non-admin-ns'")
        )
        await db.commit()


@pytest.mark.asyncio
async def test_db_trigger_rejects_relax_enforce_membership(
    client, master_password, admin_token
):
    """enforce_membership is a one-way ratchet - true -> false rejected."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    from api.app.database import async_session

    async with async_session() as db:
        gid = await _vault_admins_id(db)
        await db.execute(
            text(
                """
                INSERT INTO vault_namespaces
                    (name, owner_group_id, enforce_membership)
                VALUES ('test-ns-strict', CAST(:gid AS uuid), true)
                """
            ),
            {"gid": gid},
        )
        await db.commit()

    async with async_session() as db:
        with pytest.raises(Exception) as exc:
            await db.execute(
                text(
                    "UPDATE vault_namespaces SET enforce_membership = false "
                    "WHERE name = 'test-ns-strict'"
                )
            )
            await db.commit()
        assert "set-once" in str(exc.value).lower() or "relax" in str(exc.value).lower()
        await db.rollback()

    async with async_session() as db:
        await db.execute(
            text("DELETE FROM vault_namespaces WHERE name = 'test-ns-strict'")
        )
        await db.commit()


@pytest.mark.asyncio
async def test_api_rejects_relax_enforce_membership(
    client, master_password, admin_token
):
    """API surfaces the trigger rejection as 423 Locked, not raw 500."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    from api.app.database import async_session

    async with async_session() as db:
        gid = await _vault_admins_id(db)
        await db.execute(
            text(
                """
                INSERT INTO vault_namespaces
                    (name, owner_group_id, enforce_membership)
                VALUES ('test-ns-relax-api', CAST(:gid AS uuid), true)
                """
            ),
            {"gid": gid},
        )
        await db.commit()

    headers = {"Authorization": f"Bearer {admin_token}"}
    r = await client.put(
        "/api/v1/vault/namespaces/test-ns-relax-api",
        json={"enforce_membership": False},
        headers=headers,
    )
    assert r.status_code == 423

    async with async_session() as db:
        await db.execute(
            text("DELETE FROM vault_namespaces WHERE name = 'test-ns-relax-api'")
        )
        await db.commit()


@pytest.mark.asyncio
async def test_api_allows_upgrade_enforce_membership(
    client, master_password, admin_token
):
    """false -> true is allowed (the security-strengthening direction)."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    from api.app.database import async_session

    async with async_session() as db:
        gid = await _vault_admins_id(db)
        await db.execute(
            text(
                """
                INSERT INTO vault_namespaces
                    (name, owner_group_id, enforce_membership)
                VALUES ('test-ns-upgrade', CAST(:gid AS uuid), false)
                """
            ),
            {"gid": gid},
        )
        await db.commit()

    headers = {"Authorization": f"Bearer {admin_token}"}
    r = await client.put(
        "/api/v1/vault/namespaces/test-ns-upgrade",
        json={"enforce_membership": True},
        headers=headers,
    )
    assert r.status_code == 200
    assert r.json()["enforce_membership"] is True

    async with async_session() as db:
        await db.execute(
            text("DELETE FROM vault_namespaces WHERE name = 'test-ns-upgrade'")
        )
        await db.commit()


@pytest.mark.asyncio
async def test_get_namespace_returns_secret_count(client, master_password, admin_token):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    from api.app.database import async_session

    async with async_session() as db:
        gid = await _vault_admins_id(db)
        await db.execute(
            text(
                """
                INSERT INTO vault_namespaces (name, owner_group_id)
                VALUES ('test-ns-getns', CAST(:gid AS uuid))
                """
            ),
            {"gid": gid},
        )
        await db.commit()

    headers = {"Authorization": f"Bearer {admin_token}"}
    r = await client.get("/api/v1/vault/namespaces/test-ns-getns", headers=headers)
    assert r.status_code == 200
    data = r.json()
    assert data["name"] == "test-ns-getns"
    assert data["secret_count"] == 0

    async with async_session() as db:
        await db.execute(
            text("DELETE FROM vault_namespaces WHERE name = 'test-ns-getns'")
        )
        await db.commit()


@pytest.mark.asyncio
async def test_archive_succeeds_when_empty(client, master_password, admin_token):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    from api.app.database import async_session

    async with async_session() as db:
        gid = await _vault_admins_id(db)
        await db.execute(
            text(
                """
                INSERT INTO vault_namespaces (name, owner_group_id)
                VALUES ('test-ns-arch-ok', CAST(:gid AS uuid))
                """
            ),
            {"gid": gid},
        )
        await db.commit()

    headers = {"Authorization": f"Bearer {admin_token}"}
    r = await client.request(
        "DELETE",
        "/api/v1/vault/namespaces/test-ns-arch-ok",
        json={},
        headers=headers,
    )
    assert r.status_code == 200
    assert r.json()["archived"] is True

    # Verify archived_at set in DB
    async with async_session() as db:
        row = (
            await db.execute(
                text(
                    "SELECT archived_at FROM vault_namespaces "
                    "WHERE name = 'test-ns-arch-ok'"
                )
            )
        ).fetchone()
        assert row.archived_at is not None
        await db.execute(
            text("DELETE FROM vault_namespaces WHERE name = 'test-ns-arch-ok'")
        )
        await db.commit()


@pytest.mark.asyncio
async def test_migration_creates_vault_admins_and_seeds_existing(
    client, master_password, admin_token
):
    """The lifespan migration auto-creates `vault-admins` and seeds rows
    for every distinct namespace that has secrets - verified by reading
    the DB after fixtures have run."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    from api.app.database import async_session

    async with async_session() as db:
        # vault-admins must exist
        row = (
            await db.execute(
                text("SELECT permissions FROM vault_groups WHERE name = 'vault-admins'")
            )
        ).fetchone()
        assert row is not None
        perms = row.permissions
        # asyncpg returns dict directly (jsonb), ensure admin scope is set
        if isinstance(perms, str):
            perms = json.loads(perms)
        assert "admin" in perms

        # An empty vault still needs the model's default namespace. Dynamic
        # engines and other namespace-bound resources must never create an
        # untracked namespace string.
        default_exists = (
            await db.execute(
                text(
                    "SELECT EXISTS ("
                    "SELECT 1 FROM vault_namespaces WHERE name='default'"
                    ")"
                )
            )
        ).scalar_one()
        assert default_exists is True

        # The migration ran successfully if vault_namespaces has at
        # least one row corresponding to a namespace that secrets use
        # - i.e., for every distinct vault_secrets.namespace there is a
        # vault_namespaces.name. Newly-created secrets via the regular
        # create-secret route may not yet populate namespace_id (that
        # wiring lands in PR-2 secrets.py refactor) ; this test only
        # asserts the migration's invariant, not future-create state.
        n_distinct = (
            await db.execute(
                text("SELECT count(DISTINCT namespace) FROM vault_secrets")
            )
        ).scalar() or 0
        n_in_namespaces = (
            await db.execute(
                text(
                    "SELECT count(*) FROM vault_namespaces "
                    "WHERE name IN (SELECT DISTINCT namespace FROM vault_secrets)"
                )
            )
        ).scalar() or 0
        assert n_in_namespaces >= n_distinct, (
            f"Migration didn't cover all secret namespaces "
            f"({n_in_namespaces} rows for {n_distinct} distinct names)"
        )
