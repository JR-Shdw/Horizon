# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Per-namespace delete_protection mode (free / soft / protected).

Validates the three deletion behaviours, the one-way ratchet on the
mode itself, the soft-delete restore path, and the reaper purge.
"""

import pytest
import pytest_asyncio
from sqlalchemy import text


@pytest_asyncio.fixture(autouse=True)
async def _clean():
    from api.app.database import async_session

    async def _wipe():
        async with async_session() as db:
            dek_ids = (
                await db.execute(
                    text("SELECT dek_id FROM vault_secrets WHERE name LIKE 'dp-%'")
                )
            ).fetchall()
            await db.execute(text("DELETE FROM vault_secrets WHERE name LIKE 'dp-%'"))
            for r in dek_ids:
                await db.execute(
                    text("DELETE FROM vault_dek WHERE id = :id"),
                    {"id": str(r.dek_id)},
                )
            await db.execute(
                text("DELETE FROM vault_namespaces WHERE name LIKE 'dp-%'")
            )
            await db.commit()

    await _wipe()
    yield
    await _wipe()


async def _create_ns(client, admin_token, name, mode):
    """Create a namespace with the given delete_protection mode."""
    from api.app.database import async_session

    async with async_session() as db:
        gid = (
            await db.execute(
                text("SELECT id FROM vault_groups WHERE name = 'vault-admins'")
            )
        ).scalar()
    r = await client.post(
        "/api/v1/vault/namespaces/",
        json={
            "name": name,
            "owner_group_id": str(gid),
            "delete_protection": mode,
        },
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 201, r.text
    return r.json()


@pytest.mark.asyncio
async def test_free_mode_hard_deletes(client, master_password, admin_token):
    """In free mode, DELETE drops the row + cleans the orphaned DEK."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}
    await _create_ns(client, admin_token, "dp-ns-free", "free")

    r = await client.post(
        "/api/v1/vault/secrets/",
        json={"name": "dp-secret-free", "value": "v", "namespace": "dp-ns-free"},
        headers=headers,
    )
    assert r.status_code == 201

    r = await client.request(
        "DELETE",
        "/api/v1/vault/secrets/dp-secret-free",
        headers=headers,
    )
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "deleted"
    assert data["mode"] == "free"

    from api.app.database import async_session

    async with async_session() as db:
        row = (
            await db.execute(
                text("SELECT id FROM vault_secrets WHERE name = 'dp-secret-free'")
            )
        ).fetchone()
        assert row is None  # hard delete


@pytest.mark.asyncio
async def test_soft_mode_soft_deletes_and_can_restore(
    client, master_password, admin_token
):
    """Soft mode marks deleted_at + sets purge_after ; restore reverses it."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}
    await _create_ns(client, admin_token, "dp-ns-soft", "soft")

    r = await client.post(
        "/api/v1/vault/secrets/",
        json={"name": "dp-secret-soft", "value": "v", "namespace": "dp-ns-soft"},
        headers=headers,
    )
    assert r.status_code == 201

    # Soft delete
    r = await client.request(
        "DELETE",
        "/api/v1/vault/secrets/dp-secret-soft",
        headers=headers,
    )
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "soft-deleted"
    assert data["mode"] == "soft"
    assert data["retention_days"] == 7

    # Row still in DB but with deleted_at set
    from api.app.database import async_session

    async with async_session() as db:
        row = (
            await db.execute(
                text(
                    "SELECT deleted_at, purge_after FROM vault_secrets "
                    "WHERE name = 'dp-secret-soft'"
                )
            )
        ).fetchone()
        assert row is not None
        assert row.deleted_at is not None
        assert row.purge_after is not None

    # GET should 404 (filtered by deleted_at IS NULL)
    r = await client.get("/api/v1/vault/secrets/dp-secret-soft", headers=headers)
    assert r.status_code == 404

    # Restore
    r = await client.post(
        "/api/v1/vault/secrets/dp-secret-soft/restore", headers=headers
    )
    assert r.status_code == 200
    assert r.json()["restored"] is True

    # Now visible again
    r = await client.get("/api/v1/vault/secrets/dp-secret-soft", headers=headers)
    assert r.status_code == 200
    assert r.json()["value"] == "v"


@pytest.mark.asyncio
async def test_protected_mode_requires_admin(client, master_password, admin_token):
    """Protected mode soft-deletes + requires admin scope. Without admin
    the DELETE is refused with 403."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    admin_headers = {"Authorization": f"Bearer {admin_token}"}
    await _create_ns(client, admin_token, "dp-ns-prot", "protected")

    # Create the secret (needs admin since the namespace is in vault-admins
    # owner ; agnostic mode so root token works without group membership).
    r = await client.post(
        "/api/v1/vault/secrets/",
        json={
            "name": "dp-secret-prot",
            "value": "v",
            "namespace": "dp-ns-prot",
        },
        headers=admin_headers,
    )
    assert r.status_code == 201

    # Mint a non-root token for the negative case.
    r = await client.post(
        "/api/v1/vault/tokens/",
        json={"name": "dp-non-admin", "permissions": {"secrets": "rw"}},
        headers=admin_headers,
    )
    assert r.status_code == 201
    non_admin = r.json()["token"]

    # Non-admin DELETE refused.
    r = await client.request(
        "DELETE",
        "/api/v1/vault/secrets/dp-secret-prot",
        headers={"Authorization": f"Bearer {non_admin}"},
    )
    assert r.status_code == 403

    # Admin DELETE succeeds (no 2FA configured in tests, mode='none' bypass)
    r = await client.request(
        "DELETE",
        "/api/v1/vault/secrets/dp-secret-prot",
        headers=admin_headers,
    )
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "soft-deleted"
    assert data["mode"] == "protected"

    from api.app.database import async_session

    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_tokens WHERE name = 'dp-non-admin'"))
        await db.commit()


@pytest.mark.asyncio
async def test_db_trigger_rejects_relaxing_delete_protection(
    client, master_password, admin_token
):
    """The DB trigger refuses any rank-decreasing transition on
    delete_protection (protected->soft, soft->free, protected->free)."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    from api.app.database import async_session

    async with async_session() as db:
        gid = (
            await db.execute(
                text("SELECT id FROM vault_groups WHERE name = 'vault-admins'")
            )
        ).scalar()
        await db.execute(
            text(
                """
                INSERT INTO vault_namespaces
                    (name, owner_group_id, delete_protection)
                VALUES ('dp-ns-relax', CAST(:gid AS uuid), 'protected')
                """
            ),
            {"gid": str(gid)},
        )
        await db.commit()

    async with async_session() as db:
        with pytest.raises(Exception) as exc:
            await db.execute(
                text(
                    "UPDATE vault_namespaces "
                    "SET delete_protection = 'soft' WHERE name = 'dp-ns-relax'"
                )
            )
            await db.commit()
        assert (
            "one-way" in str(exc.value).lower() or "ratchet" in str(exc.value).lower()
        )
        await db.rollback()


@pytest.mark.asyncio
async def test_api_rejects_relaxing_delete_protection(
    client, master_password, admin_token
):
    """The API surfaces the rank-decreasing rejection as 423 Locked."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    await _create_ns(client, admin_token, "dp-ns-relax-api", "soft")

    r = await client.put(
        "/api/v1/vault/namespaces/dp-ns-relax-api",
        json={"delete_protection": "free"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 423


@pytest.mark.asyncio
async def test_api_allows_upgrade_delete_protection(
    client, master_password, admin_token
):
    """free -> soft -> protected is allowed at the API."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    await _create_ns(client, admin_token, "dp-ns-upgrade", "free")

    headers = {"Authorization": f"Bearer {admin_token}"}
    r = await client.put(
        "/api/v1/vault/namespaces/dp-ns-upgrade",
        json={"delete_protection": "soft"},
        headers=headers,
    )
    assert r.status_code == 200
    assert r.json()["delete_protection"] == "soft"

    r = await client.put(
        "/api/v1/vault/namespaces/dp-ns-upgrade",
        json={"delete_protection": "protected"},
        headers=headers,
    )
    assert r.status_code == 200
    assert r.json()["delete_protection"] == "protected"


@pytest.mark.asyncio
async def test_create_with_invalid_mode_400(client, master_password, admin_token):
    """Unknown delete_protection value -> 400 Bad Request."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    from api.app.database import async_session

    async with async_session() as db:
        gid = (
            await db.execute(
                text("SELECT id FROM vault_groups WHERE name = 'vault-admins'")
            )
        ).scalar()

    r = await client.post(
        "/api/v1/vault/namespaces/",
        json={
            "name": "dp-ns-invalid",
            "owner_group_id": str(gid),
            "delete_protection": "nuclear",
        },
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 400
