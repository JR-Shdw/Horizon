# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Tests for /api/v1/vault/secrets/{name} namespace isolation.

Regression coverage for the bug fixed 2026-05-12 :
- handlers GET/PUT/DELETE/versions/rollback/rotate/restore ignored the
  ?namespace= query param and looked up by name only
- schema enforced UNIQUE(name) instead of UNIQUE(name, namespace)
- POST / uniqueness check used name alone
- backup restore used ON CONFLICT(name)

Together these prevented true multi-namespace nominal isolation.
"""

import pytest
import pytest_asyncio
from sqlalchemy import text

SAME_NAME = "shared-secret-name"
NS_A = "iso-ns-a"
NS_B = "iso-ns-b"


@pytest_asyncio.fixture(autouse=True)
async def _wipe_iso_secrets():
    """Remove any secrets/namespaces touched by these tests, before AND after."""
    from api.app.database import async_session

    async def _wipe():
        async with async_session() as db:
            await db.execute(
                text(
                    "DELETE FROM vault_secrets "
                    "WHERE name = :n AND namespace IN (:a, :b)"
                ),
                {"n": SAME_NAME, "a": NS_A, "b": NS_B},
            )
            await db.execute(
                text("DELETE FROM vault_namespaces WHERE name IN (:a, :b)"),
                {"a": NS_A, "b": NS_B},
            )
            await db.commit()

    await _wipe()
    yield
    await _wipe()


async def _seed_pair(client, master_password, admin_token):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}
    for ns, val in ((NS_A, "value-from-A"), (NS_B, "value-from-B")):
        r = await client.post(
            "/api/v1/vault/secrets/",
            json={"name": SAME_NAME, "value": val, "namespace": ns},
            headers=headers,
        )
        assert r.status_code in (200, 201), r.text


@pytest.mark.asyncio
async def test_create_same_name_in_two_namespaces_is_allowed(
    client, master_password, admin_token
):
    await _seed_pair(client, master_password, admin_token)


@pytest.mark.asyncio
async def test_create_same_name_same_namespace_is_409(
    client, master_password, admin_token
):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}
    r1 = await client.post(
        "/api/v1/vault/secrets/",
        json={"name": SAME_NAME, "value": "v1", "namespace": NS_A},
        headers=headers,
    )
    assert r1.status_code in (200, 201), r1.text
    r2 = await client.post(
        "/api/v1/vault/secrets/",
        json={"name": SAME_NAME, "value": "v2", "namespace": NS_A},
        headers=headers,
    )
    assert r2.status_code == 409, r2.text


@pytest.mark.asyncio
async def test_get_with_namespace_returns_the_right_value(
    client, master_password, admin_token
):
    await _seed_pair(client, master_password, admin_token)
    headers = {"Authorization": f"Bearer {admin_token}"}

    r_a = await client.get(
        f"/api/v1/vault/secrets/{SAME_NAME}?namespace={NS_A}", headers=headers
    )
    assert r_a.status_code == 200, r_a.text
    assert r_a.json()["value"] == "value-from-A"

    r_b = await client.get(
        f"/api/v1/vault/secrets/{SAME_NAME}?namespace={NS_B}", headers=headers
    )
    assert r_b.status_code == 200, r_b.text
    assert r_b.json()["value"] == "value-from-B"


@pytest.mark.asyncio
async def test_get_without_namespace_is_409_when_ambiguous(
    client, master_password, admin_token
):
    await _seed_pair(client, master_password, admin_token)
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.get(f"/api/v1/vault/secrets/{SAME_NAME}", headers=headers)
    assert r.status_code == 409, r.text
    assert "ambiguous" in r.json()["detail"].lower()


@pytest.mark.asyncio
async def test_get_with_unknown_namespace_is_404(client, master_password, admin_token):
    await _seed_pair(client, master_password, admin_token)
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.get(
        f"/api/v1/vault/secrets/{SAME_NAME}?namespace=nope-not-here",
        headers=headers,
    )
    assert r.status_code == 404, r.text


@pytest.mark.asyncio
async def test_put_with_namespace_only_updates_targeted_one(
    client, master_password, admin_token
):
    await _seed_pair(client, master_password, admin_token)
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.put(
        f"/api/v1/vault/secrets/{SAME_NAME}?namespace={NS_A}",
        json={"value": "value-from-A-v2"},
        headers=headers,
    )
    assert r.status_code == 200, r.text

    r_a = await client.get(
        f"/api/v1/vault/secrets/{SAME_NAME}?namespace={NS_A}", headers=headers
    )
    r_b = await client.get(
        f"/api/v1/vault/secrets/{SAME_NAME}?namespace={NS_B}", headers=headers
    )
    assert r_a.json()["value"] == "value-from-A-v2"
    assert r_b.json()["value"] == "value-from-B"


@pytest.mark.asyncio
async def test_put_without_namespace_is_409_when_ambiguous(
    client, master_password, admin_token
):
    await _seed_pair(client, master_password, admin_token)
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.put(
        f"/api/v1/vault/secrets/{SAME_NAME}",
        json={"value": "should-not-apply"},
        headers=headers,
    )
    assert r.status_code == 409, r.text


@pytest.mark.asyncio
async def test_delete_with_namespace_only_removes_targeted_one(
    client, master_password, admin_token
):
    await _seed_pair(client, master_password, admin_token)
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.delete(
        f"/api/v1/vault/secrets/{SAME_NAME}?namespace={NS_A}", headers=headers
    )
    assert r.status_code == 200, r.text

    r_a = await client.get(
        f"/api/v1/vault/secrets/{SAME_NAME}?namespace={NS_A}", headers=headers
    )
    r_b = await client.get(
        f"/api/v1/vault/secrets/{SAME_NAME}?namespace={NS_B}", headers=headers
    )
    assert r_a.status_code == 404, r_a.text
    assert r_b.status_code == 200, r_b.text
    assert r_b.json()["value"] == "value-from-B"


@pytest.mark.asyncio
async def test_rotate_with_namespace_only_rotates_targeted_one(
    client, master_password, admin_token
):
    await _seed_pair(client, master_password, admin_token)
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.post(
        f"/api/v1/vault/secrets/{SAME_NAME}/rotate?namespace={NS_A}",
        headers=headers,
    )
    assert r.status_code == 200, r.text

    # Value preserved both sides, A version bumped, B intact
    r_a = await client.get(
        f"/api/v1/vault/secrets/{SAME_NAME}?namespace={NS_A}", headers=headers
    )
    r_b = await client.get(
        f"/api/v1/vault/secrets/{SAME_NAME}?namespace={NS_B}", headers=headers
    )
    assert r_a.json()["value"] == "value-from-A"
    assert r_a.json()["version"] == 2
    assert r_b.json()["value"] == "value-from-B"
    assert r_b.json()["version"] == 1


@pytest.mark.asyncio
async def test_versions_with_namespace_lists_only_that_secret(
    client, master_password, admin_token
):
    await _seed_pair(client, master_password, admin_token)
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Bump A to v2
    await client.put(
        f"/api/v1/vault/secrets/{SAME_NAME}?namespace={NS_A}",
        json={"value": "value-from-A-v2"},
        headers=headers,
    )

    r_a = await client.get(
        f"/api/v1/vault/secrets/{SAME_NAME}/versions?namespace={NS_A}",
        headers=headers,
    )
    r_b = await client.get(
        f"/api/v1/vault/secrets/{SAME_NAME}/versions?namespace={NS_B}",
        headers=headers,
    )
    assert r_a.status_code == 200, r_a.text
    assert r_b.status_code == 200, r_b.text
    # POST seeds an initial v=1 snapshot ; A also has v=2 from the PUT
    assert {v["version"] for v in r_a.json()["versions"]} == {1, 2}
    # B was never updated, so only its initial v=1, no leak of A's v=2
    assert {v["version"] for v in r_b.json()["versions"]} == {1}
