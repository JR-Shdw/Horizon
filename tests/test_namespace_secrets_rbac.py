# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""RBAC enforcement on secrets when their namespace has enforce_membership=true.

Validates the wiring between create / update / delete on secrets.py and
`check_namespace_membership` from auth.py. The interesting cases :

  - In agnostic namespaces (default), the existing claim-based check
    is preserved (back-compat).
  - In strict namespaces, a non-member token gets 403 even when its
    `permissions.namespaces` claim covers the namespace name.
  - Members of the owner group succeed.
  - The auto-create on create_secret transparently registers the
    namespace under vault-admins, agnostic mode, populating
    `vault_secrets.namespace_id`.
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
async def _clean_test_rows():
    """Wipe test rows before AND after each test."""
    from api.app.database import async_session

    async def _wipe():
        async with async_session() as db:
            # Capture dek_ids before deleting secrets, then delete the
            # deks afterwards (FK direction : secrets -> dek).
            dek_ids = (
                await db.execute(
                    text("SELECT dek_id FROM vault_secrets WHERE name LIKE 'rbac-%'")
                )
            ).fetchall()
            await db.execute(text("DELETE FROM vault_secrets WHERE name LIKE 'rbac-%'"))
            for r in dek_ids:
                await db.execute(
                    text("DELETE FROM vault_dek WHERE id = :id"),
                    {"id": str(r.dek_id)},
                )
            await db.execute(
                text("DELETE FROM vault_namespaces WHERE name LIKE 'rbac-%'")
            )
            await db.execute(
                text(
                    "DELETE FROM vault_group_members "
                    "WHERE external_id = 'proxy:rbac-test-user'"
                )
            )
            await db.execute(text("DELETE FROM vault_groups WHERE name LIKE 'rbac-%'"))
            await db.execute(text("DELETE FROM vault_tokens WHERE name LIKE 'rbac-%'"))
            await db.execute(
                text("DELETE FROM vault_tokens WHERE name = 'proxy:rbac-test-user'")
            )
            await db.commit()

    await _wipe()
    yield
    await _wipe()


@pytest.mark.asyncio
async def test_create_secret_in_agnostic_namespace_succeeds(
    client, master_password, admin_token
):
    """Agnostic mode (default) keeps claim-based behavior - root token
    creates a secret in any namespace without group membership."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.post(
        "/api/v1/vault/secrets/",
        json={
            "name": "rbac-secret-agnostic",
            "value": "v1",
            "namespace": "rbac-ns-open",
        },
        headers=headers,
    )
    assert r.status_code == 201, r.text

    # The namespace was auto-created in agnostic mode.
    r = await client.get("/api/v1/vault/namespaces/rbac-ns-open", headers=headers)
    assert r.status_code == 200
    data = r.json()
    assert data["enforce_membership"] is False
    # And the secret has its namespace_id populated.
    from api.app.database import async_session

    async with async_session() as db:
        row = (
            await db.execute(
                text(
                    "SELECT namespace_id FROM vault_secrets "
                    "WHERE name = 'rbac-secret-agnostic'"
                )
            )
        ).fetchone()
        assert row.namespace_id is not None


@pytest.mark.asyncio
async def test_create_secret_in_strict_namespace_blocks_non_member(
    client, master_password, admin_token
):
    """Strict mode : create_secret refuses 403 when the actor is not in
    the namespace's owner group, even with admin scope on a human session
    (covered by check_namespace_membership). For API tokens with admin
    scope the operator-bypass kicks in - that's tested separately."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    from api.app.database import async_session

    async with async_session() as db:
        await db.execute(
            text(
                """
                INSERT INTO vault_groups (name, permissions, source)
                VALUES ('rbac-team-prod', '{"admin": "rw"}'::jsonb, 'local')
                """
            )
        )
        team_id = (
            await db.execute(
                text("SELECT id FROM vault_groups WHERE name = 'rbac-team-prod'")
            )
        ).scalar()
        await db.execute(
            text(
                """
                INSERT INTO vault_namespaces
                    (name, owner_group_id, enforce_membership)
                VALUES ('rbac-ns-prod', CAST(:gid AS uuid), true)
                """
            ),
            {"gid": str(team_id)},
        )
        await db.commit()

    # Mint a human-session-style token (proxy:rbac-test-user) with admin
    # scope but NOT a member of rbac-team-prod.
    from api.app.crypto import generate_token
    from api.app.vault_state import vault as _vault

    raw = generate_token()
    token_hash = await _vault.hmac_sha512_hex(raw)
    async with async_session() as db:
        await db.execute(
            text(
                """
                INSERT INTO vault_tokens
                    (name, token_hash, permissions, created_by)
                VALUES ('proxy:rbac-test-user', :hash,
                        CAST(:perms AS jsonb), 'rbac-test-user')
                ON CONFLICT (name) WHERE active DO UPDATE SET token_hash = :hash
                """
            ),
            {"hash": token_hash, "perms": json.dumps({"admin": "rw"})},
        )
        await db.commit()

    r = await client.post(
        "/api/v1/vault/secrets/",
        json={
            "name": "rbac-secret-prod",
            "value": "v",
            "namespace": "rbac-ns-prod",
        },
        headers={"Authorization": f"Bearer {raw}"},
    )
    assert r.status_code == 403, r.text


@pytest.mark.asyncio
async def test_strict_namespace_member_can_write(client, master_password, admin_token):
    """When the human session token's user is a member of the owner
    group, strict-mode writes succeed."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    from api.app.database import async_session

    async with async_session() as db:
        await db.execute(
            text(
                """
                INSERT INTO vault_groups (name, permissions, source)
                VALUES ('rbac-team-ok', '{"admin": "rw"}'::jsonb, 'local')
                """
            )
        )
        team_id = (
            await db.execute(
                text("SELECT id FROM vault_groups WHERE name = 'rbac-team-ok'")
            )
        ).scalar()
        await db.execute(
            text(
                """
                INSERT INTO vault_namespaces
                    (name, owner_group_id, enforce_membership)
                VALUES ('rbac-ns-ok', CAST(:gid AS uuid), true)
                """
            ),
            {"gid": str(team_id)},
        )
        await db.execute(
            text(
                """
                INSERT INTO vault_group_members
                    (group_id, principal_type, external_id)
                VALUES (
                    CAST(:gid AS uuid), 'external', 'proxy:rbac-test-user'
                )
                """
            ),
            {"gid": str(team_id)},
        )
        await db.commit()

    from api.app.crypto import generate_token
    from api.app.vault_state import vault as _vault

    raw = generate_token()
    token_hash = await _vault.hmac_sha512_hex(raw)
    async with async_session() as db:
        await db.execute(
            text(
                """
                INSERT INTO vault_tokens
                    (name, token_hash, permissions, created_by)
                VALUES ('proxy:rbac-test-user', :hash,
                        CAST(:perms AS jsonb), 'rbac-test-user')
                ON CONFLICT (name) WHERE active DO UPDATE SET token_hash = :hash
                """
            ),
            {"hash": token_hash, "perms": json.dumps({"admin": "rw"})},
        )
        await db.commit()

    r = await client.post(
        "/api/v1/vault/secrets/",
        json={
            "name": "rbac-secret-ok",
            "value": "v",
            "namespace": "rbac-ns-ok",
        },
        headers={"Authorization": f"Bearer {raw}"},
    )
    assert r.status_code == 201, r.text


@pytest.mark.asyncio
async def test_strict_rbac_separates_user_name_from_token_uuid(
    client, master_password, admin_token
):
    """A user and token may share a display name without sharing access."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    admin_headers = {"Authorization": f"Bearer {admin_token}"}
    shared_name = "rbac-shared-principal"

    group = await client.post(
        "/api/v1/vault/groups/",
        json={"name": "rbac-collision-group", "permissions": {"secrets": "rw"}},
        headers=admin_headers,
    )
    assert group.status_code == 201, group.text
    group_id = group.json()["id"]

    created_token = await client.post(
        "/api/v1/vault/tokens/",
        json={
            "name": shared_name,
            "permissions": {
                "secrets": "rw",
                "namespaces": ["rbac-collision-ns"],
            },
        },
        headers=admin_headers,
    )
    assert created_token.status_code == 201, created_token.text
    raw_token = created_token.json()["token"]

    tokens = await client.get("/api/v1/vault/tokens/", headers=admin_headers)
    token_id = next(
        item["id"] for item in tokens.json()["items"] if item["name"] == shared_name
    )

    from api.app.database import async_session

    async with async_session() as db:
        await db.execute(
            text("""
                INSERT INTO vault_namespaces
                    (name, owner_group_id, enforce_membership)
                VALUES ('rbac-collision-ns', CAST(:gid AS uuid), true)
            """),
            {"gid": group_id},
        )
        await db.commit()

    added_user = await client.post(
        f"/api/v1/vault/groups/{group_id}/members",
        json={
            "principal_type": "external",
            "principal_id": f"proxy:{shared_name}",
        },
        headers=admin_headers,
    )
    assert added_user.status_code == 201, added_user.text

    denied = await client.post(
        "/api/v1/vault/secrets/",
        json={
            "name": "rbac-collision-secret-denied",
            "value": "v",
            "namespace": "rbac-collision-ns",
        },
        headers={"Authorization": f"Bearer {raw_token}"},
    )
    assert denied.status_code == 403, denied.text

    added_token = await client.post(
        f"/api/v1/vault/groups/{group_id}/members",
        json={"principal_type": "token", "principal_id": token_id},
        headers=admin_headers,
    )
    assert added_token.status_code == 201, added_token.text

    allowed = await client.post(
        "/api/v1/vault/secrets/",
        json={
            "name": "rbac-collision-secret-allowed",
            "value": "v",
            "namespace": "rbac-collision-ns",
        },
        headers={"Authorization": f"Bearer {raw_token}"},
    )
    assert allowed.status_code == 201, allowed.text

    members = await client.get(
        f"/api/v1/vault/groups/{group_id}/members", headers=admin_headers
    )
    assert {
        (item["principal_type"], item["principal_id"])
        for item in members.json()["items"]
    } == {("external", f"proxy:{shared_name}"), ("token", token_id)}

    deleted = await client.delete(
        f"/api/v1/vault/tokens/{token_id}", headers=admin_headers
    )
    assert deleted.status_code == 200, deleted.text
    members = await client.get(
        f"/api/v1/vault/groups/{group_id}/members", headers=admin_headers
    )
    assert [
        (item["principal_type"], item["principal_id"])
        for item in members.json()["items"]
    ] == [("external", f"proxy:{shared_name}")]


@pytest.mark.asyncio
async def test_strict_namespace_blocks_non_member_on_all_handlers(
    client, master_password, admin_token
):
    """Regression for the RBAC gap on /secrets/{name} variants.

    get_secret / rollback / rotate / list_versions / get_version historically
    skipped `check_namespace_membership`, so a human-session token with admin
    scope but no membership in the owner group could bypass strict-mode RBAC
    on these routes. Now the membership check is applied to all of them
    (write=True for rollback/rotate, write=False for the three read routes:
    get_secret, list_versions, get_version).
    """
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    from api.app.database import async_session

    async with async_session() as db:
        await db.execute(
            text(
                "INSERT INTO vault_groups (name, permissions, source) "
                "VALUES ('rbac-team-reg', '{\"admin\": \"rw\"}'::jsonb, 'local')"
            )
        )
        team_id = (
            await db.execute(
                text("SELECT id FROM vault_groups WHERE name = 'rbac-team-reg'")
            )
        ).scalar()
        await db.execute(
            text(
                "INSERT INTO vault_namespaces "
                "    (name, owner_group_id, enforce_membership) "
                "VALUES ('rbac-ns-reg', CAST(:gid AS uuid), true)"
            ),
            {"gid": str(team_id)},
        )
        await db.commit()

    # Admin bypass to seed a secret with 2 versions (so rollback/v1 is
    # a meaningful target).
    headers_admin = {"Authorization": f"Bearer {admin_token}"}
    r = await client.post(
        "/api/v1/vault/secrets/",
        json={"name": "rbac-secret-reg", "value": "v1", "namespace": "rbac-ns-reg"},
        headers=headers_admin,
    )
    assert r.status_code == 201, r.text
    r = await client.put(
        "/api/v1/vault/secrets/rbac-secret-reg?namespace=rbac-ns-reg",
        json={"value": "v2"},
        headers=headers_admin,
    )
    assert r.status_code == 200, r.text

    # Mint a human-session-style token (admin scope, proxy:* name) NOT
    # in the owner group.
    from api.app.crypto import generate_token
    from api.app.vault_state import vault as _vault

    raw = generate_token()
    token_hash = await _vault.hmac_sha512_hex(raw)
    async with async_session() as db:
        await db.execute(
            text(
                "INSERT INTO vault_tokens "
                "    (name, token_hash, permissions, created_by) "
                "VALUES ('proxy:rbac-test-user', :hash, "
                "        CAST(:perms AS jsonb), 'rbac-test-user') "
                "ON CONFLICT (name) WHERE active "
                "DO UPDATE SET token_hash = :hash"
            ),
            {"hash": token_hash, "perms": json.dumps({"admin": "rw"})},
        )
        await db.commit()

    headers_user = {"Authorization": f"Bearer {raw}"}

    r = await client.get(
        "/api/v1/vault/secrets/rbac-secret-reg/versions?namespace=rbac-ns-reg",
        headers=headers_user,
    )
    assert r.status_code == 403, ("list_versions", r.text)

    r = await client.get(
        "/api/v1/vault/secrets/rbac-secret-reg/versions/1?namespace=rbac-ns-reg",
        headers=headers_user,
    )
    assert r.status_code == 403, ("get_version", r.text)

    r = await client.post(
        "/api/v1/vault/secrets/rbac-secret-reg/rollback/1?namespace=rbac-ns-reg",
        headers=headers_user,
    )
    assert r.status_code == 403, ("rollback_secret", r.text)

    r = await client.post(
        "/api/v1/vault/secrets/rbac-secret-reg/rotate?namespace=rbac-ns-reg",
        headers=headers_user,
    )
    assert r.status_code == 403, ("rotate_secret", r.text)

    # get_secret (the primary read) was the one single-secret endpoint missing
    # the membership check -- a strict-namespace read bypass until fixed.
    r = await client.get(
        "/api/v1/vault/secrets/rbac-secret-reg?namespace=rbac-ns-reg",
        headers=headers_user,
    )
    assert r.status_code == 403, ("get_secret", r.text)


@pytest.mark.asyncio
async def test_missing_namespace_mapping_fails_closed_on_all_secret_routes(
    client, master_password, admin_token
):
    """A corrupt NULL namespace_id must never fall back to claim-only access."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}
    namespace = "rbac-ns-unmapped"
    name = "rbac-secret-unmapped"

    created = await client.post(
        "/api/v1/vault/secrets/",
        json={"name": name, "value": "v1", "namespace": namespace},
        headers=headers,
    )
    assert created.status_code == 201, created.text

    from api.app.database import async_session

    async with async_session() as db:
        await db.execute(
            text(
                "UPDATE vault_secrets SET namespace_id = NULL "
                "WHERE name = :name AND namespace = :namespace"
            ),
            {"name": name, "namespace": namespace},
        )
        await db.commit()

    requests = [
        ("GET", f"/api/v1/vault/secrets/?namespace={namespace}", None),
        ("GET", f"/api/v1/vault/secrets/{name}?namespace={namespace}", None),
        (
            "PUT",
            f"/api/v1/vault/secrets/{name}?namespace={namespace}",
            {"value": "v2"},
        ),
        (
            "GET",
            f"/api/v1/vault/secrets/{name}/versions?namespace={namespace}",
            None,
        ),
        (
            "GET",
            f"/api/v1/vault/secrets/{name}/versions/1?namespace={namespace}",
            None,
        ),
        (
            "POST",
            f"/api/v1/vault/secrets/{name}/rollback/1?namespace={namespace}",
            None,
        ),
        (
            "POST",
            f"/api/v1/vault/secrets/{name}/rotate?namespace={namespace}",
            None,
        ),
        ("DELETE", f"/api/v1/vault/secrets/{name}?namespace={namespace}", None),
    ]
    for method, url, body in requests:
        response = await client.request(method, url, json=body, headers=headers)
        assert response.status_code == 503, (method, url, response.text)
        assert response.json()["detail"] == "Secret namespace mapping unavailable"

    async with async_session() as db:
        await db.execute(
            text(
                "UPDATE vault_secrets SET deleted_at = NOW() "
                "WHERE name = :name AND namespace = :namespace"
            ),
            {"name": name, "namespace": namespace},
        )
        await db.commit()

    restored = await client.post(
        f"/api/v1/vault/secrets/{name}/restore?namespace={namespace}",
        headers=headers,
    )
    assert restored.status_code == 503, restored.text
    assert restored.json()["detail"] == "Secret namespace mapping unavailable"
