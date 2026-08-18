"""Backlog #1: namespace isolation on dynamic engines.

Verifies that a non-root token scoped to namespace "ns-a" cannot access
engines / roles / leases that belong to namespace "ns-b" - the gap that
was latent before the fix.
"""

import json

import pytest
from api.app.crypto import generate_token
from api.app.database import async_session
from api.app.vault_state import vault
from sqlalchemy import text


async def _make_token(name: str, perms: dict) -> str:
    """Mint a token with arbitrary permissions, returning the plaintext."""
    raw = generate_token()
    token_hash = await vault.hmac_sha512_hex(raw)
    async with async_session() as db:
        await db.execute(
            text("DELETE FROM vault_tokens WHERE name = :n"),
            {"n": name},
        )
        await db.execute(
            text("""
                INSERT INTO vault_tokens (name, token_hash, permissions, created_by)
                VALUES (:n, :h, CAST(:p AS jsonb), 'test')
            """),
            {"n": name, "h": token_hash, "p": json.dumps(perms)},
        )
        await db.commit()
    return raw


async def _make_scoped_token(name: str, namespaces: list[str]) -> str:
    """Namespace-restricted admin token used to test the namespace check
    end-to-end. check_namespace gates non-admin and namespace-restricted-admin
    tokens alike, so the admin scope here only frees us from the scope check."""
    return await _make_token(name, {"admin": "rw", "namespaces": namespaces})


async def _ensure_namespaces(*names: str) -> None:
    """Create real agnostic namespaces for dynamic-engine isolation tests."""
    async with async_session() as db:
        owner_group_id = await db.scalar(
            text("SELECT owner_group_id FROM vault_namespaces WHERE name = 'default'")
        )
        assert owner_group_id is not None
        for name in names:
            await db.execute(
                text("""
                    INSERT INTO vault_namespaces
                        (name, owner_group_id, enforce_membership, created_by)
                    VALUES (:name, :owner_group_id, false, 'test')
                    ON CONFLICT (name) DO NOTHING
                """),
                {"name": name, "owner_group_id": owner_group_id},
            )
        await db.commit()


@pytest.mark.asyncio
async def test_create_engine_in_unauthorized_namespace_rejected(
    client, master_password, admin_token
):
    """A token scoped to ['ns-a'] cannot create an engine in 'ns-b'."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    await _ensure_namespaces("ns-a", "ns-b")
    scoped = await _make_scoped_token("scoped-ns-a", ["ns-a"])

    r = await client.post(
        "/api/v1/vault/dynamic/engines",
        json={
            "name": "engine-rejected",
            "namespace": "ns-b",  # NOT in the token's allowed namespaces
            "engine_type": "postgresql",
            "connection_url": "postgresql://x:y@nowhere/z",
        },
        headers={"Authorization": f"Bearer {scoped}"},
    )
    assert r.status_code == 403
    assert "namespace" in r.json().get("detail", "").lower()


@pytest.mark.asyncio
async def test_list_engines_filtered_by_namespace(client, master_password, admin_token):
    """list_engines must only return engines in the token's allowed namespaces."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers_admin = {"Authorization": f"Bearer {admin_token}"}
    await _ensure_namespaces("isolation-a", "isolation-b")

    # Create one engine in each of two namespaces (admin can do both)
    for ns, name in [("isolation-a", "eng-iso-a"), ("isolation-b", "eng-iso-b")]:
        await client.post(
            "/api/v1/vault/dynamic/engines",
            json={
                "name": name,
                "namespace": ns,
                "engine_type": "postgresql",
                "connection_url": "postgresql://x:y@nowhere/z",
            },
            headers=headers_admin,
        )

    # Scoped token should only see ns="isolation-a"
    scoped = await _make_scoped_token("scoped-iso-a", ["isolation-a"])
    r = await client.get(
        "/api/v1/vault/dynamic/engines",
        headers={"Authorization": f"Bearer {scoped}"},
    )
    assert r.status_code == 200
    items = r.json()["items"]
    names = {item["name"] for item in items}
    assert "eng-iso-a" in names
    assert "eng-iso-b" not in names

    # Admin sees both
    r_admin = await client.get("/api/v1/vault/dynamic/engines", headers=headers_admin)
    admin_names = {item["name"] for item in r_admin.json()["items"]}
    assert {"eng-iso-a", "eng-iso-b"}.issubset(admin_names)


@pytest.mark.asyncio
async def test_generate_credentials_cross_namespace_rejected(
    client, master_password, admin_token
):
    """A scoped token cannot generate credentials on an engine in another namespace.

    This is the core gap from the memory note: namespace-scoped token
    bypassing isolation to access another team's database.
    """
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers_admin = {"Authorization": f"Bearer {admin_token}"}
    await _ensure_namespaces("team-prod", "team-staging")

    # Admin creates an engine + role in namespace "team-prod"
    r = await client.post(
        "/api/v1/vault/dynamic/engines",
        json={
            "name": "prod-engine",
            "namespace": "team-prod",
            "engine_type": "postgresql",
            "connection_url": "postgresql://x:y@nowhere/z",
        },
        headers=headers_admin,
    )
    assert r.status_code == 201
    engine_id = r.json()["id"]

    await client.post(
        f"/api/v1/vault/dynamic/engines/{engine_id}/roles",
        json={
            "name": "reader",
            "creation_sql": "CREATE ROLE x",
            "revocation_sql": "DROP ROLE x",
        },
        headers=headers_admin,
    )

    # Token scoped to "team-staging" tries to generate creds on prod
    staging_token = await _make_scoped_token("scoped-staging", ["team-staging"])
    r = await client.post(
        f"/api/v1/vault/dynamic/engines/{engine_id}/creds/reader",
        headers={"Authorization": f"Bearer {staging_token}"},
    )
    assert r.status_code == 403
    assert "namespace" in r.json().get("detail", "").lower()

    # Same token can't even read the role list
    r = await client.get(
        f"/api/v1/vault/dynamic/engines/{engine_id}/roles",
        headers={"Authorization": f"Bearer {staging_token}"},
    )
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_secrets_w_token_mints_in_namespace(client, master_password, admin_token):
    """The creds endpoint takes `secrets:w` (not `admin:w`): a non-admin token
    scoped to its namespace can mint there (least-privilege self-service) and is
    403 in another namespace. Proves the admin:w -> secrets:w relaxation."""
    import os

    import asyncpg

    raw_url = (
        os.environ.get("RHORIZON_DATABASE_URL", "")
        or os.environ.get("TEST_DATABASE_URL", "")
    ).replace("postgresql+asyncpg://", "postgresql://")
    if not raw_url:
        pytest.skip("No database URL available for real PG test")

    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers_admin = {"Authorization": f"Bearer {admin_token}"}
    await _ensure_namespaces("sw-prod", "sw-staging")

    async def _engine_with_role(name, ns):
        r = await client.post(
            "/api/v1/vault/dynamic/engines",
            json={
                "name": name,
                "namespace": ns,
                "engine_type": "postgresql",
                "connection_url": raw_url,
            },
            headers=headers_admin,
        )
        assert r.status_code == 201, r.text
        eid = r.json()["id"]
        await client.post(
            f"/api/v1/vault/dynamic/engines/{eid}/roles",
            json={
                "name": "reader",
                "creation_sql": (
                    "CREATE ROLE \"{{name}}\" LOGIN PASSWORD '{{password}}'"
                ),
                "revocation_sql": 'DROP ROLE IF EXISTS "{{name}}"',
                "default_ttl_seconds": 60,
            },
            headers=headers_admin,
        )
        return eid

    prod_id = await _engine_with_role("sw-prod-engine", "sw-prod")
    staging_id = await _engine_with_role("sw-staging-engine", "sw-staging")

    # Non-admin secrets:w token scoped to sw-prod.
    sw = await _make_token("sw-consumer", {"secrets": "w", "namespaces": ["sw-prod"]})
    sw_headers = {"Authorization": f"Bearer {sw}"}

    # In-namespace: mints (previously impossible -- endpoint required admin:w).
    r = await client.post(
        f"/api/v1/vault/dynamic/engines/{prod_id}/creds/reader", headers=sw_headers
    )
    assert r.status_code == 200, r.text
    username = r.json()["username"]
    conn = await asyncpg.connect(raw_url)
    try:
        await conn.execute(f'DROP ROLE IF EXISTS "{username}"')
    finally:
        await conn.close()

    # Cross-namespace: still 403.
    r = await client.post(
        f"/api/v1/vault/dynamic/engines/{staging_id}/creds/reader", headers=sw_headers
    )
    assert r.status_code == 403

    for eid in (prod_id, staging_id):
        await client.delete(
            f"/api/v1/vault/dynamic/engines/{eid}", headers=headers_admin
        )


@pytest.mark.asyncio
async def test_delete_engine_cross_namespace_rejected(
    client, master_password, admin_token
):
    """A scoped token cannot delete an engine in another namespace."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers_admin = {"Authorization": f"Bearer {admin_token}"}
    await _ensure_namespaces("team-x", "team-y")

    r = await client.post(
        "/api/v1/vault/dynamic/engines",
        json={
            "name": "del-test-engine",
            "namespace": "team-x",
            "engine_type": "postgresql",
            "connection_url": "postgresql://x:y@nowhere/z",
        },
        headers=headers_admin,
    )
    assert r.status_code == 201
    engine_id = r.json()["id"]

    other = await _make_scoped_token("scoped-team-y", ["team-y"])
    r = await client.delete(
        f"/api/v1/vault/dynamic/engines/{engine_id}",
        headers={"Authorization": f"Bearer {other}"},
    )
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_default_namespace_when_unspecified(client, master_password, admin_token):
    """Engines created without an explicit namespace land in 'default'."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    r = await client.post(
        "/api/v1/vault/dynamic/engines",
        json={
            "name": "default-ns-engine",
            "engine_type": "postgresql",
            "connection_url": "postgresql://x:y@nowhere/z",
        },
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 201
    assert r.json()["namespace"] == "default"
