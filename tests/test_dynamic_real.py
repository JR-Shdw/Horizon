"""Integration test for dynamic secrets against real PostgreSQL.

Uses the CI postgres-test service - creates a real temporary user,
verifies it exists, revokes it, verifies it's gone.
"""

import os

import asyncpg
import pytest


@pytest.mark.asyncio
async def test_dynamic_secrets_real_pg(client, master_password, admin_token):
    """Full lifecycle: engine, role, generate, verify, revoke."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Get the test database URL (same PG as tests use)
    raw_url = os.environ.get("RHORIZON_DATABASE_URL", "").replace(
        "postgresql+asyncpg://", "postgresql://"
    )
    if not raw_url:
        raw_url = os.environ.get("TEST_DATABASE_URL", "").replace(
            "postgresql+asyncpg://", "postgresql://"
        )
    if not raw_url:
        pytest.skip("No database URL available for real PG test")

    # asyncpg URL for the engine (rhorizon connects to this to create users)
    asyncpg_url = raw_url

    # 1. Create engine pointing to our test PG
    r = await client.post(
        "/api/v1/vault/dynamic/engines",
        json={
            "name": "real-pg-test",
            "engine_type": "postgresql",
            "connection_url": asyncpg_url,
        },
        headers=headers,
    )
    assert r.status_code == 201
    engine_id = r.json()["id"]

    # 2. Create role template
    r = await client.post(
        f"/api/v1/vault/dynamic/engines/{engine_id}/roles",
        json={
            "name": "temp-reader",
            "creation_sql": "CREATE ROLE \"{{name}}\" LOGIN PASSWORD '{{password}}'",
            "revocation_sql": 'DROP ROLE IF EXISTS "{{name}}"',
            "default_ttl_seconds": 60,
        },
        headers=headers,
    )
    assert r.status_code == 201

    # 3. Generate real credentials
    r = await client.post(
        f"/api/v1/vault/dynamic/engines/{engine_id}/creds/temp-reader",
        json={"ttl_seconds": 60},
        headers=headers,
    )
    assert r.status_code == 200
    data = r.json()
    assert data["username"].startswith("rh_temp_reader_")
    assert len(data["password"]) == 32
    assert "lease_id" in data
    assert "dn" not in data  # SQL backends return no bind DN (ldap-only field)

    username = data["username"]
    lease_id = data["lease_id"]

    # 4. Verify the user actually exists in PostgreSQL
    conn = await asyncpg.connect(asyncpg_url)
    try:
        row = await conn.fetchrow(
            "SELECT rolname FROM pg_roles WHERE rolname = $1", username
        )
        assert row is not None, f"User {username} should exist in PG"
        assert row["rolname"] == username
    finally:
        await conn.close()

    # 5. Revoke the lease (drops the user)
    r = await client.post(
        f"/api/v1/vault/dynamic/leases/{lease_id}/revoke",
        headers=headers,
    )
    assert r.status_code == 200
    assert r.json()["status"] == "revoked"

    # 6. Verify the user is gone from PostgreSQL
    conn = await asyncpg.connect(asyncpg_url)
    try:
        row = await conn.fetchrow(
            "SELECT rolname FROM pg_roles WHERE rolname = $1", username
        )
        assert row is None, f"User {username} should be dropped after revoke"
    finally:
        await conn.close()

    # 7. Verify lease shows as revoked in API
    r = await client.get("/api/v1/vault/dynamic/leases", headers=headers)
    active = [ls for ls in r.json()["items"] if ls["username"] == username]
    assert len(active) == 0, "Revoked lease should not appear in active list"

    # Cleanup
    await client.delete(f"/api/v1/vault/dynamic/engines/{engine_id}", headers=headers)
