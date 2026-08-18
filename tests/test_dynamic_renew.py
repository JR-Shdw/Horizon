"""Lease renewal: extend an active lease's expiry, capped at the role's
absolute lifetime (created_at + max_ttl).

Mirrors token renewal (tokens.renew_token): renew only moves expires_at, the
reaper holds the credential until the new time. The one extra invariant a lease
has over a token is the max_ttl cap, a credential cannot be renewed past its
absolute lifetime. These tests pin both the extension and the cap.

Real PG is only needed to mint (CREATE ROLE); renewal itself never touches the
backend. Skips when no database URL is available, like the other real-PG tests.
"""

import os
from datetime import datetime

import asyncpg
import pytest
from api.app.database import async_session
from sqlalchemy import text


def _raw_pg_url() -> str:
    url = os.environ.get("RHORIZON_DATABASE_URL", "") or os.environ.get(
        "TEST_DATABASE_URL", ""
    )
    return url.replace("postgresql+asyncpg://", "postgresql://")


async def _make_lease(client, headers, *, default_ttl=3600, max_ttl=86400):
    asyncpg_url = _raw_pg_url()
    r = await client.post(
        "/api/v1/vault/dynamic/engines",
        json={
            "name": "renew-pg-test",
            "engine_type": "postgresql",
            "connection_url": asyncpg_url,
            "max_ttl_seconds": max_ttl,
        },
        headers=headers,
    )
    assert r.status_code == 201, r.text
    engine_id = r.json()["id"]

    r = await client.post(
        f"/api/v1/vault/dynamic/engines/{engine_id}/roles",
        json={
            "name": "renew-reader",
            "creation_sql": "CREATE ROLE \"{{name}}\" LOGIN PASSWORD '{{password}}'",
            "revocation_sql": 'DROP ROLE IF EXISTS "{{name}}"',
            "default_ttl_seconds": default_ttl,
            "max_ttl_seconds": max_ttl,
        },
        headers=headers,
    )
    assert r.status_code == 201, r.text

    r = await client.post(
        f"/api/v1/vault/dynamic/engines/{engine_id}/creds/renew-reader",
        json={"ttl_seconds": default_ttl},
        headers=headers,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    return engine_id, body["username"], body["lease_id"], body["expires_at"]


async def _drop_role(username: str) -> None:
    conn = await asyncpg.connect(_raw_pg_url())
    try:
        await conn.execute(f'DROP ROLE IF EXISTS "{username}"')
    finally:
        await conn.close()


@pytest.mark.asyncio
async def test_renew_extends_expiry(client, master_password, admin_token):
    if not _raw_pg_url():
        pytest.skip("No database URL available for real PG test")
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    engine_id, username, lease_id, first_exp = await _make_lease(
        client, headers, default_ttl=600, max_ttl=86400
    )
    r = await client.post(
        f"/api/v1/vault/dynamic/leases/{lease_id}/renew",
        json={"ttl_seconds": 7200},
        headers=headers,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "renewed"
    assert body["username"] == username
    # New expiry is strictly later than the mint expiry, ttl close to 7200.
    assert datetime.fromisoformat(body["expires_at"]) > datetime.fromisoformat(
        first_exp
    )
    assert 7000 <= body["ttl_seconds"] <= 7200

    await _drop_role(username)
    await client.delete(f"/api/v1/vault/dynamic/engines/{engine_id}", headers=headers)


@pytest.mark.asyncio
async def test_renew_capped_at_max_ttl(client, master_password, admin_token):
    if not _raw_pg_url():
        pytest.skip("No database URL available for real PG test")
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Short absolute lifetime: minted now, can never be renewed past now+120s.
    engine_id, username, lease_id, _ = await _make_lease(
        client, headers, default_ttl=60, max_ttl=120
    )
    r = await client.post(
        f"/api/v1/vault/dynamic/leases/{lease_id}/renew",
        json={"ttl_seconds": 86400},  # asks for the moon
        headers=headers,
    )
    assert r.status_code == 200, r.text
    # Capped at created_at + 120s, not the requested 86400s.
    assert r.json()["ttl_seconds"] <= 120
    # The DB row never exceeds the absolute cap either.
    async with async_session() as db:
        row = (
            await db.execute(
                text(
                    "SELECT created_at, expires_at FROM vault_leases "
                    "WHERE id = CAST(:id AS uuid)"
                ),
                {"id": lease_id},
            )
        ).fetchone()
    assert (row.expires_at - row.created_at).total_seconds() <= 120 + 1

    await _drop_role(username)
    await client.delete(f"/api/v1/vault/dynamic/engines/{engine_id}", headers=headers)


@pytest.mark.asyncio
async def test_renew_409_when_already_at_cap(client, master_password, admin_token):
    if not _raw_pg_url():
        pytest.skip("No database URL available for real PG test")
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    engine_id, username, lease_id, _ = await _make_lease(
        client, headers, default_ttl=60, max_ttl=120
    )
    # First renew lands on the cap.
    r = await client.post(
        f"/api/v1/vault/dynamic/leases/{lease_id}/renew",
        json={"ttl_seconds": 86400},
        headers=headers,
    )
    assert r.status_code == 200, r.text
    # Second renew has nothing left to extend.
    r = await client.post(
        f"/api/v1/vault/dynamic/leases/{lease_id}/renew",
        json={"ttl_seconds": 86400},
        headers=headers,
    )
    assert r.status_code == 409, r.text

    await _drop_role(username)
    await client.delete(f"/api/v1/vault/dynamic/engines/{engine_id}", headers=headers)


@pytest.mark.asyncio
async def test_renew_unknown_lease_404(client, master_password, admin_token):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}
    r = await client.post(
        "/api/v1/vault/dynamic/leases/00000000-0000-0000-0000-000000000000/renew",
        json={"ttl_seconds": 3600},
        headers=headers,
    )
    assert r.status_code == 404, r.text
