"""Reaper-side lease expiry: the TTL must be enforced on the *target* DB.

The happy path here deliberately uses a creation template WITHOUT a DB-native
expiry clause (no `VALID UNTIL`), proving the reaper itself drops the role when
the lease expires - not the database.
"""

import os

import asyncpg
import pytest
from api.app.database import async_session
from api.app.routes import dynamic
from sqlalchemy import text


def _raw_pg_url() -> str:
    url = os.environ.get("RHORIZON_DATABASE_URL", "") or os.environ.get(
        "TEST_DATABASE_URL", ""
    )
    return url.replace("postgresql+asyncpg://", "postgresql://")


async def _make_engine_role_cred(client, headers, ttl_seconds=3600):
    asyncpg_url = _raw_pg_url()
    r = await client.post(
        "/api/v1/vault/dynamic/engines",
        json={
            "name": "expiry-pg-test",
            "engine_type": "postgresql",
            "connection_url": asyncpg_url,
        },
        headers=headers,
    )
    assert r.status_code == 201, r.text
    engine_id = r.json()["id"]

    r = await client.post(
        f"/api/v1/vault/dynamic/engines/{engine_id}/roles",
        json={
            # No VALID UNTIL, only the reaper can make this ephemeral.
            "name": "ttl-reader",
            "creation_sql": "CREATE ROLE \"{{name}}\" LOGIN PASSWORD '{{password}}'",
            "revocation_sql": 'DROP ROLE IF EXISTS "{{name}}"',
            "default_ttl_seconds": ttl_seconds,
        },
        headers=headers,
    )
    assert r.status_code == 201, r.text

    r = await client.post(
        f"/api/v1/vault/dynamic/engines/{engine_id}/creds/ttl-reader",
        json={"ttl_seconds": ttl_seconds},
        headers=headers,
    )
    assert r.status_code == 200, r.text
    return engine_id, r.json()["username"], r.json()["lease_id"]


async def _pg_role_exists(username: str) -> bool:
    conn = await asyncpg.connect(_raw_pg_url())
    try:
        row = await conn.fetchrow("SELECT 1 FROM pg_roles WHERE rolname = $1", username)
        return row is not None
    finally:
        await conn.close()


@pytest.mark.asyncio
async def test_reaper_drops_expired_pg_user(client, master_password, admin_token):
    if not _raw_pg_url():
        pytest.skip("No database URL available for real PG test")
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    engine_id, username, lease_id = await _make_engine_role_cred(client, headers)
    assert await _pg_role_exists(username), "role should exist after generate"

    # Remove the mutable role definition. The lease's immutable revocation
    # snapshot must still be sufficient to enforce its TTL.
    async with async_session() as db:
        await db.execute(
            text(
                "DELETE FROM vault_dynamic_roles "
                "WHERE engine_id = CAST(:id AS uuid) AND name = 'ttl-reader'"
            ),
            {"id": engine_id},
        )
        await db.commit()

    # Force the lease past its expiry without waiting on the clock.
    async with async_session() as db:
        await db.execute(
            text(
                "UPDATE vault_leases "
                "SET expires_at = NOW() - INTERVAL '1 hour', "
                "    revoked = true, revocation_verified = false "
                "WHERE id = CAST(:id AS uuid)"
            ),
            {"id": lease_id},
        )
        await db.commit()

    # Run the reaper hook.
    async with async_session() as db:
        dropped = await dynamic.expire_due_leases(db)
        await db.commit()

    assert any(d["username"] == username for d in dropped)
    assert not await _pg_role_exists(username), "reaper should have dropped the role"
    async with async_session() as db:
        state = (
            await db.execute(
                text(
                    "SELECT revoked, revocation_verified FROM vault_leases "
                    "WHERE id = CAST(:id AS uuid)"
                ),
                {"id": lease_id},
            )
        ).one()
    assert state.revoked is True
    assert state.revocation_verified is True

    # Lease is now marked revoked (no longer active).
    r = await client.get("/api/v1/vault/dynamic/leases", headers=headers)
    assert username not in {ls["username"] for ls in r.json()["items"]}

    await client.delete(f"/api/v1/vault/dynamic/engines/{engine_id}", headers=headers)


@pytest.mark.asyncio
async def test_reaper_keeps_lease_when_drop_fails(
    client, master_password, admin_token, monkeypatch
):
    """A failed drop (engine unreachable) must NOT mark the lease revoked -
    it has to retry next cycle, otherwise a live DB user is silently orphaned."""
    if not _raw_pg_url():
        pytest.skip("No database URL available for real PG test")
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    engine_id, username, lease_id = await _make_engine_role_cred(client, headers)

    async with async_session() as db:
        await db.execute(
            text(
                "UPDATE vault_leases SET expires_at = NOW() - INTERVAL '1 hour' "
                "WHERE id = CAST(:id AS uuid)"
            ),
            {"id": lease_id},
        )
        await db.commit()

    async def _boom(*args, **kwargs):
        raise OSError("engine unreachable")

    monkeypatch.setattr(dynamic, "_revoke_credential", _boom)

    async with async_session() as db:
        dropped = await dynamic.expire_due_leases(db)
        await db.commit()

    assert dropped == [], "nothing should be reported dropped"
    async with async_session() as db:
        row = (
            await db.execute(
                text(
                    "SELECT revoked, revocation_verified FROM vault_leases "
                    "WHERE id = CAST(:id AS uuid)"
                ),
                {"id": lease_id},
            )
        ).fetchone()
    assert row.revoked is False, "lease must stay un-revoked for retry"
    assert row.revocation_verified is False

    # The real DB role still exists (drop was prevented), clean it up.
    conn = await asyncpg.connect(_raw_pg_url())
    try:
        await conn.execute(f'DROP ROLE IF EXISTS "{username}"')
    finally:
        await conn.close()
    async with async_session() as db:
        await db.execute(
            text(
                "UPDATE vault_leases "
                "SET revoked = true, revocation_verified = true "
                "WHERE id = CAST(:id AS uuid)"
            ),
            {"id": lease_id},
        )
        await db.commit()
    await client.delete(f"/api/v1/vault/dynamic/engines/{engine_id}", headers=headers)


@pytest.mark.asyncio
async def test_reaper_keeps_legacy_lease_without_revocation_snapshot(
    client, master_password, admin_token, monkeypatch
):
    """Missing legacy metadata must never be recorded as target revocation."""
    if not _raw_pg_url():
        pytest.skip("No database URL available for real PG test")
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    engine_id, username, lease_id = await _make_engine_role_cred(client, headers)
    async with async_session() as db:
        await db.execute(
            text(
                "UPDATE vault_leases "
                "SET expires_at = NOW() - INTERVAL '1 hour', "
                "    revocation_sql = NULL "
                "WHERE id = CAST(:id AS uuid)"
            ),
            {"id": lease_id},
        )
        await db.commit()

    called = False

    async def _must_not_revoke(*args, **kwargs):
        nonlocal called
        called = True

    monkeypatch.setattr(dynamic, "_revoke_credential", _must_not_revoke)
    async with async_session() as db:
        dropped = await dynamic.expire_due_leases(db)
        await db.commit()

    assert dropped == []
    assert called is False
    async with async_session() as db:
        lease_state = (
            await db.execute(
                text(
                    "SELECT revoked, revocation_verified FROM vault_leases "
                    "WHERE id = CAST(:id AS uuid)"
                ),
                {"id": lease_id},
            )
        ).one()
    assert lease_state.revoked is False
    assert lease_state.revocation_verified is False

    conn = await asyncpg.connect(_raw_pg_url())
    try:
        await conn.execute(f'DROP ROLE IF EXISTS "{username}"')
    finally:
        await conn.close()
    async with async_session() as db:
        await db.execute(
            text(
                "UPDATE vault_leases SET revocation_sql = "
                "'DROP ROLE IF EXISTS \"{{name}}\"' "
                "WHERE id = CAST(:id AS uuid)"
            ),
            {"id": lease_id},
        )
        await db.commit()
    await client.delete(f"/api/v1/vault/dynamic/engines/{engine_id}", headers=headers)


@pytest.mark.asyncio
async def test_reaper_failed_batch_does_not_starve_newer_leases(
    client, master_password, admin_token, monkeypatch
):
    """A failed oldest batch moves behind credentials not yet attempted."""
    if not _raw_pg_url():
        pytest.skip("No database URL available for real PG test")
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    engine_id, username, lease_id = await _make_engine_role_cred(client, headers)
    async with async_session() as db:
        await db.execute(
            text(
                "UPDATE vault_leases "
                "SET expires_at = NOW() - INTERVAL '3 hours' "
                "WHERE id = CAST(:lease_id AS uuid)"
            ),
            {"lease_id": lease_id},
        )
        await db.execute(
            text(
                """
                INSERT INTO vault_leases (
                    engine_id, role_name, username, revocation_sql, expires_at
                )
                VALUES
                    (CAST(:engine_id AS uuid), 'ttl-reader', :second,
                     'DROP ROLE IF EXISTS "{{name}}"',
                     NOW() - INTERVAL '2 hours'),
                    (CAST(:engine_id AS uuid), 'ttl-reader', :third,
                     'DROP ROLE IF EXISTS "{{name}}"',
                     NOW() - INTERVAL '1 hour')
                """
            ),
            {
                "engine_id": engine_id,
                "second": f"{username}_second",
                "third": f"{username}_third",
            },
        )
        await db.commit()

    revoked: list[str] = []

    async def _connection_url(*_args):
        return "unused"

    async def _record_revoke(_engine_type, _conn_url, _sql, target_username):
        revoked.append(target_username)
        raise OSError("target unavailable")

    monkeypatch.setattr(dynamic, "_LEASE_REAPER_BATCH_SIZE", 2)
    monkeypatch.setattr(dynamic, "_get_connection_url", _connection_url)
    monkeypatch.setattr(dynamic, "_revoke_credential", _record_revoke)

    async with async_session() as db:
        dropped = await dynamic.expire_due_leases(db)
        await db.commit()

    assert dropped == []
    assert revoked == [
        username,
        f"{username}_second",
    ]

    revoked.clear()
    async with async_session() as db:
        dropped = await dynamic.expire_due_leases(db)
        await db.commit()

    assert dropped == []
    assert revoked[0] == f"{username}_third"

    async with async_session() as db:
        remaining = (
            (
                await db.execute(
                    text(
                        "SELECT username FROM vault_leases "
                        "WHERE NOT revoked OR NOT revocation_verified"
                    )
                )
            )
            .scalars()
            .all()
        )
        assert set(remaining) == {
            username,
            f"{username}_second",
            f"{username}_third",
        }
        await db.execute(
            text("DELETE FROM vault_leases WHERE engine_id = CAST(:engine_id AS uuid)"),
            {"engine_id": engine_id},
        )
        await db.commit()

    conn = await asyncpg.connect(_raw_pg_url())
    try:
        await conn.execute(f'DROP ROLE IF EXISTS "{username}"')
    finally:
        await conn.close()
    await client.delete(f"/api/v1/vault/dynamic/engines/{engine_id}", headers=headers)


@pytest.mark.asyncio
async def test_revoke_credential_mysql_dispatch(monkeypatch):
    """MySQL leases route through the loaded module with {{name}} substituted."""
    seen = {}

    async def _fake_mysql(conn_url, sql):
        seen["url"] = conn_url
        seen["sql"] = sql

    monkeypatch.setattr(dynamic.ENGINES["mysql"], "revoke", _fake_mysql)
    await dynamic._revoke_credential(
        "mysql", "mysql://u:p@h/db", "DROP USER '{{name}}'@'%'", "rh_x_abc"
    )
    assert seen == {"url": "mysql://u:p@h/db", "sql": "DROP USER 'rh_x_abc'@'%'"}


@pytest.mark.asyncio
async def test_provision_credential_mysql_dispatch(monkeypatch):
    seen = {}

    async def _fake_mysql(conn_url, sql):
        seen["sql"] = sql

    monkeypatch.setattr(dynamic.ENGINES["mysql"], "provision", _fake_mysql)
    await dynamic._provision_credential("mysql", "mysql://u:p@h/db", "CREATE USER x")
    assert seen["sql"] == "CREATE USER x"


@pytest.mark.asyncio
async def test_unsupported_engine_type_rejected():
    with pytest.raises(ValueError):
        await dynamic._revoke_credential("oracle", "x", "y", "z")


def test_generate_username_sanitizes_hostile_role_name():
    import re

    u = dynamic._generate_username('foo"; DROP ROLE x; --')
    # Whole username (prefix + sanitized name + hex suffix) is a safe identifier.
    assert re.fullmatch(r"rh_[a-z0-9_]+", u), u
    assert len(u) <= 32
    assert re.fullmatch(r"rh_[a-z0-9_]*_[0-9a-f]{16}", u), u
    for bad in ('"', ";", " ", "-", "'"):
        assert bad not in u
