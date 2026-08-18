"""End-to-end real test: mint a dynamic credential against a SEPARATE target
PostgreSQL (the "app database"), then actually authenticate to that database
with the minted user, renew the lease, revoke it, and prove the login dies.

Unlike test_dynamic_lease_expiry (which checks pg_roles existence), this proves
the credential is genuinely usable end-to-end: a real login + query on the
target DB, not just a row in a catalog.

Gated on RH_DYN_TARGET_URL so it only runs when a real target DB is provided,
e.g. a postgres container on node-5:

    podman run -d --name rh-dyn-target -p 5455:5432 \\
      -e POSTGRES_USER=appadmin -e POSTGRES_PASSWORD=appadminpw \\
      -e POSTGRES_DB=appdb docker.io/library/postgres:18-trixie
    RH_DYN_TARGET_URL='postgresql://appadmin:appadminpw@127.0.0.1:5455/appdb' \\
      .venv/bin/python -m pytest tests/test_dynamic_e2e_real.py -q --no-cov
"""

import os
from urllib.parse import urlparse

import asyncpg
import pytest

TARGET_URL = os.environ.get("RH_DYN_TARGET_URL", "")


async def _login_ok(username: str, password: str) -> bool:
    """True if the minted user can authenticate + query the target DB.

    Credentials are passed as explicit kwargs, not interpolated into a DSN: a
    minted password contains shell/URL-special chars (the generator uses
    !@#$%^&*) that would corrupt a postgresql:// string.
    """
    u = urlparse(TARGET_URL)
    try:
        conn = await asyncpg.connect(
            host=u.hostname,
            port=u.port or 5432,
            database=u.path.lstrip("/"),
            user=username,
            password=password,
            timeout=5,
        )
    except (
        asyncpg.InvalidPasswordError,
        asyncpg.InvalidAuthorizationSpecificationError,
    ):
        return False
    try:
        return (await conn.fetchval("SELECT 1")) == 1
    finally:
        await conn.close()


@pytest.mark.asyncio
async def test_dynamic_cred_real_login_renew_revoke(
    client, master_password, admin_token
):
    if not TARGET_URL:
        pytest.skip("Set RH_DYN_TARGET_URL to a real target PG to run the E2E test")
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    # 1. Provision an engine pointed at the real target app DB.
    r = await client.post(
        "/api/v1/vault/dynamic/engines",
        json={
            "name": "e2e-target",
            "engine_type": "postgresql",
            "connection_url": TARGET_URL,
            "max_ttl_seconds": 3600,
        },
        headers=headers,
    )
    assert r.status_code == 201, r.text
    engine_id = r.json()["id"]

    # 2. Define a login role.
    r = await client.post(
        f"/api/v1/vault/dynamic/engines/{engine_id}/roles",
        json={
            "name": "app-login",
            "creation_sql": "CREATE ROLE \"{{name}}\" LOGIN PASSWORD '{{password}}'",
            "revocation_sql": 'DROP ROLE IF EXISTS "{{name}}"',
            "default_ttl_seconds": 300,
            "max_ttl_seconds": 3600,
        },
        headers=headers,
    )
    assert r.status_code == 201, r.text

    # 3. Mint a credential.
    r = await client.post(
        f"/api/v1/vault/dynamic/engines/{engine_id}/creds/app-login",
        json={"ttl_seconds": 300},
        headers=headers,
    )
    assert r.status_code == 200, r.text
    cred = r.json()
    username, password, lease_id = (
        cred["username"],
        cred["password"],
        cred["lease_id"],
    )

    try:
        # 4. The minted credential really logs in to the target DB.
        assert await _login_ok(username, password), "minted user should authenticate"

        # 5. Renew extends the lease (and the credential keeps working).
        r = await client.post(
            f"/api/v1/vault/dynamic/leases/{lease_id}/renew",
            json={"ttl_seconds": 1800},
            headers=headers,
        )
        assert r.status_code == 200, r.text
        assert await _login_ok(username, password), "user still works after renew"

        # 6. Revoke drops the user; the login must now fail.
        r = await client.post(
            f"/api/v1/vault/dynamic/leases/{lease_id}/revoke", headers=headers
        )
        assert r.status_code == 200, r.text
        assert not await _login_ok(username, password), "login must die after revoke"
    finally:
        # Best-effort cleanup if an assertion left the role behind.
        try:
            conn = await asyncpg.connect(TARGET_URL, timeout=5)
            try:
                await conn.execute(f'DROP ROLE IF EXISTS "{username}"')
            finally:
                await conn.close()
        except Exception:
            pass
        await client.delete(
            f"/api/v1/vault/dynamic/engines/{engine_id}", headers=headers
        )
