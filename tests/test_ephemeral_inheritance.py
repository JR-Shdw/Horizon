# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Bootstrap -> ephemeral group-membership inheritance.

Use case : a long-lived API token (e.g. `ansible-prod-runner`) is added
to the `team-prod` group. Its rh-watch sidecar mints short-TTL
ephemerals every 30 minutes. Without inheritance the operator would
have to attach every random `eph-XXXX` token UUID in vault_group_members,
which is impossible. With inheritance, the API auto-replicates the
bootstrap's memberships onto each freshly-minted ephemeral, so strict-
RBAC namespaces still authorize the rotation without manual ops.
"""

import json

import pytest
import pytest_asyncio
from sqlalchemy import text


@pytest_asyncio.fixture(autouse=True)
async def _clean():
    from api.app.database import async_session

    async def _wipe():
        async with async_session() as db:
            await db.execute(text("DELETE FROM vault_tokens WHERE name LIKE 'inh-%'"))
            await db.execute(text("DELETE FROM vault_tokens WHERE name LIKE 'eph-%'"))
            await db.execute(text("DELETE FROM vault_groups WHERE name LIKE 'inh-%'"))
            await db.commit()

    await _wipe()
    yield
    await _wipe()


@pytest.mark.asyncio
async def test_inherit_group_membership_copies_groups(
    client, master_password, admin_token
):
    """Mint an ephemeral with inherit=true and assert its name is
    inserted into the same vault_group_members rows as the caller."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    from api.app.crypto import generate_token
    from api.app.database import async_session
    from api.app.vault_state import vault as _vault

    # Set up : group, bootstrap token, membership.
    async with async_session() as db:
        await db.execute(
            text(
                """
                INSERT INTO vault_groups (name, permissions, source)
                VALUES ('inh-team-prod', '{"admin": "rw"}'::jsonb, 'local')
                """
            )
        )
        team_id = (
            await db.execute(
                text("SELECT id FROM vault_groups WHERE name = 'inh-team-prod'")
            )
        ).scalar()
        await db.commit()

    raw = generate_token()
    token_hash = await _vault.hmac_sha512_hex(raw)
    async with async_session() as db:
        await db.execute(
            text(
                """
                INSERT INTO vault_tokens
                    (name, token_hash, permissions, created_by)
                VALUES ('inh-bootstrap', :hash,
                        CAST(:perms AS jsonb), 'inh-bootstrap')
                ON CONFLICT (name) WHERE active DO UPDATE SET token_hash = :hash
                """
            ),
            {
                "hash": token_hash,
                "perms": json.dumps({"tokens": "rw", "secrets": "rw"}),
            },
        )
        await db.execute(
            text(
                """
                INSERT INTO vault_group_members
                    (group_id, principal_type, token_id)
                SELECT CAST(:gid AS uuid), 'token', id
                FROM vault_tokens
                WHERE name = 'inh-bootstrap' AND active
                """
            ),
            {"gid": str(team_id)},
        )
        await db.commit()

    # Mint ephemeral with inherit_group_membership=true.
    r = await client.post(
        "/api/v1/vault/tokens/ephemeral",
        json={
            "permissions": {"secrets": "r"},
            "ttl_seconds": 300,
            "inherit_group_membership": True,
        },
        headers={"Authorization": f"Bearer {raw}"},
    )
    assert r.status_code == 201, r.text
    data = r.json()
    eph_name = data["name"]
    assert eph_name.startswith("eph-")

    # Verify the new ephemeral is now a member of the same groups.
    async with async_session() as db:
        rows = (
            await db.execute(
                text(
                    "SELECT m.group_id FROM vault_group_members AS m "
                    "JOIN vault_tokens AS t ON t.id = m.token_id "
                    "WHERE m.principal_type = 'token' AND t.name = :name"
                ),
                {"name": eph_name},
            )
        ).fetchall()
        assert len(rows) == 1
        assert str(rows[0].group_id) == str(team_id)


@pytest.mark.asyncio
async def test_inherit_default_off(client, master_password, admin_token):
    """Without inherit_group_membership=true, the new ephemeral has
    no group membership rows - back-compat with pre-feature clients."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.post(
        "/api/v1/vault/tokens/ephemeral",
        json={"permissions": {"secrets": "r"}, "ttl_seconds": 300},
        headers=headers,
    )
    assert r.status_code == 201
    eph_name = r.json()["name"]

    from api.app.database import async_session

    async with async_session() as db:
        count = (
            await db.execute(
                text(
                    "SELECT count(*) FROM vault_group_members AS m "
                    "JOIN vault_tokens AS t ON t.id = m.token_id "
                    "WHERE m.principal_type = 'token' AND t.name = :name"
                ),
                {"name": eph_name},
            )
        ).scalar()
        assert count == 0


@pytest.mark.asyncio
async def test_inherit_caller_with_no_groups_is_noop(
    client, master_password, admin_token
):
    """If the caller has zero memberships, inherit=true is a no-op
    (not a crash)."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.post(
        "/api/v1/vault/tokens/ephemeral",
        json={
            "permissions": {"secrets": "r"},
            "ttl_seconds": 300,
            "inherit_group_membership": True,
        },
        headers=headers,
    )
    assert r.status_code == 201
