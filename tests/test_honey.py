# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Honeytoken IDS - verify decoy access fires alert + audit."""

import json

import pytest
from sqlalchemy import text
from starlette.requests import Request


@pytest.mark.asyncio
async def test_honey_token_auth_fires_alert(client, master_password):
    """Authenticating with a honey token writes a 'honey_access' audit entry."""
    from api.app.crypto import generate_token
    from api.app.database import async_session
    from api.app.vault_state import vault

    await client.post("/api/v1/vault/unseal", json={"password": master_password})

    raw_token = generate_token()
    token_hash = await vault.hmac_sha512_hex(raw_token)

    async with async_session() as db:
        await db.execute(
            text("""
                INSERT INTO vault_tokens
                    (name, token_hash, permissions, created_by, is_honey)
                VALUES
                    ('honey-prod-aws', :hash,
                     CAST(:perms AS jsonb), 'test', TRUE)
                ON CONFLICT (name) WHERE active DO UPDATE SET
                    token_hash = :hash, is_honey = TRUE
            """),
            {"hash": token_hash, "perms": json.dumps({"secrets": "r"})},
        )
        await db.commit()

    # Use the honey token, request must succeed (don't tip off attacker)
    r = await client.get(
        "/api/v1/vault/secrets/",
        headers={"Authorization": f"Bearer {raw_token}"},
    )
    assert r.status_code in (200, 404)

    # Verify the honey_access audit entry was written
    async with async_session() as db:
        result = await db.execute(
            text(
                "SELECT actor, target, detail FROM vault_audit "
                "WHERE action = 'honey_access' AND target = 'honey-prod-aws' "
                "ORDER BY timestamp DESC LIMIT 1"
            )
        )
        row = result.fetchone()
    assert row is not None, "honey_access audit entry not written"
    assert row.actor == "honey-prod-aws"
    detail = row.detail if isinstance(row.detail, dict) else json.loads(row.detail)
    assert detail.get("kind") == "token"


@pytest.mark.asyncio
async def test_honey_secret_read_fires_alert(client, admin_token, master_password):
    """Reading a honey secret writes a 'honey_access' audit entry."""
    from api.app.database import async_session

    auth = {"Authorization": f"Bearer {admin_token}"}

    # Create a normal secret then mark it as honey
    r = await client.post(
        "/api/v1/vault/secrets/",
        json={"name": "honey-pgsql-master", "value": "decoy-value-not-real"},
        headers=auth,
    )
    assert r.status_code == 201

    async with async_session() as db:
        await db.execute(
            text("UPDATE vault_secrets SET is_honey = TRUE WHERE name = :n"),
            {"n": "honey-pgsql-master"},
        )
        await db.commit()

    # Read it, must succeed (don't tip off)
    r = await client.get("/api/v1/vault/secrets/honey-pgsql-master", headers=auth)
    assert r.status_code == 200
    assert r.json()["value"] == "decoy-value-not-real"

    # Verify audit entry, there will be at least 2 (honey_access + read_secret)
    async with async_session() as db:
        result = await db.execute(
            text(
                "SELECT detail FROM vault_audit "
                "WHERE action = 'honey_access' AND target = 'honey-pgsql-master' "
                "ORDER BY timestamp DESC LIMIT 1"
            )
        )
        row = result.fetchone()
    assert row is not None, "honey_access audit entry not written"
    detail = row.detail if isinstance(row.detail, dict) else json.loads(row.detail)
    assert detail.get("kind") == "secret"


@pytest.mark.asyncio
async def test_normal_secret_read_no_honey_alert(client, admin_token, master_password):
    """Reading a non-honey secret does NOT write a honey_access entry."""
    from api.app.database import async_session

    auth = {"Authorization": f"Bearer {admin_token}"}

    r = await client.post(
        "/api/v1/vault/secrets/",
        json={"name": "normal-secret-no-honey", "value": "ok"},
        headers=auth,
    )
    assert r.status_code == 201

    r = await client.get("/api/v1/vault/secrets/normal-secret-no-honey", headers=auth)
    assert r.status_code == 200

    async with async_session() as db:
        result = await db.execute(
            text(
                "SELECT count(*) FROM vault_audit "
                "WHERE action = 'honey_access' "
                "AND target = 'normal-secret-no-honey'"
            )
        )
        n = result.scalar()
    assert n == 0


@pytest.mark.asyncio
async def test_honey_notification_delivery_does_not_block_response(
    client, master_password, monkeypatch
):
    """A stalled external notification must not delay the decoy response path."""
    import asyncio

    from api.app import honey
    from api.app.routes import notifications

    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    started = asyncio.Event()
    release = asyncio.Event()

    async def _stalled_dispatch(db, event, message):
        started.set()
        await release.wait()

    monkeypatch.setattr(notifications, "dispatch_event", _stalled_dispatch)
    request = Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [],
            "client": ("127.0.0.1", 12345),
        }
    )

    try:
        await asyncio.wait_for(
            honey.alert_honey_access(
                kind="token",
                name="honey-nonblocking-test",
                request=request,
                actor="honey-nonblocking-test",
            ),
            timeout=2,
        )
        await asyncio.wait_for(started.wait(), timeout=2)
        assert not release.is_set()
    finally:
        release.set()
        tasks = tuple(honey._notification_tasks)
        if tasks:
            await asyncio.gather(*tasks)
