"""Backlog #3: hierarchical dek_key rotation.

Tests that POST /admin/rotate-dek-key:
  1. Bumps dek_key_version in vault_config
  2. Re-wraps every vault_dek entry under the new dek_key
  3. Existing secrets remain readable (sub-keys correctly threaded)
  4. Refuses to rotate without the current master password
"""

import pytest
from api.app.database import async_session
from sqlalchemy import text


@pytest.mark.asyncio
async def test_rotate_dek_key_bumps_version_and_keeps_secrets_readable(
    client, master_password, admin_token
):
    """Full lifecycle: create secret, rotate dek_key, secret still readable.

    The rotation re-wraps the secret's DEK under a fresh dek_key. The
    secret's ciphertext is untouched (no per-secret decrypt-encrypt),
    so reads after rotation must succeed and yield the original value.
    """
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    secret_value = "value-before-rotation-xyz789"
    r = await client.post(
        "/api/v1/vault/secrets/",
        headers=headers,
        json={"name": "rot-test-secret", "value": secret_value},
    )
    assert r.status_code in (200, 201)

    # Snapshot version before
    async with async_session() as db:
        before = await db.execute(
            text("SELECT value FROM vault_config WHERE key = 'dek_key_version'")
        )
        before_row = before.fetchone()
        before_version = int(before_row.value) if before_row else 1

    # Rotate
    r = await client.post(
        "/api/v1/vault/admin/rotate-dek-key",
        headers=headers,
        json={"current_password": master_password},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "rotated"
    assert body["new_version"] == before_version + 1
    assert body["deks_rewrapped"] >= 1

    # Verify version bumped in DB
    async with async_session() as db:
        after = await db.execute(
            text("SELECT value FROM vault_config WHERE key = 'dek_key_version'")
        )
        after_row = after.fetchone()
        assert int(after_row.value) == before_version + 1

        # rotated_at marker present
        ts = await db.execute(
            text("SELECT value FROM vault_config WHERE key = 'dek_key_rotated_at'")
        )
        assert ts.fetchone() is not None

    # Secret is still readable after rotation
    r = await client.get(
        "/api/v1/vault/secrets/rot-test-secret",
        headers=headers,
    )
    assert r.status_code == 200
    assert r.json()["value"] == secret_value


@pytest.mark.asyncio
async def test_rotate_dek_key_rejects_wrong_password(
    client, master_password, admin_token
):
    """Rotation requires the current master password; wrong password gets 401."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    r = await client.post(
        "/api/v1/vault/admin/rotate-dek-key",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"current_password": "definitely-not-the-master-password"},
    )
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_rotate_dek_key_aborts_when_existing_dek_cannot_unwrap(
    client, master_password, admin_token
):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.post(
        "/api/v1/vault/secrets/",
        headers=headers,
        json={"name": "rot-corrupt-dek", "value": "before-corruption"},
    )
    assert r.status_code in (200, 201)

    async with async_session() as db:
        before_r = await db.execute(
            text("SELECT value FROM vault_config WHERE key = 'dek_key_version'")
        )
        before_row = before_r.fetchone()
        before_version = int(before_row.value) if before_row else 1

        dek_r = await db.execute(
            text(
                "SELECT id, encrypted_key, nonce FROM vault_dek "
                "ORDER BY created_at DESC LIMIT 1"
            )
        )
        dek_row = dek_r.fetchone()
        assert dek_row is not None
        dek_id = str(dek_row.id)
        original_encrypted_key = bytes(dek_row.encrypted_key)
        original_nonce = bytes(dek_row.nonce)

        await db.execute(
            text(
                "UPDATE vault_dek SET encrypted_key = :ekey "
                "WHERE id = CAST(:id AS uuid)"
            ),
            {"ekey": b"\x00", "id": dek_id},
        )
        await db.commit()

    try:
        r = await client.post(
            "/api/v1/vault/admin/rotate-dek-key",
            headers=headers,
            json={"current_password": master_password},
        )
        assert r.status_code == 500
        assert "aborted" in r.json()["detail"]

        async with async_session() as db:
            after_r = await db.execute(
                text("SELECT value FROM vault_config WHERE key = 'dek_key_version'")
            )
            after_row = after_r.fetchone()
            assert int(after_row.value) == before_version
    finally:
        async with async_session() as db:
            await db.execute(
                text(
                    "UPDATE vault_dek SET encrypted_key = :ekey, nonce = :nonce "
                    "WHERE id = CAST(:id AS uuid)"
                ),
                {
                    "ekey": original_encrypted_key,
                    "nonce": original_nonce,
                    "id": dek_id,
                },
            )
            await db.commit()


@pytest.mark.asyncio
async def test_rotate_dek_key_requires_admin_scope(
    client, master_password, admin_token
):
    """A non-root token (secrets:rw) cannot trigger dek_key rotation."""
    import json as _json

    from api.app.crypto import generate_token
    from api.app.vault_state import vault

    await client.post("/api/v1/vault/unseal", json={"password": master_password})

    raw = generate_token()
    h = await vault.hmac_sha512_hex(raw)
    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_tokens WHERE name = 'no-admin'"))
        await db.execute(
            text(
                "INSERT INTO vault_tokens (name, token_hash, permissions, created_by) "
                "VALUES ('no-admin', :h, CAST(:p AS jsonb), 'test')"
            ),
            {"h": h, "p": _json.dumps({"secrets": "rw"})},
        )
        await db.commit()

    r = await client.post(
        "/api/v1/vault/admin/rotate-dek-key",
        headers={"Authorization": f"Bearer {raw}"},
        json={"current_password": master_password},
    )
    assert r.status_code == 403
