"""Targeted tests for coverage gaps - auth expiry, 2FA paths,
notifications dispatch, backup restore, dynamic MySQL."""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import pytest
from sqlalchemy import text

# auth.py: token expiry (lines 47-50)


@pytest.mark.asyncio
async def test_expired_token_rejected(client, master_password, admin_token):
    """An expired token returns 401."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Create a token with expiry in the past
    r = await client.post(
        "/api/v1/vault/tokens/",
        json={
            "name": "expired-tok",
            "permissions": {"secrets": "r"},
            "expires_at": (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(),
        },
        headers=headers,
    )
    assert r.status_code == 201
    expired_token = r.json()["token"]

    # Use expired token
    r = await client.get(
        "/api/v1/vault/secrets/",
        headers={"Authorization": f"Bearer {expired_token}"},
    )
    assert r.status_code == 401


# vault.py: 2FA verify paths (lines 300-351)


@pytest.mark.asyncio
async def test_unseal_totp_wrong_code(client, master_password, admin_token):
    """Unseal with wrong TOTP code returns 401."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Setup TOTP
    import pyotp

    r = await client.post("/api/v1/vault/totp/setup", headers=headers)
    secret = r.json()["secret"]
    totp = pyotp.TOTP(secret)
    await client.post(
        "/api/v1/vault/totp/enable",
        json={"code": totp.now()},
        headers=headers,
    )
    await client.put("/api/v1/vault/2fa", params={"mode": "totp"}, headers=headers)

    # Seal
    from api.app.vault_state import vault as vs

    vs.seal()

    # Unseal with wrong TOTP
    r = await client.post(
        "/api/v1/vault/unseal",
        json={"password": master_password, "totp_code": "000000"},
    )
    assert r.status_code == 401

    # Cleanup: unseal properly, reset mode, delete totp
    r = await client.post(
        "/api/v1/vault/unseal",
        json={"password": master_password, "totp_code": totp.now()},
    )
    await client.put("/api/v1/vault/2fa", params={"mode": "none"}, headers=headers)
    await client.delete("/api/v1/vault/totp", headers=headers)


@pytest.mark.asyncio
async def test_unseal_2fa_required_no_factor(client, master_password, admin_token):
    """Unseal without 2FA when mode is set returns 400."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Setup TOTP + set mode
    import pyotp

    r = await client.post("/api/v1/vault/totp/setup", headers=headers)
    secret = r.json()["secret"]
    totp = pyotp.TOTP(secret)
    await client.post(
        "/api/v1/vault/totp/enable",
        json={"code": totp.now()},
        headers=headers,
    )
    await client.put("/api/v1/vault/2fa", params={"mode": "totp"}, headers=headers)

    from api.app.vault_state import vault as vs

    vs.seal()

    # Unseal without TOTP code
    r = await client.post(
        "/api/v1/vault/unseal",
        json={"password": master_password},
    )
    assert r.status_code == 400

    # Cleanup
    r = await client.post(
        "/api/v1/vault/unseal",
        json={"password": master_password, "totp_code": totp.now()},
    )
    await client.put("/api/v1/vault/2fa", params={"mode": "none"}, headers=headers)
    await client.delete("/api/v1/vault/totp", headers=headers)


# notifications.py: dispatch_event (lines 239-254)


@pytest.mark.asyncio
async def test_dispatch_event(client, master_password, admin_token):
    """dispatch_event sends to enabled channels."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Create a webhook channel
    await client.post(
        "/api/v1/vault/notifications/",
        json={
            "name": "dispatch-test",
            "channel_type": "webhook",
            "config": {"url": "https://hooks.example.com/test"},
            "events": ["test_event"],
        },
        headers=headers,
    )

    # Dispatch with mocked httpx
    from api.app.database import async_session
    from api.app.routes.notifications import dispatch_event

    with patch("api.app.routes.notifications.httpx.AsyncClient") as mock_cl:
        mock_inst = AsyncMock()
        mock_resp = AsyncMock()
        mock_resp.raise_for_status = lambda: None
        mock_inst.post = AsyncMock(return_value=mock_resp)
        mock_inst.__aenter__ = AsyncMock(return_value=mock_inst)
        mock_inst.__aexit__ = AsyncMock(return_value=False)
        mock_cl.return_value = mock_inst

        async with async_session() as db:
            await dispatch_event(db, "test_event", "test message")

    # Cleanup
    r = await client.get("/api/v1/vault/notifications/", headers=headers)
    for ch in r.json().get("items", []):
        if ch["name"] == "dispatch-test":
            await client.delete(
                f"/api/v1/vault/notifications/{ch['id']}", headers=headers
            )


# backup.py: restore corrupted data (lines 198-199, 264-278)


@pytest.mark.asyncio
async def test_restore_corrupted_json(client, master_password, admin_token):
    """Restore with valid encryption but corrupted JSON returns 400."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Create a backup with valid passphrase
    import base64

    from api.app.routes.backup import _encrypt_backup

    garbage = b"not json at all"
    encrypted = _encrypt_backup(garbage, "test-passphrase-1234")

    r = await client.post(
        "/api/v1/vault/backup/restore",
        json={
            "passphrase": "test-passphrase-1234",
            "master_password_backup": master_password,
            "confirm_phrase": "RESTORE",
            "payload": base64.b64encode(encrypted).decode(),
        },
        headers=headers,
    )
    assert r.status_code == 400


# dynamic.py: credential gen failure + MySQL path (lines 366-397)


@pytest.mark.asyncio
async def test_dynamic_creds_db_failure(client, master_password, admin_token):
    """Generate credentials with DB connection failure returns 502."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Create engine + role
    r = await client.post(
        "/api/v1/vault/dynamic/engines",
        json={
            "name": "fail-pg",
            "engine_type": "postgresql",
            "connection_url": "postgresql://x:x@nowhere:5432/x",
        },
        headers=headers,
    )
    engine_id = r.json()["id"]

    await client.post(
        f"/api/v1/vault/dynamic/engines/{engine_id}/roles",
        json={
            "name": "testrole",
            "creation_sql": "CREATE ROLE {{name}} LOGIN PASSWORD '{{password}}'",
            "revocation_sql": "DROP ROLE IF EXISTS {{name}}",
        },
        headers=headers,
    )

    # Mock asyncpg to raise exception
    with patch(
        "api.app.dynamic_engines.postgresql.asyncpg.connect",
        side_effect=Exception("connection refused"),
    ):
        r = await client.post(
            f"/api/v1/vault/dynamic/engines/{engine_id}/creds/testrole",
            headers=headers,
        )
    assert r.status_code == 502

    # Cleanup
    await client.delete(f"/api/v1/vault/dynamic/engines/{engine_id}", headers=headers)


# notifications.py: _send_notification routes (lines 260, 277-288)


class TestNotificationRoutes:
    @pytest.mark.asyncio
    async def test_send_matrix_success(self):
        """Matrix send with mocked httpx succeeds."""
        from api.app.routes.notifications import _send_matrix

        with patch("api.app.routes.notifications.httpx.AsyncClient") as mock_cl:
            mock_inst = AsyncMock()
            mock_resp = AsyncMock()
            mock_resp.raise_for_status = lambda: None
            mock_inst.put = AsyncMock(return_value=mock_resp)
            mock_inst.__aenter__ = AsyncMock(return_value=mock_inst)
            mock_inst.__aexit__ = AsyncMock(return_value=False)
            mock_cl.return_value = mock_inst

            await _send_matrix(
                {
                    "homeserver": "https://matrix.test",
                    "room_id": "!room:test",
                    "token": "syt_test",
                },
                "test_event",
                "hello",
            )
            mock_inst.put.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_webhook_success(self):
        """Webhook send with mocked httpx succeeds."""
        from api.app.routes.notifications import _send_webhook

        with patch("api.app.routes.notifications.httpx.AsyncClient") as mock_cl:
            mock_inst = AsyncMock()
            mock_resp = AsyncMock()
            mock_resp.raise_for_status = lambda: None
            mock_inst.post = AsyncMock(return_value=mock_resp)
            mock_inst.__aenter__ = AsyncMock(return_value=mock_inst)
            mock_inst.__aexit__ = AsyncMock(return_value=False)
            mock_cl.return_value = mock_inst

            await _send_webhook(
                {"url": "https://hooks.example.com/x"},
                "test_event",
                "hello",
            )
            mock_inst.post.assert_called_once()


# vault.py: bootstrap root token on first boot


@pytest.mark.asyncio
async def test_first_boot_returns_root_token(client, master_password, admin_token):
    """First unseal on fresh DB returns root_token.

    Bootstrap requires triple-lock release: master_check,
    argon2_salt, and vault_initialized must all be absent. The test
    therefore wipes vault_config entirely (plus root token + audit).

    Wiping argon2_salt forces a new salt at next unseal - Argon2id derives
    a different master_key, so vault.hmac_key changes. The session-scoped
    admin_token fixture's hash is no longer valid; restore it via DB hack
    so subsequent tests can authenticate.
    """
    # hmac_token import removed: vault.hmac_sha512_hex used directly
    from api.app.database import async_session
    from api.app.vault_state import vault as vs

    async with async_session() as db:
        # Genuine fresh-install: wipe vault_config (auth state), root token,
        # audit chain, AND every secret/DEK row. Wiping argon2_salt makes the
        # new bootstrap derive a different master_key, so any preexisting DEK
        # encrypted under the old dek_key would become undecryptable and
        # break subsequent tests' rotate-password / read paths.
        await db.execute(
            text(
                "DELETE FROM vault_config WHERE key IN "
                "('master_check', 'argon2_salt', 'vault_initialized')"
            )
        )
        await db.execute(text("DELETE FROM vault_tokens WHERE name = 'root'"))
        await db.execute(text("DELETE FROM vault_audit"))
        # Cascade order: leases/engines and secret versions/secrets must release
        # every DEK reference before the fresh-install DEK wipe.
        await db.execute(text("DELETE FROM vault_leases"))
        await db.execute(text("DELETE FROM vault_dynamic_roles"))
        await db.execute(text("DELETE FROM vault_dynamic_engines"))
        await db.execute(text("DELETE FROM vault_secret_versions"))
        await db.execute(text("DELETE FROM vault_secrets"))
        await db.execute(text("DELETE FROM vault_dek"))
        await db.commit()

    vs.seal()

    r = await client.post("/api/v1/vault/unseal", json={"password": master_password})
    assert r.status_code == 200
    data = r.json()
    assert "root_token" in data
    assert data["root_token"].startswith("rh_")
    assert "warning" in data

    # Re-stamp the admin_token under the new hmac_key (bootstrap derived
    # different keys because argon2_salt was wiped -> new salt -> new master_key)
    new_hash = await vs.hmac_sha512_hex(admin_token)
    async with async_session() as db:
        await db.execute(
            text("UPDATE vault_tokens SET token_hash = :h WHERE name = 'test-admin'"),
            {"h": new_hash},
        )
        await db.commit()
