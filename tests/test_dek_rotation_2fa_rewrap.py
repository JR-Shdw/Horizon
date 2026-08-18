"""POST /admin/rotate-dek-key must move every value wrapped under dek_key.

The route re-wrapped `vault_dek`, the audit keyring and the audit identity
seed, but not the values `rotate-password` also re-wraps: `totp_secret`,
`totp_pending`, `vault_yubikeys.hmac_secret` and `prev_hmac_key`. Those stay
ciphertext under a dek_key that no longer exists, which is an unseal lockout
for the two second-factor modes and a dead lazy-migration window for tokens.

Each test below fails on the pre-fix route.
"""

import hmac as _hmac
import os
from hashlib import sha1

import pyotp
import pytest
from api.app.crypto import hmac_token
from api.app.database import async_session
from api.app.routes.vault import _encrypt_2fa
from api.app.vault_state import vault as vs
from sqlalchemy import text


async def _reset_2fa_via_db():
    """Force 2FA back to `none`. The API refuses 2FA mutations while sealed."""
    async with async_session() as db:
        await db.execute(
            text("UPDATE vault_config SET value = 'none' WHERE key = 'second_factor'")
        )
        await db.execute(text("DELETE FROM vault_yubikeys"))
        await db.execute(
            text(
                "DELETE FROM vault_config WHERE key IN "
                "('totp_secret', 'totp_pending', 'totp_last_counter')"
            )
        )
        await db.commit()
    vs.invalidate_2fa_cache()


async def _rotate_dek_key(client, master_password, headers):
    r = await client.post(
        "/api/v1/vault/admin/rotate-dek-key",
        headers=headers,
        json={"current_password": master_password},
    )
    assert r.status_code == 200, r.text
    return r.json()


@pytest.mark.asyncio
async def test_rotate_dek_key_keeps_totp_unseal_working(
    client, master_password, admin_token
):
    """TOTP still verifies at the next unseal after a dek_key rotation."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    try:
        r = await client.post("/api/v1/vault/totp/setup", headers=headers)
        assert r.status_code == 200, r.text
        totp = pyotp.TOTP(r.json()["secret"])
        r = await client.post(
            "/api/v1/vault/totp/enable", headers=headers, json={"code": totp.now()}
        )
        assert r.status_code == 200, r.text
        r = await client.put(
            "/api/v1/vault/2fa", params={"mode": "totp"}, headers=headers
        )
        assert r.status_code == 200, r.text

        await _rotate_dek_key(client, master_password, headers)

        # Restart equivalent: the next unseal derives dek_key from the password
        # at the NEW version, so totp_secret must already live under it.
        r = await client.post("/api/v1/vault/seal", headers=headers)
        assert r.status_code == 200, r.text
        r = await client.post(
            "/api/v1/vault/unseal",
            json={"password": master_password, "totp_code": totp.now()},
        )
        assert r.status_code == 200, r.text
        assert r.json()["status"] == "unsealed"
    finally:
        await _reset_2fa_via_db()
        if vs.sealed:
            await client.post(
                "/api/v1/vault/unseal", json={"password": master_password}
            )


@pytest.mark.asyncio
async def test_rotate_dek_key_keeps_yubikey_unseal_working(
    client, master_password, admin_token
):
    """A registered YubiKey secret still decrypts at unseal after rotation."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}
    secret = os.urandom(20)

    try:
        r = await client.post(
            "/api/v1/vault/yubikey",
            headers=headers,
            json={
                "serial": "dek-rot-yk",
                "name": "dek-rot-yk",
                "hmac_secret": secret.hex(),
            },
        )
        assert r.status_code in (200, 201), r.text
        r = await client.put(
            "/api/v1/vault/2fa", params={"mode": "yubikey"}, headers=headers
        )
        assert r.status_code == 200, r.text

        await _rotate_dek_key(client, master_password, headers)

        r = await client.post("/api/v1/vault/seal", headers=headers)
        assert r.status_code == 200, r.text

        r = await client.post("/api/v1/vault/challenge")
        assert r.status_code == 200, r.text
        challenge = r.json()["challenge"]
        response = _hmac.new(secret, bytes.fromhex(challenge), sha1).digest()

        r = await client.post(
            "/api/v1/vault/unseal",
            json={
                "password": master_password,
                "challenge": challenge,
                "yubikey_response": response.hex(),
            },
        )
        assert r.status_code == 200, r.text
        assert r.json()["status"] == "unsealed"
    finally:
        await _reset_2fa_via_db()
        if vs.sealed:
            await client.post(
                "/api/v1/vault/unseal", json={"password": master_password}
            )


@pytest.mark.asyncio
async def test_rotate_dek_key_keeps_pending_totp_enrolment(
    client, master_password, admin_token
):
    """An in-flight TOTP enrolment survives a rotation that lands mid-setup."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    try:
        r = await client.post("/api/v1/vault/totp/setup", headers=headers)
        assert r.status_code == 200, r.text
        totp = pyotp.TOTP(r.json()["secret"])

        await _rotate_dek_key(client, master_password, headers)

        # /totp/enable reads totp_pending under the CURRENT dek_key, which the
        # rotation just replaced -- no restart needed to see the breakage.
        r = await client.post(
            "/api/v1/vault/totp/enable", headers=headers, json={"code": totp.now()}
        )
        assert r.status_code == 200, r.text
    finally:
        await _reset_2fa_via_db()
        if vs.sealed:
            await client.post(
                "/api/v1/vault/unseal", json={"password": master_password}
            )


@pytest.mark.asyncio
async def test_rotate_dek_key_preserves_prev_hmac_migration(
    client, master_password, admin_token
):
    """A token minted before a password rotation still authenticates after a
    dek_key rotation: prev_hmac_key rides dek_key and must move with it."""
    import json as _json

    from api.app.crypto import generate_token

    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Stand in for the state rotate-password leaves behind: a previous hmac_key
    # wrapped under the current dek_key, plus a token still hashed under it.
    prev_key = os.urandom(32)
    legacy_token = generate_token()
    async with async_session() as db:
        await db.execute(
            text("""
                INSERT INTO vault_config (key, value) VALUES ('prev_hmac_key', :v)
                ON CONFLICT (key) DO UPDATE SET value = :v
            """),
            {"v": _encrypt_2fa(prev_key, vs.aesgcm)},
        )
        await db.execute(text("DELETE FROM vault_tokens WHERE name = 'dek-rot-legacy'"))
        await db.execute(
            text("""
                INSERT INTO vault_tokens (name, token_hash, permissions, created_by)
                VALUES ('dek-rot-legacy', :h, CAST(:p AS jsonb), 'test')
            """),
            {
                "h": hmac_token(prev_key, legacy_token),
                "p": _json.dumps({"secrets": "r"}),
            },
        )
        await db.commit()

    try:
        body = await _rotate_dek_key(client, master_password, headers)
        assert body["status"] == "rotated"

        # Reload prev_hmac_key from disk, as a restart would.
        r = await client.post("/api/v1/vault/seal", headers=headers)
        assert r.status_code == 200, r.text
        r = await client.post(
            "/api/v1/vault/unseal", json={"password": master_password}
        )
        assert r.status_code == 200, r.text

        r = await client.get(
            "/api/v1/vault/tokens/whoami",
            headers={"Authorization": f"Bearer {legacy_token}"},
        )
        assert r.status_code == 200, r.text
        assert r.json()["name"] == "dek-rot-legacy"
    finally:
        async with async_session() as db:
            await db.execute(
                text("DELETE FROM vault_tokens WHERE name = 'dek-rot-legacy'")
            )
            await db.execute(
                text(
                    "DELETE FROM vault_config "
                    "WHERE key IN ('prev_hmac_key', 'prev_hmac_rotated_at')"
                )
            )
            await db.commit()
        vs.clear_prev_hmac()


@pytest.mark.asyncio
async def test_rotate_dek_key_drops_unreadable_prev_hmac(
    client, master_password, admin_token
):
    """An already-orphaned prev_hmac_key does not wedge the route.

    Deployments that rotated the dek_key before this fix carry a prev_hmac_key
    nothing can decrypt. Re-wrapping fail-closed would block every later
    rotation, so the dead row is dropped instead.
    """
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    async with async_session() as db:
        await db.execute(
            text("""
                INSERT INTO vault_config (key, value) VALUES ('prev_hmac_key', :v)
                ON CONFLICT (key) DO UPDATE SET value = :v
            """),
            {"v": os.urandom(60).hex()},
        )
        await db.commit()

    try:
        await _rotate_dek_key(client, master_password, headers)
        async with async_session() as db:
            row = (
                await db.execute(
                    text("SELECT value FROM vault_config WHERE key = 'prev_hmac_key'")
                )
            ).fetchone()
        assert row is None
    finally:
        async with async_session() as db:
            await db.execute(
                text(
                    "DELETE FROM vault_config "
                    "WHERE key IN ('prev_hmac_key', 'prev_hmac_rotated_at')"
                )
            )
            await db.commit()
        vs.clear_prev_hmac()
