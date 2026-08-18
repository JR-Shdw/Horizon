"""Tests for /api/v1/vault/oneshot with TOTP and YubiKey 2FA.

Covers _verify_oneshot_2fa() (oneshot.py:72-130), which was not exercised
by the existing tests - they only test the `none` mode.
"""

import pyotp
import pytest
from api.app.database import async_session
from api.app.vault_state import vault as vs
from sqlalchemy import text

# ---------------------------------------------------------------------------
# Helpers: setup / teardown 2FA via the API + forced DB cleanup
# ---------------------------------------------------------------------------


async def _force_2fa_reset_via_db():
    """Force-reset the 2FA mode and purge YubiKeys/TOTP via direct DB access.

    The API refuses 2FA mutations when the vault is sealed -> if a test leaves
    the vault sealed with mode=yubikey/totp, the API-based cleanup loops
    forever. We bypass straight to vault_config.

    Must be called *after* attempting to unseal, as a safety net."""
    async with async_session() as db:
        await db.execute(
            text("UPDATE vault_config SET value = 'none' WHERE key = 'second_factor'")
        )
        await db.execute(text("DELETE FROM vault_yubikeys"))
        await db.execute(
            text(
                "DELETE FROM vault_config WHERE key IN "
                "('totp_secret', 'totp_enabled', 'totp_last_counter')"
            )
        )
        await db.commit()
    vs.invalidate_2fa_cache()


async def _enable_totp(client, master_password, admin_token) -> pyotp.TOTP:
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.post("/api/v1/vault/totp/setup", headers=headers)
    secret = r.json()["secret"]
    totp = pyotp.TOTP(secret)
    await client.post(
        "/api/v1/vault/totp/enable",
        json={"code": totp.now()},
        headers=headers,
    )
    await client.put("/api/v1/vault/2fa", params={"mode": "totp"}, headers=headers)
    return totp


async def _disable_totp(client, master_password, admin_token, totp):
    """Cleanup robuste : essaie via API, force-reset DB en filet."""
    try:
        if vs.sealed:
            await client.post(
                "/api/v1/vault/unseal",
                json={"password": master_password, "totp_code": totp.now()},
            )
        headers = {"Authorization": f"Bearer {admin_token}"}
        await client.put("/api/v1/vault/2fa", params={"mode": "none"}, headers=headers)
        await client.delete("/api/v1/vault/totp", headers=headers)
    finally:
        await _force_2fa_reset_via_db()
        if vs.sealed:
            await client.post(
                "/api/v1/vault/unseal", json={"password": master_password}
            )


# ---------------------------------------------------------------------------
# TOTP mode tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_oneshot_totp_success(client, master_password, admin_token):
    """Vault in TOTP mode + correct code -> /oneshot reads the secret and re-seals."""
    totp = await _enable_totp(client, master_password, admin_token)
    headers = {"Authorization": f"Bearer {admin_token}"}

    try:
        # Create a secret while the vault is unsealed
        await client.post(
            "/api/v1/vault/secrets/",
            headers=headers,
            json={"name": "oneshot-totp-target", "value": "totp-protected-value"},
        )
        await client.post("/api/v1/vault/seal", headers=headers)
        assert vs.sealed is True

        code = totp.now()
        r = await client.post(
            "/api/v1/vault/oneshot",
            json={
                "password": master_password,
                "name": "oneshot-totp-target",
                "totp_code": code,
            },
        )
        assert r.status_code == 200
        assert r.json()["value"] == "totp-protected-value"
        assert vs.sealed is True

        replay = await client.post(
            "/api/v1/vault/oneshot",
            json={
                "password": master_password,
                "name": "oneshot-totp-target",
                "totp_code": code,
            },
        )
        assert replay.status_code == 401
        assert "Invalid TOTP code" in replay.json()["detail"]
        assert vs.sealed is True
    finally:
        await _disable_totp(client, master_password, admin_token, totp)


@pytest.mark.asyncio
async def test_oneshot_totp_missing_code(client, master_password, admin_token):
    """Vault in TOTP mode + no totp_code -> 401 'TOTP code required'."""
    totp = await _enable_totp(client, master_password, admin_token)
    headers = {"Authorization": f"Bearer {admin_token}"}

    try:
        await client.post("/api/v1/vault/seal", headers=headers)
        r = await client.post(
            "/api/v1/vault/oneshot",
            json={"password": master_password, "name": "any-name"},
        )
        assert r.status_code == 401
        assert "TOTP code required" in r.json()["detail"]
        assert vs.sealed is True
    finally:
        await _disable_totp(client, master_password, admin_token, totp)


@pytest.mark.asyncio
async def test_oneshot_totp_invalid_code(client, master_password, admin_token):
    """Vault en mode TOTP + code invalide -> 401 'Invalid TOTP code'."""
    totp = await _enable_totp(client, master_password, admin_token)
    headers = {"Authorization": f"Bearer {admin_token}"}

    try:
        await client.post("/api/v1/vault/seal", headers=headers)
        r = await client.post(
            "/api/v1/vault/oneshot",
            json={
                "password": master_password,
                "name": "any-name",
                "totp_code": "000000",
            },
        )
        assert r.status_code == 401
        assert "Invalid TOTP code" in r.json()["detail"]
        assert vs.sealed is True
    finally:
        await _disable_totp(client, master_password, admin_token, totp)


# ---------------------------------------------------------------------------
# YubiKey mode tests, branches d'erreur
# ---------------------------------------------------------------------------


async def _enable_yubikey(client, master_password, admin_token, serial="999999"):
    """Register a dummy YubiKey and switch mode=yubikey.

    Without a registered YubiKey, PUT /2fa?mode=yubikey automatically falls
    back to "none", routing the tests through the wrong code path.
    """
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}
    # 20 bytes HMAC-SHA1 secret = 40 hex chars
    await client.post(
        "/api/v1/vault/yubikey",
        headers=headers,
        json={
            "serial": serial,
            "name": f"test-yk-{serial}",
            "hmac_secret": "ab" * 20,
        },
    )
    await client.put("/api/v1/vault/2fa", params={"mode": "yubikey"}, headers=headers)
    return serial


async def _disable_yubikey(client, master_password, admin_token, serial):
    """Robust cleanup. The API refuses to mutate 2FA while sealed, and unseal
    in mode=yubikey requires a valid challenge-response; as a net, we reset
    2FA + drop yubikeys directly in the DB."""
    try:
        await _force_2fa_reset_via_db()
        if vs.sealed:
            await client.post(
                "/api/v1/vault/unseal", json={"password": master_password}
            )
    finally:
        # Make sure no YubiKey row lingers for the following tests
        async with async_session() as db:
            await db.execute(
                text("DELETE FROM vault_yubikeys WHERE serial = :s"),
                {"s": serial},
            )
            await db.commit()


@pytest.mark.asyncio
async def test_oneshot_yubikey_missing_response(client, master_password, admin_token):
    """Vault en mode yubikey + body sans yubikey_response -> 401."""
    serial = await _enable_yubikey(client, master_password, admin_token, "111111")
    headers = {"Authorization": f"Bearer {admin_token}"}
    try:
        await client.post("/api/v1/vault/seal", headers=headers)
        r = await client.post(
            "/api/v1/vault/oneshot",
            json={"password": master_password, "name": "any"},
        )
        assert r.status_code == 401
        assert "YubiKey challenge+response required" in r.json()["detail"]
        assert vs.sealed is True
    finally:
        await _disable_yubikey(client, master_password, admin_token, serial)


@pytest.mark.asyncio
async def test_oneshot_yubikey_invalid_challenge(client, master_password, admin_token):
    """Challenge inconnu en DB -> 401 'Invalid or expired challenge'."""
    serial = await _enable_yubikey(client, master_password, admin_token, "222222")
    headers = {"Authorization": f"Bearer {admin_token}"}
    try:
        await client.post("/api/v1/vault/seal", headers=headers)
        r = await client.post(
            "/api/v1/vault/oneshot",
            json={
                "password": master_password,
                "name": "any",
                "challenge": "deadbeef" * 8,  # 64 hex chars, never inserted in DB
                "yubikey_response": "ab" * 20,
            },
        )
        assert r.status_code == 401
        assert "Invalid or expired challenge" in r.json()["detail"]
        assert vs.sealed is True
    finally:
        await _disable_yubikey(client, master_password, admin_token, serial)


@pytest.mark.asyncio
async def test_oneshot_yubikey_non_hex_response(client, master_password, admin_token):
    """yubikey_response non-hex -> 400 'must be hex'."""
    serial = await _enable_yubikey(client, master_password, admin_token, "333333")
    headers = {"Authorization": f"Bearer {admin_token}"}
    try:
        # Create a valid challenge in the DB to pass the 1st guard
        cr = await client.post("/api/v1/vault/challenge")
        challenge = cr.json()["challenge"]

        await client.post("/api/v1/vault/seal", headers=headers)
        r = await client.post(
            "/api/v1/vault/oneshot",
            json={
                "password": master_password,
                "name": "any",
                "challenge": challenge,
                "yubikey_response": "not-hex-at-all-zzzz",
            },
        )
        assert r.status_code == 400
        assert "hex" in r.json()["detail"].lower()
        assert vs.sealed is True
    finally:
        await _disable_yubikey(client, master_password, admin_token, serial)
