"""Coverage tests for vault.py - targets remaining uncovered lines.

Covers: WebAuthn unseal edge cases (invalid challenge, bad format, cloned key,
verification failure), YubiKey unseal validation (bad hex, wrong length),
Shamir failure paths, prev_hmac corruption, rotate-password with TOTP pending
and YubiKey, seal-already-sealed, missing master_check.
"""

import base64
import os
from unittest.mock import MagicMock, patch

import pytest
from api.app.database import async_session
from sqlalchemy import text


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


# ===================================================================
# Helper: setup yubikey mode with a fake credential
# ===================================================================


async def _setup_webauthn_mode(client, admin_token, headers):
    """Insert a fake WebAuthn credential and set mode to yubikey."""
    fake_cred_id = os.urandom(32)
    fake_cred_data = os.urandom(128)

    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_webauthn WHERE name = 'cov-wa'"))
        await db.execute(
            text(
                "INSERT INTO vault_webauthn "
                "(name, credential_id, credential_data, sign_count, registered_by) "
                "VALUES ('cov-wa', :cid, :cdata, 5, 'test-admin')"
            ),
            {"cid": fake_cred_id, "cdata": fake_cred_data},
        )
        await db.commit()

    r = await client.put(
        "/api/v1/vault/2fa", params={"mode": "yubikey"}, headers=headers
    )
    assert r.status_code == 200
    return fake_cred_id, fake_cred_data


async def _force_unseal_and_cleanup(client, master_password, headers):
    """Force 2FA reset in DB, unseal, then clean up via API."""
    # Reset 2FA mode in DB directly (works even when sealed)
    async with async_session() as db:
        await db.execute(
            text("UPDATE vault_config SET value = 'none' WHERE key = 'second_factor'")
        )
        await db.commit()

    from api.app.vault_state import vault as vs

    vs.invalidate_2fa_cache()

    # Now unseal works (no 2FA required)
    await client.post("/api/v1/vault/unseal", json={"password": master_password})

    # Clean up credentials and audit
    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_webauthn WHERE name = 'cov-wa'"))
        await db.execute(text("DELETE FROM vault_yubikeys WHERE serial = 'COV-YK'"))
        await db.execute(text("DELETE FROM vault_config WHERE key = 'totp_pending'"))
        await db.execute(text("TRUNCATE vault_audit"))
        await db.commit()

    vs.invalidate_2fa_cache()


# ===================================================================
# WebAuthn unseal, invalid/expired challenge (lines 284-292)
# ===================================================================


@pytest.mark.asyncio
async def test_webauthn_unseal_expired_challenge(client, master_password, admin_token):
    """WebAuthn unseal with expired/consumed challenge -> 400."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    fake_cred_id, _ = await _setup_webauthn_mode(client, admin_token, headers)

    # Seal
    r = await client.post("/api/v1/vault/seal", headers=headers)
    assert r.status_code == 200

    # Use a fake challenge that doesn't exist in DB
    r = await client.post(
        "/api/v1/vault/unseal",
        json={
            "password": master_password,
            "challenge": os.urandom(32).hex(),
            "webauthn_response": {
                "rawId": _b64url(fake_cred_id),
                "response": {
                    "clientDataJSON": _b64url(b"x"),
                    "authenticatorData": _b64url(b"x"),
                    "signature": _b64url(b"x"),
                },
            },
        },
    )
    assert r.status_code == 400
    assert "Invalid or expired challenge" in r.json()["detail"]

    await _force_unseal_and_cleanup(client, master_password, headers)


# ===================================================================
# WebAuthn unseal, no credentials registered (line 311)
# ===================================================================


@pytest.mark.asyncio
async def test_webauthn_unseal_no_credentials(client, master_password, admin_token):
    """WebAuthn unseal with no credentials in DB -> 400."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Set mode to yubikey by inserting then deleting credential
    fake_cred_id, _ = await _setup_webauthn_mode(client, admin_token, headers)

    # Get a challenge
    r = await client.post("/api/v1/vault/challenge")
    challenge_hex = r.json()["challenge"]

    # Delete the credential AFTER setting mode (bypass validation)
    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_webauthn"))
        await db.commit()

    # Seal
    r = await client.post("/api/v1/vault/seal", headers=headers)
    assert r.status_code == 200

    # Try unseal with WebAuthn, no credentials
    r = await client.post(
        "/api/v1/vault/unseal",
        json={
            "password": master_password,
            "challenge": challenge_hex,
            "webauthn_response": {
                "rawId": _b64url(fake_cred_id),
                "response": {
                    "clientDataJSON": _b64url(b"x"),
                    "authenticatorData": _b64url(b"x"),
                    "signature": _b64url(b"x"),
                },
            },
        },
    )
    assert r.status_code == 400
    assert "No WebAuthn credentials" in r.json()["detail"]

    await _force_unseal_and_cleanup(client, master_password, headers)


# ===================================================================
# WebAuthn unseal, invalid response format (lines 326-327)
# ===================================================================


@pytest.mark.asyncio
async def test_webauthn_unseal_invalid_format(client, master_password, admin_token):
    """WebAuthn unseal with malformed response -> 400."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    fake_cred_id, _ = await _setup_webauthn_mode(client, admin_token, headers)

    # Get a valid challenge
    r = await client.post("/api/v1/vault/challenge")
    challenge_hex = r.json()["challenge"]

    # Seal
    r = await client.post("/api/v1/vault/seal", headers=headers)
    assert r.status_code == 200

    # Mock AttestedCredentialData so fake DB creds parse OK,
    # but send invalid base64 in response to trigger lines 326-327
    with patch("fido2.webauthn.AttestedCredentialData"):
        r = await client.post(
            "/api/v1/vault/unseal",
            json={
                "password": master_password,
                "challenge": challenge_hex,
                "webauthn_response": {
                    "rawId": "!!!invalid!!!",
                    "response": {
                        "clientDataJSON": "!!!",
                        "authenticatorData": "!!!",
                        "signature": "!!!",
                    },
                },
            },
        )
    assert r.status_code == 400
    assert "Invalid WebAuthn response format" in r.json()["detail"]

    await _force_unseal_and_cleanup(client, master_password, headers)


# ===================================================================
# WebAuthn unseal, bad hex challenge (lines 331-332)
# ===================================================================


@pytest.mark.asyncio
async def test_webauthn_unseal_bad_hex_challenge(client, master_password, admin_token):
    """WebAuthn unseal with non-hex challenge -> 400."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    fake_cred_id, _ = await _setup_webauthn_mode(client, admin_token, headers)

    # Insert a challenge that is NOT hex but exists in DB
    bad_challenge = "not-hex-at-all-zzzzzzzzzzzzz"
    async with async_session() as db:
        await db.execute(
            text(
                "INSERT INTO vault_challenges (challenge, expires_at) "
                "VALUES (:ch, NOW() + interval '60 seconds')"
            ),
            {"ch": bad_challenge},
        )
        await db.commit()

    # Seal
    r = await client.post("/api/v1/vault/seal", headers=headers)
    assert r.status_code == 200

    with (
        patch("fido2.webauthn.AttestedCredentialData"),
        patch("fido2.webauthn.CollectedClientData"),
        patch("fido2.webauthn.AuthenticatorData"),
    ):
        r = await client.post(
            "/api/v1/vault/unseal",
            json={
                "password": master_password,
                "challenge": bad_challenge,
                "webauthn_response": {
                    "rawId": _b64url(fake_cred_id),
                    "response": {
                        "clientDataJSON": _b64url(b'{"type":"webauthn.get"}'),
                        "authenticatorData": _b64url(b"\xa0" * 37),
                        "signature": _b64url(b"\x00" * 64),
                    },
                },
            },
        )
    assert r.status_code == 400
    assert "hex" in r.json()["detail"].lower()

    await _force_unseal_and_cleanup(client, master_password, headers)


# ===================================================================
# WebAuthn unseal, challenge wrong length (line 334)
# ===================================================================


@pytest.mark.asyncio
async def test_webauthn_unseal_challenge_wrong_length(
    client, master_password, admin_token
):
    """WebAuthn unseal with too-short hex challenge -> 400."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    fake_cred_id, _ = await _setup_webauthn_mode(client, admin_token, headers)

    # Insert a short challenge (16 bytes instead of 32)
    short_challenge = os.urandom(16).hex()
    async with async_session() as db:
        await db.execute(
            text(
                "INSERT INTO vault_challenges (challenge, expires_at) "
                "VALUES (:ch, NOW() + interval '60 seconds')"
            ),
            {"ch": short_challenge},
        )
        await db.commit()

    # Seal
    r = await client.post("/api/v1/vault/seal", headers=headers)
    assert r.status_code == 200

    with (
        patch("fido2.webauthn.AttestedCredentialData"),
        patch("fido2.webauthn.CollectedClientData"),
        patch("fido2.webauthn.AuthenticatorData"),
    ):
        r = await client.post(
            "/api/v1/vault/unseal",
            json={
                "password": master_password,
                "challenge": short_challenge,
                "webauthn_response": {
                    "rawId": _b64url(fake_cred_id),
                    "response": {
                        "clientDataJSON": _b64url(b'{"type":"webauthn.get"}'),
                        "authenticatorData": _b64url(b"\xa0" * 37),
                        "signature": _b64url(b"\x00" * 64),
                    },
                },
            },
        )
    assert r.status_code == 400
    assert "challenge length" in r.json()["detail"].lower()

    await _force_unseal_and_cleanup(client, master_password, headers)


# ===================================================================
# WebAuthn unseal, verification failed (lines 347-356)
# ===================================================================


@pytest.mark.asyncio
async def test_webauthn_unseal_verification_failed(
    client, master_password, admin_token
):
    """WebAuthn server.authenticate_complete raises -> 401."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    fake_cred_id, _ = await _setup_webauthn_mode(client, admin_token, headers)

    # Get a valid challenge
    r = await client.post("/api/v1/vault/challenge")
    challenge_hex = r.json()["challenge"]

    # Seal
    r = await client.post("/api/v1/vault/seal", headers=headers)
    assert r.status_code == 200

    # Mock fido2 to raise on authenticate_complete
    with (
        patch("fido2.webauthn.CollectedClientData"),
        patch("fido2.webauthn.AuthenticatorData"),
        patch("fido2.webauthn.AttestedCredentialData"),
        patch("api.app.routes.webauthn._get_fido2_server") as mock_srv_fn,
    ):
        mock_srv = MagicMock()
        mock_srv.authenticate_complete.side_effect = Exception("bad signature")
        mock_srv_fn.return_value = mock_srv

        r = await client.post(
            "/api/v1/vault/unseal",
            json={
                "password": master_password,
                "challenge": challenge_hex,
                "webauthn_response": {
                    "rawId": _b64url(fake_cred_id),
                    "response": {
                        "clientDataJSON": _b64url(b'{"type":"webauthn.get"}'),
                        "authenticatorData": _b64url(b"\xa0" * 37),
                        "signature": _b64url(b"\x00" * 64),
                    },
                },
            },
        )
    assert r.status_code == 401
    assert "WebAuthn verification failed" in r.json()["detail"]

    await _force_unseal_and_cleanup(client, master_password, headers)


# ===================================================================
# WebAuthn unseal, cloned key / sign count anomaly (lines 362-370)
# ===================================================================


@pytest.mark.asyncio
async def test_webauthn_unseal_cloned_key(client, master_password, admin_token):
    """WebAuthn sign count rollback -> 401 cloned key (real assertion)."""
    from .soft_webauthn import SoftAuthenticator

    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Register a REAL soft credential with a high stored sign count
    soft = SoftAuthenticator()
    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_webauthn WHERE name = 'cov-wa'"))
        await db.execute(
            text(
                "INSERT INTO vault_webauthn "
                "(name, credential_id, credential_data, sign_count, registered_by) "
                "VALUES ('cov-wa', :cid, :cdata, 100, 'test-admin')"
            ),
            {"cid": soft.credential_id, "cdata": bytes(soft.credential_data)},
        )
        await db.commit()

    r = await client.put(
        "/api/v1/vault/2fa", params={"mode": "yubikey"}, headers=headers
    )
    assert r.status_code == 200

    # Get a valid challenge
    r = await client.post("/api/v1/vault/challenge")
    challenge_hex = r.json()["challenge"]

    # Seal
    r = await client.post("/api/v1/vault/seal", headers=headers)
    assert r.status_code == 200

    # Cryptographically valid assertion, but counter lower than stored 100
    r = await client.post(
        "/api/v1/vault/unseal",
        json={
            "password": master_password,
            "challenge": challenge_hex,
            "webauthn_response": soft.assertion(
                bytes.fromhex(challenge_hex), counter=50
            ),
        },
    )
    assert r.status_code == 401
    assert "sign count" in r.json()["detail"].lower()

    await _force_unseal_and_cleanup(client, master_password, headers)


# ===================================================================
# YubiKey unseal, bad hex challenge (lines 407-408)
# ===================================================================


@pytest.mark.asyncio
async def test_yubikey_unseal_bad_hex_challenge(client, master_password, admin_token):
    """YubiKey unseal with non-hex challenge -> 400."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Setup yubikey mode
    from api.app.vault_state import vault as vs

    aesgcm = vs.aesgcm
    from api.app.routes.vault import _encrypt_2fa

    encrypted = _encrypt_2fa(os.urandom(20), aesgcm)

    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_yubikeys WHERE serial = 'COV-YK'"))
        await db.execute(
            text(
                "INSERT INTO vault_yubikeys (serial, hmac_secret, registered_by) "
                "VALUES ('COV-YK', decode(:enc, 'hex'), 'test-admin')"
            ),
            {"enc": encrypted},
        )
        await db.commit()

    await client.put("/api/v1/vault/2fa", params={"mode": "yubikey"}, headers=headers)

    # Insert a non-hex challenge in DB
    bad_ch = "zzzz-not-hex"
    async with async_session() as db:
        await db.execute(
            text(
                "INSERT INTO vault_challenges (challenge, expires_at) "
                "VALUES (:ch, NOW() + interval '60 seconds')"
            ),
            {"ch": bad_ch},
        )
        await db.commit()

    # Seal
    r = await client.post("/api/v1/vault/seal", headers=headers)
    assert r.status_code == 200

    r = await client.post(
        "/api/v1/vault/unseal",
        json={
            "password": master_password,
            "challenge": bad_ch,
            "yubikey_response": "aa" * 20,
        },
    )
    assert r.status_code == 400
    assert "hex" in r.json()["detail"].lower()

    await _force_unseal_and_cleanup(client, master_password, headers)


# ===================================================================
# YubiKey unseal, challenge wrong length (line 410)
# ===================================================================


@pytest.mark.asyncio
async def test_yubikey_unseal_challenge_wrong_length(
    client, master_password, admin_token
):
    """YubiKey unseal with short challenge -> 400."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    from api.app.routes.vault import _encrypt_2fa
    from api.app.vault_state import vault as vs

    encrypted = _encrypt_2fa(os.urandom(20), vs.aesgcm)

    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_yubikeys WHERE serial = 'COV-YK'"))
        await db.execute(
            text(
                "INSERT INTO vault_yubikeys (serial, hmac_secret, registered_by) "
                "VALUES ('COV-YK', decode(:enc, 'hex'), 'test-admin')"
            ),
            {"enc": encrypted},
        )
        await db.commit()

    await client.put("/api/v1/vault/2fa", params={"mode": "yubikey"}, headers=headers)

    # Insert short hex challenge (16 bytes instead of 32)
    short_ch = os.urandom(16).hex()
    async with async_session() as db:
        await db.execute(
            text(
                "INSERT INTO vault_challenges (challenge, expires_at) "
                "VALUES (:ch, NOW() + interval '60 seconds')"
            ),
            {"ch": short_ch},
        )
        await db.commit()

    r = await client.post("/api/v1/vault/seal", headers=headers)
    assert r.status_code == 200

    r = await client.post(
        "/api/v1/vault/unseal",
        json={
            "password": master_password,
            "challenge": short_ch,
            "yubikey_response": "aa" * 20,
        },
    )
    assert r.status_code == 400
    assert "challenge length" in r.json()["detail"].lower()

    await _force_unseal_and_cleanup(client, master_password, headers)


# ===================================================================
# YubiKey unseal, bad hex response (lines 414-415)
# ===================================================================


@pytest.mark.asyncio
async def test_yubikey_unseal_bad_hex_response(client, master_password, admin_token):
    """YubiKey unseal with non-hex response -> 400."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    from api.app.routes.vault import _encrypt_2fa
    from api.app.vault_state import vault as vs

    encrypted = _encrypt_2fa(os.urandom(20), vs.aesgcm)

    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_yubikeys WHERE serial = 'COV-YK'"))
        await db.execute(
            text(
                "INSERT INTO vault_yubikeys (serial, hmac_secret, registered_by) "
                "VALUES ('COV-YK', decode(:enc, 'hex'), 'test-admin')"
            ),
            {"enc": encrypted},
        )
        await db.commit()

    await client.put("/api/v1/vault/2fa", params={"mode": "yubikey"}, headers=headers)

    # Get a real challenge
    r = await client.post("/api/v1/vault/challenge")
    challenge_hex = r.json()["challenge"]

    r = await client.post("/api/v1/vault/seal", headers=headers)
    assert r.status_code == 200

    r = await client.post(
        "/api/v1/vault/unseal",
        json={
            "password": master_password,
            "challenge": challenge_hex,
            "yubikey_response": "not-hex-response!!",
        },
    )
    assert r.status_code == 400
    assert "hex" in r.json()["detail"].lower()

    await _force_unseal_and_cleanup(client, master_password, headers)


# ===================================================================
# YubiKey unseal, response wrong length (line 417)
# ===================================================================


@pytest.mark.asyncio
async def test_yubikey_unseal_response_wrong_length(
    client, master_password, admin_token
):
    """YubiKey unseal with response != 20 bytes -> 400."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    from api.app.routes.vault import _encrypt_2fa
    from api.app.vault_state import vault as vs

    encrypted = _encrypt_2fa(os.urandom(20), vs.aesgcm)

    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_yubikeys WHERE serial = 'COV-YK'"))
        await db.execute(
            text(
                "INSERT INTO vault_yubikeys (serial, hmac_secret, registered_by) "
                "VALUES ('COV-YK', decode(:enc, 'hex'), 'test-admin')"
            ),
            {"enc": encrypted},
        )
        await db.commit()

    await client.put("/api/v1/vault/2fa", params={"mode": "yubikey"}, headers=headers)

    r = await client.post("/api/v1/vault/challenge")
    challenge_hex = r.json()["challenge"]

    r = await client.post("/api/v1/vault/seal", headers=headers)
    assert r.status_code == 200

    # Send 10 bytes instead of 20
    r = await client.post(
        "/api/v1/vault/unseal",
        json={
            "password": master_password,
            "challenge": challenge_hex,
            "yubikey_response": "aa" * 10,
        },
    )
    assert r.status_code == 400
    assert "20 bytes" in r.json()["detail"]

    await _force_unseal_and_cleanup(client, master_password, headers)


# ===================================================================
# Shamir: reconstruction fails (lines 531-535)
# ===================================================================


@pytest.mark.asyncio
async def test_shamir_reconstruction_fails(client, master_password, admin_token):
    """Shamir combine with garbage shares -> 401."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Init Shamir (threshold=2, total=3)
    r = await client.post(
        "/api/v1/vault/shamir/init",
        json={
            "current_password": master_password,
            "threshold": 2,
            "total": 3,
        },
        headers=headers,
    )
    assert r.status_code == 200

    # Seal
    r = await client.post("/api/v1/vault/seal", headers=headers)
    assert r.status_code == 200

    # Send garbage shares, mock shamir_combine to raise
    with patch(
        "api.app.routes.vault.shamir_combine",
        side_effect=Exception("reconstruction failed"),
    ):
        # Send two garbage shares to reach threshold. add_share() rejects
        # duplicates by first byte (the Shamir x-coordinate), so use
        # explicit distinct prefixes, random urandom prefixes collide
        # ~0.4% of the time and turn this into a flaky test.
        r = await client.post(
            "/api/v1/vault/unseal",
            json={"share": (bytes([1]) + os.urandom(160)).hex()},
        )
        assert r.status_code == 200  # share_accepted

        r = await client.post(
            "/api/v1/vault/unseal",
            json={"share": (bytes([2]) + os.urandom(160)).hex()},
        )
        assert r.status_code == 401
        assert "reconstruction failed" in r.json()["detail"].lower()

    # Unseal normally and disable Shamir
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    await client.delete("/api/v1/vault/shamir", headers=headers)


# ===================================================================
# Shamir: key material wrong size (lines 538-541)
# ===================================================================


@pytest.mark.asyncio
async def test_shamir_wrong_key_size(client, master_password, admin_token):
    """Shamir combine returns wrong size -> 401."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.post(
        "/api/v1/vault/shamir/init",
        json={
            "current_password": master_password,
            "threshold": 2,
            "total": 3,
        },
        headers=headers,
    )
    assert r.status_code == 200

    r = await client.post("/api/v1/vault/seal", headers=headers)
    assert r.status_code == 200

    # Mock shamir_combine to return wrong-size data
    with patch(
        "api.app.routes.vault.shamir_combine",
        return_value=b"too-short",
    ):
        r = await client.post(
            "/api/v1/vault/unseal",
            json={"share": (bytes([1]) + os.urandom(160)).hex()},
        )
        r = await client.post(
            "/api/v1/vault/unseal",
            json={"share": (bytes([2]) + os.urandom(160)).hex()},
        )
        assert r.status_code == 401
        assert "Invalid share data" in r.json()["detail"]

    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    await client.delete("/api/v1/vault/shamir", headers=headers)


# ===================================================================
# prev_hmac decrypt fails, normal unseal path (lines 661-662)
# ===================================================================


@pytest.mark.asyncio
async def test_prev_hmac_corrupted_normal_unseal(client, master_password, admin_token):
    """Corrupted prev_hmac_key in DB is silently ignored on unseal."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Insert corrupted prev_hmac_key
    async with async_session() as db:
        await db.execute(
            text(
                "INSERT INTO vault_config (key, value) "
                "VALUES ('prev_hmac_key', 'corrupted-garbage') "
                "ON CONFLICT (key) DO UPDATE "
                "SET value = 'corrupted-garbage'"
            )
        )
        await db.commit()

    # Seal then unseal, should succeed despite corrupted prev_hmac
    r = await client.post("/api/v1/vault/seal", headers=headers)
    assert r.status_code == 200

    r = await client.post("/api/v1/vault/unseal", json={"password": master_password})
    assert r.status_code == 200

    # Cleanup
    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_config WHERE key = 'prev_hmac_key'"))
        await db.commit()


# ===================================================================
# prev_hmac decrypt fails, Shamir path (lines 576-577)
# ===================================================================


@pytest.mark.asyncio
async def test_prev_hmac_corrupted_shamir_unseal(client, master_password, admin_token):
    """Corrupted prev_hmac_key is silently ignored on Shamir unseal."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Init Shamir
    r = await client.post(
        "/api/v1/vault/shamir/init",
        json={
            "current_password": master_password,
            "threshold": 2,
            "total": 3,
        },
        headers=headers,
    )
    assert r.status_code == 200
    shares = r.json()["shares"]

    # Insert corrupted prev_hmac_key
    async with async_session() as db:
        await db.execute(
            text(
                "INSERT INTO vault_config (key, value) "
                "VALUES ('prev_hmac_key', 'bad-data') "
                "ON CONFLICT (key) DO UPDATE "
                "SET value = 'bad-data'"
            )
        )
        await db.commit()

    # Seal
    r = await client.post("/api/v1/vault/seal", headers=headers)
    assert r.status_code == 200

    # Unseal via Shamir
    r = await client.post("/api/v1/vault/unseal", json={"share": shares[0]})
    assert r.status_code == 200

    r = await client.post("/api/v1/vault/unseal", json={"share": shares[1]})
    assert r.status_code == 200
    assert r.json()["status"] == "unsealed"

    # Cleanup: disable Shamir + remove corrupted prev_hmac_key
    headers = {"Authorization": f"Bearer {admin_token}"}
    await client.delete("/api/v1/vault/shamir", headers=headers)
    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_config WHERE key = 'prev_hmac_key'"))
        await db.commit()


# ===================================================================
# rotate-password: missing master_check (line 738)
# ===================================================================


@pytest.mark.asyncio
async def test_rotate_password_no_master_check(client, master_password, admin_token):
    """rotate-password with missing master_check -> 500."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Temporarily remove master_check
    async with async_session() as db:
        row = await db.execute(
            text("SELECT value FROM vault_config WHERE key = 'master_check'")
        )
        original = row.fetchone().value
        await db.execute(text("DELETE FROM vault_config WHERE key = 'master_check'"))
        await db.commit()

    try:
        r = await client.post(
            "/api/v1/vault/rotate-password",
            json={
                "current_password": master_password,
                "new_password": "new-pass-test-999",
            },
            headers=headers,
        )
        assert r.status_code == 500
        assert "master_check" in r.json()["detail"].lower()
    finally:
        # Restore master_check
        async with async_session() as db:
            await db.execute(
                text(
                    "INSERT INTO vault_config (key, value) "
                    "VALUES ('master_check', :val) "
                    "ON CONFLICT (key) DO UPDATE SET value = :val"
                ),
                {"val": original},
            )
            await db.commit()


# ===================================================================
# rotate-password: re-encrypts totp_pending (lines 825-827)
# ===================================================================


@pytest.mark.asyncio
async def test_rotate_password_with_totp_pending(client, master_password, admin_token):
    """rotate-password re-encrypts totp_pending if present."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Setup TOTP (creates totp_pending before enable)
    r = await client.post("/api/v1/vault/totp/setup", headers=headers)
    assert r.status_code == 200
    # Don't enable, leave it as pending

    # Rotate password
    new_pass = "rotate-pending-totp-pass"
    r = await client.post(
        "/api/v1/vault/rotate-password",
        json={
            "current_password": master_password,
            "new_password": new_pass,
        },
        headers=headers,
    )
    assert r.status_code == 200

    # Restore original password
    # hmac_token import removed: vault.hmac_sha512_hex used directly
    from api.app.vault_state import vault as vs

    token_hash = await vs.hmac_sha512_hex(admin_token)
    async with async_session() as db:
        await db.execute(
            text("UPDATE vault_tokens SET token_hash = :h WHERE name = 'test-admin'"),
            {"h": token_hash},
        )
        await db.commit()

    r = await client.post(
        "/api/v1/vault/rotate-password",
        json={
            "current_password": new_pass,
            "new_password": master_password,
            # second rotation inside the migration window -> force required.
            "force": True,
        },
        headers=headers,
    )
    assert r.status_code == 200

    # Cleanup
    token_hash2 = await vs.hmac_sha512_hex(admin_token)
    async with async_session() as db:
        await db.execute(
            text("UPDATE vault_tokens SET token_hash = :h WHERE name = 'test-admin'"),
            {"h": token_hash2},
        )
        await db.execute(text("DELETE FROM vault_config WHERE key = 'totp_pending'"))
        await db.execute(text("TRUNCATE vault_audit"))
        await db.commit()


# ===================================================================
# rotate-password: emergency mode invalidates all tokens
# ===================================================================


@pytest.mark.asyncio
async def test_rotate_password_emergency_invalidates_all_tokens(
    client, master_password, admin_token
):
    """Emergency mode (compromise scenario) invalidates the caller's own token.

    Review #5: emergency=true must skip prev_hmac_key storage AND wipe any
    previously stored prev_hmac_key - every existing token (including the
    caller's) becomes immediately unusable after the rotation completes.
    """
    # hmac_token import removed: vault.hmac_sha512_hex used directly
    from api.app.vault_state import vault as vs

    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}
    new_pass = "emergency-rotation-test-pass-zzz"

    # Baseline: token works
    r = await client.get("/api/v1/vault/secrets/", headers=headers)
    assert r.status_code == 200

    # Emergency rotation
    r = await client.post(
        "/api/v1/vault/rotate-password",
        json={
            "current_password": master_password,
            "new_password": new_pass,
            "emergency": True,
        },
        headers=headers,
    )
    assert r.status_code == 200, r.text
    assert r.json()["mode"] == "emergency"

    # Old token is now rejected
    r = await client.get("/api/v1/vault/secrets/", headers=headers)
    assert r.status_code == 401, "old token must be rejected after emergency rotation"

    # prev_hmac_key was wiped from DB
    async with async_session() as db:
        r = await db.execute(
            text("SELECT key FROM vault_config WHERE key = 'prev_hmac_key'")
        )
        assert r.fetchone() is None

    # Restore admin_token via DB hack so subsequent tests can run
    new_hash = await vs.hmac_sha512_hex(admin_token)
    async with async_session() as db:
        await db.execute(
            text("UPDATE vault_tokens SET token_hash = :h WHERE name = 'test-admin'"),
            {"h": new_hash},
        )
        await db.commit()

    r = await client.get("/api/v1/vault/secrets/", headers=headers)
    assert r.status_code == 200

    # Roll back to the original master password (regular non-emergency rotate)
    r = await client.post(
        "/api/v1/vault/rotate-password",
        json={
            "current_password": new_pass,
            "new_password": master_password,
            "emergency": False,
        },
        headers=headers,
    )
    assert r.status_code == 200
    assert r.json()["mode"] == "admin"

    # Restore admin_token hash under the now-current hmac_key
    new_hash2 = await vs.hmac_sha512_hex(admin_token)
    async with async_session() as db:
        await db.execute(
            text("UPDATE vault_tokens SET token_hash = :h WHERE name = 'test-admin'"),
            {"h": new_hash2},
        )
        await db.execute(text("TRUNCATE vault_audit"))
        await db.commit()


# ===================================================================
# rotate-password: re-encrypts YubiKey secrets (lines 835-837)
# ===================================================================


@pytest.mark.asyncio
async def test_rotate_password_with_yubikey(client, master_password, admin_token):
    """rotate-password re-encrypts YubiKey HMAC secrets."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    from api.app.routes.vault import _encrypt_2fa
    from api.app.vault_state import vault as vs

    # Insert a YubiKey
    yk_secret = os.urandom(20)
    encrypted = _encrypt_2fa(yk_secret, vs.aesgcm)

    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_yubikeys WHERE serial = 'COV-YK-ROT'"))
        await db.execute(
            text(
                "INSERT INTO vault_yubikeys (serial, hmac_secret, registered_by) "
                "VALUES ('COV-YK-ROT', decode(:enc, 'hex'), 'test-admin')"
            ),
            {"enc": encrypted},
        )
        await db.commit()

    # Rotate password
    new_pass = "rotate-yk-test-pass"
    r = await client.post(
        "/api/v1/vault/rotate-password",
        json={
            "current_password": master_password,
            "new_password": new_pass,
        },
        headers=headers,
    )
    assert r.status_code == 200

    # Restore original password
    # hmac_token import removed: vault.hmac_sha512_hex used directly

    token_hash = await vs.hmac_sha512_hex(admin_token)
    async with async_session() as db:
        await db.execute(
            text("UPDATE vault_tokens SET token_hash = :h WHERE name = 'test-admin'"),
            {"h": token_hash},
        )
        await db.commit()

    r = await client.post(
        "/api/v1/vault/rotate-password",
        json={
            "current_password": new_pass,
            "new_password": master_password,
            # second rotation inside the migration window -> force required.
            "force": True,
        },
        headers=headers,
    )
    assert r.status_code == 200

    # Cleanup
    token_hash2 = await vs.hmac_sha512_hex(admin_token)
    async with async_session() as db:
        await db.execute(
            text("UPDATE vault_tokens SET token_hash = :h WHERE name = 'test-admin'"),
            {"h": token_hash2},
        )
        await db.execute(text("DELETE FROM vault_yubikeys WHERE serial = 'COV-YK-ROT'"))
        await db.execute(text("TRUNCATE vault_audit"))
        await db.commit()


# ===================================================================
# seal: already sealed (line 892)
# ===================================================================


@pytest.mark.asyncio
async def test_seal_already_sealed_via_override(client, master_password, admin_token):
    """Seal endpoint when vault is already sealed returns already_sealed."""
    from api.app.auth import require_vault_token
    from api.app.main import app

    await client.post("/api/v1/vault/unseal", json={"password": master_password})

    # Override the base auth dependency to bypass token check while sealed
    async def _fake_token():
        return {"name": "test-admin", "permissions": {"admin": "rw"}}

    original = app.dependency_overrides.copy()
    app.dependency_overrides[require_vault_token] = _fake_token

    try:
        from api.app.vault_state import vault as vs

        vs.seal()

        r = await client.post("/api/v1/vault/seal")
        assert r.status_code == 200
        assert r.json()["status"] == "already_sealed"
    finally:
        app.dependency_overrides = original
        await client.post("/api/v1/vault/unseal", json={"password": master_password})
