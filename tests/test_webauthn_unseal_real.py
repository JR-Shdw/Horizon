# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""WebAuthn unseal 2FA with REAL assertions (no fido2 mocking).

Regression for the fido2 2.2.0 API drift: _verify_2fa used to call the
removed 6-arg Fido2Server.authenticate_complete with a malformed state
dict (raw-bytes challenge, no user_verification key), so every browser
WebAuthn unseal failed 401 at runtime while the mocked tests stayed
green. These tests drive the endpoint with cryptographically valid (and
deliberately invalid) ES256 assertions from a software authenticator.
"""

import pytest
from api.app.database import async_session
from sqlalchemy import text

from .soft_webauthn import SoftAuthenticator


async def _register(soft: SoftAuthenticator, name: str) -> None:
    async with async_session() as db:
        await db.execute(
            text(
                "INSERT INTO vault_webauthn "
                "(name, credential_id, credential_data, sign_count, registered_by) "
                "VALUES (:name, :cid, :cdata, 0, 'test-admin')"
            ),
            {
                "name": name,
                "cid": soft.credential_id,
                "cdata": bytes(soft.credential_data),
            },
        )
        await db.commit()


async def _disarm() -> None:
    """Reset 2FA state via SQL: the vault may be left sealed by a failing
    test, and a sealed vault cannot serve the PUT /2fa API. Unseal reads
    the mode fresh from vault_config so no cache invalidation is needed."""
    async with async_session() as db:
        await db.execute(
            text("UPDATE vault_config SET value = 'none' WHERE key = 'second_factor'")
        )
        await db.execute(text("DELETE FROM vault_webauthn"))
        await db.commit()


@pytest.fixture
async def sealed_with_webauthn(client, master_password, admin_token):
    """Register a soft credential, arm yubikey-mode 2FA, seal the vault."""
    soft = SoftAuthenticator()
    await _register(soft, "soft-real")
    headers = {"Authorization": f"Bearer {admin_token}"}
    r = await client.put(
        "/api/v1/vault/2fa", params={"mode": "yubikey"}, headers=headers
    )
    assert r.status_code == 200
    r = await client.post("/api/v1/vault/seal", headers=headers)
    assert r.status_code == 200
    yield soft
    await _disarm()
    await client.post("/api/v1/vault/unseal", json={"password": master_password})


async def _challenge(client) -> str:
    r = await client.post("/api/v1/vault/challenge")
    assert r.status_code == 200
    return r.json()["challenge"]


async def test_real_assertion_unseals(client, master_password, sealed_with_webauthn):
    soft = sealed_with_webauthn
    challenge_hex = await _challenge(client)
    r = await client.post(
        "/api/v1/vault/unseal",
        json={
            "password": master_password,
            "challenge": challenge_hex,
            "webauthn_response": soft.assertion(bytes.fromhex(challenge_hex)),
        },
    )
    assert r.status_code == 200, r.text

    # sign count persisted (anti-clone state advanced)
    async with async_session() as db:
        row = (
            await db.execute(
                text(
                    "SELECT sign_count FROM vault_webauthn WHERE credential_id = :cid"
                ),
                {"cid": soft.credential_id},
            )
        ).first()
    assert row.sign_count == soft.counter


async def test_tampered_signature_rejected(
    client, master_password, sealed_with_webauthn
):
    soft = sealed_with_webauthn
    challenge_hex = await _challenge(client)
    r = await client.post(
        "/api/v1/vault/unseal",
        json={
            "password": master_password,
            "challenge": challenge_hex,
            "webauthn_response": soft.assertion(
                bytes.fromhex(challenge_hex), tamper_signature=True
            ),
        },
    )
    assert r.status_code == 401
    assert "WebAuthn verification failed" in r.json()["detail"]


async def test_wrong_challenge_rejected(client, master_password, sealed_with_webauthn):
    soft = sealed_with_webauthn
    challenge_hex = await _challenge(client)
    r = await client.post(
        "/api/v1/vault/unseal",
        json={
            "password": master_password,
            "challenge": challenge_hex,
            # assertion signs a DIFFERENT challenge than the DB one
            "webauthn_response": soft.assertion(b"\x99" * 32),
        },
    )
    assert r.status_code == 401


async def test_replayed_sign_count_rejected(
    client, master_password, admin_token, sealed_with_webauthn
):
    soft = sealed_with_webauthn
    challenge_hex = await _challenge(client)
    r = await client.post(
        "/api/v1/vault/unseal",
        json={
            "password": master_password,
            "challenge": challenge_hex,
            "webauthn_response": soft.assertion(bytes.fromhex(challenge_hex)),
        },
    )
    assert r.status_code == 200

    # re-seal, then replay an assertion with the SAME counter (cloned key)
    headers = {"Authorization": f"Bearer {admin_token}"}
    r = await client.post("/api/v1/vault/seal", headers=headers)
    assert r.status_code == 200
    challenge_hex = await _challenge(client)
    r = await client.post(
        "/api/v1/vault/unseal",
        json={
            "password": master_password,
            "challenge": challenge_hex,
            "webauthn_response": soft.assertion(
                bytes.fromhex(challenge_hex), counter=soft.counter
            ),
        },
    )
    assert r.status_code == 401
    assert "sign count anomaly" in r.json()["detail"]
