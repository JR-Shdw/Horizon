"""Tests for vault seal/unseal + secrets + 2FA (YubiKey + TOTP) + chained audit."""

import hashlib
import hmac as hmac_mod
import os

import pyotp
import pytest
from sqlalchemy import text


@pytest.mark.asyncio
async def test_status_sealed(client):
    """Vault starts sealed with no 2FA."""
    from api.app.vault_state import vault

    vault.seal()

    r = await client.get("/api/v1/vault/status")
    assert r.status_code == 200
    data = r.json()
    assert data["sealed"] is True
    assert data["version"] == "1.0.0-beta"
    assert data["second_factor"] == "none"
    assert data["yubikeys_registered"] == 0
    assert data["totp_enabled"] is False
    assert data["memory_protection"] in {"mlock", "zeroize-only"}
    assert data["process_memory_protection"] in {
        "mlock",
        "swappable",
        "disabled",
        "unsupported",
        "unknown",
    }
    assert data["swap_protection"] in {"protected", "unencrypted", "unknown"}
    assert data["custody_mode"] in {"embedded", "separated"}
    if data["custody_mode"] == "embedded":
        assert data["custodian_workers_expected"] == 0
        assert data["custodian_workers_live"] == 0
        assert data["custodian_quorum_threshold"] == 0
        assert data["custodian_master_present"] is False


@pytest.mark.asyncio
async def test_health(client):
    r = await client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


@pytest.mark.asyncio
async def test_sealed_rejects_requests(client):
    """All secret operations should fail when sealed."""
    from api.app.vault_state import vault

    vault.seal()

    r = await client.get(
        "/api/v1/vault/secrets/",
        headers={"Authorization": "Bearer rh_fake"},
    )
    assert r.status_code == 503


@pytest.mark.asyncio
async def test_challenge_endpoint(client):
    """Challenge can be generated even when sealed."""
    r = await client.post("/api/v1/vault/challenge")
    assert r.status_code == 200
    data = r.json()
    assert len(data["challenge"]) == 64  # 32 bytes hex
    assert data["ttl"] == 60


@pytest.mark.asyncio
async def test_challenge_single_use(client):
    """Challenge is consumed on use (stored in DB, one-time)."""
    # Create challenge via API
    r = await client.post("/api/v1/vault/challenge")
    assert r.status_code == 200
    ch = r.json()["challenge"]

    # Use it once via the DB (simulate consume)
    from api.app.database import async_session
    from sqlalchemy import text

    async with async_session() as db:
        result = await db.execute(
            text("""
                DELETE FROM vault_challenges
                WHERE challenge = :ch AND expires_at > NOW()
                RETURNING challenge
            """),
            {"ch": ch},
        )
        assert result.fetchone() is not None  # consumed
        await db.commit()

    # Second consume fails
    async with async_session() as db:
        result = await db.execute(
            text("""
                DELETE FROM vault_challenges
                WHERE challenge = :ch AND expires_at > NOW()
                RETURNING challenge
            """),
            {"ch": ch},
        )
        assert result.fetchone() is None  # already consumed
        await db.commit()


@pytest.mark.asyncio
async def test_unseal_password_only(client, master_password):
    """Unseal with password only (no 2FA)."""
    from api.app.vault_state import vault

    vault.seal()

    r = await client.post(
        "/api/v1/vault/unseal",
        json={"password": master_password},
    )
    assert r.status_code == 200
    data = r.json()
    assert data["status"] in ("unsealed", "already_unsealed")
    assert data["second_factor"] == "none"

    r = await client.get("/api/v1/vault/status")
    data = r.json()
    assert data["sealed"] is False
    assert data["uptime"] is not None


@pytest.mark.asyncio
async def test_unseal_wrong_password(client, master_password):
    """Wrong password is rejected."""
    from api.app.vault_state import vault

    vault.seal()

    r = await client.post(
        "/api/v1/vault/unseal",
        json={"password": "wrong-password"},
    )
    assert r.status_code == 401

    r = await client.post(
        "/api/v1/vault/unseal",
        json={"password": master_password},
    )
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_secret_lifecycle(client, master_password, admin_token):
    """Create, read, update, delete a secret."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Create
    r = await client.post(
        "/api/v1/vault/secrets/",
        json={
            "name": "test-secret",
            "value": "my-secret-value",
            "namespace": "test",
        },
        headers=headers,
    )
    assert r.status_code == 201
    assert r.json()["version"] == 1

    # Read
    r = await client.get("/api/v1/vault/secrets/test-secret", headers=headers)
    assert r.status_code == 200
    assert r.json()["value"] == "my-secret-value"

    # List
    r = await client.get("/api/v1/vault/secrets/?namespace=test", headers=headers)
    assert r.status_code == 200
    assert any(i["name"] == "test-secret" for i in r.json()["items"])

    # Update
    r = await client.put(
        "/api/v1/vault/secrets/test-secret",
        json={"value": "updated-value"},
        headers=headers,
    )
    assert r.status_code == 200
    assert r.json()["version"] == 2

    # Read updated
    r = await client.get("/api/v1/vault/secrets/test-secret", headers=headers)
    assert r.json()["value"] == "updated-value"

    # Delete
    r = await client.delete("/api/v1/vault/secrets/test-secret", headers=headers)
    assert r.status_code == 200

    r = await client.get("/api/v1/vault/secrets/test-secret", headers=headers)
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_totp_setup_and_unseal(client, master_password, admin_token):
    """Full TOTP lifecycle: setup -> enable -> unseal with TOTP -> disable."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Setup TOTP, get secret + URI
    r = await client.post("/api/v1/vault/totp/setup", headers=headers)
    assert r.status_code == 200
    totp_secret = r.json()["secret"]
    assert r.json()["uri"].startswith("otpauth://totp/")

    # Generate valid code and enable
    totp = pyotp.TOTP(totp_secret)
    code = totp.now()

    r = await client.post(
        "/api/v1/vault/totp/enable",
        json={"code": code},
        headers=headers,
    )
    assert r.status_code == 200

    # Set 2FA mode to TOTP
    r = await client.put(
        "/api/v1/vault/2fa",
        params={"mode": "totp"},
        headers=headers,
    )
    assert r.status_code == 200

    # Status should reflect TOTP
    r = await client.get("/api/v1/vault/status")
    assert r.json()["totp_enabled"] is True
    assert r.json()["second_factor"] == "totp"

    # Seal and try unseal without TOTP -> rejected
    from api.app.vault_state import vault

    vault.seal()

    r = await client.post(
        "/api/v1/vault/unseal",
        json={"password": master_password},
    )
    assert r.status_code == 400  # 2FA required

    # Unseal with TOTP
    code = totp.now()
    r = await client.post(
        "/api/v1/vault/unseal",
        json={"password": master_password, "totp_code": code},
    )
    assert r.status_code == 200
    assert r.json()["second_factor"] == "totp"

    # Disable TOTP (resets to none)
    r = await client.delete("/api/v1/vault/totp", headers=headers)
    assert r.status_code == 200

    r = await client.get("/api/v1/vault/status")
    assert r.json()["totp_enabled"] is False
    assert r.json()["second_factor"] == "none"


@pytest.mark.asyncio
async def test_challenge_survives_yubikey_failure(client, master_password, admin_token):
    """A bad YubiKey response must NOT consume the challenge.

    Pre-fix: challenge was DELETEd before HMAC verification, so a wrong
    response burned the challenge and the user had to re-fetch one.
    Post-fix: challenge is only consumed after successful crypto check.
    """
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    test_secret = os.urandom(20)
    r = await client.post(
        "/api/v1/vault/yubikey",
        json={
            "serial": "33445566",
            "name": "test-pola-13",
            "hmac_secret": test_secret.hex(),
        },
        headers=headers,
    )
    assert r.status_code == 200
    r = await client.put(
        "/api/v1/vault/2fa", params={"mode": "yubikey"}, headers=headers
    )
    assert r.status_code == 200

    from api.app.vault_state import vault as vs

    vs.seal()

    r = await client.post("/api/v1/vault/challenge")
    challenge_hex = r.json()["challenge"]

    # First attempt: wrong response, challenge must survive
    bad_response = os.urandom(20).hex()
    r = await client.post(
        "/api/v1/vault/unseal",
        json={
            "password": master_password,
            "yubikey_response": bad_response,
            "challenge": challenge_hex,
        },
    )
    assert r.status_code == 401  # YubiKey verification failed
    assert vs.sealed is True

    # Second attempt with the SAME challenge + correct response, must succeed
    challenge_bytes = bytes.fromhex(challenge_hex)
    correct_response = hmac_mod.new(test_secret, challenge_bytes, hashlib.sha1).digest()
    r = await client.post(
        "/api/v1/vault/unseal",
        json={
            "password": master_password,
            "yubikey_response": correct_response.hex(),
            "challenge": challenge_hex,
        },
    )
    assert r.status_code == 200, (
        f"Pre-fix would 400 (challenge burned). Got: {r.status_code} {r.text}"
    )
    assert r.json()["second_factor"] == "yubikey"

    # Verify the challenge row is gone from DB (consumed atomically on success)
    from api.app.database import async_session

    async with async_session() as db:
        check = await db.execute(
            text("SELECT 1 FROM vault_challenges WHERE challenge = :ch"),
            {"ch": challenge_hex},
        )
        assert check.fetchone() is None, "challenge must be consumed after success"

    # Cleanup
    r = await client.delete("/api/v1/vault/yubikey/33445566", headers=headers)
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_yubikey_register_and_verify(client, master_password, admin_token):
    """Register YubiKey, set mode, verify challenge-response works."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Generate a test HMAC secret (20 bytes)
    test_secret = os.urandom(20)

    # Register YubiKey
    r = await client.post(
        "/api/v1/vault/yubikey",
        json={
            "serial": "99887766",
            "name": "test-key",
            "hmac_secret": test_secret.hex(),
        },
        headers=headers,
    )
    assert r.status_code == 200

    # Set 2FA mode to yubikey
    r = await client.put(
        "/api/v1/vault/2fa",
        params={"mode": "yubikey"},
        headers=headers,
    )
    assert r.status_code == 200

    # Seal and unseal with simulated YubiKey response
    from api.app.vault_state import vault as vs

    vs.seal()

    # Get challenge
    r = await client.post("/api/v1/vault/challenge")
    challenge_hex = r.json()["challenge"]
    challenge_bytes = bytes.fromhex(challenge_hex)

    # Simulate YubiKey: HMAC-SHA1(secret, challenge)
    yk_response = hmac_mod.new(test_secret, challenge_bytes, hashlib.sha1).digest()

    r = await client.post(
        "/api/v1/vault/unseal",
        json={
            "password": master_password,
            "yubikey_response": yk_response.hex(),
            "challenge": challenge_hex,
        },
    )
    assert r.status_code == 200
    assert r.json()["second_factor"] == "yubikey"

    # Cleanup: remove YubiKey, mode falls back
    r = await client.delete("/api/v1/vault/yubikey/99887766", headers=headers)
    assert r.status_code == 200
    assert r.json()["remaining"] == 0

    # Mode should have fallen back to none
    r = await client.get("/api/v1/vault/status")
    assert r.json()["second_factor"] == "none"


@pytest.mark.asyncio
async def test_2fa_mode_any(client, master_password, admin_token):
    """Mode 'any' accepts either YubiKey or TOTP."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Setup both factors
    test_secret = os.urandom(20)
    await client.post(
        "/api/v1/vault/yubikey",
        json={
            "serial": "11223344",
            "name": "any-test",
            "hmac_secret": test_secret.hex(),
        },
        headers=headers,
    )

    r = await client.post("/api/v1/vault/totp/setup", headers=headers)
    totp_secret = r.json()["secret"]
    totp = pyotp.TOTP(totp_secret)
    await client.post(
        "/api/v1/vault/totp/enable",
        json={"code": totp.now()},
        headers=headers,
    )

    # Set mode to 'any'
    r = await client.put(
        "/api/v1/vault/2fa",
        params={"mode": "any"},
        headers=headers,
    )
    assert r.status_code == 200

    # Unseal with TOTP
    from api.app.vault_state import vault as vs

    vs.seal()

    r = await client.post(
        "/api/v1/vault/unseal",
        json={"password": master_password, "totp_code": totp.now()},
    )
    assert r.status_code == 200
    assert r.json()["second_factor"] == "totp"

    # Seal and unseal with YubiKey
    vs.seal()
    r = await client.post("/api/v1/vault/challenge")
    ch = r.json()["challenge"]
    yk_resp = hmac_mod.new(test_secret, bytes.fromhex(ch), hashlib.sha1).digest()

    r = await client.post(
        "/api/v1/vault/unseal",
        json={
            "password": master_password,
            "yubikey_response": yk_resp.hex(),
            "challenge": ch,
        },
    )
    assert r.status_code == 200
    assert r.json()["second_factor"] == "yubikey"

    # Cleanup: reset mode before removing credentials
    await client.put("/api/v1/vault/2fa", params={"mode": "none"}, headers=headers)
    await client.delete("/api/v1/vault/yubikey/11223344", headers=headers)
    await client.delete("/api/v1/vault/totp", headers=headers)


@pytest.mark.asyncio
async def test_2fa_any_fallback_prevents_lockout(client, master_password, admin_token):
    """Removing every factor under mode 'any' must auto-fall-back to 'none'.
    Otherwise 'any' is left with nothing to satisfy it and the operator is
    locked out of unseal (and can't get an admin token to fix the mode, since
    that needs an unsealed vault). Regression for the missing 'any' branch in
    the three factor-removal routes."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    test_secret = os.urandom(20)
    await client.post(
        "/api/v1/vault/yubikey",
        json={
            "serial": "55667788",
            "name": "lockout-test",
            "hmac_secret": test_secret.hex(),
        },
        headers=headers,
    )
    r = await client.post("/api/v1/vault/totp/setup", headers=headers)
    totp = pyotp.TOTP(r.json()["secret"])
    await client.post(
        "/api/v1/vault/totp/enable", json={"code": totp.now()}, headers=headers
    )
    r = await client.put("/api/v1/vault/2fa", params={"mode": "any"}, headers=headers)
    assert r.status_code == 200

    # Disable TOTP: 'any' is still satisfiable via the YubiKey -> mode stays 'any'.
    r = await client.delete("/api/v1/vault/totp", headers=headers)
    assert r.status_code == 200
    r = await client.get("/api/v1/vault/status")
    assert r.json()["second_factor"] == "any"

    # Remove the last YubiKey: 'any' now has no factor -> must fall back to 'none'.
    r = await client.delete("/api/v1/vault/yubikey/55667788", headers=headers)
    assert r.status_code == 200
    r = await client.get("/api/v1/vault/status")
    assert r.json()["second_factor"] == "none", "lockout: 'any' left with no factors"

    # The vault can still be unsealed (mode none -> password only).
    from api.app.vault_state import vault as vs

    vs.seal()
    r = await client.post("/api/v1/vault/unseal", json={"password": master_password})
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_decrypt_2fa_secret_delegates_when_no_local_key(monkeypatch):
    """B6: with no local aesgcm, 2FA decryption routes through the RPC-delegating
    vault.aesgcm_decrypt (follower-safe) instead of dereferencing the master-only
    vault.aesgcm (None on a follower -> 500)."""
    from api.app.routes import vault as vmod

    calls = {"n": 0}

    async def _spy(ct, nonce, aad):
        calls["n"] += 1
        assert aad == b""  # empty AAD == the historical None-AAD scheme
        return b"PLAINTEXT"

    monkeypatch.setattr(vmod.vault, "aesgcm_decrypt", _spy)
    out = await vmod._decrypt_2fa_secret("00" * 12 + "deadbeef", aesgcm=None)
    assert out == b"PLAINTEXT"
    assert calls["n"] == 1


@pytest.mark.asyncio
async def test_decrypt_2fa_secret_uses_local_key_when_provided(monkeypatch):
    """With an explicit local aesgcm (unseal's password-derived key) decrypt
    directly -- never delegate (the master RPC may serve a different gen)."""
    from api.app.routes import vault as vmod

    async def _boom(*a, **k):
        raise AssertionError("must not delegate when a local key is supplied")

    monkeypatch.setattr(vmod.vault, "aesgcm_decrypt", _boom)

    class _LocalAesgcm:
        def decrypt(self, nonce, ct, aad):
            assert aad is None
            return b"LOCAL"

    out = await vmod._decrypt_2fa_secret("00" * 12 + "beef", aesgcm=_LocalAesgcm())
    assert out == b"LOCAL"


@pytest.mark.asyncio
async def test_encrypt_2fa_current_delegates(monkeypatch):
    """B6: 2FA encryption (totp setup, yubikey register) routes through the
    RPC-delegating vault.aesgcm_encrypt so it works on a follower too."""
    from api.app.routes import vault as vmod

    calls = {"n": 0}

    async def _spy(pt, aad):
        calls["n"] += 1
        assert aad == b""
        return (b"\x11\x22", b"\xaa" * 12)  # (ct, nonce)

    monkeypatch.setattr(vmod.vault, "aesgcm_encrypt", _spy)
    hexed = await vmod._encrypt_2fa_current(b"secret")
    assert calls["n"] == 1
    assert hexed == (b"\xaa" * 12 + b"\x11\x22").hex()  # hex(nonce + ct)


@pytest.mark.asyncio
async def test_audit_chain(client, master_password, admin_token):
    """Verify audit log endpoints return proper structure.

    Chain integrity is tested in test_security.py::test_audit_chain_not_broken
    (runs earlier, before seal/unseal cycles break the chain).
    """
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.get("/api/v1/vault/audit/", headers=headers)
    assert r.status_code == 200
    data = r.json()
    assert len(data["items"]) > 0
    assert "chain_intact" in data

    r = await client.get("/api/v1/vault/audit/verify", headers=headers)
    assert r.status_code == 200
    assert "chain_intact" in r.json()


@pytest.mark.asyncio
async def test_token_crud(client, master_password, admin_token):
    """Create and revoke a scoped token."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.post(
        "/api/v1/vault/tokens/",
        json={"name": "test-reader", "permissions": {"secrets": "r"}},
        headers=headers,
    )
    assert r.status_code == 201
    reader_token = r.json()["token"]
    assert reader_token.startswith("rh_")

    # Reader can read
    r = await client.get(
        "/api/v1/vault/secrets/",
        headers={"Authorization": f"Bearer {reader_token}"},
    )
    assert r.status_code == 200

    # Reader cannot write
    r = await client.post(
        "/api/v1/vault/secrets/",
        json={"name": "forbidden", "value": "nope"},
        headers={"Authorization": f"Bearer {reader_token}"},
    )
    assert r.status_code == 403

    # Revoke
    r = await client.get("/api/v1/vault/tokens/", headers=headers)
    reader_id = next(t["id"] for t in r.json()["items"] if t["name"] == "test-reader")
    r = await client.post(f"/api/v1/vault/tokens/{reader_id}/revoke", headers=headers)
    assert r.status_code == 200

    # Revoked token fails
    r = await client.get(
        "/api/v1/vault/secrets/",
        headers={"Authorization": f"Bearer {reader_token}"},
    )
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_secret_rotation(client, master_password, admin_token):
    """Rotate a secret's DEK - value unchanged, version incremented."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Create secret
    r = await client.post(
        "/api/v1/vault/secrets/",
        json={"name": "rotate-test", "value": "my-rotate-value"},
        headers=headers,
    )
    assert r.status_code == 201
    assert r.json()["version"] == 1

    # Rotate
    r = await client.post("/api/v1/vault/secrets/rotate-test/rotate", headers=headers)
    assert r.status_code == 200
    assert r.json()["version"] == 2
    assert r.json()["status"] == "rotated"

    # Value unchanged after rotation
    r = await client.get("/api/v1/vault/secrets/rotate-test", headers=headers)
    assert r.status_code == 200
    assert r.json()["value"] == "my-rotate-value"
    assert r.json()["version"] == 2

    # Cleanup
    await client.delete("/api/v1/vault/secrets/rotate-test", headers=headers)


@pytest.mark.asyncio
async def test_rotate_all_secrets(client, master_password, admin_token):
    """Bulk rotation re-encrypts all secrets."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Create 2 secrets
    for name in ("bulk-rot-1", "bulk-rot-2"):
        await client.post(
            "/api/v1/vault/secrets/",
            json={"name": name, "value": f"value-{name}"},
            headers=headers,
        )

    # Rotate all
    r = await client.post("/api/v1/vault/secrets/rotate-all", headers=headers)
    assert r.status_code == 200
    assert r.json()["rotated"] >= 2

    # Values unchanged
    for name in ("bulk-rot-1", "bulk-rot-2"):
        r = await client.get(f"/api/v1/vault/secrets/{name}", headers=headers)
        assert r.json()["value"] == f"value-{name}"
        assert r.json()["version"] == 2

    # Cleanup
    for name in ("bulk-rot-1", "bulk-rot-2"):
        await client.delete(f"/api/v1/vault/secrets/{name}", headers=headers)


@pytest.mark.asyncio
async def test_rotate_nonexistent_secret(client, master_password, admin_token):
    """Rotating a nonexistent secret returns 404."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.post(
        "/api/v1/vault/secrets/does-not-exist/rotate", headers=headers
    )
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_namespace_listing(client, master_password, admin_token):
    """List namespaces with secret counts."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Create secrets in different namespaces
    for i, ns in enumerate(("ns-test-a", "ns-test-a", "ns-test-b")):
        await client.post(
            "/api/v1/vault/secrets/",
            json={"name": f"ns-list-{i}", "value": "v", "namespace": ns},
            headers=headers,
        )

    r = await client.get("/api/v1/vault/secrets/namespaces", headers=headers)
    assert r.status_code == 200
    items = r.json()["items"]
    ns_map = {i["namespace"]: i["secret_count"] for i in items}
    assert ns_map.get("ns-test-a") == 2
    assert ns_map.get("ns-test-b") == 1

    # Cleanup
    for i in range(3):
        await client.delete(f"/api/v1/vault/secrets/ns-list-{i}", headers=headers)


@pytest.mark.asyncio
async def test_namespace_delete(client, master_password, admin_token):
    """Delete all secrets in a namespace."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Create secrets in a namespace
    for i in range(3):
        await client.post(
            "/api/v1/vault/secrets/",
            json={"name": f"ns-del-{i}", "value": "v", "namespace": "to-delete"},
            headers=headers,
        )

    # Delete namespace
    r = await client.delete(
        "/api/v1/vault/secrets/namespaces/to-delete", headers=headers
    )
    assert r.status_code == 200
    assert r.json()["secrets_deleted"] == 3

    # Secrets are gone
    r = await client.get("/api/v1/vault/secrets/?namespace=to-delete", headers=headers)
    assert len(r.json()["items"]) == 0


@pytest.mark.asyncio
async def test_cannot_delete_default_namespace(client, master_password, admin_token):
    """Deleting the default namespace is rejected."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.delete("/api/v1/vault/secrets/namespaces/default", headers=headers)
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_namespace_scoped_token(client, master_password, admin_token):
    """Token with namespace restriction can only access allowed namespaces."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Create secrets in two namespaces
    await client.post(
        "/api/v1/vault/secrets/",
        json={"name": "ns-scoped-allowed", "value": "v", "namespace": "allowed-ns"},
        headers=headers,
    )
    await client.post(
        "/api/v1/vault/secrets/",
        json={"name": "ns-scoped-denied", "value": "v", "namespace": "denied-ns"},
        headers=headers,
    )

    # Create namespace-scoped token
    r = await client.post(
        "/api/v1/vault/tokens/",
        json={
            "name": "ns-scoped",
            "permissions": {
                "secrets": "rw",
                "namespaces": ["allowed-ns"],
            },
        },
        headers=headers,
    )
    assert r.status_code == 201
    scoped_token = r.json()["token"]
    scoped_headers = {"Authorization": f"Bearer {scoped_token}"}

    # Can read allowed namespace
    r = await client.get(
        "/api/v1/vault/secrets/ns-scoped-allowed", headers=scoped_headers
    )
    assert r.status_code == 200

    # Cannot read denied namespace
    r = await client.get(
        "/api/v1/vault/secrets/ns-scoped-denied", headers=scoped_headers
    )
    assert r.status_code == 403

    # Cannot create in denied namespace
    r = await client.post(
        "/api/v1/vault/secrets/",
        json={"name": "ns-forbidden", "value": "v", "namespace": "denied-ns"},
        headers=scoped_headers,
    )
    assert r.status_code == 403

    # Cleanup
    await client.delete("/api/v1/vault/secrets/ns-scoped-allowed", headers=headers)
    await client.delete("/api/v1/vault/secrets/ns-scoped-denied", headers=headers)


@pytest.mark.asyncio
async def test_shamir_init_and_unseal(client, master_password, admin_token):
    """Init Shamir, seal, unseal with shares."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Init Shamir (3-of-5)
    r = await client.post(
        "/api/v1/vault/shamir/init",
        json={
            "current_password": master_password,
            "threshold": 3,
            "total": 5,
        },
        headers=headers,
    )
    assert r.status_code == 200
    data = r.json()
    assert len(data["shares"]) == 5
    assert data["threshold"] == 3
    shares = data["shares"]

    # Status should show Shamir enabled
    r = await client.get("/api/v1/vault/status")
    assert r.json()["shamir_enabled"] is True
    assert r.json()["shamir_threshold"] == 3
    assert r.json()["shamir_total"] == 5

    # Seal
    r = await client.post("/api/v1/vault/seal", headers=headers)
    assert r.status_code == 200

    # Unseal with 3 shares (indices 0, 2, 4)
    for i, idx in enumerate([0, 2, 4]):
        r = await client.post(
            "/api/v1/vault/unseal",
            json={"share": shares[idx]},
        )
        assert r.status_code == 200
        if i < 2:
            assert r.json()["status"] == "share_accepted"
            assert r.json()["shamir_progress"] == i + 1
        else:
            assert r.json()["status"] == "unsealed"

    # Verify vault is functional
    r = await client.get("/api/v1/vault/secrets/", headers=headers)
    assert r.status_code == 200

    # Disable Shamir
    r = await client.delete("/api/v1/vault/shamir", headers=headers)
    assert r.status_code == 200

    r = await client.get("/api/v1/vault/status")
    assert r.json()["shamir_enabled"] is False


@pytest.mark.asyncio
async def test_shamir_atomic_unseal_is_multi_worker_safe(
    client, master_password, admin_token
):
    """A full quorum in one request does not depend on worker affinity."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.post(
        "/api/v1/vault/shamir/init",
        json={
            "current_password": master_password,
            "threshold": 3,
            "total": 5,
        },
        headers=headers,
    )
    shares = r.json()["shares"]
    r = await client.post("/api/v1/vault/seal", headers=headers)
    assert r.status_code == 200

    r = await client.post(
        "/api/v1/vault/unseal",
        json={"shares": [shares[0], shares[2], shares[4]]},
    )
    assert r.status_code == 200
    assert r.json()["status"] == "unsealed"

    r = await client.delete("/api/v1/vault/shamir", headers=headers)
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_shamir_atomic_unseal_validates_quorum_shape(
    client, master_password, admin_token
):
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
    shares = r.json()["shares"]
    await client.post("/api/v1/vault/seal", headers=headers)

    r = await client.post("/api/v1/vault/unseal", json={"shares": [shares[0]]})
    assert r.status_code == 400
    r = await client.post(
        "/api/v1/vault/unseal",
        json={"share": shares[0], "shares": shares[:2]},
    )
    assert r.status_code == 400

    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    await client.delete("/api/v1/vault/shamir", headers=headers)


@pytest.mark.asyncio
async def test_shamir_invalid_shares(client, master_password, admin_token):
    """Wrong shares fail reconstruction."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Init Shamir (2-of-3)
    r = await client.post(
        "/api/v1/vault/shamir/init",
        json={
            "current_password": master_password,
            "threshold": 2,
            "total": 3,
        },
        headers=headers,
    )
    shares = r.json()["shares"]

    # Seal
    r = await client.post("/api/v1/vault/seal", headers=headers)
    assert r.status_code == 200

    # Submit one real share
    r = await client.post(
        "/api/v1/vault/unseal",
        json={"share": shares[0]},
    )
    assert r.json()["status"] == "share_accepted"

    # Submit a fake share (same length, wrong data)
    fake = (bytes([2]) + os.urandom(160)).hex()
    r = await client.post(
        "/api/v1/vault/unseal",
        json={"share": fake},
    )
    # Should fail master check
    assert r.status_code == 401

    # Clean up rate limits and unseal with password
    from api.app.database import async_session

    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_rate_limits"))
        await db.commit()

    r = await client.post("/api/v1/vault/unseal", json={"password": master_password})
    assert r.status_code == 200

    # Disable Shamir
    r = await client.delete("/api/v1/vault/shamir", headers=headers)
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_rate_limiting(client, master_password):
    """Rate limiting blocks after repeated failures (DB-backed).

    Threshold is read from RATE_LIMITS at runtime so the test stays
    valid if the policy evolves (relaxed it from 5 to 20).
    """
    from api.app.database import async_session
    from api.app.rate_limit import RATE_LIMITS
    from api.app.vault_state import vault

    threshold = RATE_LIMITS[0][0]  # first tier (lowest fail count to trigger)

    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_rate_limits"))
        await db.commit()

    vault.seal()

    # `threshold` failed attempts should trigger lockout
    for _ in range(threshold):
        r = await client.post(
            "/api/v1/vault/unseal",
            json={"password": "wrong"},
        )
        assert r.status_code == 401

    # Next attempt should be rate limited
    r = await client.post(
        "/api/v1/vault/unseal",
        json={"password": master_password},
    )
    assert r.status_code == 429

    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_rate_limits"))
        await db.commit()


# Secret update + list filters


@pytest.mark.asyncio
async def test_update_secret(client, master_password, admin_token):
    """Update a secret value - version increments, new value readable."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Create
    await client.post(
        "/api/v1/vault/secrets/",
        json={"name": "upd-test", "value": "v1"},
        headers=headers,
    )

    # Update
    r = await client.put(
        "/api/v1/vault/secrets/upd-test",
        json={"value": "v2-updated"},
        headers=headers,
    )
    assert r.status_code == 200
    assert r.json()["version"] == 2

    # Read back
    r = await client.get("/api/v1/vault/secrets/upd-test", headers=headers)
    assert r.json()["value"] == "v2-updated"
    assert r.json()["version"] == 2

    # Cleanup
    await client.delete("/api/v1/vault/secrets/upd-test", headers=headers)


@pytest.mark.asyncio
async def test_update_nonexistent_secret(client, master_password, admin_token):
    """Updating a nonexistent secret returns 404."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.put(
        "/api/v1/vault/secrets/does-not-exist",
        json={"value": "nope"},
        headers=headers,
    )
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_list_secrets_with_uuid_namespace_claim(
    client, master_password, admin_token
):
    """Regression: a token whose `namespaces` claim is a UUID (not a name) must
    still LIST the secrets in that namespace -- and only those.

    The list endpoints used to compare `vault_secrets.namespace` (the name)
    against the raw claim, so a UUID-form claim matched nothing and listed an
    empty set, even though the token could read those secrets. The fix resolves
    the claim (names + UUIDs) to names and filters on the name column, without
    ever falling back to list-all for a restricted token.
    """
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    await client.post(
        "/api/v1/vault/secrets/",
        json={"name": "uuid-scoped", "value": "v", "namespace": "uuid-claim-ns"},
        headers=headers,
    )
    await client.post(
        "/api/v1/vault/secrets/",
        json={"name": "uuid-other", "value": "v", "namespace": "uuid-other-ns"},
        headers=headers,
    )

    # Resolve the namespace UUID and mint a token claiming it by UUID, not name.
    r = await client.get("/api/v1/vault/namespaces/uuid-claim-ns", headers=headers)
    assert r.status_code == 200
    ns_uuid = r.json()["id"]
    assert len(ns_uuid) == 36 and ns_uuid.count("-") == 4

    r = await client.post(
        "/api/v1/vault/tokens/",
        json={
            "name": "uuid-claim-tok",
            "permissions": {"secrets": "r", "namespaces": [ns_uuid]},
        },
        headers=headers,
    )
    assert r.status_code == 201
    th = {"Authorization": f"Bearer {r.json()['token']}"}

    # The bug: this used to return []. Now it returns exactly the scoped secret.
    r = await client.get("/api/v1/vault/secrets/", headers=th)
    assert r.status_code == 200
    names = {i["name"] for i in r.json()["items"]}
    assert names == {"uuid-scoped"}, f"UUID-claim token listed: {names}"

    # namespace listing is scoped too (no leak of the other namespace)
    r = await client.get("/api/v1/vault/secrets/namespaces", headers=th)
    assert r.status_code == 200
    listed_ns = {i["namespace"] for i in r.json()["items"]}
    assert listed_ns == {"uuid-claim-ns"}, f"listed namespaces: {listed_ns}"

    # The admin token has NO namespaces claim -> still lists everything
    # (unrestricted). The fix must not break this no-claim = list-all path.
    r = await client.get("/api/v1/vault/secrets/", headers=headers)
    admin_names = {i["name"] for i in r.json()["items"]}
    assert {"uuid-scoped", "uuid-other"} <= admin_names, admin_names


@pytest.mark.asyncio
async def test_list_secrets_by_namespace(client, master_password, admin_token):
    """List secrets filtered by namespace."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Create secrets in different namespaces
    await client.post(
        "/api/v1/vault/secrets/",
        json={"name": "ns-a-secret", "value": "a", "namespace": "ns-filter-a"},
        headers=headers,
    )
    await client.post(
        "/api/v1/vault/secrets/",
        json={"name": "ns-b-secret", "value": "b", "namespace": "ns-filter-b"},
        headers=headers,
    )

    # Filter by namespace
    r = await client.get(
        "/api/v1/vault/secrets/?namespace=ns-filter-a", headers=headers
    )
    assert r.status_code == 200
    names = [s["name"] for s in r.json()["items"]]
    assert "ns-a-secret" in names
    assert "ns-b-secret" not in names

    # Cleanup
    await client.delete("/api/v1/vault/secrets/ns-a-secret", headers=headers)
    await client.delete("/api/v1/vault/secrets/ns-b-secret", headers=headers)


@pytest.mark.asyncio
async def test_secret_with_metadata(client, master_password, admin_token):
    """Create a secret with metadata."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.post(
        "/api/v1/vault/secrets/",
        json={
            "name": "meta-test",
            "value": "secret-val",
            "metadata": {"env": "prod", "owner": "ops"},
        },
        headers=headers,
    )
    assert r.status_code == 201

    # Cleanup
    await client.delete("/api/v1/vault/secrets/meta-test", headers=headers)


# Token delete


@pytest.mark.asyncio
async def test_delete_token(client, master_password, admin_token):
    """Delete a token permanently."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Create token
    r = await client.post(
        "/api/v1/vault/tokens/",
        json={"name": "del-test-token", "permissions": {"secrets": "r"}},
        headers=headers,
    )
    assert r.status_code == 201

    # Find its ID
    r = await client.get("/api/v1/vault/tokens/", headers=headers)
    token_id = next(t["id"] for t in r.json()["items"] if t["name"] == "del-test-token")

    # Delete
    r = await client.delete(f"/api/v1/vault/tokens/{token_id}", headers=headers)
    assert r.status_code == 200
    assert r.json()["status"] == "deleted"

    # Verify gone
    r = await client.get("/api/v1/vault/tokens/", headers=headers)
    names = [t["name"] for t in r.json()["items"]]
    assert "del-test-token" not in names


@pytest.mark.asyncio
async def test_delete_nonexistent_token(client, master_password, admin_token):
    """Deleting a nonexistent token returns 404."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.delete(
        "/api/v1/vault/tokens/00000000-0000-0000-0000-000000000000",
        headers=headers,
    )
    assert r.status_code == 404


# Audit filters


@pytest.mark.asyncio
async def test_audit_filter_by_action(client, master_password, admin_token):
    """Audit log can be filtered by action."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.get("/api/v1/vault/audit/?action=create_secret", headers=headers)
    assert r.status_code == 200
    for entry in r.json()["items"]:
        assert entry["action"] == "create_secret"


@pytest.mark.asyncio
async def test_audit_pagination(client, master_password, admin_token):
    """Audit log supports limit and offset."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.get("/api/v1/vault/audit/?limit=3&offset=0", headers=headers)
    assert r.status_code == 200
    assert r.json()["count"] <= 3


# Status endpoint


@pytest.mark.asyncio
async def test_status_unsealed(client, master_password):
    """Status shows sealed=false when unsealed."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    r = await client.get("/api/v1/vault/status")
    assert r.status_code == 200
    data = r.json()
    assert data["sealed"] is False
    assert "uptime" in data


# Seal edge cases


@pytest.mark.asyncio
async def test_seal_already_sealed(client, master_password, admin_token):
    """Sealing an already-sealed vault returns 503 (auth requires unsealed)."""
    from api.app.vault_state import vault as vs

    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}
    vs.seal()

    # Auth dependency requires unsealed vault -> 503
    r = await client.post("/api/v1/vault/seal", headers=headers)
    assert r.status_code == 503

    # Re-unseal for subsequent tests
    await client.post("/api/v1/vault/unseal", json={"password": master_password})


@pytest.mark.asyncio
async def test_unseal_already_unsealed(client, master_password):
    """Unsealing an already-unsealed vault returns already_unsealed."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    r = await client.post("/api/v1/vault/unseal", json={"password": master_password})
    assert r.json()["status"] == "already_unsealed"


@pytest.mark.asyncio
async def test_rebootstrap_supersedes_residual_root_token(client, master_password):
    """Re-bootstrap must not collide on a residual active 'root' token.

    Repro of the HA lab cluster-init wedge: when the triple-lock
    (master_check/argon2_salt/vault_initialized) is cleared to re-bootstrap but
    vault_tokens still holds an active token named 'root' (debris from an
    aborted prior bootstrap), the first-boot root mint used to collide on
    uq_vault_tokens_active_name. The unseal 500'd *after* flipping the worker
    to unsealed-in-RAM, leaving a phantom-unsealed master that answered the
    next /unseal with already_unsealed while no master crypto socket was ever
    bound -> the cluster never formed. The mint is now idempotent (ON CONFLICT)
    and the critical section re-seals on any failure.
    """
    from api.app.database import async_session
    from api.app.vault_state import vault as vs

    # This test re-bootstraps the vault, which mints a fresh master key (a new
    # argon2_salt -- _is_first_boot requires all three lock keys absent). That
    # would orphan every DEK / 2FA secret encrypted under the session master
    # key and break later tests (the suite is session-scoped). Snapshot the
    # full bootstrap/key-state config up front and restore it in `finally` so
    # the destruction is fully reversible -- the original master key (hence the
    # derived dek_key) comes back and existing ciphertext stays decryptable.
    bootstrap_keys = (
        "master_check",
        "argon2_salt",
        "vault_initialized",
        "dek_key_version",
        "prev_hmac_key",
        "prev_hmac_rotated_at",
        "second_factor",
        "totp_secret",
    )
    async with async_session() as db:
        saved_config = dict(
            (
                await db.execute(
                    text("SELECT key, value FROM vault_config WHERE key = ANY(:keys)"),
                    {"keys": list(bootstrap_keys)},
                )
            ).fetchall()
        )

    try:
        # Baseline bootstrap so an active 'root' token exists. Force a genuine
        # first-boot (clear the triple-lock + any prior root) so this unseal
        # mints one deterministically: we cannot rely on a bootstrap root token
        # surviving from an earlier test. Mirrors the re-bootstrap step below.
        async with async_session() as db:
            await db.execute(
                text(
                    "DELETE FROM vault_config WHERE key IN "
                    "('master_check', 'argon2_salt', 'vault_initialized')"
                )
            )
            await db.execute(text("DELETE FROM vault_tokens WHERE name='root'"))
            await db.commit()
        vs.seal()

        await client.post("/api/v1/vault/unseal", json={"password": master_password})

        async with async_session() as db:
            residual = (
                await db.execute(
                    text(
                        "SELECT count(*) FROM vault_tokens WHERE name='root' AND active"
                    )
                )
            ).scalar()
            assert residual >= 1, "baseline bootstrap should have minted a root token"
            # Re-enable first-boot WITHOUT clearing vault_tokens (lab condition).
            await db.execute(
                text(
                    "DELETE FROM vault_config WHERE key IN "
                    "('master_check', 'argon2_salt', 'vault_initialized')"
                )
            )
            await db.commit()

        vs.seal()

        # Re-bootstrap unseal: must succeed + re-mint a usable root, not 500.
        r = await client.post(
            "/api/v1/vault/unseal", json={"password": master_password}
        )
        assert r.status_code == 200, r.text
        data = r.json()
        assert data["status"] == "unsealed"
        assert data.get("root_token"), "re-bootstrap should mint a fresh root token"

        # Genuinely unsealed (not a phantom-unsealed worker).
        status = (await client.get("/api/v1/vault/status")).json()
        assert status["sealed"] is False

        # Exactly one active 'root' remains -- superseded in place, not dup'd.
        async with async_session() as db:
            cnt = (
                await db.execute(
                    text(
                        "SELECT count(*) FROM vault_tokens WHERE name='root' AND active"
                    )
                )
            ).scalar()
            assert cnt == 1

        # The re-minted root token actually authenticates.
        whoami = await client.get(
            "/api/v1/vault/tokens/whoami",
            headers={"Authorization": f"Bearer {data['root_token']}"},
        )
        assert whoami.status_code == 200
    finally:
        # Restore the original master key + bootstrap state so DEKs / 2FA
        # secrets encrypted under the session master key stay decryptable for
        # subsequent tests.
        async with async_session() as db:
            await db.execute(
                text("DELETE FROM vault_config WHERE key = ANY(:keys)"),
                {"keys": list(bootstrap_keys)},
            )
            for key, value in saved_config.items():
                await db.execute(
                    text(
                        "INSERT INTO vault_config (key, value) VALUES (:k, :v) "
                        "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value"
                    ),
                    {"k": key, "v": value},
                )
            await db.commit()
        vs.seal()
        if saved_config:
            await client.post(
                "/api/v1/vault/unseal", json={"password": master_password}
            )


@pytest.mark.asyncio
async def test_unseal_no_password_no_share(client, master_password):
    """Unseal without password or share returns 400."""
    from api.app.vault_state import vault as vs

    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    vs.seal()

    r = await client.post("/api/v1/vault/unseal", json={})
    assert r.status_code == 400

    # Re-unseal
    await client.post("/api/v1/vault/unseal", json={"password": master_password})


# Shamir init validations


@pytest.mark.asyncio
async def test_shamir_init_threshold_too_low(client, master_password, admin_token):
    """Shamir init with threshold < 2 returns 400."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.post(
        "/api/v1/vault/shamir/init",
        json={
            "current_password": master_password,
            "threshold": 1,
            "total": 3,
        },
        headers=headers,
    )
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_shamir_init_total_less_than_threshold(
    client, master_password, admin_token
):
    """Shamir init with total < threshold returns 400."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.post(
        "/api/v1/vault/shamir/init",
        json={
            "current_password": master_password,
            "threshold": 5,
            "total": 3,
        },
        headers=headers,
    )
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_shamir_init_rejects_wrong_current_password(
    client, master_password, admin_token
):
    """Shamir shares cannot be minted without re-authenticating the operator."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.post(
        "/api/v1/vault/shamir/init",
        json={
            "current_password": "definitely-not-the-master-password",
            "threshold": 2,
            "total": 3,
        },
        headers=headers,
    )
    assert r.status_code == 401
    assert r.json()["detail"] == "Current password is incorrect"


@pytest.mark.asyncio
async def test_shamir_non_hex_share(client, master_password, admin_token):
    """Shamir unseal with non-hex share returns 400."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Enable Shamir
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

    from api.app.vault_state import vault as vs

    vs.seal()

    r = await client.post("/api/v1/vault/unseal", json={"share": "not-hex-data!"})
    assert r.status_code == 400

    # Cleanup: unseal with password, disable Shamir
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    await client.delete("/api/v1/vault/shamir", headers=headers)


# 2FA mode validations


@pytest.mark.asyncio
async def test_2fa_invalid_mode(client, master_password, admin_token):
    """Setting invalid 2FA mode returns 400."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.put(
        "/api/v1/vault/2fa", params={"mode": "invalid"}, headers=headers
    )
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_2fa_yubikey_mode_without_keys(client, master_password, admin_token):
    """Setting yubikey mode without registered keys returns 400."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.put(
        "/api/v1/vault/2fa", params={"mode": "yubikey"}, headers=headers
    )
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_2fa_totp_mode_without_setup(client, master_password, admin_token):
    """Setting totp mode without TOTP configured returns 400."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.put("/api/v1/vault/2fa", params={"mode": "totp"}, headers=headers)
    assert r.status_code == 400


# YubiKey management edge cases


@pytest.mark.asyncio
async def test_yubikey_list_empty(client, master_password, admin_token):
    """List YubiKeys when none registered."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.get("/api/v1/vault/yubikey", headers=headers)
    assert r.status_code == 200
    assert isinstance(r.json()["items"], list)


@pytest.mark.asyncio
async def test_yubikey_register_wrong_secret_length(
    client, master_password, admin_token
):
    """Registering a YubiKey with wrong secret length returns 400."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.post(
        "/api/v1/vault/yubikey",
        json={"serial": "badkey", "name": "test", "hmac_secret": "aabb"},
        headers=headers,
    )
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_yubikey_register_malformed_hex(client, master_password, admin_token):
    """Non-hex hmac_secret returns 400, not a 500 from bytes.fromhex."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.post(
        "/api/v1/vault/yubikey",
        json={"serial": "badkey", "name": "test", "hmac_secret": "zz" * 20},
        headers=headers,
    )
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_yubikey_delete_not_found(client, master_password, admin_token):
    """Deleting a nonexistent YubiKey returns 404."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.delete("/api/v1/vault/yubikey/00000000", headers=headers)
    assert r.status_code == 404


# TOTP management edge cases


@pytest.mark.asyncio
async def test_totp_enable_without_setup(client, master_password, admin_token):
    """Enabling TOTP without pending setup returns 400."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.post(
        "/api/v1/vault/totp/enable",
        json={"code": "123456"},
        headers=headers,
    )
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_totp_enable_wrong_code(client, master_password, admin_token):
    """Enabling TOTP with wrong code returns 401."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Setup TOTP
    r = await client.post("/api/v1/vault/totp/setup", headers=headers)
    assert r.status_code == 200

    # Try with wrong code
    r = await client.post(
        "/api/v1/vault/totp/enable",
        json={"code": "000000"},
        headers=headers,
    )
    assert r.status_code == 401

    # Cleanup pending
    await client.delete("/api/v1/vault/totp", headers=headers)


@pytest.mark.asyncio
async def test_totp_setup_already_configured(client, master_password, admin_token):
    """Setting up TOTP when already configured returns 409."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Setup + enable
    r = await client.post("/api/v1/vault/totp/setup", headers=headers)
    secret = r.json()["secret"]
    totp = pyotp.TOTP(secret)
    await client.post(
        "/api/v1/vault/totp/enable",
        json={"code": totp.now()},
        headers=headers,
    )

    # Try setup again
    r = await client.post("/api/v1/vault/totp/setup", headers=headers)
    assert r.status_code == 409

    # Cleanup
    await client.delete("/api/v1/vault/totp", headers=headers)


@pytest.mark.asyncio
async def test_totp_disable_explicit(client, master_password, admin_token):
    """Explicitly disabling TOTP works."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.delete("/api/v1/vault/totp", headers=headers)
    assert r.status_code == 200
    assert r.json()["status"] == "totp_disabled"


# Revoke token edge case


@pytest.mark.asyncio
async def test_revoke_nonexistent_token(client, master_password, admin_token):
    """Revoking a nonexistent token returns 404."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.post(
        "/api/v1/vault/tokens/00000000-0000-0000-0000-000000000000/revoke",
        headers=headers,
    )
    assert r.status_code == 404


# Delete secret edge case


@pytest.mark.asyncio
async def test_delete_nonexistent_secret(client, master_password, admin_token):
    """Deleting a nonexistent secret returns 404."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.delete("/api/v1/vault/secrets/ghost-secret", headers=headers)
    assert r.status_code == 404


# Manual per-secret DEK rotation bookkeeping


@pytest.mark.asyncio
async def test_dek_rotated_at_set_on_create(client, master_password, admin_token):
    """Every new secret records the initial DEK creation time."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.post(
        "/api/v1/vault/secrets/",
        json={"name": "rot-auto-1", "value": "v"},
        headers=headers,
    )
    assert r.status_code == 201

    r = await client.get("/api/v1/vault/secrets/", headers=headers)
    found = [s for s in r.json()["items"] if s["name"] == "rot-auto-1"]
    assert found[0]["dek_rotated_at"] is not None

    await client.delete("/api/v1/vault/secrets/rot-auto-1", headers=headers)


@pytest.mark.asyncio
async def test_rotate_updates_dek_rotated_at(client, master_password, admin_token):
    """Manual rotate via POST /{name}/rotate updates dek_rotated_at."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    await client.post(
        "/api/v1/vault/secrets/",
        json={"name": "rot-ts-1", "value": "v"},
        headers=headers,
    )

    r = await client.get("/api/v1/vault/secrets/", headers=headers)
    before = [s for s in r.json()["items"] if s["name"] == "rot-ts-1"][0][
        "dek_rotated_at"
    ]

    # Small delay to ensure timestamp changes
    import asyncio

    await asyncio.sleep(0.1)

    r = await client.post("/api/v1/vault/secrets/rot-ts-1/rotate", headers=headers)
    assert r.status_code == 200

    r = await client.get("/api/v1/vault/secrets/", headers=headers)
    after = [s for s in r.json()["items"] if s["name"] == "rot-ts-1"][0][
        "dek_rotated_at"
    ]
    assert after > before

    await client.delete("/api/v1/vault/secrets/rot-ts-1", headers=headers)


# Ephemeral tokens


@pytest.mark.asyncio
async def test_ephemeral_token_crud(client, master_password, admin_token):
    """Create an ephemeral token, use it, verify it works with correct scope."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Create a secret to read with ephemeral token
    await client.post(
        "/api/v1/vault/secrets/",
        json={"name": "eph-test-secret", "value": "eph-val"},
        headers=headers,
    )

    # Create ephemeral token (read-only secrets)
    r = await client.post(
        "/api/v1/vault/tokens/ephemeral",
        json={"permissions": {"secrets": "r"}, "ttl_seconds": 300},
        headers=headers,
    )
    assert r.status_code == 201
    data = r.json()
    assert data["token"].startswith("rh_")
    assert data["name"].startswith("eph-")
    assert data["ttl_seconds"] == 300
    assert data["expires_at"] is not None

    # Use ephemeral token to read secret
    eph_headers = {"Authorization": f"Bearer {data['token']}"}
    r = await client.get("/api/v1/vault/secrets/eph-test-secret", headers=eph_headers)
    assert r.status_code == 200
    assert r.json()["value"] == "eph-val"

    # Ephemeral token cannot write
    r = await client.post(
        "/api/v1/vault/secrets/",
        json={"name": "eph-nope", "value": "x"},
        headers=eph_headers,
    )
    assert r.status_code == 403

    # Cleanup
    await client.delete("/api/v1/vault/secrets/eph-test-secret", headers=headers)


@pytest.mark.asyncio
async def test_ephemeral_token_no_admin(client, master_password, admin_token):
    """Ephemeral tokens cannot have admin scope."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.post(
        "/api/v1/vault/tokens/ephemeral",
        json={"permissions": {"admin": "rw"}, "ttl_seconds": 60},
        headers=headers,
    )
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_ephemeral_token_ttl_bounds(client, master_password, admin_token):
    """TTL must be between 60s and 86400s."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Too short
    r = await client.post(
        "/api/v1/vault/tokens/ephemeral",
        json={"permissions": {"secrets": "r"}, "ttl_seconds": 10},
        headers=headers,
    )
    assert r.status_code == 422

    # Too long
    r = await client.post(
        "/api/v1/vault/tokens/ephemeral",
        json={"permissions": {"secrets": "r"}, "ttl_seconds": 999999},
        headers=headers,
    )
    assert r.status_code == 422
