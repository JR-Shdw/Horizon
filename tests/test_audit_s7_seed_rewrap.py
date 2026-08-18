# SPDX-License-Identifier: AGPL-3.0-or-later
"""S7 -- the at-rest Ed25519 audit seed survives a dek_key rotation.

The audit identity seed is stored wrapped under dek_key. Master-password
rotation (and manual dek-key rotation) re-derives dek_key, so without a re-wrap
the stored seed becomes undecryptable at the NEXT unseal and the chain silently
reverts to hmac. S7 re-wraps audit_identity_seed_enc old->new dek inside the
rotation txn. The live in-RAM signer is untouched (it keeps signing); this test
proves the AT-REST blob is re-wrapped by reloading it after the rotation.
"""

import json

import pytest
from api.app.audit_identity import load_audit_identity_into_ram
from api.app.crypto import generate_token, verify_audit_ed25519
from api.app.database import async_session
from api.app.vault_state import vault
from sqlalchemy import text


async def _admin_token_under_current() -> str:
    """admin:rw token hashed under the CURRENT (unsealed) hmac_key."""
    raw = generate_token()
    token_hash = await vault.hmac_sha512_hex(raw)
    async with async_session() as db:
        await db.execute(
            text("""
                INSERT INTO vault_tokens (name, token_hash, permissions, created_by)
                VALUES ('s7-temp', :h, CAST(:p AS jsonb), 'test')
                ON CONFLICT (name) WHERE active DO UPDATE SET token_hash = :h
            """),
            {"h": token_hash, "p": json.dumps({"admin": "rw"})},
        )
        await db.commit()
    return raw


async def _rotate_password(client, current_pw: str, new_pw: str):
    tok = await _admin_token_under_current()
    return await client.post(
        "/api/v1/vault/rotate-password",
        json={"current_password": current_pw, "new_password": new_pw, "force": True},
        headers={"Authorization": f"Bearer {tok}"},
    )


async def _teardown(client, restore_to: str, current_pw: str):
    """Rotate the password back to the canonical one + scrub the rotation +
    identity state so the next test's admin_token fixture re-unseals cleanly."""
    if current_pw != restore_to:
        r = await _rotate_password(client, current_pw, restore_to)
        assert r.status_code == 200, r.text
    async with async_session() as db:
        await db.execute(
            text(
                "DELETE FROM vault_config WHERE key IN "
                "('prev_hmac_key', 'prev_hmac_rotated_at', "
                "'audit_identity_seed_enc', 'audit_identity_pub')"
            )
        )
        await db.execute(text("DELETE FROM vault_audit_verification_anchors"))
        await db.execute(text("DELETE FROM vault_audit_signer_certs"))
        await db.execute(text("TRUNCATE vault_audit"))
        await db.execute(
            text(
                "DELETE FROM vault_tokens WHERE name = 's7-temp' "
                "OR name LIKE 'root-emergency-%'"
            )
        )
        await db.commit()
    vault.clear_prev_hmac()
    vault._audit_signer = None


@pytest.mark.asyncio
async def test_seed_reloads_after_password_rotation(
    client, master_password, admin_token
):
    """After rotating the master password, the stored seed still decrypts under
    the new dek_key and reloads to the same identity (would fail without S7)."""
    # Force a real sealed->unsealed transition so the S6 bootstrap runs.
    vault.seal()
    r = await client.post("/api/v1/vault/unseal", json={"password": master_password})
    assert r.status_code == 200
    assert vault.has_audit_identity
    pub_before = vault.audit_identity_pub
    new_pw = "s7-rotate-pw-abc"
    try:
        rr = await _rotate_password(client, master_password, new_pw)
        assert rr.status_code == 200, rr.text

        # Simulate the NEXT unseal: drop the live signer and reload from the
        # at-rest seed, now wrapped under the rotated dek_key (vault.aesgcm).
        vault._audit_signer = None
        async with async_session() as db:
            loaded = await load_audit_identity_into_ram(db)
        assert loaded is True
        assert vault.audit_identity_pub == pub_before

        # The reloaded signer still produces verifiable chained signatures.
        payload = "root|probe|s7|{}"
        prev = "c" * 128
        sig = vault._audit_sign_identity_local(payload, prev)
        assert verify_audit_ed25519(pub_before, payload, prev, sig) is True
    finally:
        await _teardown(client, master_password, new_pw)


@pytest.mark.asyncio
async def test_seed_reloads_after_dek_key_rotation(
    client, master_password, admin_token
):
    """Manual dek-key rotation re-wraps the seed too (same helper, second call
    site): the identity reloads under the bumped dek_key generation."""
    vault.seal()
    r = await client.post("/api/v1/vault/unseal", json={"password": master_password})
    assert r.status_code == 200
    assert vault.has_audit_identity
    pub_before = vault.audit_identity_pub
    try:
        tok = await _admin_token_under_current()
        rr = await client.post(
            "/api/v1/vault/admin/rotate-dek-key",
            json={"current_password": master_password},
            headers={"Authorization": f"Bearer {tok}"},
        )
        assert rr.status_code == 200, rr.text

        vault._audit_signer = None
        async with async_session() as db:
            loaded = await load_audit_identity_into_ram(db)
        assert loaded is True
        assert vault.audit_identity_pub == pub_before
    finally:
        await _teardown(client, master_password, master_password)
