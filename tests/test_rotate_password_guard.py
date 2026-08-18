# SPDX-License-Identifier: AGPL-3.0-or-later
"""Regression: master password rotation hardening.

Covers the two behaviours added alongside the HA C/D test work:

  1. In-window second-rotation guard -- only one prev_hmac generation is
     retained, so a second NON-emergency rotation inside the migration window
     would silently strand every token minted before the first. The handler now
     refuses it with 409 unless force=true. Emergency rotations are exempt.

  2. Emergency rotation mints a one-time admin:rw root token and returns it,
     so emergency rotation is no longer a self-lockout (the caller's own token,
     and the stored root token, are invalidated and a plain re-unseal of an
     already-initialised vault mints nothing).
"""

import json

import pytest
from api.app.database import async_session
from sqlalchemy import text


async def _bootstrap_admin_under_current() -> str:
    """Insert an admin:rw token hashed under the CURRENT (unsealed) hmac_key."""
    from api.app.crypto import generate_token
    from api.app.vault_state import vault as vs

    raw = generate_token()
    token_hash = await vs.hmac_sha512_hex(raw)
    async with async_session() as db:
        await db.execute(
            text("""
                INSERT INTO vault_tokens (name, token_hash, permissions, created_by)
                VALUES ('guard-temp', :h, CAST(:p AS jsonb), 'test')
                ON CONFLICT (name) WHERE active DO UPDATE SET token_hash = :h
            """),
            {"h": token_hash, "p": json.dumps({"admin": "rw"})},
        )
        await db.commit()
    return raw


async def _restore_master(client, target_pw: str, current_pw: str) -> None:
    """Rotate current_pw -> target_pw (force) and scrub rotation side-effects.

    Leaves vault_config.master_check matching target_pw so the next test's
    admin_token fixture (which seals + unseals with the canonical password)
    succeeds, and clears the prev_hmac trace + broken audit chain.
    """
    tok = await _bootstrap_admin_under_current()
    r = await client.post(
        "/api/v1/vault/rotate-password",
        json={
            "current_password": current_pw,
            "new_password": target_pw,
            "force": True,
        },
        headers={"Authorization": f"Bearer {tok}"},
    )
    assert r.status_code == 200, r.text
    async with async_session() as db:
        await db.execute(
            text(
                "DELETE FROM vault_config "
                "WHERE key IN ('prev_hmac_key', 'prev_hmac_rotated_at')"
            )
        )
        await db.execute(text("TRUNCATE vault_audit"))
        await db.execute(
            text(
                "DELETE FROM vault_tokens "
                "WHERE name = 'guard-temp' OR name LIKE 'root-emergency-%'"
            )
        )
        await db.commit()
    from api.app.vault_state import vault as vs

    vs.clear_prev_hmac()


@pytest.mark.asyncio
async def test_second_nonemergency_rotation_blocked_without_force(
    client, master_password, admin_token
):
    """A 2nd non-emergency rotation inside the window 409s; force overrides."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    h = {"Authorization": f"Bearer {admin_token}"}
    p1, p2 = "guard-pw-1-xyz", "guard-pw-2-xyz"

    r1 = await client.post(
        "/api/v1/vault/rotate-password",
        json={"current_password": master_password, "new_password": p1},
        headers=h,
    )
    assert r1.status_code == 200, r1.text

    # admin_token still authenticates via prev_hmac lazy migration.
    r2 = await client.post(
        "/api/v1/vault/rotate-password",
        json={"current_password": p1, "new_password": p2},
        headers=h,
    )
    assert r2.status_code == 409
    assert "force=true" in r2.json()["detail"]

    # force=true proceeds.
    r3 = await client.post(
        "/api/v1/vault/rotate-password",
        json={"current_password": p1, "new_password": p2, "force": True},
        headers=h,
    )
    assert r3.status_code == 200, r3.text

    await _restore_master(client, master_password, p2)


@pytest.mark.asyncio
async def test_rotation_keeps_all_previously_used_tokens_migratable(
    client, master_password, admin_token
):
    """The first lazy migration must not retire the key needed by a second token."""
    from api.app.crypto import generate_token
    from api.app.vault_state import vault as vs

    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    tokens = [generate_token(), generate_token()]
    names = ["guard-lazy-a", "guard-lazy-b"]

    async with async_session() as db:
        for name, raw in zip(names, tokens, strict=True):
            await db.execute(
                text("""
                    INSERT INTO vault_tokens
                        (name, token_hash, permissions, created_by, last_used_at)
                    VALUES (:name, :hash, '{"secrets":"r"}'::jsonb, 'test', NOW())
                    ON CONFLICT (name) WHERE active DO UPDATE SET
                        token_hash = EXCLUDED.token_hash,
                        permissions = EXCLUDED.permissions,
                        last_used_at = NOW()
                """),
                {"name": name, "hash": await vs.hmac_sha512_hex(raw)},
            )
        # Make the pre-rotation state deterministic: without the rotation reset,
        # the first migrated token would appear to be the last outstanding one.
        await db.execute(
            text("UPDATE vault_tokens SET last_used_at = NOW() WHERE active = true")
        )
        await db.commit()

    rotated_password = "guard-lazy-rotation-pw"
    rotated = False
    try:
        response = await client.post(
            "/api/v1/vault/rotate-password",
            json={
                "current_password": master_password,
                "new_password": rotated_password,
            },
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 200, response.text
        rotated = True

        async with async_session() as db:
            timestamps = (
                await db.execute(
                    text(
                        "SELECT name, last_used_at FROM vault_tokens "
                        "WHERE name = ANY(:names) ORDER BY name"
                    ),
                    {"names": names},
                )
            ).fetchall()
        assert [row.last_used_at for row in timestamps] == [None, None]

        first = await client.get(
            "/api/v1/vault/tokens/whoami",
            headers={"Authorization": f"Bearer {tokens[0]}"},
        )
        assert first.status_code == 200, first.text

        second = await client.get(
            "/api/v1/vault/tokens/whoami",
            headers={"Authorization": f"Bearer {tokens[1]}"},
        )
        assert second.status_code == 200, second.text
    finally:
        if rotated:
            await _restore_master(client, master_password, rotated_password)
        async with async_session() as db:
            await db.execute(
                text("DELETE FROM vault_tokens WHERE name = ANY(:names)"),
                {"names": names},
            )
            await db.commit()


@pytest.mark.asyncio
async def test_emergency_rotation_exempt_and_mints_root_token(
    client, master_password, admin_token
):
    """Emergency rotation skips the in-window guard and returns a usable token."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    h = {"Authorization": f"Bearer {admin_token}"}
    p1 = "guard-em-base"

    # Set the in-window marker with a non-emergency rotation first.
    r1 = await client.post(
        "/api/v1/vault/rotate-password",
        json={"current_password": master_password, "new_password": p1},
        headers=h,
    )
    assert r1.status_code == 200, r1.text

    # Emergency rotation inside the window must NOT be blocked by the guard.
    r2 = await client.post(
        "/api/v1/vault/rotate-password",
        json={
            "current_password": p1,
            "new_password": "guard-em-2",
            "emergency": True,
        },
        headers=h,
    )
    assert r2.status_code == 200, r2.text
    data = r2.json()
    assert data["mode"] == "emergency"

    # ...and it minted a one-time root token.
    assert data.get("root_token", "").startswith("rh_")
    assert data["root_token_name"].startswith("root-emergency-")

    # The caller's old token is dead (emergency invalidates everything).
    assert (
        await client.get("/api/v1/vault/tokens/whoami", headers=h)
    ).status_code == 401

    # The minted root token authenticates and carries admin:rw.
    nh = {"Authorization": f"Bearer {data['root_token']}"}
    assert (
        await client.get("/api/v1/vault/tokens/whoami", headers=nh)
    ).status_code == 200
    assert (await client.get("/api/v1/vault/tokens/", headers=nh)).status_code == 200

    await _restore_master(client, master_password, "guard-em-2")


@pytest.mark.asyncio
async def test_rotate_password_survives_stale_dek_cache(
    client, master_password, admin_token
):
    """S4 C1 regression: rotate-password decrypts the DEKs with the key derived
    from the live ``dek_key_version`` -- NOT the in-RAM ``vault.aesgcm``.

    On a multi-host cluster, a peer whose in-RAM keys lag another host's
    dek-key rotation holds a stale ``aesgcm`` while the ``vault_dek`` rows are
    already re-wrapped under the new ``dek_key``. The old handler fed that stale
    cache into ``decrypt_dek`` -> ``InvalidTag`` on every DEK -> unhandled 500
    (the 'concurrent-rotation winner 500s' symptom in s4_cdi). The fix sources
    ``old_aesgcm`` from ``old_keys['dek_key']``, so a behind host rotates
    correctly and self-heals onto the new generation at the unseal that follows.

    We reproduce the lag by poisoning ``vault._aesgcm`` with a key that cannot
    unwrap the on-disk DEKs -- the same observable state a stale peer reaches
    after a peer's rotation. With the fix the rotation returns 200 and the secret
    survives; the pre-fix code 500s here.
    """
    from api.app.vault_state import vault as vs
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    h = {"Authorization": f"Bearer {admin_token}"}

    secret_val = "stale-cache-survivor-7f3a"
    r = await client.post(
        "/api/v1/vault/secrets/",
        headers=h,
        json={"name": "stale-cache-secret", "value": secret_val},
    )
    assert r.status_code in (200, 201), r.text

    # Poison the in-RAM dek cache so it can no longer unwrap the on-disk DEKs,
    # exactly as a stale peer's cache would after another host's rotation.
    healthy_aesgcm = vs._aesgcm
    vs._aesgcm = AESGCM(b"\x00" * 32)
    new_pw = "stale-cache-pw-xyz"
    try:
        tok = await _bootstrap_admin_under_current()  # hmac path, cache-agnostic
        rr = await client.post(
            "/api/v1/vault/rotate-password",
            json={
                "current_password": master_password,
                "new_password": new_pw,
                "force": True,
            },
            headers={"Authorization": f"Bearer {tok}"},
        )
        # Pre-fix this is 500 (InvalidTag from the poisoned cache).
        assert rr.status_code == 200, rr.text
    except BaseException:
        # A 500 leaves the vault un-flipped (rotation rolled back) and the cache
        # poisoned; restore it so the suite's other tests keep working.
        vs._aesgcm = healthy_aesgcm
        raise

    # The rotation re-unsealed onto the new generation (self-heal); the secret
    # still decrypts, proving the DEKs were re-wrapped, not corrupted.
    g = await client.get("/api/v1/vault/secrets/stale-cache-secret", headers=h)
    assert g.status_code == 200, g.text
    assert g.json()["value"] == secret_val

    await _restore_master(client, master_password, new_pw)
    async with async_session() as db:
        await db.execute(
            text("DELETE FROM vault_secrets WHERE name = 'stale-cache-secret'")
        )
        await db.commit()
