"""Security-focused tests - auth bypass, permission escalation, input validation.

These tests verify that the vault correctly rejects malicious or malformed
requests, enforces permission boundaries, and handles edge cases safely.
"""

import pytest
from sqlalchemy import text

# Auth bypass attempts


@pytest.mark.asyncio
async def test_no_auth_header_rejected(client, master_password):
    """Requests without Authorization header are rejected."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})

    r = await client.get("/api/v1/vault/secrets/")
    assert r.status_code == 401

    r = await client.get("/api/v1/vault/tokens/")
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_empty_bearer_rejected(client, master_password):
    """Empty Bearer token is rejected."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})

    r = await client.get(
        "/api/v1/vault/secrets/",
        headers={"Authorization": "Bearer "},
    )
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_wrong_prefix_rejected(client, master_password):
    """Token without rh_ prefix is rejected."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})

    r = await client.get(
        "/api/v1/vault/secrets/",
        headers={"Authorization": "Bearer not_a_vault_token_1234567890"},
    )
    assert r.status_code == 401


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "token",
    [
        "rh_short",
        "rh_" + "A" * 44,
        "rh_" + "A" * 42 + "!",
    ],
)
async def test_malformed_vault_token_rejected(client, master_password, token):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})

    r = await client.get(
        "/api/v1/vault/secrets/",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_basic_auth_rejected(client, master_password):
    """Basic auth scheme is not accepted."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})

    r = await client.get(
        "/api/v1/vault/secrets/",
        headers={"Authorization": "Basic dXNlcjpwYXNz"},
    )
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_forged_token_rejected(client, master_password):
    """A well-formed but forged token (rh_ prefix) is rejected."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})

    fake = "rh_" + "A" * 43
    r = await client.get(
        "/api/v1/vault/secrets/",
        headers={"Authorization": f"Bearer {fake}"},
    )
    assert r.status_code == 401


# Permission escalation


@pytest.mark.asyncio
async def test_reader_cannot_create_secret(client, master_password, admin_token):
    """A read-only token cannot write secrets."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Create a read-only token
    r = await client.post(
        "/api/v1/vault/tokens/",
        json={"name": "sec-reader", "permissions": {"secrets": "r"}},
        headers=headers,
    )
    assert r.status_code == 201
    reader_token = r.json()["token"]

    # Try to create a secret with read-only token
    r = await client.post(
        "/api/v1/vault/secrets/",
        json={"name": "escalation-test", "value": "should-fail"},
        headers={"Authorization": f"Bearer {reader_token}"},
    )
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_secrets_token_cannot_manage_tokens(client, master_password, admin_token):
    """A token scoped to secrets cannot manage other tokens."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Create a secrets-only token
    r = await client.post(
        "/api/v1/vault/tokens/",
        json={"name": "sec-secrets-only", "permissions": {"secrets": "rw"}},
        headers=headers,
    )
    assert r.status_code == 201
    secrets_token = r.json()["token"]

    # Try to list tokens with secrets-only token
    r = await client.get(
        "/api/v1/vault/tokens/",
        headers={"Authorization": f"Bearer {secrets_token}"},
    )
    assert r.status_code == 403

    # Try to create another token
    r = await client.post(
        "/api/v1/vault/tokens/",
        json={"name": "escalated", "permissions": {"admin": "rw"}},
        headers={"Authorization": f"Bearer {secrets_token}"},
    )
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_tokens_w_cannot_grant_admin(client, master_password, admin_token):
    """A non-root tokens:w caller cannot mint an root token."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.post(
        "/api/v1/vault/tokens/",
        json={"name": "sec-pola-mgr", "permissions": {"tokens": "w"}},
        headers=headers,
    )
    assert r.status_code == 201
    mgr_token = r.json()["token"]

    r = await client.post(
        "/api/v1/vault/tokens/",
        json={"name": "sec-pola-pwn", "permissions": {"admin": "rw"}},
        headers={"Authorization": f"Bearer {mgr_token}"},
    )
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_tokens_w_cannot_grant_unheld_scope(client, master_password, admin_token):
    """POLA: cannot grant a scope the caller does not hold."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.post(
        "/api/v1/vault/tokens/",
        json={"name": "sec-pola-tokens-only", "permissions": {"tokens": "w"}},
        headers=headers,
    )
    mgr_token = r.json()["token"]

    r = await client.post(
        "/api/v1/vault/tokens/",
        json={"name": "sec-pola-leak", "permissions": {"secrets": "r"}},
        headers={"Authorization": f"Bearer {mgr_token}"},
    )
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_caller_cannot_elevate_grant_level(client, master_password, admin_token):
    """POLA: a caller with 'r' on a scope cannot grant 'rw' on it."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.post(
        "/api/v1/vault/tokens/",
        json={
            "name": "sec-pola-reader-mgr",
            "permissions": {"secrets": "r", "tokens": "w"},
        },
        headers=headers,
    )
    mgr_token = r.json()["token"]

    r = await client.post(
        "/api/v1/vault/tokens/",
        json={"name": "sec-pola-elevated", "permissions": {"secrets": "rw"}},
        headers={"Authorization": f"Bearer {mgr_token}"},
    )
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_ephemeral_cannot_grant_unheld_scope(
    client, master_password, admin_token
):
    """Ephemeral tokens also enforce POLA, on top of the no-admin rule."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.post(
        "/api/v1/vault/tokens/",
        json={"name": "sec-pola-eph-mgr", "permissions": {"tokens": "w"}},
        headers=headers,
    )
    mgr_token = r.json()["token"]

    r = await client.post(
        "/api/v1/vault/tokens/ephemeral",
        json={"permissions": {"secrets": "r"}, "ttl_seconds": 60},
        headers={"Authorization": f"Bearer {mgr_token}"},
    )
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_non_admin_cannot_seal(client, master_password, admin_token):
    """Only admin-scoped tokens can seal the vault."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Create a non-root token
    r = await client.post(
        "/api/v1/vault/tokens/",
        json={"name": "sec-no-seal", "permissions": {"secrets": "rw"}},
        headers=headers,
    )
    assert r.status_code == 201
    limited_token = r.json()["token"]

    r = await client.post(
        "/api/v1/vault/seal",
        headers={"Authorization": f"Bearer {limited_token}"},
    )
    assert r.status_code == 403


# Bootstrap lock


@pytest.mark.asyncio
async def test_bootstrap_locked_after_init(client, master_password, admin_token):
    """Re-bootstrap is blocked even if master_check is deleted."""
    from api.app.database import async_session
    from api.app.vault_state import vault

    await client.post("/api/v1/vault/unseal", json={"password": master_password})

    # Snapshot current master_check + verify vault_initialized was set
    async with async_session() as db:
        r = await db.execute(
            text(
                "SELECT key, value FROM vault_config "
                "WHERE key IN ('master_check', 'vault_initialized')"
            )
        )
        rows = {row.key: row.value for row in r.fetchall()}
        assert "vault_initialized" in rows, "vault_initialized must be set on bootstrap"
        original_check = rows["master_check"]

    vault.seal()

    # Attacker deletes master_check (vault_initialized + argon2_salt remain)
    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_config WHERE key = 'master_check'"))
        await db.commit()

    # Bootstrap attempt with attacker-chosen password must be rejected
    r = await client.post(
        "/api/v1/vault/unseal",
        json={"password": "attacker-chosen-password-xyz"},
    )
    assert r.status_code == 401
    assert vault.sealed is True

    # Restore master_check so subsequent tests can unseal normally
    async with async_session() as db:
        await db.execute(
            text("INSERT INTO vault_config (key, value) VALUES ('master_check', :v)"),
            {"v": original_check},
        )
        await db.commit()

    r = await client.post("/api/v1/vault/unseal", json={"password": master_password})
    assert r.status_code == 200


# Sealed vault enforcement


@pytest.mark.asyncio
async def test_sealed_rejects_all_secret_ops(client, master_password, admin_token):
    """All CRUD operations on secrets fail when vault is sealed."""
    from api.app.vault_state import vault

    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    vault.seal()

    endpoints = [
        ("GET", "/api/v1/vault/secrets/"),
        ("POST", "/api/v1/vault/secrets/"),
        ("GET", "/api/v1/vault/secrets/test"),
        ("PUT", "/api/v1/vault/secrets/test"),
        ("DELETE", "/api/v1/vault/secrets/test"),
        ("GET", "/api/v1/vault/tokens/"),
        ("POST", "/api/v1/vault/tokens/"),
        ("GET", "/api/v1/vault/audit/"),
    ]
    for method, path in endpoints:
        r = await getattr(client, method.lower())(path, headers=headers)
        assert r.status_code == 503, f"{method} {path} should return 503 when sealed"

    # Re-unseal for subsequent tests
    await client.post("/api/v1/vault/unseal", json={"password": master_password})


# Input validation


@pytest.mark.asyncio
async def test_invalid_uuid_in_revoke(client, master_password, admin_token):
    """Invalid UUID in token revoke returns 400."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.post("/api/v1/vault/tokens/not-a-uuid/revoke", headers=headers)
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_invalid_uuid_in_delete_token(client, master_password, admin_token):
    """Invalid UUID in token delete returns 400."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.delete("/api/v1/vault/tokens/not-a-uuid", headers=headers)
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_nonexistent_secret_returns_404(client, master_password, admin_token):
    """Reading a nonexistent secret returns 404, not 500."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.get("/api/v1/vault/secrets/this-does-not-exist", headers=headers)
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_duplicate_secret_name_rejected(client, master_password, admin_token):
    """Creating a secret with an existing name returns 409."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    await client.post(
        "/api/v1/vault/secrets/",
        json={"name": "sec-dup-test", "value": "v1"},
        headers=headers,
    )

    r = await client.post(
        "/api/v1/vault/secrets/",
        json={"name": "sec-dup-test", "value": "v2"},
        headers=headers,
    )
    assert r.status_code == 409

    # Cleanup
    await client.delete("/api/v1/vault/secrets/sec-dup-test", headers=headers)


@pytest.mark.asyncio
async def test_duplicate_token_name_rejected(client, master_password, admin_token):
    """Creating a token with an existing name returns 409."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.post(
        "/api/v1/vault/tokens/",
        json={"name": "sec-dup-token", "permissions": {"secrets": "r"}},
        headers=headers,
    )
    assert r.status_code == 201

    r = await client.post(
        "/api/v1/vault/tokens/",
        json={"name": "sec-dup-token", "permissions": {"secrets": "rw"}},
        headers=headers,
    )
    assert r.status_code == 409


@pytest.mark.asyncio
async def test_empty_password_unseal(client):
    """Empty password is handled gracefully."""
    from api.app.vault_state import vault

    vault.seal()

    r = await client.post(
        "/api/v1/vault/unseal",
        json={"password": ""},
    )
    # Should fail (wrong/empty password) not crash
    assert r.status_code in (400, 401, 422)


# Challenge replay


@pytest.mark.asyncio
async def test_challenge_cannot_be_reused(client):
    """A consumed challenge cannot be replayed (DB-backed)."""
    from api.app.database import async_session
    from sqlalchemy import text

    # Create via API
    r = await client.post("/api/v1/vault/challenge")
    ch = r.json()["challenge"]

    # Consume once
    async with async_session() as db:
        result = await db.execute(
            text(
                "DELETE FROM vault_challenges "
                "WHERE challenge = :ch AND expires_at > NOW() "
                "RETURNING challenge"
            ),
            {"ch": ch},
        )
        assert result.fetchone() is not None
        await db.commit()

    # Replay rejected
    async with async_session() as db:
        result = await db.execute(
            text(
                "DELETE FROM vault_challenges "
                "WHERE challenge = :ch AND expires_at > NOW() "
                "RETURNING challenge"
            ),
            {"ch": ch},
        )
        assert result.fetchone() is None
        await db.commit()


@pytest.mark.asyncio
async def test_challenge_purpose_isolation(client):
    """A 'register' challenge cannot be consumed in 'unseal' mode."""
    from api.app.database import async_session
    from api.app.routes.vault import _check_challenge_exists

    test_ch = "deadbeef" * 8

    async with async_session() as db:
        await db.execute(
            text("DELETE FROM vault_challenges WHERE challenge = :ch"),
            {"ch": test_ch},
        )
        await db.execute(
            text("""
                INSERT INTO vault_challenges (challenge, expires_at, purpose)
                VALUES (:ch, NOW() + INTERVAL '60 seconds', 'register')
            """),
            {"ch": test_ch},
        )
        await db.commit()

    async with async_session() as db:
        # Same challenge string, but purpose='unseal' must NOT match the row
        with pytest.raises(Exception) as exc:
            await _check_challenge_exists(db, test_ch, None, purpose="unseal")
        assert "Invalid or expired" in str(exc.value)

    async with async_session() as db:
        # purpose='register' should match
        await _check_challenge_exists(db, test_ch, None, purpose="register")
        # No exception -> test passes

    # Cleanup
    async with async_session() as db:
        await db.execute(
            text("DELETE FROM vault_challenges WHERE challenge = :ch"),
            {"ch": test_ch},
        )
        await db.commit()


@pytest.mark.asyncio
async def test_webauthn_auth_begin_tags_unseal(client):
    """auth/begin INSERTs a row with purpose='unseal'."""
    from api.app.database import async_session

    # Need at least one webauthn credential or auth/begin returns 400
    async with async_session() as db:
        existing = await db.execute(text("SELECT count(*) FROM vault_webauthn"))
        if existing.scalar() == 0:
            pytest.skip("No WebAuthn credential registered - auth/begin returns 400")

    r = await client.post("/api/v1/vault/webauthn/auth/begin")
    if r.status_code != 200:
        pytest.skip(f"auth/begin returned {r.status_code} - skipping purpose check")
    challenge_id = r.json()["challenge_id"]

    async with async_session() as db:
        row = await db.execute(
            text("SELECT purpose FROM vault_challenges WHERE challenge = :ch"),
            {"ch": challenge_id},
        )
        result = row.fetchone()
        assert result is not None
        assert result.purpose == "unseal"


@pytest.mark.asyncio
async def test_fake_challenge_rejected(client):
    """A fabricated challenge is rejected (not in DB)."""
    from api.app.database import async_session
    from sqlalchemy import text

    async with async_session() as db:
        result = await db.execute(
            text(
                "DELETE FROM vault_challenges "
                "WHERE challenge = :ch AND expires_at > NOW() "
                "RETURNING challenge"
            ),
            {"ch": "deadbeef" * 8},
        )
        assert result.fetchone() is None
        await db.commit()


# Revoked token enforcement


@pytest.mark.asyncio
async def test_revoked_token_cannot_authenticate(client, master_password, admin_token):
    """A revoked token is rejected even if it was previously valid."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Create and immediately revoke a token
    r = await client.post(
        "/api/v1/vault/tokens/",
        json={"name": "sec-revoke-test", "permissions": {"secrets": "r"}},
        headers=headers,
    )
    token = r.json()["token"]

    # Verify it works
    r = await client.get(
        "/api/v1/vault/secrets/",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 200

    # Revoke it
    r = await client.get("/api/v1/vault/tokens/", headers=headers)
    token_id = next(
        t["id"] for t in r.json()["items"] if t["name"] == "sec-revoke-test"
    )
    r = await client.post(f"/api/v1/vault/tokens/{token_id}/revoke", headers=headers)
    assert r.status_code == 200

    # Now it should fail
    r = await client.get(
        "/api/v1/vault/secrets/",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 401


# Audit integrity


@pytest.mark.asyncio
async def test_audit_log_records_all_sensitive_actions(
    client, master_password, admin_token
):
    """Verify that sensitive operations create audit entries."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Create + read + delete a secret
    await client.post(
        "/api/v1/vault/secrets/",
        json={"name": "sec-audit-trace", "value": "traced"},
        headers=headers,
    )
    await client.get("/api/v1/vault/secrets/sec-audit-trace", headers=headers)
    await client.delete("/api/v1/vault/secrets/sec-audit-trace", headers=headers)

    # audit-split: state-changing ops (create / delete) go to
    # the chained vault_audit, reads (read_secret) go to vault_audit_lite.
    # Check both sources.
    r_chained = await client.get("/api/v1/vault/audit/", headers=headers)
    assert r_chained.status_code == 200
    chained_actions = [e["action"] for e in r_chained.json()["items"]]

    r_lite = await client.get("/api/v1/vault/audit/lite", headers=headers)
    assert r_lite.status_code == 200
    lite_actions = [e["action"] for e in r_lite.json()["items"]]

    assert "create_secret" in chained_actions
    assert "delete_secret" in chained_actions
    assert "read_secret" in lite_actions


@pytest.mark.asyncio
async def test_audit_chain_not_broken(client, master_password, admin_token):
    """Full chain verification after multiple operations."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.get("/api/v1/vault/audit/verify", headers=headers)
    assert r.status_code == 200
    assert r.json()["chain_intact"] is True


# Secret value isolation


@pytest.mark.asyncio
async def test_secret_values_not_in_list(client, master_password, admin_token):
    """List endpoint never exposes secret values."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    await client.post(
        "/api/v1/vault/secrets/",
        json={"name": "sec-list-check", "value": "super-secret-password"},
        headers=headers,
    )

    r = await client.get("/api/v1/vault/secrets/", headers=headers)
    response_text = r.text

    # The value should never appear in the list response
    assert "super-secret-password" not in response_text

    # Cleanup
    await client.delete("/api/v1/vault/secrets/sec-list-check", headers=headers)


@pytest.mark.asyncio
async def test_token_hash_not_exposed(client, master_password, admin_token):
    """Token list never exposes the hash."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.get("/api/v1/vault/tokens/", headers=headers)
    response_text = r.text

    assert "token_hash" not in response_text


# Rate limiting


@pytest.mark.asyncio
async def test_relaxed_threshold_locks_at_20_fails(client):
    """Lockout triggers at the 20th failure, not the 5th."""
    from api.app.database import async_session
    from api.app.rate_limit import record_failure

    test_ip = "192.0.2.50"

    async with async_session() as db:
        await db.execute(
            text("DELETE FROM vault_rate_limits WHERE ip_address = :ip"),
            {"ip": test_ip},
        )
        await db.commit()

        for _ in range(19):
            await record_failure(db, test_ip)
        r = await db.execute(
            text(
                "SELECT fail_count, locked_until FROM vault_rate_limits "
                "WHERE ip_address = :ip"
            ),
            {"ip": test_ip},
        )
        row = r.fetchone()
        assert row.fail_count == 19
        assert row.locked_until is None, "should not lock at 19 (threshold is 20)"

        await record_failure(db, test_ip)
        r = await db.execute(
            text(
                "SELECT fail_count, locked_until FROM vault_rate_limits "
                "WHERE ip_address = :ip"
            ),
            {"ip": test_ip},
        )
        row = r.fetchone()
        assert row.fail_count == 20
        assert row.locked_until is not None, "should lock at 20"

        await db.execute(
            text("DELETE FROM vault_rate_limits WHERE ip_address = :ip"),
            {"ip": test_ip},
        )
        await db.commit()


@pytest.mark.asyncio
async def test_rate_limit_window_de_escalates_stale_counter(client):
    """A failing IP that goes quiet past the findtime window resets to 1 (A2).

    The counter is cumulative-for-life and token auth never clears it on
    success, so without windowing a legit IP that once crossed a threshold
    relocks forever. record_failure must RESET (not increment) when the last
    failure aged out of the window.
    """
    from api.app.database import async_session
    from api.app.rate_limit import record_failure

    test_ip = "192.0.2.77"

    async with async_session() as db:
        # Seed a high count with a STALE updated_at (older than the 3600s
        # default window) -- as if an old burst left the counter near a lockout.
        await db.execute(
            text("DELETE FROM vault_rate_limits WHERE ip_address = :ip"),
            {"ip": test_ip},
        )
        await db.execute(
            text("""
                INSERT INTO vault_rate_limits (ip_address, fail_count, updated_at)
                VALUES (:ip, 19, NOW() - INTERVAL '2 hours')
            """),
            {"ip": test_ip},
        )
        await db.commit()

        await record_failure(db, test_ip)
        r = await db.execute(
            text(
                "SELECT fail_count, locked_until FROM vault_rate_limits "
                "WHERE ip_address = :ip"
            ),
            {"ip": test_ip},
        )
        row = r.fetchone()
        assert row.fail_count == 1, "stale counter must reset, not climb to 20"
        assert row.locked_until is None, "reset IP must not lock"

        # A second failure WITHIN the window now increments (not resets).
        await record_failure(db, test_ip)
        r = await db.execute(
            text("SELECT fail_count FROM vault_rate_limits WHERE ip_address = :ip"),
            {"ip": test_ip},
        )
        assert r.fetchone().fail_count == 2, "in-window failures still accumulate"

        await db.execute(
            text("DELETE FROM vault_rate_limits WHERE ip_address = :ip"),
            {"ip": test_ip},
        )
        await db.commit()


@pytest.mark.asyncio
async def test_whitelist_cidr_matches_subnet(client):
    """A CIDR in RHORIZON_RATE_LIMIT_WHITELIST matches every IP inside."""
    import ipaddress

    from api.app.rate_limit import _WHITELIST_CIDRS, _is_whitelisted

    original = list(_WHITELIST_CIDRS)
    _WHITELIST_CIDRS.clear()
    _WHITELIST_CIDRS.append(ipaddress.ip_network("10.0.0.1/24"))
    try:
        assert _is_whitelisted("10.0.0.1") is True
        assert _is_whitelisted("10.0.0.1") is True
        assert _is_whitelisted("10.0.0.1") is True
        assert _is_whitelisted("10.0.1.1") is False
        assert _is_whitelisted("172.16.0.1") is False
        assert _is_whitelisted("not-an-ip") is False
    finally:
        _WHITELIST_CIDRS.clear()
        _WHITELIST_CIDRS.extend(original)


@pytest.mark.asyncio
async def test_admin_can_unblock_locked_ip(client, master_password, admin_token):
    """Admin can clear a lockout for any IP via DELETE /rate-limits/{ip}."""
    from api.app.database import async_session

    test_ip = "192.0.2.99"
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    async with async_session() as db:
        await db.execute(
            text("DELETE FROM vault_rate_limits WHERE ip_address = :ip"),
            {"ip": test_ip},
        )
        await db.execute(
            text("""
                INSERT INTO vault_rate_limits
                    (ip_address, fail_count, locked_until, updated_at)
                VALUES (:ip, 25, NOW() + INTERVAL '60 seconds', NOW())
            """),
            {"ip": test_ip},
        )
        await db.commit()

    r = await client.delete(f"/api/v1/vault/rate-limits/{test_ip}", headers=headers)
    assert r.status_code == 200
    assert r.json()["status"] == "unblocked"

    async with async_session() as db:
        r = await db.execute(
            text("SELECT 1 FROM vault_rate_limits WHERE ip_address = :ip"),
            {"ip": test_ip},
        )
        assert r.fetchone() is None


@pytest.mark.asyncio
async def test_rate_limit_resets_on_success(client, master_password):
    """Successful unseal clears the failure counter (DB-backed)."""
    from api.app.database import async_session
    from api.app.vault_state import vault

    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_rate_limits"))
        await db.commit()
    vault.seal()

    # 3 failed attempts
    for _ in range(3):
        await client.post("/api/v1/vault/unseal", json={"password": "wrong"})

    # Successful unseal
    r = await client.post("/api/v1/vault/unseal", json={"password": master_password})
    assert r.status_code == 200

    # Counter should be reset, seal and try again
    vault.seal()
    r = await client.post("/api/v1/vault/unseal", json={"password": "wrong"})
    assert r.status_code == 401  # not 429

    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_rate_limits"))
        await db.commit()


# Vault state machine


@pytest.mark.asyncio
async def test_vault_state_keys_zeroed_on_seal(client, master_password):
    """Keys are unusable after sealing; the bytes properties were removed.

    The test now verifies that the operation methods raise VaultSealedError
    when sealed and succeed when unsealed, which proves the encrypted-buffer
    backing is wiped on seal without exposing the plaintext key in Python.
    """
    from api.app.vault_state import VaultSealedError, vault

    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    assert await vault.hmac_sha512_hex("probe")  # 128-char hex
    ct, nonce = await vault.aesgcm_encrypt(b"x", b"aad")
    assert await vault.aesgcm_decrypt(ct, nonce, b"aad") == b"x"
    assert await vault.audit_sign("payload") != ""

    vault.seal()
    assert vault.sealed is True
    with pytest.raises(VaultSealedError):
        await vault.hmac_sha512_hex("probe")
    with pytest.raises(VaultSealedError):
        await vault.aesgcm_encrypt(b"x", b"aad")
    with pytest.raises(VaultSealedError):
        await vault.audit_sign("payload")
