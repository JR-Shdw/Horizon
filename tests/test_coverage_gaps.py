"""Targeted tests for remaining coverage gaps.

Covers: crypto (Shamir edge cases), audit filters,
dynamic (role 404, MySQL mock, revoke failure), groups (update/member 404),
notifications (update fields, test fail, dispatch filter),
secrets (namespace restrictions, delete namespace, versions/rollback 404),
vault (seal already sealed, Shamir validation, password required).
"""

from unittest.mock import AsyncMock, patch

import pytest
from api.app.database import async_session
from sqlalchemy import text

# crypto.py: Shamir edge cases (lines 245, 299)


class TestShamirEdgeCases:
    def test_gf_inv_zero_raises(self):
        """_gf_inv(0) raises ValueError."""
        from api.app.crypto import _gf_inv

        with pytest.raises(ValueError, match="Cannot invert zero"):
            _gf_inv(0)

    def test_shamir_combine_different_lengths(self):
        """Shares with different lengths raise ValueError."""
        from api.app.crypto import shamir_combine

        # Build shares with mismatched lengths (index byte + payload)
        share_a = bytes([1, 10, 20])  # index 1, 2 payload bytes
        share_b = bytes([2, 30, 40, 50])  # index 2, 3 payload bytes

        with pytest.raises(ValueError, match="different lengths"):
            shamir_combine([share_a, share_b])


# audit.py: filter by actor and action (lines 32-33)


@pytest.mark.asyncio
async def test_audit_filter_by_actor(client, master_password, admin_token):
    """Audit list filtered by actor."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.get("/api/v1/vault/audit/?actor=nonexistent-user", headers=headers)
    assert r.status_code == 200
    assert r.json()["items"] == []


@pytest.mark.asyncio
async def test_audit_filter_by_action(client, master_password, admin_token):
    """Audit list filtered by action."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.get(
        "/api/v1/vault/audit/?action=nonexistent-action", headers=headers
    )
    assert r.status_code == 200
    assert r.json()["items"] == []


# dynamic.py: role for nonexistent engine (line 216)


@pytest.mark.asyncio
async def test_dynamic_role_engine_not_found(client, master_password, admin_token):
    """Creating a role for a nonexistent engine returns 404."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.post(
        "/api/v1/vault/dynamic/engines/00000000-0000-0000-0000-000000000000/roles",
        json={
            "name": "orphan",
            "creation_sql": "CREATE ROLE {{name}}",
            "revocation_sql": "DROP ROLE IF EXISTS {{name}}",
        },
        headers=headers,
    )
    assert r.status_code == 404


# dynamic.py: creds for nonexistent engine (line 297)


@pytest.mark.asyncio
async def test_dynamic_creds_engine_not_found(client, master_password, admin_token):
    """Generate creds for a nonexistent engine returns 404."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.post(
        "/api/v1/vault/dynamic/engines/00000000-0000-0000-0000-000000000000/creds/x",
        headers=headers,
    )
    assert r.status_code == 404


# dynamic.py: MySQL path with aiomysql ImportError (lines 370-398)


@pytest.mark.asyncio
async def test_dynamic_mysql_import_error(client, master_password, admin_token):
    """A configured MySQL engine whose driver disappeared returns 501."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Engine creation now fails fast when its driver is absent. Simulate a
    # driver that was present during setup but was removed before provisioning.
    with patch("api.app.routes.dynamic.driver_available", return_value=True):
        r = await client.post(
            "/api/v1/vault/dynamic/engines",
            json={
                "name": "mysql-test",
                "engine_type": "mysql",
                "connection_url": "mysql://root:pass@db:3306/test",
            },
            headers=headers,
        )
    assert r.status_code == 201, r.text
    engine_id = r.json()["id"]

    r = await client.post(
        f"/api/v1/vault/dynamic/engines/{engine_id}/roles",
        json={
            "name": "mysqlrole",
            "creation_sql": "CREATE USER '{{name}}'@'%' IDENTIFIED BY '{{password}}'",
            "revocation_sql": "DROP USER IF EXISTS '{{name}}'@'%'",
        },
        headers=headers,
    )
    assert r.status_code == 201, r.text

    # Patch aiomysql import to fail
    import builtins

    real_import = builtins.__import__

    def mock_import(name, *args, **kwargs):
        if name == "aiomysql":
            raise ImportError("No module named 'aiomysql'")
        return real_import(name, *args, **kwargs)

    with (
        patch("builtins.__import__", side_effect=mock_import),
        patch("api.app.routes.dynamic.driver_available", return_value=False),
    ):
        r = await client.post(
            f"/api/v1/vault/dynamic/engines/{engine_id}/creds/mysqlrole",
            headers=headers,
        )
    assert r.status_code == 501

    await client.delete(f"/api/v1/vault/dynamic/engines/{engine_id}", headers=headers)


# dynamic.py: a target failure must leave the lease retryable.


@pytest.mark.asyncio
async def test_dynamic_revoke_db_failure(client, master_password, admin_token):
    """Revoke with DB failure returns 502 and keeps the lease unverified."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Create engine + role + generate creds
    r = await client.post(
        "/api/v1/vault/dynamic/engines",
        json={
            "name": "revoke-fail-pg",
            "engine_type": "postgresql",
            "connection_url": "postgresql://admin:pass@db:5432/test",
        },
        headers=headers,
    )
    engine_id = r.json()["id"]

    await client.post(
        f"/api/v1/vault/dynamic/engines/{engine_id}/roles",
        json={
            "name": "rvkfail",
            "creation_sql": "CREATE ROLE {{name}} LOGIN PASSWORD '{{password}}'",
            "revocation_sql": "DROP ROLE IF EXISTS {{name}}",
        },
        headers=headers,
    )

    mock_conn = AsyncMock()
    mock_conn.execute = AsyncMock()
    mock_conn.close = AsyncMock()

    with patch(
        "api.app.dynamic_engines.postgresql.asyncpg.connect",
        return_value=mock_conn,
    ):
        r = await client.post(
            f"/api/v1/vault/dynamic/engines/{engine_id}/creds/rvkfail",
            headers=headers,
        )
    lease_id = r.json()["lease_id"]

    # A target connection error must not produce a false revocation record.
    with patch(
        "api.app.dynamic_engines.postgresql.asyncpg.connect",
        side_effect=Exception("connection refused"),
    ):
        r = await client.post(
            f"/api/v1/vault/dynamic/leases/{lease_id}/revoke",
            headers=headers,
        )
    assert r.status_code == 502
    async with async_session() as db:
        state = (
            await db.execute(
                text(
                    "SELECT revoked, revocation_verified FROM vault_leases "
                    "WHERE id = CAST(:id AS uuid)"
                ),
                {"id": lease_id},
            )
        ).one()
        assert state.revoked is False
        assert state.revocation_verified is False
        # The target was mocked, so no real credential exists to repair.
        await db.execute(
            text("DELETE FROM vault_leases WHERE id = CAST(:id AS uuid)"),
            {"id": lease_id},
        )
        await db.commit()

    await client.delete(f"/api/v1/vault/dynamic/engines/{engine_id}", headers=headers)


# groups.py: update nonexistent group (line 137)


@pytest.mark.asyncio
async def test_group_update_not_found(client, master_password, admin_token):
    """Updating a nonexistent group returns 404."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.put(
        "/api/v1/vault/groups/00000000-0000-0000-0000-000000000000",
        json={"permissions": {"secrets": "r"}},
        headers=headers,
    )
    assert r.status_code == 404


# groups.py: add member to nonexistent group (line 220)


@pytest.mark.asyncio
async def test_group_add_member_not_found(client, master_password, admin_token):
    """Adding a member to a nonexistent group returns 404."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.post(
        "/api/v1/vault/groups/00000000-0000-0000-0000-000000000000/members",
        json={"principal_type": "external", "principal_id": "ldap:ghost"},
        headers=headers,
    )
    assert r.status_code == 404


# groups.py: remove nonexistent member (line 262)


@pytest.mark.asyncio
async def test_group_remove_member_not_found(client, master_password, admin_token):
    """Removing a nonexistent member returns 404."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Create a real group first
    r = await client.post(
        "/api/v1/vault/groups/",
        json={"name": "rm-member-test", "permissions": {"secrets": "r"}},
        headers=headers,
    )
    gid = r.json()["id"]

    r = await client.delete(
        f"/api/v1/vault/groups/{gid}/members/00000000-0000-0000-0000-000000000000",
        headers=headers,
    )
    assert r.status_code == 404

    await client.delete(f"/api/v1/vault/groups/{gid}", headers=headers)


# notifications.py: update with config + events fields (lines 140-144)


@pytest.mark.asyncio
async def test_notification_update_config_and_events(
    client, master_password, admin_token
):
    """Update channel config and events fields."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.post(
        "/api/v1/vault/notifications/",
        json={
            "name": "upd-fields",
            "channel_type": "webhook",
            "config": {"url": "https://old.hook.com"},
        },
        headers=headers,
    )
    cid = r.json()["id"]

    # Update config + events
    r = await client.put(
        f"/api/v1/vault/notifications/{cid}",
        json={
            "config": {"url": "https://new.hook.com"},
            "events": ["secret_created", "secret_deleted"],
        },
        headers=headers,
    )
    assert r.status_code == 200

    await client.delete(f"/api/v1/vault/notifications/{cid}", headers=headers)


# notifications.py: update nonexistent channel (line 162)


@pytest.mark.asyncio
async def test_notification_update_not_found(client, master_password, admin_token):
    """Updating a nonexistent channel returns 404."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.put(
        "/api/v1/vault/notifications/00000000-0000-0000-0000-000000000000",
        json={"enabled": False},
        headers=headers,
    )
    assert r.status_code == 404


# notifications.py: test channel failure (lines 230-232)


@pytest.mark.asyncio
async def test_notification_test_delivery_failure(client, master_password, admin_token):
    """Test channel that fails delivery returns 502."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.post(
        "/api/v1/vault/notifications/",
        json={
            "name": "fail-test",
            "channel_type": "webhook",
            "config": {"url": "https://hooks.example.com/fail"},
        },
        headers=headers,
    )
    cid = r.json()["id"]

    with patch(
        "api.app.routes.notifications._send_notification",
        side_effect=Exception("delivery failed"),
    ):
        r = await client.post(
            f"/api/v1/vault/notifications/{cid}/test", headers=headers
        )
    assert r.status_code == 502

    await client.delete(f"/api/v1/vault/notifications/{cid}", headers=headers)


# notifications.py: dispatch skips non-matching events (lines 249-254)


@pytest.mark.asyncio
async def test_dispatch_skips_non_matching_event(client, master_password, admin_token):
    """dispatch_event skips channels not subscribed to the event."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Channel subscribed to "backup_failed" only
    await client.post(
        "/api/v1/vault/notifications/",
        json={
            "name": "skip-test",
            "channel_type": "webhook",
            "config": {
                "url": "https://hooks.example.com/skip",
                "events": ["backup_failed"],
            },
            "events": ["backup_failed"],
        },
        headers=headers,
    )

    from api.app.database import async_session
    from api.app.routes.notifications import dispatch_event

    with patch("api.app.routes.notifications._send_notification") as mock_send:
        async with async_session() as db:
            await dispatch_event(db, "unrelated_event", "should be skipped")

    # Should not have been called for skip-test (subscribed to backup_failed only)
    # It may have been called for other channels with empty events list
    for call in mock_send.call_args_list:
        if call[0][1].get("url") == "https://hooks.example.com/skip":
            pytest.fail("Should not have dispatched to non-matching channel")

    # Cleanup
    r = await client.get("/api/v1/vault/notifications/", headers=headers)
    for ch in r.json().get("items", []):
        if ch["name"] == "skip-test":
            await client.delete(
                f"/api/v1/vault/notifications/{ch['id']}", headers=headers
            )


# secrets.py: namespace-restricted token (lines 142-143, 422, 434-436)


@pytest.mark.asyncio
async def test_secrets_namespace_restricted_token(client, master_password, admin_token):
    """Token with namespace restriction can only see its namespaces."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Create secrets in two namespaces
    await client.post(
        "/api/v1/vault/secrets/",
        json={"name": "ns-a-secret", "value": "val-a", "namespace": "ns-a"},
        headers=headers,
    )
    await client.post(
        "/api/v1/vault/secrets/",
        json={"name": "ns-b-secret", "value": "val-b", "namespace": "ns-b"},
        headers=headers,
    )

    # Create restricted token (only ns-a)
    r = await client.post(
        "/api/v1/vault/tokens/",
        json={
            "name": "ns-restricted",
            "permissions": {"secrets": "r", "namespaces": ["ns-a"]},
        },
        headers=headers,
    )
    restricted_token = r.json()["token"]
    rh = {"Authorization": f"Bearer {restricted_token}"}

    # List all, should only see ns-a
    r = await client.get("/api/v1/vault/secrets/", headers=rh)
    assert r.status_code == 200
    names = [s["name"] for s in r.json()["items"]]
    assert "ns-a-secret" in names
    assert "ns-b-secret" not in names

    # List by namespace ns-a, allowed
    r = await client.get("/api/v1/vault/secrets/?namespace=ns-a", headers=rh)
    assert r.status_code == 200

    # List by namespace ns-b, forbidden
    r = await client.get("/api/v1/vault/secrets/?namespace=ns-b", headers=rh)
    assert r.status_code == 403

    # List namespaces, should only show ns-a
    r = await client.get("/api/v1/vault/secrets/namespaces", headers=rh)
    assert r.status_code == 200
    ns_names = [n["namespace"] for n in r.json()["items"]]
    assert "ns-a" in ns_names
    assert "ns-b" not in ns_names

    # Cleanup
    await client.delete("/api/v1/vault/secrets/ns-a-secret", headers=headers)
    await client.delete("/api/v1/vault/secrets/ns-b-secret", headers=headers)


# secrets.py: delete namespace (line 171)


@pytest.mark.asyncio
async def test_delete_namespace_not_found(client, master_password, admin_token):
    """Delete nonexistent namespace returns 404."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.delete(
        "/api/v1/vault/secrets/namespaces/nonexistent-ns-99", headers=headers
    )
    assert r.status_code == 404


# secrets.py: versions/rollback on nonexistent secret (lines 569, 611, 670)


@pytest.mark.asyncio
async def test_versions_secret_not_found(client, master_password, admin_token):
    """Version history for nonexistent secret returns 404."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.get("/api/v1/vault/secrets/ghost-secret/versions", headers=headers)
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_read_version_secret_not_found(client, master_password, admin_token):
    """Read specific version of nonexistent secret returns 404."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.get(
        "/api/v1/vault/secrets/ghost-secret/versions/1", headers=headers
    )
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_rollback_secret_not_found(client, master_password, admin_token):
    """Rollback nonexistent secret returns 404."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.post(
        "/api/v1/vault/secrets/ghost-secret/rollback/1", headers=headers
    )
    assert r.status_code == 404


# secrets.py: version pruning with orphaned DEKs (line 74)


@pytest.mark.asyncio
async def test_secret_version_pruning(client, master_password, admin_token):
    """Creating many versions triggers pruning of old ones."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Create secret
    await client.post(
        "/api/v1/vault/secrets/",
        json={"name": "prune-test", "value": "v1"},
        headers=headers,
    )

    # Update 12 times (default max_versions=10, should trigger prune)
    for i in range(2, 14):
        await client.put(
            "/api/v1/vault/secrets/prune-test",
            json={"value": f"v{i}"},
            headers=headers,
        )

    # Check versions, should be capped
    r = await client.get("/api/v1/vault/secrets/prune-test/versions", headers=headers)
    assert r.status_code == 200
    assert len(r.json()["versions"]) <= 10

    await client.delete("/api/v1/vault/secrets/prune-test", headers=headers)


# vault.py: seal + re-unseal cycle


@pytest.mark.asyncio
async def test_seal_and_reopen(client, master_password, admin_token):
    """Seal vault, verify 503 on secret access, re-unseal."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.post("/api/v1/vault/seal", headers=headers)
    assert r.status_code == 200

    # Sealed: secret access blocked
    r = await client.get("/api/v1/vault/secrets/", headers=headers)
    assert r.status_code == 503

    # Re-unseal
    r = await client.post("/api/v1/vault/unseal", json={"password": master_password})
    assert r.status_code == 200


# vault.py: wrong 2FA factor for mode (line 355)


@pytest.mark.asyncio
async def test_unseal_wrong_factor_for_mode(client, master_password, admin_token):
    """Providing TOTP when mode is yubikey-only returns 400."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    import pyotp

    # Setup TOTP
    r = await client.post("/api/v1/vault/totp/setup", headers=headers)
    secret = r.json()["secret"]
    totp = pyotp.TOTP(secret)
    await client.post(
        "/api/v1/vault/totp/enable",
        json={"code": totp.now()},
        headers=headers,
    )

    # Register a fake YubiKey
    await client.post(
        "/api/v1/vault/yubikey",
        json={
            "serial": "99999999",
            "name": "test-yk",
            "hmac_secret": "aa" * 20,
        },
        headers=headers,
    )

    # Set mode to yubikey-only
    await client.put("/api/v1/vault/2fa", params={"mode": "yubikey"}, headers=headers)

    from api.app.vault_state import vault as vs

    vs.seal()

    # Try unseal with TOTP code (but mode is yubikey)
    r = await client.post(
        "/api/v1/vault/unseal",
        json={"password": master_password, "totp_code": totp.now()},
    )
    assert r.status_code == 400
    assert "not accepted" in r.json()["detail"]

    # Cleanup: unseal with password (reset mode first requires unseal)
    # Reset mode to none via DB directly
    from api.app.database import async_session
    from sqlalchemy import text

    async with async_session() as db:
        await db.execute(
            text("UPDATE vault_config SET value = 'none' WHERE key = 'second_factor'")
        )
        await db.commit()

    vs.invalidate_2fa_cache()

    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}
    await client.put("/api/v1/vault/2fa", params={"mode": "none"}, headers=headers)
    await client.delete("/api/v1/vault/totp", headers=headers)
    await client.delete("/api/v1/vault/yubikey/99999999", headers=headers)


# vault.py: Shamir validation errors (lines 629-634)


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
    assert "Threshold" in r.json()["detail"]


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
    assert "Total" in r.json()["detail"]


@pytest.mark.asyncio
async def test_shamir_init_too_many_shares(client, master_password, admin_token):
    """Shamir init with total > 255 returns 400."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.post(
        "/api/v1/vault/shamir/init",
        json={
            "current_password": master_password,
            "threshold": 3,
            "total": 300,
        },
        headers=headers,
    )
    assert r.status_code == 400
    assert "255" in r.json()["detail"]


# vault.py: password required when no Shamir (line 473-474)


@pytest.mark.asyncio
async def test_unseal_no_password_no_shamir(client):
    """Unseal without password and without Shamir returns 400."""
    from api.app.database import async_session
    from api.app.routes import vault as vault_route
    from api.app.vault_state import vault as vs

    # This assertion is specifically for password-only mode. Earlier Shamir
    # tests may leave both DB configuration and the 10-second route cache set.
    async with async_session() as db:
        await db.execute(
            text(
                "DELETE FROM vault_config WHERE key IN "
                "('shamir_enabled', 'shamir_threshold', 'shamir_total')"
            )
        )
        await db.commit()
    vault_route._shamir_cache = None
    vs.seal()

    r = await client.post("/api/v1/vault/unseal", json={})
    assert r.status_code == 400
    assert "Password required" in r.json()["detail"]


# vault.py: 2FA cache hit (line 240)


@pytest.mark.asyncio
async def test_2fa_cache_hit(client, master_password, admin_token):
    """Second status call within 10s hits the 2FA cache."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})

    # First call populates cache
    r1 = await client.get("/api/v1/vault/status")
    assert r1.status_code == 200

    # Second call hits cache
    r2 = await client.get("/api/v1/vault/status")
    assert r2.status_code == 200
    assert r1.json()["second_factor"] == r2.json()["second_factor"]
