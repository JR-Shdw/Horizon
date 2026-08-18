"""Tests for LDAP/AD authentication module.

Covers: _resolve_permissions, config CRUD, mappings CRUD,
        login without config (501), login flow with mocked LDAP.
"""

from unittest.mock import AsyncMock, patch

import pytest
from api.app.routes.auth_ldap import _build_group_filter, _resolve_permissions
from sqlalchemy import text

# Unit tests, _resolve_permissions (no DB needed)


class TestResolvePermissions:
    def test_single_group_match(self):
        mappings = {"vault-admins": {"admin": "rw"}}
        result = _resolve_permissions(["vault-admins"], mappings)
        assert result == {"admin": "rw"}

    def test_no_group_match(self):
        mappings = {"vault-admins": {"admin": "rw"}}
        result = _resolve_permissions(["unknown-group"], mappings)
        assert result == {}

    def test_multiple_groups_merge(self):
        mappings = {
            "vault-ops": {"secrets": "rw", "audit": "r"},
            "vault-readers": {"secrets": "r"},
        }
        # rw wins over r for secrets
        result = _resolve_permissions(["vault-readers", "vault-ops"], mappings)
        assert result["secrets"] == "rw"
        assert result["audit"] == "r"

    def test_rw_wins_over_r(self):
        mappings = {
            "readers": {"secrets": "r"},
            "writers": {"secrets": "rw"},
        }
        result = _resolve_permissions(["readers", "writers"], mappings)
        assert result["secrets"] == "rw"

    def test_namespace_union(self):
        mappings = {
            "team-a": {"secrets": "rw", "namespaces": ["prod/a"]},
            "team-b": {"secrets": "r", "namespaces": ["prod/b"]},
        }
        result = _resolve_permissions(["team-a", "team-b"], mappings)
        assert set(result["namespaces"]) == {"prod/a", "prod/b"}

    def test_empty_groups(self):
        mappings = {"vault-admins": {"admin": "rw"}}
        result = _resolve_permissions([], mappings)
        assert result == {}

    def test_empty_mappings(self):
        result = _resolve_permissions(["vault-admins"], {})
        assert result == {}


class TestGroupFilterEscaping:
    def test_normal_dn_unchanged(self):
        # A normal DN has no filter metacharacters -> substituted verbatim.
        f = _build_group_filter("(member={user_dn})", "CN=jdoe,OU=Users,DC=corp")
        assert f == "(member=CN=jdoe,OU=Users,DC=corp)"

    def test_dn_metacharacters_escaped(self):
        # A DN carrying filter metacharacters must be escaped, not injected raw
        # (else a '*' would widen the group match -> permission escalation).
        f = _build_group_filter("(member={user_dn})", "CN=ev*il)(uid=admin,DC=x")
        assert "\\2a" in f  # *
        assert "\\28" in f  # (
        assert "\\29" in f  # )
        assert "ev*il" not in f
        assert ")(uid=admin" not in f


# Integration tests, config + mappings CRUD


@pytest.mark.asyncio
async def test_ldap_login_not_configured(client, master_password):
    """Login without LDAP config returns 501."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})

    r = await client.post(
        "/api/v1/vault/auth/ldap",
        json={"username": "jdoe", "password": "secret"},
    )
    assert r.status_code == 501


@pytest.mark.asyncio
async def test_ldap_config_not_set(client, master_password, admin_token):
    """Get config when not configured returns configured=False."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.get("/api/v1/vault/auth/ldap/config", headers=headers)
    assert r.status_code == 200
    assert r.json()["configured"] is False


@pytest.mark.asyncio
async def test_ldap_configure(client, master_password, admin_token):
    """Set LDAP configuration."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    config = {
        "url": "ldaps://dc.test.local:636",
        "bind_dn": "cn=rhorizon,ou=services,dc=test,dc=local",
        "bind_password": "svc-password",
        "user_base": "ou=users,dc=test,dc=local",
        "group_base": "ou=groups,dc=test,dc=local",
    }
    r = await client.post(
        "/api/v1/vault/auth/ldap/config", json=config, headers=headers
    )
    assert r.status_code == 200
    assert r.json()["status"] == "configured"

    # Verify config is saved (password masked)
    r = await client.get("/api/v1/vault/auth/ldap/config", headers=headers)
    assert r.status_code == 200
    assert r.json()["configured"] is True
    assert r.json()["url"] == "ldaps://dc.test.local:636"
    assert r.json()["bind_password"] == "********"

    # Cleanup
    from api.app.database import async_session

    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_config WHERE key = 'ldap_config'"))
        await db.commit()


@pytest.mark.asyncio
async def test_ldap_mappings_default(client, master_password, admin_token):
    """Default mappings include builtins."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.get("/api/v1/vault/auth/ldap/mappings", headers=headers)
    assert r.status_code == 200
    mappings = r.json()["mappings"]
    assert "vault-admins" in mappings
    assert "vault-ops" in mappings
    assert "vault-readers" in mappings


@pytest.mark.asyncio
async def test_ldap_mappings_update(client, master_password, admin_token):
    """Update group mappings."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    custom = {
        "dba-team": {"secrets": "rw", "namespaces": ["prod/db"]},
        "devs": {"secrets": "r"},
    }
    r = await client.put(
        "/api/v1/vault/auth/ldap/mappings", json=custom, headers=headers
    )
    assert r.status_code == 200
    assert set(r.json()["groups"]) == {"dba-team", "devs"}

    # Verify saved
    r = await client.get("/api/v1/vault/auth/ldap/mappings", headers=headers)
    assert r.json()["mappings"]["dba-team"]["secrets"] == "rw"

    # Cleanup
    from api.app.database import async_session

    async with async_session() as db:
        await db.execute(
            text("DELETE FROM vault_config WHERE key = 'ldap_group_mappings'")
        )
        await db.commit()


# Login with mocked LDAP (no real LDAP server needed)


@pytest.mark.asyncio
async def test_ldap_login_success(client, master_password, admin_token):
    """Full LDAP login flow with mocked bonsai."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Set config
    config = {
        "url": "ldap://localhost:389",
        "bind_dn": "cn=svc,dc=test,dc=local",
        "bind_password": "svc-pass",
        "user_base": "ou=users,dc=test,dc=local",
        "group_base": "ou=groups,dc=test,dc=local",
        "session_ttl_hours": 1,
    }
    await client.post("/api/v1/vault/auth/ldap/config", json=config, headers=headers)

    # Mock _ldap_authenticate to return user + groups
    with patch(
        "api.app.routes.auth_ldap._ldap_authenticate",
        new_callable=AsyncMock,
        return_value=("cn=jdoe,ou=users,dc=test,dc=local", ["vault-ops"]),
    ):
        r = await client.post(
            "/api/v1/vault/auth/ldap",
            json={"username": "jdoe", "password": "user-pass"},
        )

    assert r.status_code == 200
    data = r.json()
    assert data["username"] == "jdoe"
    assert data["token"].startswith("rh_")
    assert "vault-ops" in data["groups"]
    assert data["permissions"]["secrets"] == "rw"
    assert "expires_at" in data

    # Cleanup
    from api.app.database import async_session

    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_config WHERE key = 'ldap_config'"))
        await db.execute(text("DELETE FROM vault_tokens WHERE name = 'ldap:jdoe'"))
        await db.commit()


@pytest.mark.asyncio
async def test_ldap_login_no_matching_groups(client, master_password, admin_token):
    """Login with groups that don't map to any permissions returns 403."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    config = {
        "url": "ldap://localhost:389",
        "bind_dn": "cn=svc,dc=test,dc=local",
        "bind_password": "svc-pass",
        "user_base": "ou=users,dc=test,dc=local",
        "group_base": "ou=groups,dc=test,dc=local",
    }
    await client.post("/api/v1/vault/auth/ldap/config", json=config, headers=headers)

    with patch(
        "api.app.routes.auth_ldap._ldap_authenticate",
        new_callable=AsyncMock,
        return_value=("cn=nobody,ou=users,dc=test,dc=local", ["random-group"]),
    ):
        r = await client.post(
            "/api/v1/vault/auth/ldap",
            json={"username": "nobody", "password": "pass"},
        )

    assert r.status_code == 403

    # Cleanup
    from api.app.database import async_session

    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_config WHERE key = 'ldap_config'"))
        await db.commit()


@pytest.mark.asyncio
async def test_ldap_login_admin_group(client, master_password, admin_token):
    """Login with vault-admins group gets admin:rw."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    config = {
        "url": "ldap://localhost:389",
        "bind_dn": "cn=svc,dc=test,dc=local",
        "bind_password": "svc-pass",
        "user_base": "ou=users,dc=test,dc=local",
        "group_base": "ou=groups,dc=test,dc=local",
    }
    await client.post("/api/v1/vault/auth/ldap/config", json=config, headers=headers)

    with patch(
        "api.app.routes.auth_ldap._ldap_authenticate",
        new_callable=AsyncMock,
        return_value=("cn=admin,ou=users,dc=test,dc=local", ["vault-admins"]),
    ):
        r = await client.post(
            "/api/v1/vault/auth/ldap",
            json={"username": "admin", "password": "admin-pass"},
        )

    assert r.status_code == 200
    assert r.json()["permissions"] == {"admin": "rw"}

    # Cleanup
    from api.app.database import async_session

    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_config WHERE key = 'ldap_config'"))
        await db.execute(text("DELETE FROM vault_tokens WHERE name = 'ldap:admin'"))
        await db.commit()
