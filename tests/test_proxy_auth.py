"""Tests for SSO reverse proxy authentication (Authelia/Authentik/Keycloak).

Covers: trusted IP validation, header parsing, group mapping,
        token creation, disabled state, missing headers, untrusted IP.
"""

from unittest.mock import patch

import pytest
from api.app.routes.auth_proxy import (
    ProxyAuthConfigUpdate,
    _is_trusted,
    _parse_trusted_networks,
)
from pydantic import ValidationError
from sqlalchemy import text

# Unit tests, IP trust validation (no DB needed)


class TestParseTrustedNetworks:
    def test_empty_string(self):
        with patch("api.app.routes.auth_proxy.settings") as mock:
            mock.proxy_trusted_ips = ""
            assert _parse_trusted_networks() == []

    def test_single_ip(self):
        with patch("api.app.routes.auth_proxy.settings") as mock:
            mock.proxy_trusted_ips = "10.0.0.1"
            nets = _parse_trusted_networks()
            assert len(nets) == 1

    def test_cidr_network(self):
        with patch("api.app.routes.auth_proxy.settings") as mock:
            mock.proxy_trusted_ips = "172.18.0.0/16"
            nets = _parse_trusted_networks()
            assert len(nets) == 1

    def test_multiple_entries(self):
        with patch("api.app.routes.auth_proxy.settings") as mock:
            mock.proxy_trusted_ips = "10.0.0.1, 172.18.0.0/16, 192.168.1.1"
            nets = _parse_trusted_networks()
            assert len(nets) == 3

    def test_invalid_entry_skipped(self):
        with patch("api.app.routes.auth_proxy.settings") as mock:
            mock.proxy_trusted_ips = "10.0.0.1, not-an-ip, 192.168.1.1"
            nets = _parse_trusted_networks()
            assert len(nets) == 2


def test_enabled_proxy_config_requires_trusted_ips():
    with pytest.raises(ValidationError, match="trusted_ips is required"):
        ProxyAuthConfigUpdate(enabled=True, trusted_ips="")

    disabled = ProxyAuthConfigUpdate(enabled=False, trusted_ips="")
    assert disabled.trusted_ips == ""


class TestIsTrusted:
    def test_trusted_exact_ip(self):
        with patch("api.app.routes.auth_proxy.settings") as mock:
            mock.proxy_trusted_ips = "10.0.0.1"
            assert _is_trusted("10.0.0.1") is True

    def test_untrusted_ip(self):
        with patch("api.app.routes.auth_proxy.settings") as mock:
            mock.proxy_trusted_ips = "10.0.0.1"
            assert _is_trusted("10.0.0.1") is False

    def test_trusted_cidr(self):
        with patch("api.app.routes.auth_proxy.settings") as mock:
            mock.proxy_trusted_ips = "172.18.0.0/16"
            assert _is_trusted("172.18.5.10") is True

    def test_no_trusted_ips(self):
        with patch("api.app.routes.auth_proxy.settings") as mock:
            mock.proxy_trusted_ips = ""
            assert _is_trusted("10.0.0.1") is False

    def test_invalid_client_ip(self):
        with patch("api.app.routes.auth_proxy.settings") as mock:
            mock.proxy_trusted_ips = "10.0.0.1"
            assert _is_trusted("not-an-ip") is False


# Integration tests, proxy auth endpoint


def _enable_proxy(trusted_ip="testclient"):
    """Patch settings to enable proxy auth with given trusted IP."""
    return patch.multiple(
        "api.app.routes.auth_proxy.settings",
        proxy_auth_enabled=True,
        proxy_user_header="Remote-User",
        proxy_groups_header="Remote-Groups",
        proxy_trusted_ips=trusted_ip,
        proxy_session_ttl_hours=8,
    )


@pytest.mark.asyncio
async def test_proxy_disabled(client, master_password):
    """Returns 501 when proxy auth is not enabled."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})

    r = await client.post(
        "/api/v1/vault/auth/proxy",
        headers={"Remote-User": "jdoe", "Remote-Groups": "vault-ops"},
    )
    assert r.status_code == 501


@pytest.mark.asyncio
async def test_proxy_untrusted_ip(client, master_password):
    """Rejects requests from untrusted IPs."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})

    with patch.multiple(
        "api.app.routes.auth_proxy.settings",
        proxy_auth_enabled=True,
        proxy_user_header="Remote-User",
        proxy_groups_header="Remote-Groups",
        proxy_trusted_ips="10.0.0.1",  # not testclient
        proxy_session_ttl_hours=8,
    ):
        r = await client.post(
            "/api/v1/vault/auth/proxy",
            headers={"Remote-User": "jdoe", "Remote-Groups": "vault-ops"},
        )
    assert r.status_code == 403
    assert "trusted" in r.json()["detail"].lower()


@pytest.mark.asyncio
async def test_proxy_missing_user_header(client, master_password):
    """Rejects when Remote-User header is missing."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})

    with _enable_proxy():
        # _is_trusted will check "testclient", patch it to pass
        with patch("api.app.routes.auth_proxy._is_trusted", return_value=True):
            r = await client.post(
                "/api/v1/vault/auth/proxy",
                headers={"Remote-Groups": "vault-ops"},
            )
    assert r.status_code == 400
    assert "Remote-User" in r.json()["detail"]


@pytest.mark.asyncio
async def test_proxy_login_success(client, master_password):
    """Full proxy login with matching groups."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})

    with _enable_proxy():
        with patch("api.app.routes.auth_proxy._is_trusted", return_value=True):
            r = await client.post(
                "/api/v1/vault/auth/proxy",
                headers={
                    "Remote-User": "jdoe",
                    "Remote-Groups": "vault-ops,vault-readers",
                },
            )

    assert r.status_code == 200
    data = r.json()
    assert data["username"] == "jdoe"
    assert data["token"].startswith("rh_")
    assert "vault-ops" in data["groups"]
    assert "vault-readers" in data["groups"]
    assert data["permissions"]["secrets"] == "rw"
    assert "expires_at" in data

    # Cleanup
    from api.app.database import async_session

    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_tokens WHERE name = 'proxy:jdoe'"))
        await db.commit()


@pytest.mark.asyncio
async def test_proxy_login_admin_group(client, master_password):
    """Proxy login with vault-admins gets admin:rw."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})

    with _enable_proxy():
        with patch("api.app.routes.auth_proxy._is_trusted", return_value=True):
            r = await client.post(
                "/api/v1/vault/auth/proxy",
                headers={
                    "Remote-User": "admin-user",
                    "Remote-Groups": "vault-admins",
                },
            )

    assert r.status_code == 200
    assert r.json()["permissions"] == {"admin": "rw"}

    # Cleanup
    from api.app.database import async_session

    async with async_session() as db:
        await db.execute(
            text("DELETE FROM vault_tokens WHERE name = 'proxy:admin-user'")
        )
        await db.commit()


@pytest.mark.asyncio
async def test_proxy_login_no_matching_groups(client, master_password):
    """Proxy login with unrecognized groups returns 403."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})

    with _enable_proxy():
        with patch("api.app.routes.auth_proxy._is_trusted", return_value=True):
            r = await client.post(
                "/api/v1/vault/auth/proxy",
                headers={
                    "Remote-User": "nobody",
                    "Remote-Groups": "random-group",
                },
            )

    assert r.status_code == 403


@pytest.mark.asyncio
async def test_proxy_login_no_groups_header(client, master_password):
    """Proxy login without groups header returns 403 (no permissions)."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})

    with _enable_proxy():
        with patch("api.app.routes.auth_proxy._is_trusted", return_value=True):
            r = await client.post(
                "/api/v1/vault/auth/proxy",
                headers={"Remote-User": "jdoe"},
            )

    assert r.status_code == 403


@pytest.mark.asyncio
async def test_proxy_login_space_separated_groups(client, master_password):
    """Groups can be space-separated (Authentik style)."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})

    with _enable_proxy():
        with patch("api.app.routes.auth_proxy._is_trusted", return_value=True):
            r = await client.post(
                "/api/v1/vault/auth/proxy",
                headers={
                    "Remote-User": "jdoe2",
                    "Remote-Groups": "vault-ops vault-readers",
                },
            )

    assert r.status_code == 200
    assert "vault-ops" in r.json()["groups"]
    assert "vault-readers" in r.json()["groups"]

    # Cleanup
    from api.app.database import async_session

    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_tokens WHERE name = 'proxy:jdoe2'"))
        await db.commit()


@pytest.mark.asyncio
async def test_proxy_config_endpoint(client, master_password, admin_token):
    """Admin can read proxy auth config."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.get("/api/v1/vault/auth/proxy/config", headers=headers)
    assert r.status_code == 200
    data = r.json()
    assert "enabled" in data
    assert "user_header" in data
    assert "trusted_ips" in data


@pytest.mark.asyncio
async def test_proxy_sealed_rejects(client):
    """Proxy auth fails when vault is sealed."""
    from api.app.vault_state import vault

    vault.seal()

    with _enable_proxy():
        with patch("api.app.routes.auth_proxy._is_trusted", return_value=True):
            r = await client.post(
                "/api/v1/vault/auth/proxy",
                headers={
                    "Remote-User": "jdoe",
                    "Remote-Groups": "vault-ops",
                },
            )

    assert r.status_code == 503


@pytest.mark.asyncio
async def test_proxy_login_token_records_username_not_literal_proxy(
    client, master_password
):
    """Regression : `vault_tokens.created_by` must be the SSO user, not "proxy".

    Before the fix, the INSERT bound `:actor` to the literal string "proxy",
    which made `created_by` useless for tracing who minted the session token.
    The bug surfaced as "no name in Jets" because audit consumers and admin
    UIs cross-reference `created_by` for session attribution.
    """
    await client.post("/api/v1/vault/unseal", json={"password": master_password})

    with _enable_proxy():
        with patch("api.app.routes.auth_proxy._is_trusted", return_value=True):
            r = await client.post(
                "/api/v1/vault/auth/proxy",
                headers={
                    "Remote-User": "jdoe",
                    "Remote-Groups": "vault-ops",
                },
            )

    assert r.status_code == 200

    from api.app.database import async_session

    async with async_session() as db:
        row = (
            await db.execute(
                text(
                    "SELECT name, created_by FROM vault_tokens "
                    "WHERE name = 'proxy:jdoe'"
                )
            )
        ).fetchone()
        assert row is not None
        assert row.name == "proxy:jdoe"
        assert row.created_by == "jdoe"  # not "proxy"
        await db.execute(text("DELETE FROM vault_tokens WHERE name = 'proxy:jdoe'"))
        await db.commit()


@pytest.mark.asyncio
async def test_proxy_login_audit_actor_is_bare_username(client, master_password):
    """Regression : audit entries for proxy_login must show "jdoe", not "proxy:jdoe".

    The audit row for the login itself was already correct (writes
    `actor=username` directly). This test guards the contract so a future
    refactor doesn't accidentally use `token_info["name"]` (the prefixed form).
    """
    await client.post("/api/v1/vault/unseal", json={"password": master_password})

    with _enable_proxy():
        with patch("api.app.routes.auth_proxy._is_trusted", return_value=True):
            r = await client.post(
                "/api/v1/vault/auth/proxy",
                headers={
                    "Remote-User": "jdoe",
                    "Remote-Groups": "vault-ops",
                },
            )

    assert r.status_code == 200

    from api.app.database import async_session

    async with async_session() as db:
        actor = (
            await db.execute(
                text(
                    "SELECT actor FROM vault_audit "
                    "WHERE action = 'proxy_login' "
                    "ORDER BY timestamp DESC LIMIT 1"
                )
            )
        ).scalar()
        assert actor == "jdoe"  # bare, no "proxy:" prefix
        await db.execute(text("DELETE FROM vault_tokens WHERE name = 'proxy:jdoe'"))
        await db.commit()
