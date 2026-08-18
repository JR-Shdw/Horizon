# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Coverage targete sur api/app/routes/auth_proxy.py (83 % -> ~96 %).

Cible :
  - L89    : entry vide ignoree dans _parse_trusted_networks
  - L137   : proxy_group_mappings present en DB
  - L143   : fallback sur ldap_group_mappings
  - L162-165, L171 : merging namespaces dans _merge_permissions
  - L323-352 : PUT /auth/proxy/config admin endpoint
  - L361-362 : GET /auth/proxy/mappings
  - L373-391 : PUT /auth/proxy/mappings admin endpoint
"""

import json

import pytest
from sqlalchemy import text


@pytest.mark.asyncio
async def test_parse_trusted_networks_skips_empty_entries():
    """L88-89 : entries comma-separated avec espaces vides sont ignorees."""
    from api.app.routes.auth_proxy import _parse_trusted_networks

    nets = _parse_trusted_networks("10.0.0.0/8, , 192.168.0.0/16,  ")
    assert len(nets) == 2  # les deux entries vides sautees


def test_merge_permissions_namespaces_union():
    """L161-171 : namespaces de plusieurs groupes union'es + sorted."""
    from api.app.routes.auth_proxy import _merge_permissions

    mappings = {
        "g1": {"secrets": "r", "namespaces": ["prod", "staging"]},
        "g2": {"secrets": "rw", "namespaces": ["staging", "dev"]},
    }
    out = _merge_permissions(["g1", "g2"], mappings)
    assert out["secrets"] == "rw"  # strongest wins
    assert out["namespaces"] == ["dev", "prod", "staging"]  # union + tri


def test_merge_permissions_namespaces_string_value_ignored():
    """L163 : isinstance(v, list) check - string value ignoree."""
    from api.app.routes.auth_proxy import _merge_permissions

    mappings = {"g": {"namespaces": "not-a-list"}}
    out = _merge_permissions(["g"], mappings)
    # has_ns_restriction=True but empty ns_set -> no namespaces key in out
    assert "namespaces" not in out


@pytest.mark.asyncio
async def test_get_proxy_mappings_from_proxy_group_mappings(
    client, master_password, admin_token
):
    """L132-137 : si proxy_group_mappings present en DB, retourne ca."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    from api.app.database import async_session

    custom = {"vault-special": {"secrets": "r", "namespaces": ["test-ns"]}}
    async with async_session() as db:
        await db.execute(
            text(
                "INSERT INTO vault_config (key, value) "
                "VALUES ('proxy_group_mappings', :v) "
                "ON CONFLICT (key) DO UPDATE SET value = :v"
            ),
            {"v": json.dumps(custom)},
        )
        await db.commit()

    try:
        r = await client.get(
            "/api/v1/vault/auth/proxy/mappings",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 200
        assert r.json()["mappings"] == custom
    finally:
        async with async_session() as db:
            await db.execute(
                text("DELETE FROM vault_config WHERE key = 'proxy_group_mappings'")
            )
            await db.commit()


@pytest.mark.asyncio
async def test_get_proxy_mappings_fallback_ldap(client, master_password, admin_token):
    """L138-143 : proxy_group_mappings absent -> fallback sur ldap_group_mappings."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    from api.app.database import async_session

    ldap_map = {"vault-ldap-group": {"secrets": "rw"}}
    async with async_session() as db:
        # Cleanup proxy_group_mappings au cas ou.
        await db.execute(
            text("DELETE FROM vault_config WHERE key = 'proxy_group_mappings'")
        )
        await db.execute(
            text(
                "INSERT INTO vault_config (key, value) "
                "VALUES ('ldap_group_mappings', :v) "
                "ON CONFLICT (key) DO UPDATE SET value = :v"
            ),
            {"v": json.dumps(ldap_map)},
        )
        await db.commit()

    try:
        r = await client.get(
            "/api/v1/vault/auth/proxy/mappings",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 200
        assert r.json()["mappings"] == ldap_map
    finally:
        async with async_session() as db:
            await db.execute(
                text("DELETE FROM vault_config WHERE key = 'ldap_group_mappings'")
            )
            await db.commit()


@pytest.mark.asyncio
async def test_put_proxy_config(client, master_password, admin_token):
    """L323-352 : PUT /auth/proxy/config exercise full body."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    r = await client.post(
        "/api/v1/vault/auth/proxy/config",
        json={
            "enabled": True,
            "user_header": "Remote-User",
            "groups_header": "Remote-Groups",
            "trusted_ips": "10.0.0.1/24",
            "session_ttl_hours": 12,
        },
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "configured"
    assert body["enabled"] is True
    assert body["trusted_ips"] == "10.0.0.1/24"
    assert body["restart_required"] is True

    invalid = await client.post(
        "/api/v1/vault/auth/proxy/config",
        json={
            "enabled": True,
            "trusted_ips": "10.0.0.1/99",
            "session_ttl_hours": 12,
        },
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert invalid.status_code == 422

    # Cleanup
    from api.app.database import async_session

    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_config WHERE key = 'proxy_config'"))
        await db.commit()


@pytest.mark.asyncio
async def test_put_proxy_mappings(client, master_password, admin_token):
    """L365-391 : PUT /auth/proxy/mappings exercise full body + log_action."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    new_map = {
        "external-group-a": {"secrets": "r"},
        "external-group-b": {"secrets": "rw", "namespaces": ["client-x"]},
    }
    r = await client.put(
        "/api/v1/vault/auth/proxy/mappings",
        json=new_map,
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "updated"
    assert set(body["groups"]) == {"external-group-a", "external-group-b"}

    # Verify the write to the DB
    from api.app.database import async_session

    async with async_session() as db:
        row = (
            await db.execute(
                text(
                    "SELECT value FROM vault_config WHERE key = 'proxy_group_mappings'"
                )
            )
        ).fetchone()
        assert row is not None
        assert json.loads(row.value) == new_map
        # Cleanup
        await db.execute(
            text("DELETE FROM vault_config WHERE key = 'proxy_group_mappings'")
        )
        await db.commit()
