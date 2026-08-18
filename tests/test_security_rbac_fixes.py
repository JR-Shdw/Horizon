# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Regression tests for the RBAC / namespace-boundary fixes (2026-06).

Locks in three corrections surfaced by a security review:

  - require_permission mode enforcement (auth.py): an admin:r token is
    read-only everywhere (cannot pass an admin:w dependency), and a
    write-only scope cannot satisfy a read dependency.
  - legacy bulk delete_namespace (secrets.py): now admin:w + refuses
    namespaces whose delete_protection is not 'free'.
  - rotate-all (secrets.py): now admin:w, unreachable by a scoped
    secrets:w token (no more cross-namespace re-encryption).

Tokens with non-standard permission values (admin:r, secrets:w) are
minted directly via SQL, mirroring the admin_token fixture - the POLA
grant check at POST /tokens/ would otherwise refuse some of these, and
the point here is to test the auth dependency layer in isolation.
"""

from __future__ import annotations

import json

import pytest
from sqlalchemy import text


async def _mint(perms: dict, name: str) -> str:
    """Mint a token with arbitrary permissions via direct SQL. Returns the
    raw token string."""
    from api.app.crypto import generate_token
    from api.app.database import async_session
    from api.app.vault_state import vault

    raw = generate_token()
    token_hash = await vault.hmac_sha512_hex(raw)
    async with async_session() as db:
        await db.execute(
            text(
                """
                INSERT INTO vault_tokens (name, token_hash, permissions, created_by)
                VALUES (:name, :hash, CAST(:perms AS jsonb), 'rbac-test')
                ON CONFLICT (name) WHERE active DO UPDATE SET token_hash = :hash
                """
            ),
            {"name": name, "hash": token_hash, "perms": json.dumps(perms)},
        )
        await db.commit()
    return raw


def _h(tok: str) -> dict:
    return {"Authorization": f"Bearer {tok}"}


# --------------------------------------------------------------------------
# Fix #1, require_permission mode enforcement
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_read_write_mode_requires_both_capabilities():
    """The documented rw mode accepts only a combined read/write grant."""
    from api.app.auth import require_permission
    from fastapi import HTTPException

    check = require_permission("secrets", "rw")
    token_info = {"permissions": {"secrets": "rw"}}
    assert await check(token_info=token_info) is token_info

    with pytest.raises(HTTPException) as exc:
        await check(token_info={"permissions": {"secrets": "r"}})
    assert exc.value.status_code == 403


def test_invalid_permission_mode_rejected_at_definition_time():
    """A route typo must fail during import instead of becoming a hidden 403."""
    from api.app.auth import require_permission

    with pytest.raises(ValueError, match="permission mode"):
        require_permission("secrets", "x")


def test_namespace_claim_fails_closed_on_malformed_permissions():
    """Corrupt permission containers must not become unrestricted claims."""
    from api.app.auth import namespace_claim

    assert namespace_claim({}) is None
    assert namespace_claim({"permissions": {}}) is None
    assert namespace_claim({"permissions": []}) == []
    assert namespace_claim({"permissions": "corrupt"}) == []
    assert namespace_claim({"permissions": {"namespaces": "prod"}}) == []


@pytest.mark.asyncio
async def test_admin_read_cannot_write(client, master_password, admin_token):
    """admin:r (monitoring) must NOT pass an admin:w endpoint."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    tok = await _mint({"admin": "r"}, "rbac-admin-r")
    r = await client.post("/api/v1/vault/secrets/rotate-all", headers=_h(tok))
    assert r.status_code == 403, r.text


@pytest.mark.asyncio
async def test_admin_read_can_read(client, master_password, admin_token):
    """admin:r still satisfies a read dependency (here tokens:r)."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    tok = await _mint({"admin": "r"}, "rbac-admin-r2")
    r = await client.get("/api/v1/vault/tokens/", headers=_h(tok))
    assert r.status_code == 200, r.text


@pytest.mark.asyncio
async def test_write_only_scope_cannot_read(client, master_password, admin_token):
    """A write-only secrets:w token must NOT satisfy a secrets:r read dep."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    await client.delete("/api/v1/vault/secrets/rbac-wo-secret", headers=_h(admin_token))
    r = await client.post(
        "/api/v1/vault/secrets/",
        json={"name": "rbac-wo-secret", "value": "v"},
        headers=_h(admin_token),
    )
    assert r.status_code == 201, r.text

    tok = await _mint({"secrets": "w"}, "rbac-secrets-w")
    r = await client.get("/api/v1/vault/secrets/rbac-wo-secret", headers=_h(tok))
    assert r.status_code == 403, r.text

    await client.delete("/api/v1/vault/secrets/rbac-wo-secret", headers=_h(admin_token))


@pytest.mark.asyncio
async def test_write_only_scope_can_write(client, master_password, admin_token):
    """secrets:w still writes (regression guard for the new check)."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    await client.delete("/api/v1/vault/secrets/rbac-wo-write", headers=_h(admin_token))
    tok = await _mint({"secrets": "w"}, "rbac-secrets-w2")
    r = await client.post(
        "/api/v1/vault/secrets/",
        json={"name": "rbac-wo-write", "value": "v"},
        headers=_h(tok),
    )
    assert r.status_code == 201, r.text
    await client.delete("/api/v1/vault/secrets/rbac-wo-write", headers=_h(admin_token))


@pytest.mark.asyncio
async def test_read_only_scope_cannot_write(client, master_password, admin_token):
    """secrets:r must NOT pass a secrets:w write dep (mode rejection works)."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    tok = await _mint({"secrets": "r"}, "rbac-secrets-r")
    r = await client.post(
        "/api/v1/vault/secrets/",
        json={"name": "rbac-ro-write", "value": "v"},
        headers=_h(tok),
    )
    assert r.status_code == 403, r.text


# --------------------------------------------------------------------------
# Fix #3, rotate-all requires admin:w
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_rotate_all_rejects_scoped_secrets_token(
    client, master_password, admin_token
):
    """A namespace-scoped secrets:w token can no longer trigger a global
    re-encryption of every namespace's secrets."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    tok = await _mint({"secrets": "w", "namespaces": ["dev"]}, "rbac-rotate-scoped")
    r = await client.post("/api/v1/vault/secrets/rotate-all", headers=_h(tok))
    assert r.status_code == 403, r.text


@pytest.mark.asyncio
async def test_rotate_all_allows_admin(client, master_password, admin_token):
    """admin:w still performs the bulk rotation."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    await client.post(
        "/api/v1/vault/secrets/",
        json={"name": "rbac-rot-1", "value": "v1"},
        headers=_h(admin_token),
    )
    r = await client.post("/api/v1/vault/secrets/rotate-all", headers=_h(admin_token))
    assert r.status_code == 200, r.text
    await client.delete("/api/v1/vault/secrets/rbac-rot-1", headers=_h(admin_token))


# --------------------------------------------------------------------------
# Fix #2, legacy bulk delete_namespace hardened
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_delete_namespace_rejects_scoped_secrets_token(
    client, master_password, admin_token
):
    """The legacy bulk namespace delete now requires admin:w; a secrets:w
    token (even matching the namespace claim) is rejected."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    await client.post(
        "/api/v1/vault/secrets/",
        json={"name": "rbac-del-1", "value": "v", "namespace": "rbac-del-ns"},
        headers=_h(admin_token),
    )
    tok = await _mint(
        {"secrets": "w", "namespaces": ["rbac-del-ns"]}, "rbac-del-scoped"
    )
    r = await client.delete(
        "/api/v1/vault/secrets/namespaces/rbac-del-ns", headers=_h(tok)
    )
    assert r.status_code == 403, r.text
    # cleanup via admin
    await client.delete(
        "/api/v1/vault/secrets/namespaces/rbac-del-ns", headers=_h(admin_token)
    )


@pytest.mark.asyncio
async def test_delete_namespace_admin_free_ok(client, master_password, admin_token):
    """admin:w can bulk-delete a free-protection namespace."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    await client.post(
        "/api/v1/vault/secrets/",
        json={"name": "rbac-del-2", "value": "v", "namespace": "rbac-del-free"},
        headers=_h(admin_token),
    )
    r = await client.delete(
        "/api/v1/vault/secrets/namespaces/rbac-del-free", headers=_h(admin_token)
    )
    assert r.status_code == 200, r.text
    assert r.json()["secrets_deleted"] >= 1


@pytest.mark.asyncio
async def test_delete_namespace_refuses_protected(client, master_password, admin_token):
    """Bulk delete is refused (409) on a namespace with delete_protection
    != 'free'. The free namespace is auto-created by the secret write, then
    ratcheted up to 'protected' via the proper admin endpoint."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    await client.post(
        "/api/v1/vault/secrets/",
        json={"name": "rbac-prot-1", "value": "v", "namespace": "rbac-prot-ns"},
        headers=_h(admin_token),
    )
    up = await client.put(
        "/api/v1/vault/namespaces/rbac-prot-ns",
        json={"delete_protection": "protected"},
        headers=_h(admin_token),
    )
    assert up.status_code == 200, up.text

    r = await client.delete(
        "/api/v1/vault/secrets/namespaces/rbac-prot-ns", headers=_h(admin_token)
    )
    assert r.status_code == 409, r.text
