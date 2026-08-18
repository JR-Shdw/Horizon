"""Regression tests for the 2026-04-29 security audit findings.

HIGH#1 - token namespace escalation in _check_grant_permissions
HIGH#2 - legacy plaintext export endpoint removed entirely
MEDIUM#1 - oneshot non-constant-time master_check (no direct test, just
           verifies the call still works after switching to compare_digest)
"""

import secrets as _sec

import pytest


@pytest.mark.asyncio
async def test_token_create_namespace_escalation_blocked(
    client, master_password, admin_token
):
    """A non-root token restricted to ['dev'] cannot mint a child token
    with namespaces=['prod'] - HIGH#1 from the audit."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers_admin = {"Authorization": f"Bearer {admin_token}"}

    # Mint a parent token: tokens:w + secrets:rw, restricted to namespace dev
    parent_name = f"parent-ns-esc-{_sec.token_hex(4)}"
    r = await client.post(
        "/api/v1/vault/tokens/",
        headers=headers_admin,
        json={
            "name": parent_name,
            "permissions": {
                "tokens": "w",
                "secrets": "rw",
                "namespaces": ["dev"],
            },
        },
    )
    assert r.status_code in (200, 201), r.text
    parent_token = r.json()["token"]

    # Try to escalate: parent token mints child in ['prod'] (not in parent's ns)
    r2 = await client.post(
        "/api/v1/vault/tokens/",
        headers={"Authorization": f"Bearer {parent_token}"},
        json={
            "name": f"child-prod-{_sec.token_hex(4)}",
            "permissions": {"secrets": "rw", "namespaces": ["prod"]},
        },
    )
    assert r2.status_code == 403, r2.text
    assert "namespace" in r2.json().get("detail", "").lower()

    # Also blocked: child WITHOUT a namespaces claim (effectively unrestricted)
    r3 = await client.post(
        "/api/v1/vault/tokens/",
        headers={"Authorization": f"Bearer {parent_token}"},
        json={
            "name": f"child-unrestricted-{_sec.token_hex(4)}",
            "permissions": {"secrets": "rw"},
        },
    )
    assert r3.status_code == 403, r3.text

    # Allowed: child within parent's namespace subset
    r4 = await client.post(
        "/api/v1/vault/tokens/",
        headers={"Authorization": f"Bearer {parent_token}"},
        json={
            "name": f"child-dev-{_sec.token_hex(4)}",
            "permissions": {"secrets": "r", "namespaces": ["dev"]},
        },
    )
    assert r4.status_code in (200, 201), r4.text


@pytest.mark.asyncio
async def test_token_create_admin_with_namespaces_cannot_grant_unrestricted(
    client, master_password, admin_token
):
    """A namespace-restricted admin cannot mint an unrestricted root token.

    Closes the loophole where 'admin in caller_perms' bypassed all checks.
    """
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers_admin = {"Authorization": f"Bearer {admin_token}"}

    parent_name = f"restricted-admin-{_sec.token_hex(4)}"
    r = await client.post(
        "/api/v1/vault/tokens/",
        headers=headers_admin,
        json={
            "name": parent_name,
            "permissions": {"admin": "rw", "namespaces": ["dev"]},
        },
    )
    parent_token = r.json()["token"]

    # Try to mint an unrestricted root token from a restricted admin
    r2 = await client.post(
        "/api/v1/vault/tokens/",
        headers={"Authorization": f"Bearer {parent_token}"},
        json={
            "name": f"escalated-{_sec.token_hex(4)}",
            "permissions": {"admin": "rw"},
        },
    )
    assert r2.status_code == 403, r2.text


@pytest.mark.asyncio
async def test_plaintext_export_endpoint_removed(client, master_password, admin_token):
    """HIGH#2's endpoint no longer exists; age backup is the export path."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers_admin = {"Authorization": f"Bearer {admin_token}"}

    # Admin (unrestricted) creates one secret in each of two namespaces
    for ns, name in [
        ("audit-export-a", "secret-a"),
        ("audit-export-b", "secret-b"),
    ]:
        await client.post(
            "/api/v1/vault/secrets/",
            headers=headers_admin,
            json={"name": name, "namespace": ns, "value": f"val-{ns}"},
        )

    # Mint a namespace-restricted admin (namespaces=["audit-export-a"])
    name = f"restricted-{_sec.token_hex(4)}"
    raw = (
        await client.post(
            "/api/v1/vault/tokens/",
            headers=headers_admin,
            json={
                "name": name,
                "permissions": {"admin": "rw", "namespaces": ["audit-export-a"]},
            },
        )
    ).json()["token"]

    # /export is now just a normal secret-name route; no bulk plaintext export.
    r = await client.get(
        "/api/v1/vault/secrets/export?namespace=audit-export-a",
        headers={"Authorization": f"Bearer {raw}"},
    )
    assert r.status_code == 404

    r2 = await client.get(
        "/api/v1/vault/secrets/export?namespace=audit-export-b",
        headers={"Authorization": f"Bearer {raw}"},
    )
    assert r2.status_code in {403, 404}


@pytest.mark.asyncio
async def test_oneshot_invalid_password_constant_time(
    client, master_password, admin_token
):
    """oneshot still rejects invalid passwords correctly (regression for the
    switch to compare_digest)."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers_admin = {"Authorization": f"Bearer {admin_token}"}

    # Pre-create a secret + seal
    await client.post(
        "/api/v1/vault/secrets/",
        headers=headers_admin,
        json={"name": "oneshot-ct-test", "value": "v"},
    )
    await client.post("/api/v1/vault/seal", headers=headers_admin)

    # Wrong password -> 401
    r = await client.post(
        "/api/v1/vault/oneshot",
        json={"password": "definitely-wrong", "name": "oneshot-ct-test"},
    )
    assert r.status_code == 401

    # Cleanup: re-unseal so other tests don't fail
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
