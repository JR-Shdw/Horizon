"""Tests for POST /tokens/{id}/rotate - in-place secret rotation.

Covers the happy path (old value dies, new value works, identity +
metadata preserved), the not-found / bad-uuid branches, and the POLA
authorization gate (tokens:w required; a namespace-restricted caller may
only rotate tokens it could itself grant - never a root or out-of-namespace
token).
"""

import pytest


async def _create(client, headers, name, permissions):
    r = await client.post(
        "/api/v1/vault/tokens/",
        headers=headers,
        json={"name": name, "permissions": permissions},
    )
    assert r.status_code == 201, r.text
    return r.json()["token"]


async def _row(client, headers, name):
    r = await client.get("/api/v1/vault/tokens/", headers=headers)
    assert r.status_code == 200
    return next(t for t in r.json()["items"] if t["name"] == name)


@pytest.mark.asyncio
async def test_rotate_swaps_secret_in_place(client, master_password, admin_token):
    """Old plaintext dies, new one works, id/name/permissions preserved."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    old = await _create(client, headers, "rotate-me", {"secrets": "r"})
    before = await _row(client, headers, "rotate-me")

    # The token authenticates before rotation (also sets last_used_at).
    r = await client.get(
        "/api/v1/vault/tokens/whoami",
        headers={"Authorization": f"Bearer {old}"},
    )
    assert r.status_code == 200

    r = await client.post(
        f"/api/v1/vault/tokens/{before['id']}/rotate", headers=headers
    )
    assert r.status_code == 200, r.text
    body = r.json()
    new = body["token"]
    assert body["name"] == "rotate-me"
    assert new != old

    # Inspect the row before anyone uses the new value: identity + scopes
    # preserved, rotated_at stamped, last_used_at reset to NULL.
    after = await _row(client, headers, "rotate-me")
    assert after["id"] == before["id"]  # same identity
    assert after["permissions"] == {"secrets": "r"}  # scopes preserved
    assert after["rotated_at"] is not None
    assert after["last_used_at"] is None  # reset on rotation

    # Old value no longer authenticates; new value does.
    r = await client.get(
        "/api/v1/vault/tokens/whoami",
        headers={"Authorization": f"Bearer {old}"},
    )
    assert r.status_code == 401
    r = await client.get(
        "/api/v1/vault/tokens/whoami",
        headers={"Authorization": f"Bearer {new}"},
    )
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_rotate_unknown_id_returns_404(client, master_password, admin_token):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}
    r = await client.post(
        "/api/v1/vault/tokens/00000000-0000-0000-0000-000000000000/rotate",
        headers=headers,
    )
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_rotate_bad_uuid_returns_400(client, master_password, admin_token):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}
    r = await client.post("/api/v1/vault/tokens/not-a-uuid/rotate", headers=headers)
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_rotate_revoked_token_returns_404(client, master_password, admin_token):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}
    await _create(client, headers, "rotate-revoked", {"secrets": "r"})
    row = await _row(client, headers, "rotate-revoked")
    await client.post(f"/api/v1/vault/tokens/{row['id']}/revoke", headers=headers)
    r = await client.post(f"/api/v1/vault/tokens/{row['id']}/rotate", headers=headers)
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_rotate_requires_tokens_write(client, master_password, admin_token):
    """A caller without tokens:w cannot rotate (403 missing scope)."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    admin_h = {"Authorization": f"Bearer {admin_token}"}

    target = await _create(client, admin_h, "rotate-target-1", {"secrets": "r"})
    row = await _row(client, admin_h, "rotate-target-1")
    reader = await _create(client, admin_h, "reader-only", {"secrets": "r"})

    r = await client.post(
        f"/api/v1/vault/tokens/{row['id']}/rotate",
        headers={"Authorization": f"Bearer {reader}"},
    )
    assert r.status_code == 403
    assert target  # silence unused


@pytest.mark.asyncio
async def test_namespace_subadmin_rotate_pola(client, master_password, admin_token):
    """A namespace sub-admin rotates within its namespace, never outside it
    nor a root token."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    admin_h = {"Authorization": f"Bearer {admin_token}"}

    # Sub-admin scoped to namespace "dev".
    sub = await _create(
        client,
        admin_h,
        "dev-subadmin",
        {"secrets": "rw", "tokens": "rw", "namespaces": ["dev"]},
    )
    sub_h = {"Authorization": f"Bearer {sub}"}

    in_ns = await _create(
        client, admin_h, "dev-token", {"secrets": "r", "namespaces": ["dev"]}
    )
    out_ns = await _create(
        client, admin_h, "prod-token", {"secrets": "r", "namespaces": ["prod"]}
    )
    root = await _create(client, admin_h, "root-token", {"admin": "rw"})
    assert in_ns and out_ns and root

    in_row = await _row(client, admin_h, "dev-token")
    out_row = await _row(client, admin_h, "prod-token")
    root_row = await _row(client, admin_h, "root-token")

    # Allowed: same namespace, grantable scopes.
    r = await client.post(f"/api/v1/vault/tokens/{in_row['id']}/rotate", headers=sub_h)
    assert r.status_code == 200, r.text

    # Denied: namespace outside the sub-admin's claim.
    r = await client.post(f"/api/v1/vault/tokens/{out_row['id']}/rotate", headers=sub_h)
    assert r.status_code == 403

    # Denied: cannot re-issue a root (admin) token it could not grant.
    r = await client.post(
        f"/api/v1/vault/tokens/{root_row['id']}/rotate", headers=sub_h
    )
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_namespace_subadmin_revoke_delete_pola(
    client, master_password, admin_token
):
    """revoke + delete are namespace-confined like rotate: a sub-admin acts on
    its own namespace, never on a root or out-of-namespace token."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    admin_h = {"Authorization": f"Bearer {admin_token}"}
    sub = await _create(
        client, admin_h, "dev-sub-rd", {"tokens": "rw", "namespaces": ["dev"]}
    )
    sub_h = {"Authorization": f"Bearer {sub}"}

    await _create(
        client, admin_h, "dev-tok-rd", {"secrets": "r", "namespaces": ["dev"]}
    )
    await _create(
        client, admin_h, "prod-tok-rd", {"secrets": "r", "namespaces": ["prod"]}
    )
    await _create(client, admin_h, "root-tok-rd", {"admin": "rw"})
    in_row = await _row(client, admin_h, "dev-tok-rd")
    out_row = await _row(client, admin_h, "prod-tok-rd")
    root_row = await _row(client, admin_h, "root-tok-rd")

    # Denied: revoke / delete out-of-namespace + root.
    for tid in (out_row["id"], root_row["id"]):
        r = await client.post(f"/api/v1/vault/tokens/{tid}/revoke", headers=sub_h)
        assert r.status_code == 403, r.text
        r = await client.request("DELETE", f"/api/v1/vault/tokens/{tid}", headers=sub_h)
        assert r.status_code == 403, r.text

    # Allowed: revoke then delete its own-namespace token (delete works on the
    # now-revoked row too).
    r = await client.post(f"/api/v1/vault/tokens/{in_row['id']}/revoke", headers=sub_h)
    assert r.status_code == 200, r.text
    r = await client.request(
        "DELETE", f"/api/v1/vault/tokens/{in_row['id']}", headers=sub_h
    )
    assert r.status_code == 200, r.text


@pytest.mark.asyncio
async def test_namespace_subadmin_renew_pola(client, master_password, admin_token):
    """renew is namespace-confined: a sub-admin can extend its own ephemeral,
    not one in another namespace."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    admin_h = {"Authorization": f"Bearer {admin_token}"}
    sub = await _create(
        client, admin_h, "dev-sub-renew", {"tokens": "rw", "namespaces": ["dev"]}
    )
    sub_h = {"Authorization": f"Bearer {sub}"}

    dev_eph = (
        await client.post(
            "/api/v1/vault/tokens/ephemeral",
            json={"permissions": {"secrets": "r", "namespaces": ["dev"]}},
            headers=admin_h,
        )
    ).json()["name"]
    prod_eph = (
        await client.post(
            "/api/v1/vault/tokens/ephemeral",
            json={"permissions": {"secrets": "r", "namespaces": ["prod"]}},
            headers=admin_h,
        )
    ).json()["name"]
    dev_row = await _row(client, admin_h, dev_eph)
    prod_row = await _row(client, admin_h, prod_eph)

    body = {"ttl_seconds": 7200}
    r = await client.post(
        f"/api/v1/vault/tokens/{prod_row['id']}/renew", json=body, headers=sub_h
    )
    assert r.status_code == 403, r.text
    r = await client.post(
        f"/api/v1/vault/tokens/{dev_row['id']}/renew", json=body, headers=sub_h
    )
    assert r.status_code == 200, r.text


@pytest.mark.asyncio
async def test_list_tokens_filtered_by_namespace(client, master_password, admin_token):
    """A namespace sub-admin only sees tokens it could manage (its-namespace
    subset); root / cross-namespace tokens are hidden. Admin sees all."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    admin_h = {"Authorization": f"Bearer {admin_token}"}
    sub = await _create(
        client, admin_h, "dev-sub-list", {"tokens": "rw", "namespaces": ["dev"]}
    )
    sub_h = {"Authorization": f"Bearer {sub}"}
    await _create(
        client, admin_h, "dev-visible", {"secrets": "r", "namespaces": ["dev"]}
    )
    await _create(
        client, admin_h, "prod-hidden", {"secrets": "r", "namespaces": ["prod"]}
    )
    await _create(client, admin_h, "root-hidden", {"admin": "rw"})

    names = {
        t["name"]
        for t in (await client.get("/api/v1/vault/tokens/", headers=sub_h)).json()[
            "items"
        ]
    }
    assert "dev-visible" in names
    assert "dev-sub-list" in names  # its own token (namespaces=["dev"])
    assert "prod-hidden" not in names
    assert "root-hidden" not in names

    anames = {
        t["name"]
        for t in (await client.get("/api/v1/vault/tokens/", headers=admin_h)).json()[
            "items"
        ]
    }
    assert {"dev-visible", "prod-hidden", "root-hidden"}.issubset(anames)
