"""Tests for POST /tokens/{id}/allowed-ips - in-place IP allowlist change.

Covers the happy path (allowlist persisted + echoed), that the new allowlist
takes effect on the token's next request, clearing the restriction, CIDR
validation, not-found / bad-uuid / revoked branches, the POLA authorization
gate (tokens:w required; a namespace-restricted caller may only change tokens
it could itself grant), and that the change lands in the chained audit log.
"""

import pytest
from api.app.database import async_session
from sqlalchemy import text


async def _create(client, headers, name, permissions, allowed_ips=None):
    body = {"name": name, "permissions": permissions}
    if allowed_ips is not None:
        body["allowed_ips"] = allowed_ips
    r = await client.post("/api/v1/vault/tokens/", headers=headers, json=body)
    assert r.status_code == 201, r.text
    return r.json()["token"]


async def _row(client, headers, name):
    r = await client.get("/api/v1/vault/tokens/", headers=headers)
    assert r.status_code == 200
    return next(t for t in r.json()["items"] if t["name"] == name)


@pytest.mark.asyncio
async def test_set_allowed_ips_persists_and_takes_effect(
    client, master_password, admin_token
):
    """Allowlist is stored + echoed, and enforced on the token's next request."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    tok = await _create(client, headers, "ip-target", {"secrets": "r"})
    row = await _row(client, headers, "ip-target")

    # Unrestricted to start: the token authenticates fine.
    r = await client.get(
        "/api/v1/vault/tokens/whoami", headers={"Authorization": f"Bearer {tok}"}
    )
    assert r.status_code == 200

    # Restrict to a TEST-NET CIDR the test client is not in.
    r = await client.post(
        f"/api/v1/vault/tokens/{row['id']}/allowed-ips",
        headers=headers,
        json={"allowed_ips": "203.0.113.0/24"},
    )
    assert r.status_code == 200, r.text
    assert r.json()["allowed_ips"] == "203.0.113.0/24"
    assert (await _row(client, headers, "ip-target"))["allowed_ips"] == "203.0.113.0/24"

    # Takes effect: the token can no longer authenticate from this IP.
    r = await client.get(
        "/api/v1/vault/tokens/whoami", headers={"Authorization": f"Bearer {tok}"}
    )
    assert r.status_code == 403

    # Clearing it (empty -> NULL) restores unrestricted access.
    r = await client.post(
        f"/api/v1/vault/tokens/{row['id']}/allowed-ips",
        headers=headers,
        json={"allowed_ips": ""},
    )
    assert r.status_code == 200, r.text
    assert r.json()["allowed_ips"] in (None, "")
    r = await client.get(
        "/api/v1/vault/tokens/whoami", headers={"Authorization": f"Bearer {tok}"}
    )
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_set_allowed_ips_chained_audit(client, master_password, admin_token):
    """The change writes a chained `update_token_allowed_ips` audit row."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}
    await _create(client, headers, "ip-audit", {"secrets": "r"})
    row = await _row(client, headers, "ip-audit")

    r = await client.post(
        f"/api/v1/vault/tokens/{row['id']}/allowed-ips",
        headers=headers,
        json={"allowed_ips": "10.0.0.1/24"},
    )
    assert r.status_code == 200, r.text

    async with async_session() as db:
        n = (
            await db.execute(
                text(
                    "SELECT count(*) FROM vault_audit "
                    "WHERE action = 'update_token_allowed_ips' AND target = 'ip-audit'"
                )
            )
        ).scalar()
    assert n >= 1


@pytest.mark.asyncio
async def test_set_allowed_ips_bad_cidr_400(client, master_password, admin_token):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}
    await _create(client, headers, "ip-badcidr", {"secrets": "r"})
    row = await _row(client, headers, "ip-badcidr")
    r = await client.post(
        f"/api/v1/vault/tokens/{row['id']}/allowed-ips",
        headers=headers,
        json={"allowed_ips": "not-a-cidr"},
    )
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_set_allowed_ips_unknown_404(client, master_password, admin_token):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}
    r = await client.post(
        "/api/v1/vault/tokens/00000000-0000-0000-0000-000000000000/allowed-ips",
        headers=headers,
        json={"allowed_ips": "10.0.0.0/8"},
    )
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_set_allowed_ips_bad_uuid_400(client, master_password, admin_token):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}
    r = await client.post(
        "/api/v1/vault/tokens/not-a-uuid/allowed-ips",
        headers=headers,
        json={"allowed_ips": "10.0.0.0/8"},
    )
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_set_allowed_ips_revoked_404(client, master_password, admin_token):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}
    await _create(client, headers, "ip-revoked", {"secrets": "r"})
    row = await _row(client, headers, "ip-revoked")
    await client.post(f"/api/v1/vault/tokens/{row['id']}/revoke", headers=headers)
    r = await client.post(
        f"/api/v1/vault/tokens/{row['id']}/allowed-ips",
        headers=headers,
        json={"allowed_ips": "10.0.0.0/8"},
    )
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_set_allowed_ips_requires_tokens_write(
    client, master_password, admin_token
):
    """A caller without tokens:w cannot change a token's allowlist (403)."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    admin_h = {"Authorization": f"Bearer {admin_token}"}
    await _create(client, admin_h, "ip-w-target", {"secrets": "r"})
    row = await _row(client, admin_h, "ip-w-target")
    reader = await _create(client, admin_h, "ip-reader", {"secrets": "r"})
    r = await client.post(
        f"/api/v1/vault/tokens/{row['id']}/allowed-ips",
        headers={"Authorization": f"Bearer {reader}"},
        json={"allowed_ips": "10.0.0.0/8"},
    )
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_namespace_subadmin_set_ips_pola(client, master_password, admin_token):
    """A namespace sub-admin may change allowlists within its namespace only,
    never outside it nor on a root token."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    admin_h = {"Authorization": f"Bearer {admin_token}"}

    sub = await _create(
        client,
        admin_h,
        "ip-dev-subadmin",
        {"secrets": "rw", "tokens": "rw", "namespaces": ["dev"]},
    )
    sub_h = {"Authorization": f"Bearer {sub}"}

    await _create(
        client, admin_h, "ip-dev-token", {"secrets": "r", "namespaces": ["dev"]}
    )
    await _create(
        client, admin_h, "ip-prod-token", {"secrets": "r", "namespaces": ["prod"]}
    )
    await _create(client, admin_h, "ip-root-token", {"admin": "rw"})

    in_row = await _row(client, admin_h, "ip-dev-token")
    out_row = await _row(client, admin_h, "ip-prod-token")
    root_row = await _row(client, admin_h, "ip-root-token")

    body = {"allowed_ips": "10.0.0.1/24"}
    # Allowed: same namespace.
    r = await client.post(
        f"/api/v1/vault/tokens/{in_row['id']}/allowed-ips", headers=sub_h, json=body
    )
    assert r.status_code == 200, r.text
    # Denied: namespace outside the sub-admin's claim.
    r = await client.post(
        f"/api/v1/vault/tokens/{out_row['id']}/allowed-ips", headers=sub_h, json=body
    )
    assert r.status_code == 403
    # Denied: cannot touch a root token it could not grant.
    r = await client.post(
        f"/api/v1/vault/tokens/{root_row['id']}/allowed-ips", headers=sub_h, json=body
    )
    assert r.status_code == 403
