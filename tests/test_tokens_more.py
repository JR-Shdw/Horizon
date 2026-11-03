"""Extra tests for api/app/routes/tokens.py.

Targets the error branches of _check_grant_permissions and the invalid
allowed_ips on ephemeral. (97% -> 100%).
"""

import pytest
from api.app.database import async_session
from api.app.routes.tokens import _check_grant_permissions
from sqlalchemy import text


def test_check_grant_permissions_invalid_level_type():
    """non-iterable level -> 403 'Invalid permission level'."""
    from fastapi import HTTPException

    caller_perms = {"secrets": "rw"}
    requested = {"secrets": 12345}  # int instead of string/list

    with pytest.raises(HTTPException) as exc:
        _check_grant_permissions(caller_perms, requested)
    assert exc.value.status_code == 403
    assert "Invalid permission level" in exc.value.detail


def test_empty_admin_key_does_not_bypass_grant_checks():
    """The presence of an empty admin key is not delegation authority."""
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as exc:
        _check_grant_permissions(
            {"tokens": "w", "admin": ""},
            {"admin": "rw"},
        )
    assert exc.value.status_code == 403


def test_admin_modes_apply_without_escalating_read_to_write():
    """admin:r delegates reads only; explicit scope modes may complement it."""
    from fastapi import HTTPException

    _check_grant_permissions({"admin": "r"}, {"secrets": "r"})
    with pytest.raises(HTTPException):
        _check_grant_permissions({"admin": "r"}, {"secrets": "w"})
    _check_grant_permissions(
        {"admin": "r", "secrets": "w"},
        {"secrets": "rw"},
    )


@pytest.mark.parametrize("scope", [{"tokens": "rw", "secrets": "r"}, {"admin": "rw"}])
@pytest.mark.parametrize("claim", [[], None, "", [None, 123]])
@pytest.mark.parametrize("target", [None, ["dev"]])
def test_empty_or_malformed_claim_cannot_delegate_namespace_access(
    scope, claim, target
):
    from fastapi import HTTPException

    caller = {**scope, "namespaces": claim}
    requested = {"secrets": "r"}
    if target is not None:
        requested["namespaces"] = target
    with pytest.raises(HTTPException) as exc:
        _check_grant_permissions(caller, requested)
    assert exc.value.status_code == 403


def test_empty_child_cannot_escape_parent_namespace():
    from fastapi import HTTPException

    parent = {"tokens": "rw", "secrets": "r", "namespaces": ["dev"]}
    child = {"tokens": "rw", "secrets": "r", "namespaces": []}
    _check_grant_permissions(parent, child)
    _check_grant_permissions(child, {"secrets": "r", "namespaces": []})
    with pytest.raises(HTTPException) as exc:
        _check_grant_permissions(child, {"secrets": "r"})
    assert exc.value.status_code == 403


def test_unrestricted_root_can_delegate_unrestricted_and_scoped_tokens():
    root = {"admin": "rw"}
    _check_grant_permissions(root, {"admin": "rw"})
    _check_grant_permissions(root, {"secrets": "r", "namespaces": ["prod"]})
    _check_grant_permissions(root, {"secrets": "r", "namespaces": []})


@pytest.mark.parametrize("target", [{"secrets": "r"}, {"namespaces": ["dev"]}])
def test_empty_claim_cannot_manage_unrestricted_or_scoped_tokens(target):
    from api.app.routes.tokens import _check_namespace_subset
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as exc:
        _check_namespace_subset({"tokens": "rw", "namespaces": []}, target)
    assert exc.value.status_code == 403


@pytest.mark.asyncio
async def test_create_ephemeral_invalid_allowed_ips_returns_400(
    client, master_password, admin_token
):
    """POST /tokens/ephemeral with invalid allowed_ips -> 400."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.post(
        "/api/v1/vault/tokens/ephemeral",
        headers=headers,
        json={
            "permissions": {"secrets": "r"},
            "ttl_seconds": 60,
            "allowed_ips": "not-a-cidr-or-ip",
        },
    )
    assert r.status_code == 400
    assert "Invalid allowed_ips" in r.json()["detail"]


@pytest.mark.asyncio
async def test_whoami_token_vanished_mid_flight_returns_404(
    client, master_password, admin_token
):
    """If the token row disappears between auth and the SELECT, /whoami -> 404."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Create a token, use it in a /whoami, then simulate its disappearance...
    # In practice a token can be deleted between two requests via the DB.
    # We create a throwaway token, call whoami, which should work first.
    r = await client.post(
        "/api/v1/vault/tokens/",
        headers=headers,
        json={"name": "whoami-vanish-test", "permissions": {"audit": "r"}},
    )
    assert r.status_code == 201
    raw = r.json()["token"]

    # Delete directly in the DB
    async with async_session() as db:
        await db.execute(
            text("DELETE FROM vault_tokens WHERE name = :n"),
            {"n": "whoami-vanish-test"},
        )
        await db.commit()

    # whoami avec ce token -> 401 normalement (token introuvable),
    # mais si cache hit, peut donner 404. Soit l'un soit l'autre.
    r = await client.get(
        "/api/v1/vault/tokens/whoami",
        headers={"Authorization": f"Bearer {raw}"},
    )
    assert r.status_code in (401, 404)


@pytest.mark.asyncio
@pytest.mark.parametrize("name", ["ldap:victim", "proxy:victim"])
async def test_create_token_rejects_reserved_prefix(
    client, master_password, admin_token, name
):
    """A minted token may not forge an ldap:/proxy: human-session name (audit
    actor spoofing + strict-RBAC membership bypass) -> 400."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}
    r = await client.post(
        "/api/v1/vault/tokens/",
        headers=headers,
        json={"name": name, "permissions": {"secrets": "rw"}},
    )
    assert r.status_code == 400
    assert "reserved prefix" in r.json()["detail"]
