"""Per-token IP allowlist - creation, validation, enforcement.

The httpx ASGI transport reports the client as `127.0.0.1`, which lets us
distinguish:
  - allowlist matching the test IP    -> request succeeds
  - allowlist NOT matching the test IP -> request fails with 403
  - empty allowlist                    -> no restriction (default)
"""

import pytest
from api.app.ip_acl import ip_in_allowlist, normalize_allowed_ips, parse_allowed_ips

# ---------------------------------------------------------------------------
# Unit tests, pure parsing/matching, no DB
# ---------------------------------------------------------------------------


def test_parse_empty_returns_empty_list():
    assert parse_allowed_ips(None) == []
    assert parse_allowed_ips("") == []
    assert parse_allowed_ips("   ") == []


def test_parse_single_ip_treated_as_host_route():
    nets = parse_allowed_ips("10.89.1.4")
    assert len(nets) == 1
    assert str(nets[0]) == "10.89.1.4/32"


def test_parse_cidr_v4_and_v6_mixed():
    nets = parse_allowed_ips("10.0.0.0/8, 2001:db8::/32, ::1")
    rendered = sorted(str(n) for n in nets)
    assert rendered == ["10.0.0.0/8", "2001:db8::/32", "::1/128"]


def test_parse_invalid_raises_valueerror():
    with pytest.raises(ValueError):
        parse_allowed_ips("not-an-ip")
    with pytest.raises(ValueError):
        parse_allowed_ips("10.0.0.0/8, garbage")


def test_normalize_returns_none_for_empty():
    assert normalize_allowed_ips(None) is None
    assert normalize_allowed_ips("") is None
    assert normalize_allowed_ips("   ") is None


def test_normalize_canonicalizes_entries():
    # bare IP -> /32, whitespace stripped, host bits silently zeroed
    out = normalize_allowed_ips("10.89.1.4 , 10.0.0.0/8")
    assert out == "10.89.1.4/32,10.0.0.0/8"


def test_ip_in_allowlist_empty_means_unrestricted():
    assert ip_in_allowlist("1.2.3.4", None) is True
    assert ip_in_allowlist("1.2.3.4", "") is True


def test_ip_in_allowlist_match_and_miss():
    assert ip_in_allowlist("10.89.1.4", "10.89.0.0/16") is True
    assert ip_in_allowlist("10.90.1.4", "10.89.0.0/16") is False
    assert ip_in_allowlist("::1", "::1/128") is True
    assert ip_in_allowlist("2001:db8::1", "2001:db8::/32") is True


def test_ip_in_allowlist_explicit_list_of_ips():
    """A list of bare IPs (no CIDRs) - common shape for service-account ACLs."""
    allowlist = "10.0.0.1, 10.0.0.1, 127.0.0.1"
    assert ip_in_allowlist("10.0.0.1", allowlist) is True
    assert ip_in_allowlist("10.0.0.1", allowlist) is True
    assert ip_in_allowlist("127.0.0.1", allowlist) is True
    # Off-by-one: 10.0.0.1 is NOT in the list
    assert ip_in_allowlist("10.0.0.1", allowlist) is False
    # Different subnet
    assert ip_in_allowlist("10.0.0.1", allowlist) is False


def test_ip_in_allowlist_mixed_v4_v6_list():
    """IPv4 + IPv6 in the same allowlist resolve correctly per family."""
    allowlist = "10.0.0.1/24, 2001:db8::/64, ::1"
    assert ip_in_allowlist("10.0.0.1", allowlist) is True
    assert ip_in_allowlist("2001:db8::dead", allowlist) is True
    assert ip_in_allowlist("::1", allowlist) is True
    assert ip_in_allowlist("172.17.0.5", allowlist) is False
    assert ip_in_allowlist("fe80::1", allowlist) is False


def test_ip_in_allowlist_invalid_client_fails_closed():
    assert ip_in_allowlist("not-an-ip", "10.0.0.0/8") is False


def test_ip_in_allowlist_corrupt_db_fails_closed():
    # A corrupt allowlist string in the DB must not silently allow anyone.
    assert ip_in_allowlist("10.0.0.5", "garbage") is False


# ---------------------------------------------------------------------------
# Integration tests, full HTTP roundtrip
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_token_with_invalid_ip_returns_400(
    client, master_password, admin_token
):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.post(
        "/api/v1/vault/tokens/",
        json={
            "name": "ipacl-bad",
            "permissions": {"secrets": "r"},
            "allowed_ips": "not-a-cidr",
        },
        headers=headers,
    )
    assert r.status_code == 400
    assert "allowed_ips" in r.json().get("detail", "").lower()


@pytest.mark.asyncio
async def test_create_token_without_allowed_ips_works_from_any_ip(
    client, master_password, admin_token
):
    """Default behaviour - backwards-compatible."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.post(
        "/api/v1/vault/tokens/",
        json={"name": "ipacl-unrestricted", "permissions": {"secrets": "r"}},
        headers=headers,
    )
    assert r.status_code == 201
    body = r.json()
    assert body["allowed_ips"] is None

    # Use the token, must succeed.
    r2 = await client.get(
        "/api/v1/vault/secrets/",
        headers={"Authorization": f"Bearer {body['token']}"},
    )
    assert r2.status_code == 200


@pytest.mark.asyncio
async def test_token_with_matching_allowlist_accepted(
    client, master_password, admin_token
):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Test client IP is 127.0.0.1
    r = await client.post(
        "/api/v1/vault/tokens/",
        json={
            "name": "ipacl-matching",
            "permissions": {"secrets": "r"},
            "allowed_ips": "127.0.0.0/8",
        },
        headers=headers,
    )
    assert r.status_code == 201
    body = r.json()
    assert body["allowed_ips"] == "127.0.0.0/8"

    r2 = await client.get(
        "/api/v1/vault/secrets/",
        headers={"Authorization": f"Bearer {body['token']}"},
    )
    assert r2.status_code == 200


@pytest.mark.asyncio
async def test_token_with_non_matching_allowlist_rejected(
    client, master_password, admin_token
):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.post(
        "/api/v1/vault/tokens/",
        json={
            "name": "ipacl-restricted",
            "permissions": {"secrets": "r"},
            "allowed_ips": "10.0.0.0/8",
        },
        headers=headers,
    )
    assert r.status_code == 201
    raw = r.json()["token"]

    # Caller is 127.0.0.1, allowlist is 10/8 -> 403
    r2 = await client.get(
        "/api/v1/vault/secrets/",
        headers={"Authorization": f"Bearer {raw}"},
    )
    assert r2.status_code == 403
    assert "ip" in r2.json().get("detail", "").lower()


@pytest.mark.asyncio
async def test_whoami_blocked_by_ip_acl(client, master_password, admin_token):
    """An IP-blocked token cannot even introspect itself."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.post(
        "/api/v1/vault/tokens/",
        json={
            "name": "ipacl-whoami-block",
            "permissions": {"secrets": "r"},
            "allowed_ips": "10.0.0.0/8",
        },
        headers=headers,
    )
    raw = r.json()["token"]

    r2 = await client.get(
        "/api/v1/vault/tokens/whoami",
        headers={"Authorization": f"Bearer {raw}"},
    )
    assert r2.status_code == 403


@pytest.mark.asyncio
async def test_list_tokens_exposes_allowed_ips(client, master_password, admin_token):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    await client.post(
        "/api/v1/vault/tokens/",
        json={
            "name": "ipacl-listed",
            "permissions": {"secrets": "r"},
            "allowed_ips": "192.168.1.0/24",
        },
        headers=headers,
    )

    r = await client.get("/api/v1/vault/tokens/", headers=headers)
    assert r.status_code == 200
    items = r.json()["items"]
    listed = next((t for t in items if t["name"] == "ipacl-listed"), None)
    assert listed is not None
    assert listed["allowed_ips"] == "192.168.1.0/24"


@pytest.mark.asyncio
async def test_ephemeral_token_supports_allowed_ips(
    client, master_password, admin_token
):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.post(
        "/api/v1/vault/tokens/ephemeral",
        json={
            "permissions": {"secrets": "r"},
            "ttl_seconds": 300,
            "allowed_ips": "10.0.0.0/8",
        },
        headers=headers,
    )
    assert r.status_code == 201
    body = r.json()
    assert body["allowed_ips"] == "10.0.0.0/8"

    r2 = await client.get(
        "/api/v1/vault/secrets/",
        headers={"Authorization": f"Bearer {body['token']}"},
    )
    assert r2.status_code == 403


@pytest.mark.asyncio
async def test_token_with_explicit_ip_list_match_and_miss(
    client, master_password, admin_token
):
    """Auth with a bare-IP list - caller must be in the list (not just same subnet)."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Allow 127.0.0.1 (the test client) but two other unrelated hosts too.
    r = await client.post(
        "/api/v1/vault/tokens/",
        json={
            "name": "ipacl-list-match",
            "permissions": {"secrets": "r"},
            "allowed_ips": "127.0.0.1, 10.0.0.1, 10.0.0.1",
        },
        headers=headers,
    )
    assert r.status_code == 201
    raw = r.json()["token"]
    # All three IPs canonicalized as /32
    assert r.json()["allowed_ips"] == "127.0.0.1/32,10.0.0.1/32,10.0.0.1/32"

    # Test client (127.0.0.1) is in the list -> 200
    r2 = await client.get(
        "/api/v1/vault/secrets/",
        headers={"Authorization": f"Bearer {raw}"},
    )
    assert r2.status_code == 200

    # Now create one whose list excludes 127.0.0.1 -> 403
    r = await client.post(
        "/api/v1/vault/tokens/",
        json={
            "name": "ipacl-list-miss",
            "permissions": {"secrets": "r"},
            "allowed_ips": "10.0.0.1, 10.0.0.1, 10.0.0.1",
        },
        headers=headers,
    )
    raw_miss = r.json()["token"]
    r3 = await client.get(
        "/api/v1/vault/secrets/",
        headers={"Authorization": f"Bearer {raw_miss}"},
    )
    assert r3.status_code == 403


def test_openapi_schema_documents_allowed_ips():
    """The Pydantic Field description is wired into the OpenAPI schema -
    operators reading the generated reference (or any tooling that
    introspects the schema) see what the field is for."""
    from api.app.main import app

    schema = app.openapi()
    # TokenCreate
    tok = schema["components"]["schemas"]["TokenCreate"]["properties"]["allowed_ips"]
    assert "comma-separated" in (tok.get("description") or "").lower()
    assert "ipv4" in (tok.get("description") or "").lower()
    # EphemeralTokenCreate
    eph = schema["components"]["schemas"]["EphemeralTokenCreate"]["properties"][
        "allowed_ips"
    ]
    assert "comma-separated" in (eph.get("description") or "").lower()


@pytest.mark.asyncio
async def test_create_token_normalizes_allowlist(client, master_password, admin_token):
    """Bare IPs are stored as /32, whitespace is stripped."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}

    r = await client.post(
        "/api/v1/vault/tokens/",
        json={
            "name": "ipacl-normalized",
            "permissions": {"secrets": "r"},
            "allowed_ips": " 10.89.1.4 , 10.0.0.0/8 ",
        },
        headers=headers,
    )
    assert r.status_code == 201
    assert r.json()["allowed_ips"] == "10.89.1.4/32,10.0.0.0/8"
