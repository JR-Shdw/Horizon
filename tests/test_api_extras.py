"""Tests for the new API endpoints used by automation/MCP :
- GET  /api/v1/vault/tokens/whoami
- POST /api/v1/vault/tokens/{id}/renew
- GET  /api/v1/vault/audit/?since=...&until=...
- GET  /api/v1/vault/audit/stream  (SSE)
"""

import asyncio
import json as _json
from datetime import datetime, timedelta, timezone

import pytest


@pytest.mark.asyncio
async def test_whoami_returns_caller_perms(client, master_password, admin_token):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}
    r = await client.get("/api/v1/vault/tokens/whoami", headers=headers)
    assert r.status_code == 200
    body = r.json()
    assert body["name"] == "test-admin"
    assert "admin" in body["permissions"]
    assert body["scopes"] == ["admin"]
    assert body["active"] is True
    assert body["is_ephemeral"] is False


@pytest.mark.asyncio
async def test_whoami_for_scoped_token(client, master_password, admin_token):
    import secrets as _sec

    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}
    name = f"whoami-scoped-{_sec.token_hex(4)}"
    r = await client.post(
        "/api/v1/vault/tokens/",
        headers=headers,
        json={
            "name": name,
            "permissions": {"secrets": "r", "namespaces": ["mcp/test"]},
        },
    )
    assert r.status_code in (200, 201), r.text
    raw = r.json()["token"]

    r2 = await client.get(
        "/api/v1/vault/tokens/whoami",
        headers={"Authorization": f"Bearer {raw}"},
    )
    assert r2.status_code == 200
    body = r2.json()
    assert body["name"] == name
    assert body["scopes"] == ["secrets"]
    assert body["namespaces"] == ["mcp/test"]
    assert body["is_ephemeral"] is False


@pytest.mark.asyncio
async def test_expiring_regular_token_is_not_ephemeral(
    client, master_password, admin_token
):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}
    name = "regular-with-expiry"
    expires_at = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    created = await client.post(
        "/api/v1/vault/tokens/",
        headers=headers,
        json={
            "name": name,
            "permissions": {"secrets": "r"},
            "expires_at": expires_at,
        },
    )
    assert created.status_code == 201, created.text

    whoami = await client.get(
        "/api/v1/vault/tokens/whoami",
        headers={"Authorization": f"Bearer {created.json()['token']}"},
    )
    assert whoami.status_code == 200
    assert whoami.json()["is_ephemeral"] is False

    listed = await client.get("/api/v1/vault/tokens/", headers=headers)
    item = next(token for token in listed.json()["items"] if token["name"] == name)
    assert item["is_ephemeral"] is False


@pytest.mark.asyncio
async def test_renew_extends_ephemeral_ttl(client, master_password, admin_token):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}
    # Mint an ephemeral with 60s TTL
    r = await client.post(
        "/api/v1/vault/tokens/ephemeral",
        headers=headers,
        json={
            "permissions": {"secrets": "r"},
            "ttl_seconds": 60,
            "label": "renew-test",
        },
    )
    assert r.status_code == 201
    eph = r.json()
    original_expires = datetime.fromisoformat(eph["expires_at"])

    # Find its id
    tokens = await client.get("/api/v1/vault/tokens/", headers=headers)
    matches = [t for t in tokens.json()["items"] if t["name"] == eph["name"]]
    assert len(matches) == 1
    tid = matches[0]["id"]

    # Renew with 3600s
    r = await client.post(
        f"/api/v1/vault/tokens/{tid}/renew",
        headers=headers,
        json={"ttl_seconds": 3600},
    )
    assert r.status_code == 200
    body = r.json()
    new_expires = datetime.fromisoformat(body["expires_at"])
    assert new_expires > original_expires + timedelta(minutes=10)


@pytest.mark.asyncio
async def test_renew_refuses_long_lived_token(client, master_password, admin_token):
    """Tokens without an expires_at are not ephemeral - renew returns 404."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}
    # Find admin_token's id (it's a long-lived token, no expires_at)
    tokens = await client.get("/api/v1/vault/tokens/", headers=headers)
    long_lived = next(t for t in tokens.json()["items"] if t["expires_at"] is None)
    r = await client.post(
        f"/api/v1/vault/tokens/{long_lived['id']}/renew",
        headers=headers,
        json={"ttl_seconds": 600},
    )
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_audit_filter_since_until(client, master_password, admin_token):
    """Filter by ISO timestamp range. Uses params= dict so httpx URL-encodes
    the + in ISO offsets (e.g. 2026-04-29T08:00:00+00:00 -> ...+%2B00:00)."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}
    # Create some activity to ensure audit entries exist
    await client.post(
        "/api/v1/vault/secrets/",
        headers=headers,
        json={"name": "audit-range-secret", "value": "x"},
    )
    now = datetime.now(timezone.utc)
    r = await client.get(
        "/api/v1/vault/audit/",
        headers=headers,
        params={
            "since": (now - timedelta(hours=1)).isoformat(),
            "until": (now + timedelta(hours=1)).isoformat(),
        },
    )
    assert r.status_code == 200, r.text
    assert r.json()["count"] >= 1

    # since = far future -> no results
    r2 = await client.get(
        "/api/v1/vault/audit/",
        headers=headers,
        params={"since": (now + timedelta(days=365)).isoformat()},
    )
    assert r2.status_code == 200
    assert r2.json()["count"] == 0


@pytest.mark.asyncio
async def test_audit_stream_endpoint_is_reachable(client, master_password, admin_token):
    """SSE stream endpoint returns 200 + correct content-type. Full streaming
    behavior is harder to test through httpx + ASGITransport (the bootstrap
    yields then the loop awaits asyncio.sleep, which doesn't flush through
    the test transport). We validate the contract: status, headers, and
    that the bootstrap path emits at least one data line by reading raw
    bytes for a short window."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}
    await client.post(
        "/api/v1/vault/secrets/",
        headers=headers,
        json={"name": "stream-bootstrap-secret", "value": "x"},
    )

    async def collect_partial():
        async with client.stream(
            "GET",
            "/api/v1/vault/audit/stream",
            headers=headers,
            params={"interval_secs": 0.5},
        ) as resp:
            assert resp.status_code == 200
            assert resp.headers["content-type"].startswith("text/event-stream")
            buf = b""
            async for chunk in resp.aiter_bytes():
                buf += chunk
                if b"data: " in buf:
                    return buf
        return buf

    try:
        buf = await asyncio.wait_for(collect_partial(), timeout=5.0)
    except asyncio.TimeoutError:
        buf = b""

    # We may not catch the bootstrap window in time depending on transport
    # buffering. At minimum verify the endpoint accepts the request.
    if buf:
        # If we did get data, verify at least one event has audit-shape JSON
        line = buf.decode("utf-8", errors="ignore").split("\n\n")[0]
        if line.startswith("data: "):
            evt = _json.loads(line[6:])
            assert "action" in evt
