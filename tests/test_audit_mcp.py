# SPDX-License-Identifier: AGPL-3.0-or-later
"""MCP audit chain (vault_audit_mcp): ingest + list + verify + tamper-evidence.

Server side of the optional MCP hub gateway. The ingest endpoint derives actor +
agent_token_id from the AUTHENTICATED bearer (never the body), so an agent cannot
forge another's attribution; the chain is tamper-evident like the main audit chain.
"""

import json

import pytest
from api.app.crypto import generate_token
from api.app.database import async_session
from api.app.vault_state import vault
from sqlalchemy import text

AUDIT = "/api/v1/vault/audit"


async def _make_token(name: str, perms: dict) -> str:
    raw = generate_token()
    token_hash = await vault.hmac_sha512_hex(raw)
    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_tokens WHERE name = :n"), {"n": name})
        await db.execute(
            text(
                "INSERT INTO vault_tokens (name, token_hash, permissions, created_by) "
                "VALUES (:n, :h, CAST(:p AS jsonb), 'test')"
            ),
            {"n": name, "h": token_hash, "p": json.dumps(perms)},
        )
        await db.commit()
    return raw


async def _token_id(name: str) -> str:
    async with async_session() as db:
        row = (
            await db.execute(
                text("SELECT id FROM vault_tokens WHERE name = :n"), {"n": name}
            )
        ).fetchone()
    return str(row.id)


@pytest.mark.asyncio
async def test_mcp_audit_chain_lifecycle(client, master_password, admin_token):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_audit_mcp"))
        await db.commit()

    agent = await _make_token("mcp-agent-test", {"secrets": "r", "namespaces": ["mcp"]})
    agent_id = await _token_id("mcp-agent-test")
    ah = {"Authorization": f"Bearer {agent}"}

    # Two events emitted with the AGENT's own bearer.
    r = await client.post(
        f"{AUDIT}/mcp",
        json={
            "backend": "rhorizon",
            "tool": "vault_get_secret",
            "target": "mcp/k1",
            "decision": "allowed",
            "hub": "test-hub",
        },
        headers=ah,
    )
    assert r.status_code == 201, r.text
    r = await client.post(
        f"{AUDIT}/mcp",
        json={
            "backend": "rhorizon",
            "tool": "vault_get_secret",
            "target": "prod/root",
            "decision": "policy_denied",
            "detail": {"reason": "not whitelisted"},
        },
        headers=ah,
    )
    assert r.status_code == 201, r.text

    # Spoof attempt: body-supplied actor/agent MUST be ignored.
    r = await client.post(
        f"{AUDIT}/mcp",
        json={
            "backend": "docker",
            "tool": "ps",
            "decision": "allowed",
            "actor": "someone-else",
            "agent_token_id": "00000000-0000-0000-0000-000000000000",
        },
        headers=ah,
    )
    assert r.status_code == 201, r.text

    # Bad decision rejected.
    r = await client.post(
        f"{AUDIT}/mcp",
        json={"backend": "x", "tool": "y", "decision": "bogus"},
        headers=ah,
    )
    assert r.status_code == 400, r.text

    # List via audit:r; attribution comes from the token, never the body.
    h = {"Authorization": f"Bearer {admin_token}"}
    body = (await client.get(f"{AUDIT}/mcp", headers=h)).json()
    assert body["count"] == 3
    assert body["chain_intact"] is True
    for item in body["items"]:
        assert item["actor"] == "mcp-agent-test"
        assert item["agent_token_id"] == agent_id
        assert item["verified"] is True
    assert body["items"][1]["decision"] == "policy_denied"
    assert body["items"][1]["detail"] == {"reason": "not whitelisted"}
    # hub is a first-class, self-declared source label; absent -> null.
    assert body["items"][0]["hub"] == "test-hub"
    assert body["items"][2]["hub"] is None

    # Filter by decision (non-contiguous -> verified None but rows returned).
    denied = (await client.get(f"{AUDIT}/mcp?decision=policy_denied", headers=h)).json()
    assert denied["count"] == 1 and denied["items"][0]["tool"] == "vault_get_secret"

    # Filter by hub.
    byhub = (await client.get(f"{AUDIT}/mcp?hub=test-hub", headers=h)).json()
    assert byhub["count"] == 1 and byhub["items"][0]["hub"] == "test-hub"

    # Full-chain verify.
    v = (await client.get(f"{AUDIT}/mcp/verify", headers=h)).json()
    assert v["chain_intact"] is True and v["total_entries"] == 3

    # Tamper the SIGNED hub value -> chain breaks (proves hub is in the payload).
    async with async_session() as db:
        await db.execute(
            text(
                "UPDATE vault_audit_mcp SET hub = 'evil-hub' "
                "WHERE decision = 'allowed' AND hub = 'test-hub'"
            )
        )
        await db.commit()
    v = (await client.get(f"{AUDIT}/mcp/verify", headers=h)).json()
    assert v["chain_intact"] is False
    assert v["broken_at"] is not None


@pytest.mark.asyncio
async def test_mcp_audit_ingest_requires_token(client, master_password):
    """No bearer -> rejected; the ingest endpoint is not anonymous."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    r = await client.post(
        f"{AUDIT}/mcp", json={"backend": "x", "tool": "y", "decision": "allowed"}
    )
    assert r.status_code in (401, 403, 422)
