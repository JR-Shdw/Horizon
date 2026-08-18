"""Backlog #4: decrypt-and-die mode.

POST /api/v1/vault/oneshot - unseal, read one secret, re-seal in a single
call. Used by CI runners and one-shot crons that don't need to keep the
vault unsealed.
"""

import pytest
from api.app.vault_state import vault as vs


@pytest.mark.asyncio
async def test_oneshot_returns_secret_then_re_seals(
    client, master_password, admin_token
):
    """Full happy path: vault sealed -> POST /oneshot -> secret returned ->
    vault is sealed again afterwards."""
    # Pre-create a secret while vault is unsealed
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}
    await client.post(
        "/api/v1/vault/secrets/",
        headers=headers,
        json={"name": "oneshot-target", "value": "ephemeral-value-123"},
    )
    # Seal first, oneshot expects sealed state
    await client.post("/api/v1/vault/seal", headers=headers)
    assert vs.sealed is True

    r = await client.post(
        "/api/v1/vault/oneshot",
        json={
            "password": master_password,
            "name": "oneshot-target",
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert body["value"] == "ephemeral-value-123"
    assert body["name"] == "oneshot-target"
    assert body["namespace"] == "default"

    # Vault must be sealed again after oneshot
    assert vs.sealed is True

    # Restore unsealed for downstream tests
    await client.post("/api/v1/vault/unseal", json={"password": master_password})


@pytest.mark.asyncio
async def test_oneshot_re_seals_on_secret_not_found(
    client, master_password, admin_token
):
    """If the secret doesn't exist, vault is still re-sealed (finally block)."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}
    await client.post("/api/v1/vault/seal", headers=headers)
    assert vs.sealed is True

    r = await client.post(
        "/api/v1/vault/oneshot",
        json={
            "password": master_password,
            "name": "does-not-exist",
        },
    )
    assert r.status_code == 404
    # Most importantly: vault is sealed after the failure
    assert vs.sealed is True

    await client.post("/api/v1/vault/unseal", json={"password": master_password})


@pytest.mark.asyncio
async def test_oneshot_rejects_when_already_unsealed(client, master_password):
    """Vault unsealed -> oneshot is the wrong tool, returns 409 conflict."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    assert vs.sealed is False

    r = await client.post(
        "/api/v1/vault/oneshot",
        json={"password": master_password, "name": "any"},
    )
    assert r.status_code == 409
    assert "unsealed" in r.json().get("detail", "").lower()


@pytest.mark.asyncio
async def test_oneshot_rejects_wrong_password(client, master_password, admin_token):
    """Wrong password -> 401, vault stays sealed (never unsealed in the first place)."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}
    await client.post("/api/v1/vault/seal", headers=headers)
    assert vs.sealed is True

    r = await client.post(
        "/api/v1/vault/oneshot",
        json={
            "password": "definitely-wrong-password",
            "name": "anything",
        },
    )
    assert r.status_code == 401
    assert vs.sealed is True

    await client.post("/api/v1/vault/unseal", json={"password": master_password})


@pytest.mark.asyncio
async def test_oneshot_concurrent_calls_all_succeed(
    client, master_password, admin_token
):
    """Concurrent oneshot calls must not seal the vault out from under each
    other's read/audit. Without the _oneshot_lock an interleave surfaces a
    spurious VaultSealedError 503 on the loser; with it, all return 200."""
    import asyncio

    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}
    await client.post(
        "/api/v1/vault/secrets/",
        headers=headers,
        json={"name": "oneshot-concurrent", "value": "shared-value-xyz"},
    )
    await client.post("/api/v1/vault/seal", headers=headers)
    assert vs.sealed is True

    async def _one():
        return await client.post(
            "/api/v1/vault/oneshot",
            json={"password": master_password, "name": "oneshot-concurrent"},
        )

    results = await asyncio.gather(*[_one() for _ in range(8)])
    codes = [r.status_code for r in results]
    assert all(c == 200 for c in codes), codes
    assert all(r.json()["value"] == "shared-value-xyz" for r in results)
    assert vs.sealed is True

    await client.post("/api/v1/vault/unseal", json={"password": master_password})


@pytest.mark.asyncio
async def test_oneshot_namespace_isolation(client, master_password, admin_token):
    """Reading a secret from a different namespace returns 404."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}
    await client.post(
        "/api/v1/vault/secrets/",
        headers=headers,
        json={
            "name": "ns-secret",
            "namespace": "team-a",
            "value": "team-a-only",
        },
    )
    await client.post("/api/v1/vault/seal", headers=headers)

    # Try to read it from the wrong namespace
    r = await client.post(
        "/api/v1/vault/oneshot",
        json={
            "password": master_password,
            "name": "ns-secret",
            "namespace": "team-b",
        },
    )
    assert r.status_code == 404
    assert vs.sealed is True

    await client.post("/api/v1/vault/unseal", json={"password": master_password})
