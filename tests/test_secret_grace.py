"""Rotation grace window for static secrets.

A non-emergency value update leaves the prior version readable via
GET /{name}?previous=true for `secret_grace_seconds`. An emergency update
suppresses it. Off by default (secret_grace_seconds = 0). Mirrors the
master-password emergency split.
"""

import pytest
from api.app.config import settings
from api.app.database import async_session
from sqlalchemy import text


async def _create(client, headers, name, value):
    r = await client.post(
        "/api/v1/vault/secrets/",
        json={"name": name, "value": value, "namespace": "default"},
        headers=headers,
    )
    assert r.status_code == 201, r.text


async def _update(client, headers, name, value, emergency=False):
    r = await client.put(
        f"/api/v1/vault/secrets/{name}",
        json={"value": value, "emergency": emergency},
        headers=headers,
    )
    assert r.status_code == 200, r.text


@pytest.fixture
async def _unsealed(client, master_password):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})


@pytest.mark.asyncio
async def test_grace_serves_prior_value(client, _unsealed, admin_token, monkeypatch):
    monkeypatch.setattr(settings, "secret_grace_seconds", 300)
    headers = {"Authorization": f"Bearer {admin_token}"}
    await _create(client, headers, "grace-a", "old-value")
    await _update(client, headers, "grace-a", "new-value")

    # Current read is the new value.
    r = await client.get("/api/v1/vault/secrets/grace-a", headers=headers)
    assert r.json()["value"] == "new-value"
    # Grace read serves the prior value, tagged with the old version number.
    r = await client.get("/api/v1/vault/secrets/grace-a?previous=true", headers=headers)
    assert r.status_code == 200, r.text
    assert r.json()["value"] == "old-value"
    assert r.json()["version"] == 1


@pytest.mark.asyncio
async def test_emergency_suppresses_grace(client, _unsealed, admin_token, monkeypatch):
    monkeypatch.setattr(settings, "secret_grace_seconds", 300)
    headers = {"Authorization": f"Bearer {admin_token}"}
    await _create(client, headers, "grace-emg", "leaked")
    await _update(client, headers, "grace-emg", "rotated", emergency=True)

    r = await client.get(
        "/api/v1/vault/secrets/grace-emg?previous=true", headers=headers
    )
    assert r.status_code == 404, r.text


@pytest.mark.asyncio
async def test_grace_disabled_by_default(client, _unsealed, admin_token):
    # settings.secret_grace_seconds defaults to 0 -> no grace pointer set.
    headers = {"Authorization": f"Bearer {admin_token}"}
    await _create(client, headers, "grace-off", "old")
    await _update(client, headers, "grace-off", "new")
    r = await client.get(
        "/api/v1/vault/secrets/grace-off?previous=true", headers=headers
    )
    assert r.status_code == 404, r.text


@pytest.mark.asyncio
async def test_grace_expires(client, _unsealed, admin_token, monkeypatch):
    monkeypatch.setattr(settings, "secret_grace_seconds", 300)
    headers = {"Authorization": f"Bearer {admin_token}"}
    await _create(client, headers, "grace-exp", "old")
    await _update(client, headers, "grace-exp", "new")
    # Force the grace window into the past.
    async with async_session() as db:
        await db.execute(
            text(
                "UPDATE vault_secret_versions v "
                "SET grace_until = NOW() - INTERVAL '1 hour' "
                "FROM vault_secrets s "
                "WHERE s.name = 'grace-exp' AND v.secret_id = s.id"
            )
        )
        await db.commit()
    r = await client.get(
        "/api/v1/vault/secrets/grace-exp?previous=true", headers=headers
    )
    assert r.status_code == 404, r.text


@pytest.mark.asyncio
async def test_second_update_moves_grace_to_newer_prior(
    client, _unsealed, admin_token, monkeypatch
):
    """Only the immediately-prior version is in grace; an older one is cleared."""
    monkeypatch.setattr(settings, "secret_grace_seconds", 300)
    headers = {"Authorization": f"Bearer {admin_token}"}
    await _create(client, headers, "grace-chain", "v1")
    await _update(client, headers, "grace-chain", "v2")
    await _update(client, headers, "grace-chain", "v3")
    r = await client.get(
        "/api/v1/vault/secrets/grace-chain?previous=true", headers=headers
    )
    assert r.status_code == 200, r.text
    # The prior value is v2, not v1.
    assert r.json()["value"] == "v2"
    assert r.json()["version"] == 2
