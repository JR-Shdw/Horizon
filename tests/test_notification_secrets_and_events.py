"""Channel credentials are encrypted at rest, and offered events really fire."""

import asyncio
import json
import re
from pathlib import Path
from unittest.mock import PropertyMock, patch

import pytest
from api.app import audit
from api.app.database import async_session
from api.app.routes import notifications as mod
from api.app.vault_state import vault
from prometheus_client import REGISTRY
from sqlalchemy import text

from .test_audit_s7_seed_rewrap import _admin_token_under_current, _teardown

BASE = "/api/v1/vault/notifications/"
MATRIX = {"homeserver": "https://m.example", "room_id": "!r", "token": "SECRETTOKEN"}
EMAIL = {"smtp_host": "smtp.example", "smtp_password": "SECRETPASS", "to": ["a@b.c"]}
HOOK = {
    "url": "https://h.example/SECRETPATH",
    "headers": {"Authorization": "Bearer SECRETHEADER"},
}


async def wipe():
    async with async_session() as db:
        result = await db.execute(
            text("DELETE FROM vault_notification_channels RETURNING dek_id")
        )
        for row in result.fetchall():
            await mod._delete_dek(db, row.dek_id)
        await db.commit()


@pytest.fixture
async def session(client, master_password, admin_token):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    await wipe()
    yield {"Authorization": f"Bearer {admin_token}"}
    await drain()
    await wipe()


@pytest.fixture
def sent(monkeypatch):
    calls = []

    async def send(channel_type, config, event, message):
        calls.append((channel_type, config, event, message))

    monkeypatch.setattr(mod, "_send_notification", send)
    return calls


async def drain():
    while audit._notification_tasks:
        await asyncio.gather(*audit._notification_tasks, return_exceptions=True)


async def create(client, headers, name, kind, config, events=()):
    response = await client.post(
        BASE,
        json={
            "name": name,
            "channel_type": kind,
            "config": config,
            "events": list(events),
        },
        headers=headers,
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]


async def raw(name):
    async with async_session() as db:
        result = await db.execute(
            text(
                "SELECT config::text AS config, secrets_ct, dek_id "
                "FROM vault_notification_channels WHERE name = :n"
            ),
            {"n": name},
        )
        return result.fetchone()


async def dek_exists(dek_id):
    async with async_session() as db:
        result = await db.execute(
            text("SELECT 1 FROM vault_dek WHERE id = CAST(:i AS uuid)"),
            {"i": str(dek_id)},
        )
        return result.fetchone() is not None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "kind, config", [("matrix", MATRIX), ("email", EMAIL), ("webhook", HOOK)]
)
async def test_credentials_are_absent_from_storage_and_listing(
    session, client, sent, kind, config
):
    channel = await create(client, session, "c", kind, config)
    row = await raw("c")
    assert "SECRET" not in row.config
    assert b"SECRET" not in bytes(row.secrets_ct)

    listed = (await client.get(BASE, headers=session)).json()["items"][0]
    assert "SECRET" not in json.dumps(listed)
    assert listed["has_secrets"] is True

    response = await client.post(f"{BASE}{channel}/test", headers=session)
    assert response.status_code == 200
    assert sent[0][1] == config


@pytest.mark.asyncio
async def test_plaintext_channel_is_encrypted_by_the_next_dispatch(session, sent):
    async with async_session() as db:
        await db.execute(
            text(
                "INSERT INTO vault_notification_channels "
                "(name, channel_type, config) VALUES "
                "('old', 'matrix', CAST(:c AS jsonb))"
            ),
            {"c": json.dumps(MATRIX)},
        )
        await db.commit()

    async with async_session() as db:
        await mod.dispatch_event(db, "honey_access", "alert")

    assert "SECRET" not in (await raw("old")).config
    assert sent[0][1] == MATRIX


@pytest.mark.asyncio
async def test_listing_masks_a_channel_not_yet_encrypted(session, client):
    async with async_session() as db:
        await db.execute(
            text(
                "INSERT INTO vault_notification_channels "
                "(name, channel_type, config) VALUES "
                "('old', 'email', CAST(:c AS jsonb))"
            ),
            {"c": json.dumps(EMAIL)},
        )
        await db.commit()
    listed = (await client.get(BASE, headers=session)).json()["items"][0]
    assert listed["config"]["smtp_password"] == "********"


@pytest.mark.asyncio
async def test_credentials_survive_dek_key_rotation(
    session, client, sent, master_password
):
    channel = await create(client, session, "c", "matrix", MATRIX)
    try:
        token = await _admin_token_under_current()
        headers = {"Authorization": f"Bearer {token}"}
        rotated = await client.post(
            "/api/v1/vault/admin/rotate-dek-key",
            json={"current_password": master_password},
            headers=headers,
        )
        assert rotated.status_code == 200, rotated.text
        response = await client.post(f"{BASE}{channel}/test", headers=headers)
        assert response.status_code == 200, response.text
        assert sent[0][1] == MATRIX
    finally:
        await _teardown(client, master_password, master_password)


@pytest.mark.asyncio
async def test_ciphertext_is_bound_to_its_channel(session, client):
    first = await create(client, session, "a", "matrix", MATRIX)
    second = await create(client, session, "b", "matrix", MATRIX)
    async with async_session() as db:
        await db.execute(
            text(
                "UPDATE vault_notification_channels AS t "
                "SET secrets_ct = s.secrets_ct, secrets_nonce = s.secrets_nonce, "
                "dek_id = s.dek_id FROM vault_notification_channels AS s "
                "WHERE t.id = CAST(:t AS uuid) AND s.id = CAST(:s AS uuid)"
            ),
            {"t": second, "s": first},
        )
        await db.commit()
    response = await client.post(f"{BASE}{second}/test", headers=session)
    assert response.status_code == 502
    assert "reconfigure this channel" in response.json()["detail"]
    async with async_session() as db:
        await db.execute(
            text(
                "UPDATE vault_notification_channels SET dek_id = NULL, "
                "secrets_ct = NULL, secrets_nonce = NULL "
                "WHERE id = CAST(:t AS uuid)"
            ),
            {"t": second},
        )
        await db.commit()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "change", [{"room_id": "!new"}, {"room_id": "!new", "token": "********"}]
)
async def test_update_keeps_a_secret_left_out_or_masked(session, client, sent, change):
    channel = await create(client, session, "c", "matrix", MATRIX)
    old_dek = (await raw("c")).dek_id
    response = await client.put(
        f"{BASE}{channel}",
        json={"config": {"homeserver": MATRIX["homeserver"], **change}},
        headers=session,
    )
    assert response.status_code == 200, response.text
    await client.post(f"{BASE}{channel}/test", headers=session)
    assert sent[0][1]["token"] == "SECRETTOKEN"
    assert sent[0][1]["room_id"] == "!new"
    assert not await dek_exists(old_dek)


@pytest.mark.asyncio
async def test_update_can_replace_and_remove_a_secret(session, client, sent):
    channel = await create(client, session, "c", "email", EMAIL)
    await client.put(
        f"{BASE}{channel}",
        json={"config": {"smtp_password": "NEW"}},
        headers=session,
    )
    await client.post(f"{BASE}{channel}/test", headers=session)
    assert sent[-1][1]["smtp_password"] == "NEW"

    await client.put(
        f"{BASE}{channel}", json={"config": {"smtp_password": None}}, headers=session
    )
    assert (await raw("c")).secrets_ct is None


@pytest.mark.asyncio
async def test_delete_removes_the_channel_key(session, client):
    channel = await create(client, session, "c", "matrix", MATRIX)
    dek_id = (await raw("c")).dek_id
    await client.delete(f"{BASE}{channel}", headers=session)
    assert not await dek_exists(dek_id)


@pytest.mark.asyncio
async def test_sealed_vault_delivers_only_to_secret_free_channels(
    session, client, sent, caplog
):
    await create(client, session, "locked", "matrix", MATRIX)
    await create(client, session, "open", "email", {"smtp_host": "s", "to": ["a@b.c"]})
    with patch.object(type(vault), "sealed", PropertyMock(return_value=True)):
        async with async_session() as db:
            await mod.dispatch_event(db, "critical", "alert")
    assert [call[0] for call in sent] == ["email"]
    assert "channel=locked event=critical: vault is sealed" in caplog.text
    state = (await client.get(BASE, headers=session)).json()["items"]
    assert all(item["status"] != "failing" for item in state)


@pytest.mark.asyncio
async def test_sealed_vault_with_only_encrypted_channels_counts_the_loss(
    session, client, sent, caplog
):
    await create(client, session, "locked", "matrix", MATRIX)
    labels = {"event": "critical"}
    metric = "rhorizon_notification_undelivered_total"
    before = REGISTRY.get_sample_value(metric, labels) or 0
    with patch.object(type(vault), "sealed", PropertyMock(return_value=True)):
        async with async_session() as db:
            await mod.dispatch_event(db, "critical", "alert")
    assert sent == []
    assert REGISTRY.get_sample_value(metric, labels) == before + 1
    assert "Alert not delivered: event=critical" in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize("event", ["critical", "chain_broken"])
async def test_urgent_events_ignore_the_subscription_list(session, client, sent, event):
    await create(client, session, "c", "matrix", MATRIX, events=["token_created"])
    async with async_session() as db:
        await mod.dispatch_event(db, event, "alert")
    assert [call[2] for call in sent] == [event]


@pytest.mark.asyncio
async def test_audited_action_reaches_a_subscribed_channel(session, client, sent):
    await create(client, session, "c", "matrix", MATRIX, events=["secret_created"])
    response = await client.post(
        "/api/v1/vault/secrets/",
        json={"name": "notify-probe", "value": "v"},
        headers=session,
    )
    assert response.status_code in (200, 201), response.text
    await drain()
    assert [call[2] for call in sent] == ["secret_created"]
    assert "action=create_secret" in sent[0][3]
    assert "target=notify-probe" in sent[0][3]
    await client.delete("/api/v1/vault/secrets/notify-probe", headers=session)
    await drain()


@pytest.mark.asyncio
async def test_seal_alert_leaves_before_the_keys_go(
    session, client, monkeypatch, master_password
):
    await create(client, session, "c", "matrix", MATRIX, events=["seal"])
    sealed_at_send = []

    async def send(_channel_type, _config, event, _message):
        sealed_at_send.append((event, vault.sealed))

    monkeypatch.setattr(mod, "_send_notification", send)
    response = await client.post("/api/v1/vault/seal", headers=session)
    assert response.status_code == 200
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    assert ("seal", False) in sealed_at_send


@pytest.mark.asyncio
async def test_slow_channel_does_not_hold_up_the_seal(
    session, client, monkeypatch, master_password
):
    await create(client, session, "c", "matrix", MATRIX, events=["seal"])
    release = asyncio.Event()

    async def hang(*_args):
        await release.wait()

    monkeypatch.setattr(mod, "_send_notification", hang)
    monkeypatch.setattr("api.app.routes.vault._SEAL_ALERT_WAIT_SECONDS", 0.05)
    response = await asyncio.wait_for(
        client.post("/api/v1/vault/seal", headers=session), timeout=5
    )
    assert response.status_code == 200
    release.set()
    await drain()
    await client.post("/api/v1/vault/unseal", json={"password": master_password})


@pytest.mark.asyncio
async def test_full_queue_drops_and_counts(monkeypatch, caplog):
    monkeypatch.setattr(audit, "_MAX_PENDING_NOTIFICATIONS", 0)
    labels = {"event": "secret_created"}
    metric = "rhorizon_notification_undelivered_total"
    before = REGISTRY.get_sample_value(metric, labels) or 0
    assert audit.notify_event("secret_created", "m") is None
    assert REGISTRY.get_sample_value(metric, labels) == before + 1
    assert "queue full: event=secret_created" in caplog.text


def test_every_offered_event_has_a_source():
    """The UI must not offer a subscription that nothing ever sends."""
    root = Path(__file__).parent.parent
    pulsar = (root / "frontend/js/views/pulsar.js").read_text()
    offered = set(re.findall(r"\{ name: '([a-z0-9_]+)'", pulsar))
    assert "secret_created" in offered
    code = "\n".join(p.read_text() for p in (root / "api/app").rglob("*.py"))
    sources = set(audit._ACTION_EVENTS.values())
    sources |= set(re.findall(r'event="([a-z_]+)"', code))
    sources |= set(re.findall(r'notify_event\(\s*"([a-z_]+)"', code))
    sources |= set(re.findall(r'dispatch_event\([a-z_]+, "([a-z_]+)"', code))
    sources.add("notification_channel_failed")
    assert offered <= sources, offered - sources
    assert offered <= mod.EVENTS
