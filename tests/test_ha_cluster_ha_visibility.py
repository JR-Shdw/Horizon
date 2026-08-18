# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""GET /cluster/ha + GET /cluster/ha/self visibility.

Coverage :
- /cluster/init inserts a vault_cluster_nodes row for the primary
  row carries ha_state='primary',
  non-empty cert_fingerprint, last_heartbeat seeded NOW().
- /cluster/ha 409 when cluster_id absent.
- /cluster/ha 403 with a non-admin token.
- /cluster/ha 200 lists primary + joining + filters evicted out.
- /cluster/ha exposes ha_loaded and uuid_ip_conflicts_total counter.
- /cluster/ha/self requires a bearer token (401 without one).
- /cluster/ha/self resolves node_uuid server-side and returns the
  matching row.
- /cluster/ha/self returns ha_state=None when the local node has no
  membership row yet (pre-JOIN polling shape).
"""

import json

import pytest
import pytest_asyncio
from api.app import ha_password as hp
from api.app import metrics as _m
from api.app import node_uuid as nu
from api.app.config import settings
from api.app.crypto import generate_token
from api.app.database import async_session
from api.app.vault_state import vault
from sqlalchemy import text

_CLUSTER_CONFIG_KEYS = (
    "cluster_id",
    "ha_password_encrypted",
    "cluster_ca_cert",
    "cluster_ca_key",
    "primary_uuid",
    "primary_since",
)


@pytest_asyncio.fixture(autouse=True)
async def _wipe_cluster_state():
    """Reset cluster state before/after each test in this module.

    The lifespan-time ``init_node_uuid`` does not fire under
    ASGITransport, so we initialise it here -- /cluster/init reads
    ``get_node_uuid()`` for the primary row.
    """
    nu.init_node_uuid(settings.node_uuid_path)
    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_cluster_nodes"))
        await db.execute(
            text("DELETE FROM vault_cluster_config WHERE key = ANY(:ks)"),
            {"ks": list(_CLUSTER_CONFIG_KEYS)},
        )
        await db.commit()
    hp.clear()
    yield
    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_cluster_nodes"))
        await db.execute(
            text("DELETE FROM vault_cluster_config WHERE key = ANY(:ks)"),
            {"ks": list(_CLUSTER_CONFIG_KEYS)},
        )
        await db.commit()
    hp.clear()


async def _make_token(name: str, perms: dict) -> str:
    """Create a vault token with arbitrary permissions for auth tests."""
    raw = generate_token()
    token_hash = await vault.hmac_sha512_hex(raw)
    async with async_session() as db:
        await db.execute(
            text(
                "INSERT INTO vault_tokens (name, token_hash, permissions, "
                "created_by) VALUES (:n, :h, CAST(:p AS jsonb), 'test') "
                "ON CONFLICT (name) WHERE active DO UPDATE SET token_hash = :h, "
                "permissions = CAST(:p AS jsonb)"
            ),
            {"n": name, "h": token_hash, "p": json.dumps(perms)},
        )
        await db.commit()
    return raw


async def _init_cluster(client, admin_token):
    r = await client.post(
        "/api/v1/vault/cluster/init",
        json={"cluster_name": "slice8-test"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 200, r.text
    return r.json()


# --- primary row at /cluster/init --------------------


@pytest.mark.asyncio
async def test_init_inserts_primary_membership_row(admin_token, client):
    payload = await _init_cluster(client, admin_token)
    async with async_session() as db:
        row = (
            await db.execute(
                text(
                    "SELECT node_uuid, ha_state, cert_fingerprint, "
                    "       last_heartbeat, quarantine_until "
                    "FROM vault_cluster_nodes WHERE node_uuid = :u"
                ),
                {"u": payload["primary_uuid"]},
            )
        ).fetchone()
    assert row is not None
    assert row.ha_state == "primary"
    assert row.cert_fingerprint
    assert len(row.cert_fingerprint) == 64  # sha256 hex
    assert row.last_heartbeat is not None
    assert row.quarantine_until is None


@pytest.mark.asyncio
async def test_init_uses_configured_advertised_ip(admin_token, client, monkeypatch):
    monkeypatch.setattr(settings, "cluster_advertise_ip", "10.0.0.1")
    payload = await _init_cluster(client, admin_token)
    async with async_session() as db:
        source_ip = await db.scalar(
            text(
                "SELECT host(source_ip) FROM vault_cluster_nodes WHERE node_uuid = :u"
            ),
            {"u": payload["primary_uuid"]},
        )
    assert source_ip == "10.0.0.1"


# --- /cluster/ha auth + state gating -------------------------------------


@pytest.mark.asyncio
async def test_cluster_ha_returns_409_when_not_initialised(admin_token, client):
    r = await client.get(
        "/api/v1/vault/cluster/ha",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 409
    assert "not initialised" in r.json()["detail"]


@pytest.mark.asyncio
async def test_cluster_ha_requires_admin_scope(admin_token, client):
    await _init_cluster(client, admin_token)
    secrets_only = await _make_token("slice8-secrets-r", {"secrets": "r"})
    r = await client.get(
        "/api/v1/vault/cluster/ha",
        headers={"Authorization": f"Bearer {secrets_only}"},
    )
    assert r.status_code == 403


# --- /cluster/ha body shape ----------------------------------------------


@pytest.mark.asyncio
async def test_cluster_ha_lists_primary_and_joining_filters_evicted(
    admin_token, client
):
    init_payload = await _init_cluster(client, admin_token)
    primary_uuid = init_payload["primary_uuid"]

    # Inject one joining node + one evicted node by hand. The evicted
    # row must not surface ; the joining row must, with ha_state and
    # quarantine_until populated.
    async with async_session() as db:
        await db.execute(
            text(
                "INSERT INTO vault_cluster_nodes ("
                "    node_uuid, source_ip, ha_state, quarantine_until,"
                "    cluster_version, cert_fingerprint, cert_not_after,"
                "    last_heartbeat"
                ") VALUES ("
                "    'joiner-uuid-aaaa', CAST('10.0.0.1' AS INET), 'joining',"
                "    NOW() + INTERVAL '15 seconds',"
                "    '1.0.0-beta', 'fpr-joiner', NOW() + INTERVAL '30 days',"
                "    NOW() - INTERVAL '1 second'"
                ")"
            )
        )
        await db.execute(
            text(
                "INSERT INTO vault_cluster_nodes ("
                "    node_uuid, source_ip, ha_state, quarantine_until,"
                "    cluster_version, cert_fingerprint, cert_not_after,"
                "    last_heartbeat"
                ") VALUES ("
                "    'evicted-uuid-bbbb', CAST('10.0.0.1' AS INET), 'evicted',"
                "    NULL, '1.0.0-beta', 'fpr-evicted',"
                "    NOW() + INTERVAL '30 days', NULL"
                ")"
            )
        )
        await db.commit()

    r = await client.get(
        "/api/v1/vault/cluster/ha",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["cluster_id"] == init_payload["cluster_id"]
    assert body["primary_uuid"] == primary_uuid
    assert body["cluster_version"] == settings.version
    uuids = {n["node_uuid"] for n in body["nodes"]}
    assert primary_uuid in uuids
    assert "joiner-uuid-aaaa" in uuids
    assert "evicted-uuid-bbbb" not in uuids

    joining = next(n for n in body["nodes"] if n["node_uuid"] == "joiner-uuid-aaaa")
    assert joining["ha_state"] == "joining"
    assert joining["quarantine_until"] is not None
    assert joining["last_heartbeat"] is not None
    assert joining["source_ip"] == "10.0.0.1"


@pytest.mark.asyncio
async def test_cluster_ha_exposes_ha_loaded_and_conflicts_counter(admin_token, client):
    await _init_cluster(client, admin_token)
    # ha_password is loaded in RAM right after /cluster/init
    # (set_ha_password updates the singleton on the master worker).
    assert hp.is_loaded()

    before = int(_m.cluster_uuid_ip_conflicts._value.get())
    _m.cluster_uuid_ip_conflicts.inc()
    _m.cluster_uuid_ip_conflicts.inc()

    r = await client.get(
        "/api/v1/vault/cluster/ha",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["ha_loaded"] is True
    assert body["uuid_ip_conflicts_total"] == before + 2


# --- /cluster/ha/self -----------------------------------------------------


@pytest.mark.asyncio
async def test_cluster_ha_self_requires_bearer(client):
    r = await client.get("/api/v1/vault/cluster/ha/self")
    # FastAPI surfaces a missing Authorization header as 422 (Header(...)
    # is a required dependency) ; either 401 or 422 means "no token, no
    # row" which is what the endpoint guarantees.
    assert r.status_code in (401, 422)


@pytest.mark.asyncio
async def test_cluster_ha_self_returns_null_state_before_join(admin_token, client):
    # No /cluster/init yet -- the local node has no membership row.
    # Any valid bearer token (including admin) must see ha_state=None.
    r = await client.get(
        "/api/v1/vault/cluster/ha/self",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["node_uuid"] == nu.get_node_uuid()
    assert body["ha_state"] is None
    assert body["quarantine_until"] is None
    assert body["last_heartbeat"] is None


@pytest.mark.asyncio
async def test_cluster_ha_self_returns_local_node_after_init(admin_token, client):
    payload = await _init_cluster(client, admin_token)
    # Token with minimal scope -- /cluster/ha/self accepts any vault
    # bearer ; the row is resolved server-side from get_node_uuid().
    minimal = await _make_token("slice8-minimal", {"secrets": "r"})
    r = await client.get(
        "/api/v1/vault/cluster/ha/self",
        headers={"Authorization": f"Bearer {minimal}"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["node_uuid"] == payload["primary_uuid"]
    assert body["ha_state"] == "primary"
    assert body["ha_loaded"] is True


# --- /cluster/ha/membership/<uuid> ----------------------------------------


@pytest.mark.asyncio
async def test_membership_returns_minimal_payload_for_known_uuid(admin_token, client):
    """The joiner-side 409 discriminator hits this route
    with no auth and expects {node_uuid, ha_state, cert_fingerprint,
    cert_not_after}. The primary row inserted by /cluster/init is the
    most stable target -- its fingerprint is the cluster CA-signed cert
    of the primary itself.
    """
    payload = await _init_cluster(client, admin_token)
    primary_uuid = payload["primary_uuid"]
    r = await client.get(f"/api/v1/vault/cluster/ha/membership/{primary_uuid}")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["node_uuid"] == primary_uuid
    assert body["ha_state"] == "primary"
    assert len(body["cert_fingerprint"]) == 64  # sha256 hex
    assert body["cert_not_after"]
    # Confidentiality surface : the leaky fields must NOT appear.
    assert "source_ip" not in body
    assert "last_heartbeat" not in body
    assert "joined_at" not in body
    assert "cluster_version" not in body
    assert "primary_uuid" not in body


@pytest.mark.asyncio
async def test_membership_404_on_unknown_uuid(admin_token, client):
    await _init_cluster(client, admin_token)
    r = await client.get(
        "/api/v1/vault/cluster/ha/membership/00000000-0000-0000-0000-000000000000"
    )
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_membership_hides_evicted_as_404(admin_token, client):
    """The revoked list stays private ; the membership lookup
    must surface 404 for an evicted row so a probe cannot map a uuid
    to its 'evicted' state without auth.
    """
    await _init_cluster(client, admin_token)
    async with async_session() as db:
        await db.execute(
            text(
                "INSERT INTO vault_cluster_nodes ("
                "    node_uuid, source_ip, ha_state, quarantine_until,"
                "    cluster_version, cert_fingerprint, cert_not_after,"
                "    last_heartbeat"
                ") VALUES ("
                "    'evicted-bugC-cccc', CAST('10.0.0.1' AS INET),"
                "    'evicted', NULL, '1.0.0-beta',"
                "    'fpr-evicted-bugC', NOW() + INTERVAL '30 days', NULL"
                ")"
            )
        )
        await db.commit()
    r = await client.get("/api/v1/vault/cluster/ha/membership/evicted-bugC-cccc")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_membership_503_when_sealed(admin_token, client, monkeypatch):
    """Sealed clusters must not leak even the minimal membership shape.
    The 503 also gates the diagnostic value -- a sealed cluster cannot
    serve JOINs, so the 409 -> membership discriminator never runs
    against one in practice.
    """
    payload = await _init_cluster(client, admin_token)
    monkeypatch.setattr(type(vault), "sealed", property(lambda _self: True))
    r = await client.get(
        f"/api/v1/vault/cluster/ha/membership/{payload['primary_uuid']}"
    )
    assert r.status_code == 503
    assert r.headers.get("retry-after") == "5"
