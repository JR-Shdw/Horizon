# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""POST /cluster/init + POST /cluster/repair.

Coverage:
- happy path init writes cluster_id, ha_password_encrypted,
  cluster_ca_cert, cluster_ca_key, primary_uuid, primary_since
- response carries ha_password (base64), ca_fingerprint, primary_uuid
- second init returns 409 cluster_already_initialised, leaves state intact
- 403 without admin scope
- ha_password length == 32 bytes (b64-decoded)
- ca_fingerprint matches sha256 of the persisted cert DER
- audit row cluster_init written ; plaintext ha_password not leaked in detail
- rollback : if cluster_ca.mint_cluster_ca raises, no row is persisted and the
  ha_password RAM cache is cleared
- /cluster/repair restores ha_password + CA + primary_* when missing
- /cluster/repair returns 409 when cluster_id absent
"""

import base64
import json
from hashlib import sha256
from unittest.mock import patch

import pytest
import pytest_asyncio
from api.app import cluster_ca
from api.app import ha_password as hp
from api.app import node_uuid as nu
from api.app.config import settings
from api.app.database import async_session
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import text

_CLUSTER_KEYS = (
    "cluster_id",
    "ha_password_encrypted",
    "cluster_ca_cert",
    "cluster_ca_key",
    "primary_uuid",
    "primary_since",
)


@pytest_asyncio.fixture(autouse=True)
async def _wipe_cluster_config():
    """Each test starts from an uninitialised cluster state.

    The lifespan-time `init_node_uuid()` does not fire under ASGITransport,
    so we initialise it here -- /cluster/init reads `get_node_uuid()` for
    the primary_uuid row.
    """
    nu.init_node_uuid(settings.node_uuid_path)
    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_cluster_nodes"))
        await db.execute(
            text("DELETE FROM vault_cluster_config WHERE key = ANY(:ks)"),
            {"ks": list(_CLUSTER_KEYS)},
        )
        await db.commit()
    hp.clear()
    yield
    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_cluster_nodes"))
        await db.execute(
            text("DELETE FROM vault_cluster_config WHERE key = ANY(:ks)"),
            {"ks": list(_CLUSTER_KEYS)},
        )
        await db.commit()
    hp.clear()


async def _config_value(key: str) -> str | None:
    async with async_session() as db:
        row = (
            await db.execute(
                text("SELECT value FROM vault_cluster_config WHERE key = :k"),
                {"k": key},
            )
        ).fetchone()
    return None if row is None else row.value


async def _all_config_keys() -> set[str]:
    async with async_session() as db:
        rows = (
            await db.execute(text("SELECT key FROM vault_cluster_config"))
        ).fetchall()
    return {r.key for r in rows}


# --- happy path ----------------------------------------------------------


@pytest.mark.asyncio
async def test_init_writes_all_rows_and_returns_payload(admin_token, client):
    r = await client.post(
        "/api/v1/vault/cluster/init",
        json={"cluster_name": "test-cluster-A"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 200, r.text
    body = r.json()

    # Response shape
    assert set(body.keys()) == {
        "cluster_id",
        "ha_password",
        "primary_uuid",
        "ca_fingerprint",
        "warning",
    }
    assert body["ca_fingerprint"]  # non-empty
    assert body["warning"]
    assert body["primary_uuid"]

    # ha_password is 32 raw bytes b64-encoded
    pw = base64.b64decode(body["ha_password"])
    assert len(pw) == 32

    # All six rows persisted
    keys = await _all_config_keys()
    for k in _CLUSTER_KEYS:
        assert k in keys, f"missing row {k}; keys={keys}"

    # cluster_id matches what's in DB
    assert body["cluster_id"] == await _config_value("cluster_id")


@pytest.mark.asyncio
async def test_init_caches_ha_password_in_ram(admin_token, client):
    r = await client.post(
        "/api/v1/vault/cluster/init",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 200
    assert hp.is_loaded(), "ha_password must be cached after init"


@pytest.mark.asyncio
async def test_init_ca_fingerprint_matches_persisted_cert(admin_token, client):
    r = await client.post(
        "/api/v1/vault/cluster/init",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 200
    expected_fpr = r.json()["ca_fingerprint"]

    cert_pem = (await _config_value("cluster_ca_cert")).encode("ascii")
    cert = x509.load_pem_x509_certificate(cert_pem)
    der = cert.public_bytes(serialization.Encoding.DER)
    assert sha256(der).hexdigest() == expected_fpr


@pytest.mark.asyncio
async def test_init_ca_key_unwraps_and_matches_cert_pubkey(admin_token, client):
    r = await client.post(
        "/api/v1/vault/cluster/init",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 200

    async with async_session() as db:
        loaded = await cluster_ca.load_cluster_ca(db)
    assert loaded is not None
    cert_pem, key_pem = loaded
    cert = x509.load_pem_x509_certificate(cert_pem)
    key = serialization.load_pem_private_key(key_pem, password=None)
    assert isinstance(key, Ed25519PrivateKey)
    cert_pub_raw = cert.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    key_pub_raw = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    assert cert_pub_raw == key_pub_raw


# --- idempotency / 409 ---------------------------------------------------


@pytest.mark.asyncio
async def test_double_init_returns_409(admin_token, client):
    r1 = await client.post(
        "/api/v1/vault/cluster/init",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r1.status_code == 200
    cluster_id_first = r1.json()["cluster_id"]

    r2 = await client.post(
        "/api/v1/vault/cluster/init",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r2.status_code == 409
    assert "already initialised" in r2.json()["detail"]

    # First init's data is untouched
    assert await _config_value("cluster_id") == cluster_id_first


# --- audit ---------------------------------------------------------------


@pytest.mark.asyncio
async def test_init_emits_cluster_init_audit_row_without_plaintext(admin_token, client):
    async with async_session() as db:
        before = (
            await db.execute(
                text("SELECT COUNT(*) AS c FROM vault_audit WHERE action = :a"),
                {"a": "cluster_init"},
            )
        ).fetchone()

    r = await client.post(
        "/api/v1/vault/cluster/init",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 200
    pw_b64 = r.json()["ha_password"]
    pw_raw = base64.b64decode(pw_b64)

    async with async_session() as db:
        after = (
            await db.execute(
                text(
                    "SELECT actor, action, target, detail FROM vault_audit "
                    "WHERE action = :a ORDER BY timestamp DESC LIMIT 1"
                ),
                {"a": "cluster_init"},
            )
        ).fetchone()
        count_after = (
            await db.execute(
                text("SELECT COUNT(*) AS c FROM vault_audit WHERE action = :a"),
                {"a": "cluster_init"},
            )
        ).fetchone()
    assert count_after.c == before.c + 1
    assert after.action == "cluster_init"
    detail = (
        after.detail if isinstance(after.detail, dict) else json.loads(after.detail)
    )
    assert "ca_fingerprint" in detail
    assert "cluster_name" in detail
    # Plaintext ha_password (raw OR b64) must NEVER appear in the audit row.
    detail_str = json.dumps(detail)
    assert pw_b64 not in detail_str
    assert pw_raw.hex() not in detail_str


# --- rollback ------------------------------------------------------------


@pytest.mark.asyncio
async def test_init_rolls_back_when_ca_mint_fails(admin_token, client):
    """If cluster_ca.mint_cluster_ca raises mid-transaction, no row must
    survive in vault_cluster_config and the ha_password RAM cache must
    be cleared. The endpoint re-raises the underlying RuntimeError after
    rollback ; ASGITransport surfaces it directly under tests."""

    def _boom(*_a, **_kw):
        raise RuntimeError("mint failure under test")

    with patch.object(cluster_ca, "mint_cluster_ca", side_effect=_boom):
        with pytest.raises(RuntimeError, match="mint failure under test"):
            await client.post(
                "/api/v1/vault/cluster/init",
                headers={"Authorization": f"Bearer {admin_token}"},
            )

    keys = await _all_config_keys()
    for k in _CLUSTER_KEYS:
        assert k not in keys, f"row {k} leaked after rollback: keys={keys}"
    assert not hp.is_loaded(), "ha_password RAM cache must be cleared on rollback"


# --- /cluster/repair ----------------------------------------------------


@pytest.mark.asyncio
async def test_repair_409_when_not_initialised(admin_token, client):
    r = await client.post(
        "/api/v1/vault/cluster/repair",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 409
    assert "not initialised" in r.json()["detail"]


@pytest.mark.asyncio
async def test_repair_completes_partial_state(admin_token, client):
    """Simulate a partial init by writing only cluster_id, then /cluster/repair
    must mint the missing ha_password + CA + primary_* rows."""
    async with async_session() as db:
        await db.execute(
            text(
                "INSERT INTO vault_cluster_config (key, value) "
                "VALUES ('cluster_id', :v)"
            ),
            {"v": "00000000-0000-0000-0000-000000000001"},
        )
        await db.commit()

    r = await client.post(
        "/api/v1/vault/cluster/repair",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert set(body["repaired"]) == {
        "ha_password_encrypted",
        "cluster_ca",
        "primary_uuid",
        "primary_since",
    }
    assert body["ha_password"]  # plaintext present because row was missing
    assert body["ca_fingerprint"]

    keys = await _all_config_keys()
    for k in _CLUSTER_KEYS:
        assert k in keys, f"missing row {k} after repair; keys={keys}"


@pytest.mark.asyncio
async def test_repair_is_noop_when_already_complete(admin_token, client):
    """After a successful /cluster/init, /cluster/repair must touch nothing."""
    r0 = await client.post(
        "/api/v1/vault/cluster/init",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r0.status_code == 200
    cert_before = await _config_value("cluster_ca_cert")
    key_before = await _config_value("cluster_ca_key")
    primary_before = await _config_value("primary_uuid")

    r = await client.post(
        "/api/v1/vault/cluster/repair",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["repaired"] == []
    assert body["ha_password"] is None  # nothing minted

    assert await _config_value("cluster_ca_cert") == cert_before
    assert await _config_value("cluster_ca_key") == key_before
    assert await _config_value("primary_uuid") == primary_before


# --- auth ---------------------------------------------------------------


@pytest.mark.asyncio
async def test_init_rejected_without_admin_scope(client):
    """A non-admin token must be rejected with 403 ; the cluster stays
    uninitialised on the failed call."""
    from api.app.crypto import generate_token
    from api.app.vault_state import vault as _vault

    raw_token = generate_token()
    token_hash = await _vault.hmac_sha512_hex(raw_token)
    async with async_session() as db:
        await db.execute(
            text("""
                INSERT INTO vault_tokens
                    (name, token_hash, permissions, created_by)
                VALUES
                    ('reader-only-init', :hash,
                     CAST(:perms AS jsonb), 'bootstrap')
                ON CONFLICT (name) WHERE active DO UPDATE SET token_hash = :hash
            """),
            {"hash": token_hash, "perms": json.dumps({"secrets": "r"})},
        )
        await db.commit()

    r = await client.post(
        "/api/v1/vault/cluster/init",
        headers={"Authorization": f"Bearer {raw_token}"},
    )
    assert r.status_code == 403
    assert "cluster_id" not in await _all_config_keys()


# --- follower-routed /cluster/init via RPC -----------


@pytest.mark.asyncio
async def test_init_succeeds_when_ha_wrap_delegated_via_rpc(
    admin_token, client, monkeypatch
):
    """/cluster/init no longer surfaces 503 on a worker that
    lacks ``_ha_wrap_enc``. The wrap of ha_password and the CA private
    key is delegated to the master via :meth:`VaultState.ha_wrap_encrypt`,
    which routes through :attr:`_rpc_client` when attached. We simulate
    the routing with an in-process fake client that proxies
    ``ha_wrap_encrypt`` / ``ha_wrap_decrypt`` to a side master with its
    own ``_ha_wrap_enc`` and delegates other ops back to the singleton
    (which keeps its hmac/dek/audit subkeys for token auth + audit
    signing).
    """
    import os as _os

    from api.app.vault_state import VaultState
    from api.app.vault_state import vault as _vault

    side_master = VaultState()
    side_master.unseal(
        {
            "hmac_key": _os.urandom(32),
            "dek_key": _os.urandom(32),
            "audit_key": _os.urandom(32),
            "ha_wrap_key": _os.urandom(32),
            "pki_wrap_key": _os.urandom(32),
        }
    )

    calls = {"encrypt": 0, "decrypt": 0}

    class _FakeRpcClient:
        async def call(self, op: str, args: dict):
            if op == "ha_wrap_encrypt":
                calls["encrypt"] += 1
                plain = bytes.fromhex(args["plaintext"])
                aad = bytes.fromhex(args["aad"])
                return side_master._ha_wrap_encrypt_local(plain, aad).hex()
            if op == "ha_wrap_decrypt":
                calls["decrypt"] += 1
                wrapped = bytes.fromhex(args["wrapped"])
                aad = bytes.fromhex(args["aad"])
                return side_master._ha_wrap_decrypt_local(wrapped, aad).hex()
            if op == "hmac_sha512":
                msg = bytes.fromhex(args["message"])
                return _vault._hmac_sha512_hex_local(msg)
            if op == "hmac_sha512_prev":
                msg = bytes.fromhex(args["message"])
                r = _vault._hmac_sha512_hex_prev_local(msg)
                return r if r is not None else ""
            if op == "aesgcm_encrypt":
                plain = bytes.fromhex(args["plaintext"])
                aad = bytes.fromhex(args["aad"])
                ct, nonce = _vault._aesgcm_encrypt_local(plain, aad)
                return nonce.hex() + ct.hex()
            if op == "aesgcm_decrypt":
                ct = bytes.fromhex(args["ciphertext"])
                nonce = bytes.fromhex(args["nonce"])
                aad = bytes.fromhex(args["aad"])
                return _vault._aesgcm_decrypt_local(ct, nonce, aad).hex()
            if op == "audit_sign":
                return _vault._audit_sign_local(
                    args["payload"], args.get("prev_signature", "")
                )
            if op == "ha_password_hmac":
                msg = bytes.fromhex(args["message"])
                return _vault._ha_password_hmac_local(msg)
            raise ValueError(f"unknown op: {op}")

    saved_ha_wrap = _vault._ha_wrap_enc
    _vault._ha_wrap_enc = None
    _vault.attach_rpc_client(_FakeRpcClient())
    try:
        r = await client.post(
            "/api/v1/vault/cluster/init",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
    finally:
        _vault.detach_rpc_client()
        _vault._ha_wrap_enc = saved_ha_wrap

    assert r.status_code == 200, r.text
    body = r.json()
    assert "cluster_id" in body
    assert "ha_password" in body
    # ha_password wrap + CA key wrap minimum.
    assert calls["encrypt"] >= 2, calls
    assert "cluster_id" in await _all_config_keys()


@pytest.mark.asyncio
async def test_repair_no_longer_503_on_follower(admin_token, client, monkeypatch):
    """the master-only gate on /cluster/repair was
    removed. The wraps it performs (``ha_password.set_ha_password`` +
    ``cluster_ca.set_cluster_ca``) route through
    :meth:`VaultState.ha_wrap_encrypt`, which dispatches to master via
    RPC when ``_rpc_client`` is attached. In this single-process unit
    test no RPC client is attached and the subkeys live locally, so the
    code path falls back to the local primitive ; the assertion is that
    the route no longer surfaces 503 + Retry-After: 1.
    """
    from api.app.vault_state import vault as _vault

    async with async_session() as db:
        await db.execute(
            text(
                "INSERT INTO vault_cluster_config (key, value) "
                "VALUES ('cluster_id', :v)"
            ),
            {"v": "00000000-0000-0000-0000-000000000002"},
        )
        await db.commit()

    monkeypatch.setattr(type(_vault), "is_master", property(lambda _self: False))

    r = await client.post(
        "/api/v1/vault/cluster/repair",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    # Before : 503 + Retry-After: 1. After : any status
    # except the historical gate response is acceptable here -- the
    # gate is gone. /cluster/repair may surface 200 / 409 / 500 etc.
    # depending on the prepared state ; the regression we guard
    # against is specifically the 503 + Retry-After signature.
    if r.status_code == 503:
        assert r.headers.get("retry-after") != "1", r.text
