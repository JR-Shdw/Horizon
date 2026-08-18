# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""cluster CA rotation + grace window tests.

Coverage map :

cluster_ca rotation helpers
- has_active_rotation toggles false -> true after rotate
- rotate_cluster_ca returns (cert, fingerprint, rotated_at) + writes
  cluster_ca_cert_prev + cluster_ca_rotated_at + swaps cert/key
- rotate_cluster_ca raises ClusterCaRotationInGraceError when prev set
- rotate_cluster_ca raises ClusterCaError when no current CA
- load_cluster_ca_prev_cert / get_rotated_at / drop_cluster_ca_prev
- drop_cluster_ca_prev idempotent

POST /cluster/rotate-ca (admin:w)
- happy path : 200 + body shape + force_renew_all flipped
- 409 in-grace when called twice without reaper drop in between
- 503 when CA not initialised
- 409 when vault sealed
- auth gate : no admin token -> 401/403/422
- audit row cluster_ca_rotated emitted

mTLS dual-CA verify pipeline
- cert signed under prev CA still authenticates during grace window
- cert signed under random other key rejected (both CAs fail)
- once reaper drops prev, prev-signed cert rejected

Reaper drop-prev hybrid op (cluster_ha_loops._reap_ca_grace)
- drops prev when all active rows have force_renew_at IS NULL (all_rotated)
- drops prev when NOW - rotated_at > grace_window (grace_expired)
- does NOT drop while grace not expired AND some force_renew_at NOT NULL
- no-op when no rotation pending
- evicted / draining rows NOT counted in the all_rotated predicate

Setting validator
- cluster_ca_grace_window_secs allows at least two renewal polls, max 2592000
"""

import urllib.parse
import uuid as _uuid
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from api.app import (
    cluster_ca,
    cluster_ha_loops,
    cluster_mtls,
    cluster_nodes,
)
from api.app import node_uuid as nu
from api.app.config import Settings, settings
from api.app.database import async_session
from api.app.ha_password import clear as hp_clear
from sqlalchemy import text

_CLUSTER_KEYS = (
    "cluster_id",
    "ha_password_encrypted",
    "cluster_ca_cert",
    "cluster_ca_key",
    "cluster_ca_cert_prev",
    "cluster_ca_rotated_at",
    "primary_uuid",
    "primary_since",
)


# --- fixtures ---------------------------------------------------------------


@pytest_asyncio.fixture
async def _fresh_cluster(tmp_path, monkeypatch, admin_token, client):
    """Boot a fresh cluster via /cluster/init + isolated cert paths."""
    cert_p = tmp_path / "cluster-cert.pem"
    key_p = tmp_path / "cluster-cert.key"
    monkeypatch.setattr(settings, "cluster_cert_path", str(cert_p))
    monkeypatch.setattr(settings, "cluster_cert_key_path", str(key_p))
    monkeypatch.setattr(settings, "proxy_trusted_ips", "127.0.0.1/32")
    nu.init_node_uuid(settings.node_uuid_path)

    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_cluster_nodes"))
        await db.execute(
            text("DELETE FROM vault_cluster_config WHERE key = ANY(:ks)"),
            {"ks": list(_CLUSTER_KEYS)},
        )
        await db.commit()
    hp_clear()

    r = await client.post(
        "/api/v1/vault/cluster/init",
        json={"cluster_name": "ca-rotation-test"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 200, r.text
    yield
    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_cluster_nodes"))
        await db.execute(
            text("DELETE FROM vault_cluster_config WHERE key = ANY(:ks)"),
            {"ks": list(_CLUSTER_KEYS)},
        )
        await db.commit()
    hp_clear()


async def _sign_node_cert(node_uuid: str, source_ip: str = "127.0.0.1"):
    """Sign a node cert under the CURRENT cluster CA (helper for the tests)."""
    async with async_session() as db:
        pair = await cluster_ca.load_cluster_ca(db)
    assert pair is not None
    ca_cert_pem, ca_key_pem = pair
    return cluster_ca.sign_node_cert(ca_cert_pem, ca_key_pem, node_uuid, source_ip)


async def _insert_member(
    node_uuid: str,
    cert_pem: bytes,
    source_ip: str = "127.0.0.1",
    ha_state: str = "secondary",
    force_renew: bool = False,
) -> None:
    fpr = cluster_ca.compute_fingerprint(cert_pem)
    nbf = cluster_ca.parse_cert(cert_pem).not_valid_after_utc
    async with async_session() as db:
        await db.execute(
            text(
                "INSERT INTO vault_cluster_nodes (node_uuid, source_ip, "
                "ha_state, cluster_version, cert_fingerprint, cert_not_after, "
                "force_renew_at) "
                "VALUES (:u, CAST(:ip AS INET), :st, :v, :f, :n, "
                "        CASE WHEN :fr THEN NOW() ELSE NULL END)"
            ),
            {
                "u": node_uuid,
                "ip": source_ip,
                "st": ha_state,
                "v": "1.0.0-test",
                "f": fpr,
                "n": nbf,
                "fr": force_renew,
            },
        )
        await db.commit()


def _x_client_cert_header(cert_pem: bytes) -> str:
    return urllib.parse.quote(cert_pem.decode("ascii"))


class _StubRequest:
    """Minimal Request stand-in for direct authenticate() calls."""

    class _Client:
        def __init__(self, host: str) -> None:
            self.host = host

    def __init__(self, headers: dict[str, str], host: str = "127.0.0.1") -> None:
        self.headers = headers
        self.client = self._Client(host)


# --- cluster_ca helpers -----------------------------------------------------


@pytest.mark.asyncio
async def test_has_active_rotation_toggles_after_rotate(_fresh_cluster):
    async with async_session() as db:
        assert await cluster_ca.has_active_rotation(db) is False
        await cluster_ca.rotate_cluster_ca(db)
        await db.commit()
    async with async_session() as db:
        assert await cluster_ca.has_active_rotation(db) is True


@pytest.mark.asyncio
async def test_rotate_cluster_ca_writes_prev_and_new(_fresh_cluster):
    async with async_session() as db:
        pair_before = await cluster_ca.load_cluster_ca(db)
        assert pair_before is not None
        before_cert_pem, _before_key = pair_before
        before_fp = cluster_ca.compute_fingerprint(before_cert_pem)

        new_cert_pem, new_fp, rotated_at = await cluster_ca.rotate_cluster_ca(db)
        await db.commit()

    assert new_cert_pem.startswith(b"-----BEGIN CERTIFICATE-----")
    assert len(new_fp) == 64  # SHA-256 hex
    assert new_fp != before_fp  # genuine new key material
    assert isinstance(rotated_at, datetime)
    assert rotated_at.tzinfo is not None

    async with async_session() as db:
        prev_pem = await cluster_ca.load_cluster_ca_prev_cert(db)
        assert prev_pem == before_cert_pem
        got_at = await cluster_ca.get_rotated_at(db)
        assert got_at is not None
        # Within 5s (mostly process delta only -- both writes are NOW()).
        assert abs((got_at - rotated_at).total_seconds()) < 5

        pair_after = await cluster_ca.load_cluster_ca(db)
        assert pair_after is not None
        after_cert_pem, _after_key = pair_after
        assert cluster_ca.compute_fingerprint(after_cert_pem) == new_fp


@pytest.mark.asyncio
async def test_rotate_cluster_ca_raises_when_prev_still_set(_fresh_cluster):
    async with async_session() as db:
        await cluster_ca.rotate_cluster_ca(db)
        await db.commit()
    async with async_session() as db:
        with pytest.raises(cluster_ca.ClusterCaRotationInGraceError):
            await cluster_ca.rotate_cluster_ca(db)


@pytest.mark.asyncio
async def test_rotate_cluster_ca_raises_when_ca_not_initialised(
    tmp_path, monkeypatch, admin_token, client
):
    """Wipe cluster config -- rotate must refuse without a current CA."""
    monkeypatch.setattr(settings, "cluster_cert_path", str(tmp_path / "cert.pem"))
    monkeypatch.setattr(settings, "cluster_cert_key_path", str(tmp_path / "cert.key"))
    nu.init_node_uuid(settings.node_uuid_path)
    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_cluster_nodes"))
        await db.execute(
            text("DELETE FROM vault_cluster_config WHERE key = ANY(:ks)"),
            {"ks": list(_CLUSTER_KEYS)},
        )
        await db.commit()
    hp_clear()
    async with async_session() as db:
        with pytest.raises(cluster_ca.ClusterCaError):
            await cluster_ca.rotate_cluster_ca(db)


@pytest.mark.asyncio
async def test_drop_cluster_ca_prev_clears_both_rows(_fresh_cluster):
    async with async_session() as db:
        await cluster_ca.rotate_cluster_ca(db)
        await db.commit()
    async with async_session() as db:
        dropped = await cluster_ca.drop_cluster_ca_prev(db)
        await db.commit()
        assert dropped is True
        assert await cluster_ca.has_active_rotation(db) is False
        assert await cluster_ca.load_cluster_ca_prev_cert(db) is None
        assert await cluster_ca.get_rotated_at(db) is None


@pytest.mark.asyncio
async def test_drop_cluster_ca_prev_idempotent(_fresh_cluster):
    async with async_session() as db:
        dropped = await cluster_ca.drop_cluster_ca_prev(db)
        await db.commit()
    assert dropped is False


# --- POST /cluster/rotate-ca route -----------------------------------------


@pytest.mark.asyncio
async def test_rotate_ca_happy_path(_fresh_cluster, client, admin_token):
    # Insert a second member so we can observe force-renew broadcast.
    node_uuid = str(_uuid.uuid4())
    cert_pem, _ = await _sign_node_cert(node_uuid, source_ip="10.0.0.1")
    await _insert_member(node_uuid, cert_pem, source_ip="10.0.0.1")

    r = await client.post(
        "/api/v1/vault/cluster/rotate-ca",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["new_fingerprint"]) == 64
    assert body["rotated_at"]
    assert body["grace_window_secs"] == settings.cluster_ca_grace_window_secs
    # Primary row from /cluster/init + the secondary we just added.
    assert body["flipped"] >= 2

    async with async_session() as db:
        # Every non-evicted row now has force_renew_at NOT NULL.
        row = (
            await db.execute(
                text(
                    "SELECT COUNT(*) AS n FROM vault_cluster_nodes "
                    "WHERE force_renew_at IS NULL"
                )
            )
        ).fetchone()
        assert int(row.n) == 0
        assert await cluster_ca.has_active_rotation(db) is True


@pytest.mark.asyncio
async def test_rotate_ca_409_in_grace(_fresh_cluster, client, admin_token):
    r = await client.post(
        "/api/v1/vault/cluster/rotate-ca",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 200, r.text

    r2 = await client.post(
        "/api/v1/vault/cluster/rotate-ca",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r2.status_code == 409, r2.text
    assert "cluster_ca_rotation_in_grace" in r2.text


@pytest.mark.asyncio
async def test_rotate_ca_503_when_uninit(client, admin_token, monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "cluster_cert_path", str(tmp_path / "cert.pem"))
    monkeypatch.setattr(settings, "cluster_cert_key_path", str(tmp_path / "cert.key"))
    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_cluster_nodes"))
        await db.execute(
            text("DELETE FROM vault_cluster_config WHERE key = ANY(:ks)"),
            {"ks": list(_CLUSTER_KEYS)},
        )
        await db.commit()
    hp_clear()
    r = await client.post(
        "/api/v1/vault/cluster/rotate-ca",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 503, r.text


@pytest.mark.asyncio
async def test_rotate_ca_no_admin_token_blocked(_fresh_cluster, client):
    r = await client.post("/api/v1/vault/cluster/rotate-ca")
    assert r.status_code in (401, 403, 422)


@pytest.mark.asyncio
async def test_rotate_ca_audit_row_emitted(_fresh_cluster, client, admin_token):
    r = await client.post(
        "/api/v1/vault/cluster/rotate-ca",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 200
    async with async_session() as db:
        row = (
            await db.execute(
                text(
                    "SELECT actor, target, action FROM vault_audit "
                    "WHERE action = 'cluster_ca_rotated' "
                    "ORDER BY id DESC LIMIT 1"
                )
            )
        ).fetchone()
    assert row is not None
    assert row.target == "cluster"


# --- mTLS dual-CA verify ----------------------------------------------------


@pytest.mark.asyncio
async def test_mtls_accepts_prev_signed_cert_during_grace(_fresh_cluster):
    # Sign a node cert under the CURRENT CA, then rotate -- the cert
    # is now signed under what becomes the prev CA. The dual-verify
    # pipeline must accept it during the grace window.
    node_uuid = str(_uuid.uuid4())
    old_cert_pem, _old_key = await _sign_node_cert(node_uuid)
    await _insert_member(node_uuid, old_cert_pem)

    async with async_session() as db:
        await cluster_ca.rotate_cluster_ca(db)
        await db.commit()

    req = _StubRequest({"X-Client-Cert": _x_client_cert_header(old_cert_pem)})
    async with async_session() as db:
        identity = await cluster_mtls.authenticate(req, db)
    assert identity.node_uuid == node_uuid


@pytest.mark.asyncio
async def test_mtls_accepts_new_signed_cert_during_grace(_fresh_cluster):
    # After rotation, a cert signed under the NEW CA still authenticates.
    async with async_session() as db:
        await cluster_ca.rotate_cluster_ca(db)
        await db.commit()
    node_uuid = str(_uuid.uuid4())
    new_cert_pem, _ = await _sign_node_cert(node_uuid)
    await _insert_member(node_uuid, new_cert_pem)

    req = _StubRequest({"X-Client-Cert": _x_client_cert_header(new_cert_pem)})
    async with async_session() as db:
        identity = await cluster_mtls.authenticate(req, db)
    assert identity.node_uuid == node_uuid


@pytest.mark.asyncio
async def test_mtls_rejects_unsigned_during_grace(_fresh_cluster):
    # A cert signed under a totally unrelated Ed25519 key must fail
    # both the current and the prev CA verification -- 401.
    node_uuid = str(_uuid.uuid4())
    # Build a foreign CA + sign a foreign cert under it.
    foreign_ca_cert_pem, foreign_ca_key_pem, _ = cluster_ca.mint_cluster_ca(
        common_name="foreign-ca", validity_days=10
    )
    foreign_cert_pem, _ = cluster_ca.sign_node_cert(
        foreign_ca_cert_pem, foreign_ca_key_pem, node_uuid, "127.0.0.1"
    )
    async with async_session() as db:
        await cluster_ca.rotate_cluster_ca(db)
        await db.commit()

    req = _StubRequest({"X-Client-Cert": _x_client_cert_header(foreign_cert_pem)})
    async with async_session() as db:
        with pytest.raises(cluster_mtls.MtlsBadSignatureError):
            await cluster_mtls.authenticate(req, db)


@pytest.mark.asyncio
async def test_mtls_rejects_prev_cert_after_grace_drop(_fresh_cluster):
    # Once the reaper drops the prev CA, a still-deployed cert signed
    # under it must no longer authenticate.
    node_uuid = str(_uuid.uuid4())
    old_cert_pem, _ = await _sign_node_cert(node_uuid)
    await _insert_member(node_uuid, old_cert_pem, force_renew=False)

    async with async_session() as db:
        await cluster_ca.rotate_cluster_ca(db)
        # Simulate the node having refreshed (force_renew_at NULL).
        # The fresh insert above had force_renew=False so it's already NULL,
        # but rotate_cluster_ca is followed in the real flow by
        # set_force_renew_all -- here we skip the flip to exercise the
        # all_rotated drop path.
        await db.commit()
    async with async_session() as db:
        dropped = await cluster_ca.drop_cluster_ca_prev(db)
        await db.commit()
    assert dropped is True

    req = _StubRequest({"X-Client-Cert": _x_client_cert_header(old_cert_pem)})
    async with async_session() as db:
        with pytest.raises(cluster_mtls.MtlsBadSignatureError):
            await cluster_mtls.authenticate(req, db)


# --- Reaper drop-prev hybrid op --------------------------------------------


@pytest.mark.asyncio
async def test_reaper_drops_prev_when_all_rotated(_fresh_cluster):
    # Mark the primary row's force_renew_at to NULL after a rotate -- the
    # reaper observes all_rotated and drops prev.
    async with async_session() as db:
        await cluster_ca.rotate_cluster_ca(db)
        await cluster_nodes.set_force_renew_all(db)
        await db.commit()
    # Clear every flag (simulates renewal-loop success on every node).
    async with async_session() as db:
        await db.execute(
            text(
                "UPDATE vault_cluster_nodes "
                "SET force_renew_at = NULL "
                "WHERE ha_state NOT IN ('evicted','draining')"
            )
        )
        await db.commit()

    async with async_session() as db:
        dropped = await cluster_ha_loops._reap_ca_grace(db)
    assert dropped == 1
    async with async_session() as db:
        assert await cluster_ca.has_active_rotation(db) is False


@pytest.mark.asyncio
async def test_reaper_drops_prev_when_grace_expired(_fresh_cluster, monkeypatch):
    # Set a tiny grace window so the time path fires deterministically
    # even with force_renew_at still pending on every row.
    monkeypatch.setattr(settings, "cluster_ca_grace_window_secs", 3600)

    async with async_session() as db:
        await cluster_ca.rotate_cluster_ca(db)
        await cluster_nodes.set_force_renew_all(db)
        # Backdate rotated_at to 2h ago -- past the 1h grace.
        past = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
        await db.execute(
            text(
                "UPDATE vault_cluster_config SET value = :v "
                "WHERE key = 'cluster_ca_rotated_at'"
            ),
            {"v": past},
        )
        await db.commit()

    async with async_session() as db:
        dropped = await cluster_ha_loops._reap_ca_grace(db)
    assert dropped == 1
    async with async_session() as db:
        assert await cluster_ca.has_active_rotation(db) is False


@pytest.mark.asyncio
async def test_reaper_does_not_drop_while_in_grace_with_pending(_fresh_cluster):
    # Default grace = 7d, fresh rotation, force_renew_at still NOT NULL :
    # the reaper must NOT drop.
    async with async_session() as db:
        await cluster_ca.rotate_cluster_ca(db)
        await cluster_nodes.set_force_renew_all(db)
        await db.commit()
    async with async_session() as db:
        dropped = await cluster_ha_loops._reap_ca_grace(db)
    assert dropped == 0
    async with async_session() as db:
        assert await cluster_ca.has_active_rotation(db) is True


@pytest.mark.asyncio
async def test_reaper_no_op_without_rotation(_fresh_cluster):
    # No rotate happened : nothing to drop.
    async with async_session() as db:
        dropped = await cluster_ha_loops._reap_ca_grace(db)
    assert dropped == 0


@pytest.mark.asyncio
async def test_reaper_ignores_evicted_for_all_rotated(_fresh_cluster):
    # An evicted row with force_renew_at NOT NULL must not hold the
    # grace open -- evicted rows are excluded from the predicate.
    evicted_uuid = str(_uuid.uuid4())
    cert_pem, _ = await _sign_node_cert(evicted_uuid, source_ip="10.0.0.99")
    await _insert_member(
        evicted_uuid,
        cert_pem,
        source_ip="10.0.0.99",
        ha_state="evicted",
        force_renew=True,
    )
    async with async_session() as db:
        await cluster_ca.rotate_cluster_ca(db)
        # Primary row : clear force_renew_at so the all_rotated path fires.
        await db.execute(
            text(
                "UPDATE vault_cluster_nodes "
                "SET force_renew_at = NULL "
                "WHERE ha_state NOT IN ('evicted','draining')"
            )
        )
        await db.commit()
    async with async_session() as db:
        dropped = await cluster_ha_loops._reap_ca_grace(db)
    assert dropped == 1


# --- Setting validator ------------------------------------------------------


def test_grace_window_setting_clamps_low():
    s = Settings(cluster_ca_grace_window_secs=10)
    assert s.cluster_ca_grace_window_secs == 86400


def test_grace_window_setting_tracks_renewal_poll():
    s = Settings(
        cluster_cert_renewal_poll_secs=3600,
        cluster_ca_grace_window_secs=3600,
    )
    assert s.cluster_ca_grace_window_secs == 7200


def test_grace_window_setting_clamps_high():
    s = Settings(cluster_ca_grace_window_secs=99_999_999)
    assert s.cluster_ca_grace_window_secs == 2_592_000


def test_grace_window_setting_passes_in_range():
    s = Settings(cluster_ca_grace_window_secs=172800)
    assert s.cluster_ca_grace_window_secs == 172800


# --- Coverage gap : rewrap_for_master_rotation ------------------------------


@pytest.mark.asyncio
async def test_rewrap_for_master_rotation_returns_false_when_no_row():
    """Master rotation called on a cluster without a CA initialised yet :
    no row in vault_cluster_config under ``cluster_ca_key`` -> no-op,
    returns ``False``. Covers cluster_ca.py L284-285 (early-return path
    of ``rewrap_for_master_rotation``)."""
    import os as _os

    from api.app import cluster_ca as _cluster_ca
    from api.app.database import async_session as _async_session
    from sqlalchemy import text as _text

    async with _async_session() as db:
        await db.execute(
            _text("DELETE FROM vault_cluster_config WHERE key = :k"),
            {"k": _cluster_ca._CONFIG_KEY_KEY},
        )
        await db.commit()
    async with _async_session() as db:
        result = await _cluster_ca.rewrap_for_master_rotation(
            db,
            old_ha_wrap_key=_os.urandom(32),
            new_ha_wrap_key=_os.urandom(32),
        )
        assert result is False


@pytest.mark.asyncio
async def test_rewrap_for_master_rotation_re_encrypts_under_new_key():
    """Happy path : a CA private key wrapped under the old ha_wrap_key
    is re-encrypted under the new one in a single transaction. Post-call
    the row decrypts under the new key only ; the old key fails (AES-GCM
    AuthenticationFailed). Covers cluster_ca.py L287-300 (the wrap +
    UPDATE body of ``rewrap_for_master_rotation``)."""
    import os as _os

    from api.app import cluster_ca as _cluster_ca
    from api.app.database import async_session as _async_session
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from sqlalchemy import text as _text

    old_key = _os.urandom(32)
    new_key = _os.urandom(32)
    plaintext_ca_key = (
        b"-----BEGIN PRIVATE KEY-----\nFAKE-FOR-COVERAGE\n-----END PRIVATE KEY-----\n"
    )

    # Seed : encrypt under old key and INSERT
    nonce = _os.urandom(12)
    ct = AESGCM(old_key).encrypt(nonce, plaintext_ca_key, _cluster_ca._AAD)
    seeded_blob = (nonce + ct).hex()
    async with _async_session() as db:
        await db.execute(
            _text("DELETE FROM vault_cluster_config WHERE key = :k"),
            {"k": _cluster_ca._CONFIG_KEY_KEY},
        )
        await db.execute(
            _text("INSERT INTO vault_cluster_config (key, value) VALUES (:k, :v)"),
            {"k": _cluster_ca._CONFIG_KEY_KEY, "v": seeded_blob},
        )
        await db.commit()

    try:
        async with _async_session() as db:
            result = await _cluster_ca.rewrap_for_master_rotation(
                db, old_ha_wrap_key=old_key, new_ha_wrap_key=new_key
            )
            await db.commit()
            assert result is True

        async with _async_session() as db:
            row = (
                await db.execute(
                    _text("SELECT value FROM vault_cluster_config WHERE key = :k"),
                    {"k": _cluster_ca._CONFIG_KEY_KEY},
                )
            ).fetchone()
        assert row is not None
        new_blob = bytes.fromhex(row.value)
        new_nonce, new_ct = new_blob[:12], new_blob[12:]
        recovered = AESGCM(new_key).decrypt(new_nonce, new_ct, _cluster_ca._AAD)
        assert recovered == plaintext_ca_key
        with pytest.raises(InvalidTag):
            AESGCM(old_key).decrypt(new_nonce, new_ct, _cluster_ca._AAD)
    finally:
        async with _async_session() as db:
            await db.execute(
                _text("DELETE FROM vault_cluster_config WHERE key = :k"),
                {"k": _cluster_ca._CONFIG_KEY_KEY},
            )
            await db.commit()
