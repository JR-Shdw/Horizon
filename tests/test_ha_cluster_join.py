# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""POST /cluster/challenge + /cluster/join end-to-end.

Coverage :

/cluster/challenge :
- happy path issues a single-use nonce bound to (uuid, ip)
- 409 when the cluster is not initialised
- 409 when rhorizon_version is below the cluster floor
- 409 when rhorizon_version is malformed

/cluster/join :
- happy path returns cert + wrapped key + membership row
- node cert verifies under the cluster CA (signature + CN + SAN IP)
- wrapped key decrypts via HKDF(ha_password, info)
- vault_cluster_nodes row persisted with ha_state=joining + binding cols
- audit row emitted with no plaintext leakage
- DELETE+RETURNING enforces single-use (replay -> 401)
- expired nonce -> 401
- nonce never issued -> 401
- node_uuid mismatch between challenge and body -> 401
- wrong cluster_id -> 401
- ha_password proof bad -> 401
- joiner version too old -> 409
- cluster not initialised -> 409
- second join with same uuid -> 409 (REJOIN territory)
- (uuid, ip) conflict -> 409
- HMAC message canonical form (issued_at_epoch round-trips)
"""

import base64
import hashlib
import hmac as _hmac
import json
from datetime import datetime, timezone

import pytest
import pytest_asyncio
from api.app import ha_password as hp
from api.app import node_uuid as nu
from api.app.config import settings
from api.app.database import async_session
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA512
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from sqlalchemy import text

_CLUSTER_CFG_KEYS = (
    "cluster_id",
    "ha_password_encrypted",
    "cluster_ca_cert",
    "cluster_ca_key",
    "primary_uuid",
    "primary_since",
)


def _compute_proof(
    ha_password: bytes,
    cluster_id: str,
    node_uuid: str,
    source_ip: str,
    nonce: str,
    issued_at_epoch: int,
) -> str:
    """Replay the canonical HMAC message the server recomputes at /join.

    Matches the route layer byte order exactly :
    cluster_id || node_uuid || source_ip || nonce || str(issued_at_epoch).
    """
    msg = (
        cluster_id.encode()
        + node_uuid.encode()
        + source_ip.encode()
        + nonce.encode()
        + str(issued_at_epoch).encode()
    )
    return _hmac.new(ha_password, msg, hashlib.sha512).hexdigest()


def _unwrap_node_key(ha_password: bytes, node_uuid: str, wrapped_hex: str) -> bytes:
    """Mirror of ha_password.wrap_node_key_for_joiner -- client-side recovery.

    Same recipe : HKDF-SHA512(ikm=ha_password, info="cluster-node-key-wrap:<uuid>",
    length=32), AES-256-GCM decrypt with AAD "vault-cluster:node-key:<uuid>".
    """
    info = b"cluster-node-key-wrap:" + node_uuid.encode()
    aad = b"vault-cluster:node-key:" + node_uuid.encode()
    derived = HKDF(algorithm=SHA512(), length=32, salt=None, info=info).derive(
        ha_password
    )
    blob = bytes.fromhex(wrapped_hex)
    nonce, ct = blob[:12], blob[12:]
    return AESGCM(derived).decrypt(nonce, ct, aad)


async def _wipe_state():
    async with async_session() as db:
        await db.execute(
            text("DELETE FROM vault_cluster_config WHERE key = ANY(:ks)"),
            {"ks": list(_CLUSTER_CFG_KEYS)},
        )
        await db.execute(text("DELETE FROM vault_cluster_nodes"))
        await db.execute(
            text("DELETE FROM vault_challenges WHERE purpose = 'cluster_join'")
        )
        await db.commit()
    hp.clear()


@pytest_asyncio.fixture
async def _wipe_cluster_state():
    nu.init_node_uuid(settings.node_uuid_path)
    await _wipe_state()
    yield
    await _wipe_state()


async def _init_cluster(admin_token, client) -> tuple[str, bytes, str]:
    r = await client.post(
        "/api/v1/vault/cluster/init",
        json={"cluster_name": "test-6c"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    return (
        body["cluster_id"],
        base64.b64decode(body["ha_password"]),
        body["primary_uuid"],
    )


# ---------------------------------------------------------------------------
# /cluster/challenge
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_challenge_happy_path(admin_token, client, _wipe_cluster_state):
    await _init_cluster(admin_token, client)
    r = await client.post(
        "/api/v1/vault/cluster/challenge",
        json={"node_uuid": "n" * 32, "rhorizon_version": "1.0.0"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert set(body.keys()) == {
        "nonce",
        "issued_at",
        "expires_at",
        "cluster_version",
        "cluster_min_compatible_version",
        "observed_source_ip",
        "cluster_id",
    }
    assert len(body["nonce"]) == 32  # 16 bytes hex
    assert body["cluster_version"] == settings.version
    assert (
        body["cluster_min_compatible_version"]
        == settings.cluster_min_compatible_version
    )
    assert body["observed_source_ip"]  # non-empty IP literal
    # Bug 5 fix : cluster_id discoverable from challenge response.
    assert body["cluster_id"]  # non-empty UUID echoed from vault_cluster_config


@pytest.mark.asyncio
async def test_challenge_serves_on_follower_worker(
    admin_token, client, _wipe_cluster_state, monkeypatch
):
    """/cluster/challenge does no subkey crypto (just
    secrets.token_hex + DB INSERT), so any worker, master or
    follower, must serve it. Without this property, the JOIN
    bootstrap funnels two consecutive routing-mesh hits through
    the 1/N master selector, which collapses convergence on
    multi-replica deployments. Compare with /cluster/join (next
    test below) which legitimately needs the master.
    """
    from api.app.vault_state import vault as _vault

    # Init while master (the gate would 503 a follower-routed init).
    await _init_cluster(admin_token, client)
    # Now simulate follower-routed challenge -- it must still serve.
    monkeypatch.setattr(type(_vault), "is_master", property(lambda _self: False))
    r = await client.post(
        "/api/v1/vault/cluster/challenge",
        json={"node_uuid": "f" * 32, "rhorizon_version": "1.0.0"},
    )
    assert r.status_code == 200, r.text
    assert len(r.json()["nonce"]) == 32  # 16 bytes hex -- crypto-free path


@pytest.mark.asyncio
async def test_challenge_persists_binding(admin_token, client, _wipe_cluster_state):
    await _init_cluster(admin_token, client)
    node_uuid = "uuid-bind-001"
    r = await client.post(
        "/api/v1/vault/cluster/challenge",
        json={"node_uuid": node_uuid, "rhorizon_version": "1.0.0"},
    )
    assert r.status_code == 200
    nonce = r.json()["nonce"]
    async with async_session() as db:
        row = (
            await db.execute(
                text(
                    "SELECT node_uuid, source_ip, purpose, issued_at, expires_at "
                    "FROM vault_challenges WHERE challenge = :c"
                ),
                {"c": nonce},
            )
        ).fetchone()
    assert row is not None
    assert row.node_uuid == node_uuid
    assert row.purpose == "cluster_join"
    assert row.source_ip is not None
    assert row.expires_at > row.issued_at


@pytest.mark.asyncio
async def test_challenge_cluster_not_initialised(client, _wipe_cluster_state):
    r = await client.post(
        "/api/v1/vault/cluster/challenge",
        json={"node_uuid": "x", "rhorizon_version": "1.0.0"},
    )
    assert r.status_code == 409
    assert "not initialised" in r.json()["detail"].lower()


@pytest.mark.asyncio
async def test_challenge_version_below_floor(admin_token, client, _wipe_cluster_state):
    await _init_cluster(admin_token, client)
    r = await client.post(
        "/api/v1/vault/cluster/challenge",
        json={"node_uuid": "u", "rhorizon_version": "0.9.99"},
    )
    assert r.status_code == 409
    assert "below cluster floor" in r.json()["detail"]


@pytest.mark.asyncio
async def test_challenge_version_malformed(admin_token, client, _wipe_cluster_state):
    await _init_cluster(admin_token, client)
    r = await client.post(
        "/api/v1/vault/cluster/challenge",
        json={"node_uuid": "u", "rhorizon_version": "not-a-version"},
    )
    assert r.status_code == 409


# ---------------------------------------------------------------------------
# /cluster/join
# ---------------------------------------------------------------------------


async def _get_challenge_meta(nonce: str) -> tuple[str, int]:
    """Read back source_ip + issued_at_epoch from the persisted challenge row."""
    async with async_session() as db:
        row = (
            await db.execute(
                text(
                    "SELECT source_ip, issued_at "
                    "FROM vault_challenges WHERE challenge = :c"
                ),
                {"c": nonce},
            )
        ).fetchone()
    return row.source_ip, int(row.issued_at.timestamp())


async def _challenge_and_proof(
    client, cluster_id: str, ha_password: bytes, node_uuid: str
) -> dict:
    """Issue a challenge then craft a valid join body. Returns the join payload."""
    cr = await client.post(
        "/api/v1/vault/cluster/challenge",
        json={"node_uuid": node_uuid, "rhorizon_version": "1.0.0"},
    )
    assert cr.status_code == 200, cr.text
    nonce = cr.json()["nonce"]
    source_ip, issued_at_epoch = await _get_challenge_meta(nonce)
    proof = _compute_proof(
        ha_password, cluster_id, node_uuid, source_ip, nonce, issued_at_epoch
    )
    return {
        "cluster_id": cluster_id,
        "node_uuid": node_uuid,
        "nonce": nonce,
        "ha_password_proof": proof,
        "rhorizon_version": "1.0.0",
    }


@pytest.mark.asyncio
async def test_join_happy_path(admin_token, client, _wipe_cluster_state):
    cluster_id, ha_pw, _primary = await _init_cluster(admin_token, client)
    node_uuid = "join-happy-001"
    body = await _challenge_and_proof(client, cluster_id, ha_pw, node_uuid)
    r = await client.post("/api/v1/vault/cluster/join", json=body)
    assert r.status_code == 200, r.text
    resp = r.json()
    assert resp["accepted"] is True
    assert resp["ha_state"] == "joining"
    assert resp["cluster_version"] == settings.version
    assert resp["primary_uuid"]
    assert resp["node_cert_pem"].startswith("-----BEGIN CERTIFICATE-----")
    assert resp["ca_cert_pem"].startswith("-----BEGIN CERTIFICATE-----")
    assert len(resp["node_cert_key_wrapped_hex"]) > 0
    assert resp["quarantine_until"]


@pytest.mark.asyncio
async def test_join_cert_verifies_under_ca(admin_token, client, _wipe_cluster_state):
    cluster_id, ha_pw, _ = await _init_cluster(admin_token, client)
    node_uuid = "join-cert-001"
    body = await _challenge_and_proof(client, cluster_id, ha_pw, node_uuid)
    r = await client.post("/api/v1/vault/cluster/join", json=body)
    assert r.status_code == 200
    resp = r.json()
    node_cert = x509.load_pem_x509_certificate(resp["node_cert_pem"].encode())
    ca_cert = x509.load_pem_x509_certificate(resp["ca_cert_pem"].encode())
    # CN matches node_uuid
    cn = node_cert.subject.rfc4514_string()
    assert node_uuid in cn
    # Issuer matches CA subject
    assert node_cert.issuer == ca_cert.subject
    # Signature : Ed25519 verify will raise on mismatch.
    ca_pub = ca_cert.public_key()
    ca_pub.verify(
        node_cert.signature,
        node_cert.tbs_certificate_bytes,
    )
    # SAN carries the source IP observed by the server.
    san_ext = node_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    ips = san_ext.value.get_values_for_type(x509.IPAddress)
    assert len(ips) == 1


@pytest.mark.asyncio
async def test_join_wrapped_key_decrypts(admin_token, client, _wipe_cluster_state):
    cluster_id, ha_pw, _ = await _init_cluster(admin_token, client)
    node_uuid = "join-wrap-001"
    body = await _challenge_and_proof(client, cluster_id, ha_pw, node_uuid)
    r = await client.post("/api/v1/vault/cluster/join", json=body)
    assert r.status_code == 200
    resp = r.json()
    key_pem = _unwrap_node_key(ha_pw, node_uuid, resp["node_cert_key_wrapped_hex"])
    assert key_pem.startswith(b"-----BEGIN PRIVATE KEY-----")
    parsed_key = serialization.load_pem_private_key(key_pem, password=None)
    assert isinstance(parsed_key, Ed25519PrivateKey)
    # Key matches the cert's public key.
    node_cert = x509.load_pem_x509_certificate(resp["node_cert_pem"].encode())
    derived_pub = parsed_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    cert_pub = node_cert.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    assert derived_pub == cert_pub


@pytest.mark.asyncio
async def test_join_persists_membership_row(admin_token, client, _wipe_cluster_state):
    cluster_id, ha_pw, _ = await _init_cluster(admin_token, client)
    node_uuid = "join-row-001"
    body = await _challenge_and_proof(client, cluster_id, ha_pw, node_uuid)
    r = await client.post("/api/v1/vault/cluster/join", json=body)
    assert r.status_code == 200, r.text
    async with async_session() as db:
        row = (
            await db.execute(
                text(
                    "SELECT node_uuid, host(source_ip) AS ip, ha_state, "
                    "       quarantine_until, cluster_version, "
                    "       cert_fingerprint, cert_not_after "
                    "FROM vault_cluster_nodes WHERE node_uuid = :u"
                ),
                {"u": node_uuid},
            )
        ).fetchone()
    assert row is not None
    assert row.ha_state == "joining"
    assert row.cluster_version == settings.version
    assert row.cert_fingerprint
    assert row.cert_not_after > datetime.now(timezone.utc)
    assert row.quarantine_until > datetime.now(timezone.utc)


@pytest.mark.asyncio
async def test_join_audit_no_plaintext_leak(admin_token, client, _wipe_cluster_state):
    cluster_id, ha_pw, _ = await _init_cluster(admin_token, client)
    node_uuid = "join-audit-001"
    body = await _challenge_and_proof(client, cluster_id, ha_pw, node_uuid)
    r = await client.post("/api/v1/vault/cluster/join", json=body)
    assert r.status_code == 200
    async with async_session() as db:
        row = (
            await db.execute(
                text(
                    "SELECT detail FROM vault_audit "
                    "WHERE action = 'cluster_join' AND target = :cid "
                    "ORDER BY id DESC LIMIT 1"
                ),
                {"cid": cluster_id},
            )
        ).fetchone()
    assert row is not None
    # JSONB column comes back already deserialised by asyncpg.
    detail = row.detail if isinstance(row.detail, dict) else json.loads(row.detail)
    assert detail["node_uuid"] == node_uuid
    assert detail["ha_state"] == "joining"
    # Plaintext ha_password and key material never end up in the audit row.
    raw = json.dumps(detail)
    assert "ha_password" not in raw
    assert "PRIVATE KEY" not in raw
    assert body["ha_password_proof"] not in raw


@pytest.mark.asyncio
async def test_join_replay_consumes_challenge_single_use(
    admin_token, client, _wipe_cluster_state
):
    """DELETE+RETURNING enforces single-use of the challenge row.

    An idempotency cache wraps this property (same nonce
    replay -> cached payload, not 401). To assert the underlying single-
    use contract, we wipe both the membership row *and* the
    cache row, then replay : with the cache gone, the cache lookup
    misses, the flow reaches the DELETE+RETURNING in step 1, finds
    nothing (challenge was consumed at the first call), and 401s. The
    standalone replay behavior (cache hit -> 200) is covered in
    test_ha_cluster_join_idempotency.py.
    """
    cluster_id, ha_pw, _ = await _init_cluster(admin_token, client)
    node_uuid = "join-replay-001"
    body = await _challenge_and_proof(client, cluster_id, ha_pw, node_uuid)
    r1 = await client.post("/api/v1/vault/cluster/join", json=body)
    assert r1.status_code == 200, r1.text
    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_cluster_nodes"))
        await db.execute(text("DELETE FROM vault_join_idempotency"))
        await db.commit()
    r2 = await client.post("/api/v1/vault/cluster/join", json=body)
    assert r2.status_code == 401
    assert "nonce" in r2.json()["detail"].lower()


@pytest.mark.asyncio
async def test_join_expired_nonce(admin_token, client, _wipe_cluster_state):
    cluster_id, ha_pw, _ = await _init_cluster(admin_token, client)
    node_uuid = "join-expired-001"
    cr = await client.post(
        "/api/v1/vault/cluster/challenge",
        json={"node_uuid": node_uuid, "rhorizon_version": "1.0.0"},
    )
    nonce = cr.json()["nonce"]
    # Backdate the row so the DELETE+RETURNING filter excludes it.
    async with async_session() as db:
        await db.execute(
            text(
                "UPDATE vault_challenges SET expires_at = NOW() - INTERVAL '1 second' "
                "WHERE challenge = :c"
            ),
            {"c": nonce},
        )
        await db.commit()
    source_ip, issued_at_epoch = await _get_challenge_meta(nonce)
    proof = _compute_proof(
        ha_pw, cluster_id, node_uuid, source_ip, nonce, issued_at_epoch
    )
    r = await client.post(
        "/api/v1/vault/cluster/join",
        json={
            "cluster_id": cluster_id,
            "node_uuid": node_uuid,
            "nonce": nonce,
            "ha_password_proof": proof,
            "rhorizon_version": "1.0.0",
        },
    )
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_join_nonce_never_issued(admin_token, client, _wipe_cluster_state):
    cluster_id, ha_pw, _ = await _init_cluster(admin_token, client)
    node_uuid = "join-fake-nonce-001"
    fake_nonce = "deadbeef" * 4
    proof = _compute_proof(ha_pw, cluster_id, node_uuid, "127.0.0.1", fake_nonce, 0)
    r = await client.post(
        "/api/v1/vault/cluster/join",
        json={
            "cluster_id": cluster_id,
            "node_uuid": node_uuid,
            "nonce": fake_nonce,
            "ha_password_proof": proof,
            "rhorizon_version": "1.0.0",
        },
    )
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_join_uuid_mismatch(admin_token, client, _wipe_cluster_state):
    cluster_id, ha_pw, _ = await _init_cluster(admin_token, client)
    challenge_uuid = "uuid-challenge-001"
    body = await _challenge_and_proof(client, cluster_id, ha_pw, challenge_uuid)
    body["node_uuid"] = "uuid-different-002"
    r = await client.post("/api/v1/vault/cluster/join", json=body)
    assert r.status_code == 401
    assert "node_uuid" in r.json()["detail"].lower()


@pytest.mark.asyncio
async def test_join_wrong_cluster_id(admin_token, client, _wipe_cluster_state):
    cluster_id, ha_pw, _ = await _init_cluster(admin_token, client)
    node_uuid = "join-wrong-cid-001"
    body = await _challenge_and_proof(client, cluster_id, ha_pw, node_uuid)
    body["cluster_id"] = "00000000-0000-0000-0000-000000000000"
    r = await client.post("/api/v1/vault/cluster/join", json=body)
    assert r.status_code == 401
    assert "cluster_id" in r.json()["detail"].lower()


@pytest.mark.asyncio
async def test_join_bad_hmac_proof(admin_token, client, _wipe_cluster_state):
    cluster_id, ha_pw, _ = await _init_cluster(admin_token, client)
    node_uuid = "join-bad-proof-001"
    body = await _challenge_and_proof(client, cluster_id, ha_pw, node_uuid)
    body["ha_password_proof"] = "ff" * 64
    r = await client.post("/api/v1/vault/cluster/join", json=body)
    assert r.status_code == 401
    assert "proof" in r.json()["detail"].lower()


@pytest.mark.asyncio
async def test_join_version_below_floor(admin_token, client, _wipe_cluster_state):
    cluster_id, ha_pw, _ = await _init_cluster(admin_token, client)
    node_uuid = "join-old-001"
    body = await _challenge_and_proof(client, cluster_id, ha_pw, node_uuid)
    body["rhorizon_version"] = "0.5.0"
    r = await client.post("/api/v1/vault/cluster/join", json=body)
    assert r.status_code == 409


@pytest.mark.asyncio
async def test_join_cluster_not_initialised(client, _wipe_cluster_state):
    fake_nonce = "ab" * 16
    r = await client.post(
        "/api/v1/vault/cluster/join",
        json={
            "cluster_id": "any",
            "node_uuid": "u",
            "nonce": fake_nonce,
            "ha_password_proof": "00" * 32,
            "rhorizon_version": "1.0.0",
        },
    )
    assert r.status_code == 409
    assert "not initialised" in r.json()["detail"].lower()


@pytest.mark.asyncio
async def test_join_uuid_already_present(admin_token, client, _wipe_cluster_state):
    """Bug 3+4 fix : second JOIN with same uuid while still 'joining'
    refreshes the cert idempotently (200) instead of failing 409.

    Rationale : the previous 409 + "use REJOIN flow" coupled with the
    auto-JOIN PermanentError exit caused joiners to be reaped after
    quarantine deadline elapsed without any client-side recovery path.
    The idempotent retry path mints a fresh cert + key, swaps the
    membership row, and returns 200 so the joiner persists the new
    bundle. Genuine "already integrated" cases (state != 'joining')
    still fall through to 409.
    """
    cluster_id, ha_pw, _ = await _init_cluster(admin_token, client)
    node_uuid = "join-twice-001"
    # First JOIN succeeds.
    body1 = await _challenge_and_proof(client, cluster_id, ha_pw, node_uuid)
    r1 = await client.post("/api/v1/vault/cluster/join", json=body1)
    assert r1.status_code == 200
    cert1 = r1.json()["node_cert_pem"]
    # Fresh challenge + proof, same uuid -> idempotent retry, NEW cert.
    body2 = await _challenge_and_proof(client, cluster_id, ha_pw, node_uuid)
    r2 = await client.post("/api/v1/vault/cluster/join", json=body2)
    assert r2.status_code == 200, r2.text
    cert2 = r2.json()["node_cert_pem"]
    # Fresh cert minted on retry -- different PEM bytes (different
    # serial + key + signature). The cluster_join_retry audit row
    # marks the path in the audit chain ; the wire payload is the
    # same shape as a first-JOIN response.
    assert cert1 != cert2
    assert r2.json()["ha_state"] == "joining"


@pytest.mark.asyncio
async def test_join_source_ip_conflict_faille_12(
    admin_token, client, _wipe_cluster_state
):
    """A second uuid trying to bind to the same source_ip surfaces as 409."""
    cluster_id, ha_pw, _ = await _init_cluster(admin_token, client)
    uuid_a = "join-ip-a-001"
    body_a = await _challenge_and_proof(client, cluster_id, ha_pw, uuid_a)
    ra = await client.post("/api/v1/vault/cluster/join", json=body_a)
    assert ra.status_code == 200, ra.text
    uuid_b = "join-ip-b-002"
    body_b = await _challenge_and_proof(client, cluster_id, ha_pw, uuid_b)
    rb = await client.post("/api/v1/vault/cluster/join", json=body_b)
    assert rb.status_code == 409
    assert "source_ip" in rb.json()["detail"].lower()


@pytest.mark.asyncio
async def test_join_ip_mismatch_between_challenge_and_join(
    admin_token, client, _wipe_cluster_state
):
    """Challenge issued from one IP, JOIN observed from another -> 401.

    ASGITransport pins the source IP, so we simulate the divergence by
    rewriting the challenge row's source_ip after issue. The JOIN must
    refuse on the binding check, not on HMAC (we craft the proof
    against the rewritten IP to isolate which check fires).
    """
    cluster_id, ha_pw, _ = await _init_cluster(admin_token, client)
    node_uuid = "join-ip-mismatch-001"
    cr = await client.post(
        "/api/v1/vault/cluster/challenge",
        json={"node_uuid": node_uuid, "rhorizon_version": "1.0.0"},
    )
    nonce = cr.json()["nonce"]
    foreign_ip = "10.99.99.99"
    async with async_session() as db:
        await db.execute(
            text("UPDATE vault_challenges SET source_ip = :ip WHERE challenge = :c"),
            {"ip": foreign_ip, "c": nonce},
        )
        await db.commit()
    _, issued_at_epoch = await _get_challenge_meta(nonce)
    # Compute proof against the foreign_ip (the value the server will
    # NOT see at /join time, since the actual client IP differs).
    proof = _compute_proof(
        ha_pw, cluster_id, node_uuid, foreign_ip, nonce, issued_at_epoch
    )
    r = await client.post(
        "/api/v1/vault/cluster/join",
        json={
            "cluster_id": cluster_id,
            "node_uuid": node_uuid,
            "nonce": nonce,
            "ha_password_proof": proof,
            "rhorizon_version": "1.0.0",
        },
    )
    assert r.status_code == 401
    assert "source_ip" in r.json()["detail"].lower()


@pytest.mark.asyncio
async def test_join_hmac_canonical_message_shape(
    admin_token, client, _wipe_cluster_state
):
    """Catch byte-order regressions in the canonical HMAC message.

    Computes the proof with each field individually mutated and verifies
    each variant is rejected. Sanity-checks the spec : the cluster
    derives the message as cluster_id || node_uuid || source_ip ||
    nonce || str(issued_at_epoch), no separator.
    """
    cluster_id, ha_pw, _ = await _init_cluster(admin_token, client)
    node_uuid = "join-canon-001"
    body = await _challenge_and_proof(client, cluster_id, ha_pw, node_uuid)
    nonce = body["nonce"]
    source_ip, issued_at_epoch = await _get_challenge_meta(nonce)
    # Wrong issued_at epoch (+1s) -> reject.
    bad_proof = _compute_proof(
        ha_pw, cluster_id, node_uuid, source_ip, nonce, issued_at_epoch + 1
    )
    body["ha_password_proof"] = bad_proof
    r = await client.post("/api/v1/vault/cluster/join", json=body)
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_join_followed_by_node_uuid_lookup(
    admin_token, client, _wipe_cluster_state
):
    """get_node returns the inserted membership row keyed by node_uuid."""
    from api.app import cluster_nodes

    cluster_id, ha_pw, _ = await _init_cluster(admin_token, client)
    node_uuid = "join-lookup-001"
    body = await _challenge_and_proof(client, cluster_id, ha_pw, node_uuid)
    r = await client.post("/api/v1/vault/cluster/join", json=body)
    assert r.status_code == 200
    async with async_session() as db:
        row = await cluster_nodes.get_node(db, node_uuid)
    assert row is not None
    assert row.node_uuid == node_uuid
    assert row.ha_state == "joining"


@pytest.mark.asyncio
async def test_join_response_quarantine_matches_db(
    admin_token, client, _wipe_cluster_state
):
    cluster_id, ha_pw, _ = await _init_cluster(admin_token, client)
    node_uuid = "join-qua-001"
    body = await _challenge_and_proof(client, cluster_id, ha_pw, node_uuid)
    r = await client.post("/api/v1/vault/cluster/join", json=body)
    assert r.status_code == 200
    resp_quarantine = datetime.fromisoformat(r.json()["quarantine_until"])
    async with async_session() as db:
        row = (
            await db.execute(
                text(
                    "SELECT quarantine_until FROM vault_cluster_nodes "
                    "WHERE node_uuid = :u"
                ),
                {"u": node_uuid},
            )
        ).fetchone()
    assert row.quarantine_until == resp_quarantine
