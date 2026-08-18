"""Signed, per-node sealed-box rekey envelope.

Covers the publish (master) + consume (peer) crypto and the heartbeat
roll-forward adoption :

- publish_envelope writes a shared row ('*') + one sealed per-recipient row,
  excludes self / evicted / revoked, and supersedes older generations.
- A recipient with the matching X25519 private key recovers the bundle ; the
  Ed25519 signature verifies against the on-disk CA-signed signer cert.
- consume_envelope returns the validated bundle ONLY when origin auth (CA +
  signature), the sealed box, the AEAD, and the master_check all check out ;
  it REJECTS a forged signature, a wrong recipient, and a master_check
  mismatch (a DB-write attacker can neither read nor inject keys -- I1/I2).
- The roll-forward body adopts the bundle in place and tears down its own row.
- Teardown : superseded epochs leave no rows.

These exercise the crypto/verification core directly. The Shamir re-split +
follower RPC refresh inside the roll-forward path are no-op'd by the conftest
``_bypass_cluster_ipc`` autouse fixture (single-worker test).
"""

import os
from pathlib import Path

import pytest
import pytest_asyncio
from api.app import cluster_ca
from api.app.cluster_ha_loops import _rekey_republish_body, _rekey_roll_forward_body
from api.app.cluster_rekey import (
    SHARED_ROW_UUID,
    _aad,
    _signed_digest,
    consume_envelope,
    publish_envelope,
)
from api.app.config import settings
from api.app.crypto import derive_keys, derive_master_key
from api.app.database import async_session
from api.app.node_uuid import init_node_uuid
from api.app.vault_state import vault
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from nacl.public import PrivateKey, PublicKey, SealedBox
from sqlalchemy import text

_CLUSTER_ID = "test-cluster-id"
_TEST_IP = "203.0.113.55"

# Faille-12 (vault_cluster_nodes_active_ip): one active node per source_ip.
# Tests insert several nodes, so auto-assign a distinct IP per node in the doc
# /24 (recipient/renewal logic keys on node_uuid, not IP). Explicit ip= still
# overrides (e.g. self pinned to _TEST_IP). Cleanup reaps the whole /24.
_ip_seq = [99]  # next() yields .100, .101, ... (avoids _TEST_IP=.55)


def _next_ip() -> str:
    _ip_seq[0] += 1
    return f"203.0.113.{_ip_seq[0]}"


@pytest_asyncio.fixture(autouse=True)
async def _isolate_synthetic_epoch():
    """Keep this file's fabricated epochs out of the session-wide audit chain.

    Every test here pokes the GLOBAL ``vault_config['key_epoch']`` counter to a
    synthetic value (via ``_set_db_epoch``) and adopts the *real* current keys
    as a stand-in for that epoch's bundle -- a desync that only exists in the
    test. Two ways it leaks into the shared session DB and false-breaks
    ``/audit/verify`` (test_security.py::test_audit_chain_not_broken) for every
    later test:

    1. The stale counter mis-tags audit rows that the function-scoped
       ``admin_token`` unseal writes for the *next* test -- signed with the real
       audit_key but tagged with the synthetic epoch, so verify recomputes them
       with the wrong archived key.
    2. The roll-forward path itself logs ``cluster_node_rolled_forward`` while
       the counter is poked, tagged synthetic-epoch / signed real-key.

    So we snapshot the epoch AND the audit tail before each test, then restore
    the counter and drop every audit row this test appended. The dropped rows
    are always a contiguous tail (single-threaded run) and teardown precedes the
    next test's setup, so the surviving chain stays linear and verifiable.
    """
    async with async_session() as db:
        epoch_row = (
            await db.execute(
                text("SELECT value FROM vault_config WHERE key = 'key_epoch'")
            )
        ).fetchone()
        orig_epoch = epoch_row.value if epoch_row else None
        wm_row = (
            await db.execute(text("SELECT max(timestamp) AS wm FROM vault_audit"))
        ).fetchone()
        watermark = wm_row.wm
    yield
    async with async_session() as db:
        if watermark is None:
            await db.execute(text("DELETE FROM vault_audit"))
        else:
            await db.execute(
                text("DELETE FROM vault_audit WHERE timestamp > :wm"),
                {"wm": watermark},
            )
        if orig_epoch is None:
            await db.execute(text("DELETE FROM vault_config WHERE key = 'key_epoch'"))
        else:
            await db.execute(
                text(
                    "INSERT INTO vault_config (key, value) VALUES ('key_epoch', :v) "
                    "ON CONFLICT (key) DO UPDATE SET value = :v"
                ),
                {"v": orig_epoch},
            )
        await db.commit()


# -- low-level DB helpers --------------------------------------------------


async def _get(db, table, key):
    row = (
        await db.execute(
            text(f"SELECT value FROM {table} WHERE key = :k"),  # noqa: S608
            {"k": key},
        )
    ).fetchone()
    return row.value if row else None


async def _set(db, table, key, value):
    await db.execute(
        text(
            f"INSERT INTO {table} (key, value) VALUES (:k, :v) "  # noqa: S608
            "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value"
        ),
        {"k": key, "v": value},
    )


async def _set_db_epoch(db, value):
    await _set(db, "vault_config", "key_epoch", str(value))


async def _insert_node(db, node_uuid, pub, state="secondary", ip=None):
    if ip is None:
        ip = _next_ip()
    await db.execute(
        text("DELETE FROM vault_cluster_nodes WHERE node_uuid = :u"),
        {"u": node_uuid},
    )
    await db.execute(
        text(
            "INSERT INTO vault_cluster_nodes "
            "(node_uuid, source_ip, ha_state, cluster_version, cert_fingerprint, "
            " cert_not_after, rekey_pub) "
            "VALUES (:u, :ip, :s, '1', 'fp', NOW() + INTERVAL '90 days', :p)"
        ),
        {"u": node_uuid, "ip": ip, "s": state, "p": pub},
    )


async def _envelope_rows(db, epoch):
    rows = (
        await db.execute(
            text(
                "SELECT node_uuid FROM vault_rekey_envelope WHERE key_epoch = :e "
                "ORDER BY node_uuid"
            ),
            {"e": epoch},
        )
    ).fetchall()
    return [r.node_uuid for r in rows]


async def _real_bundle(db, password):
    """Derive the current generation's 128B bundle so master_check passes."""
    salt = bytes.fromhex(await _get(db, "vault_config", "argon2_salt"))
    ver = await _get(db, "vault_config", "dek_key_version")
    ver = int(ver) if ver else 1
    mk = derive_master_key(password.encode(), salt)
    k = derive_keys(mk, ver)
    return bytearray(
        k["hmac_key"]
        + k["dek_key"]
        + k["audit_key"]
        + k["ha_wrap_key"]
        + k["pki_wrap_key"]
    )


def _craft_rows(
    epoch, recipient_uuid, recipient_pub, bundle, signer_key, signer_cert_pem
):
    """Build (shared_row, node_row) tuples the way publish does -- for crafting
    consume inputs directly (incl. adversarial variants)."""
    k = os.urandom(32)
    nonce = os.urandom(12)
    ct = AESGCM(k).encrypt(nonce, bytes(bundle), _aad(_CLUSTER_ID, epoch))
    blob = nonce + ct
    sig = signer_key.sign(_signed_digest(_CLUSTER_ID, epoch, blob))
    wrapped = SealedBox(PublicKey(recipient_pub)).encrypt(k)
    shared = {
        "e": epoch,
        "u": SHARED_ROW_UUID,
        "blob": blob,
        "sig": sig,
        "cert": signer_cert_pem.decode("ascii"),
    }
    node = {"e": epoch, "u": recipient_uuid, "w": wrapped}
    return shared, node


async def _write_rows(db, shared, node):
    await db.execute(
        text(
            "INSERT INTO vault_rekey_envelope "
            "(key_epoch, node_uuid, blob, sig, signer_cert) "
            "VALUES (:e, :u, :blob, :sig, :cert)"
        ),
        shared,
    )
    await db.execute(
        text(
            "INSERT INTO vault_rekey_envelope (key_epoch, node_uuid, wrapped_k) "
            "VALUES (:e, :u, :w)"
        ),
        node,
    )


# -- fixture : a real cluster identity (CA in DB, node cert on disk) --------


@pytest_asyncio.fixture
async def cluster_identity(admin_token):
    """Mint a cluster CA, store it, sign this node's cert to disk, set cluster_id.

    Yields dict with node_uuid, ca cert/key, signer key, and signer cert PEM.
    Cleans up cert files + envelope rows + test config/node rows after.
    """
    node_uuid = init_node_uuid(os.environ["RHORIZON_NODE_UUID_PATH"])
    ca_cert, ca_key, _fpr = cluster_ca.mint_cluster_ca(
        common_name="test-cluster", validity_days=30
    )
    cert_pem, key_pem = cluster_ca.sign_node_cert(
        ca_cert, ca_key, node_uuid, _TEST_IP, validity_days=30
    )
    # A prior cluster-init test may have left 0400 (read-only) files here;
    # unlink before writing so the overwrite does not hit EACCES.
    Path(settings.cluster_cert_path).unlink(missing_ok=True)
    Path(settings.cluster_cert_key_path).unlink(missing_ok=True)
    Path(settings.cluster_cert_path).write_bytes(cert_pem)
    Path(settings.cluster_cert_key_path).write_bytes(key_pem)
    signer_key = cluster_ca.parse_key(key_pem)

    async with async_session() as db:
        await _set(db, "vault_cluster_config", "cluster_id", _CLUSTER_ID)
        await _set(
            db, "vault_cluster_config", "cluster_ca_cert", ca_cert.decode("ascii")
        )
        await db.commit()

    yield {
        "node_uuid": node_uuid,
        "ca_cert": ca_cert,
        "ca_key": ca_key,
        "signer_key": signer_key,
        "signer_cert_pem": cert_pem,
    }

    for p in (settings.cluster_cert_path, settings.cluster_cert_key_path):
        Path(p).unlink(missing_ok=True)
    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_rekey_envelope"))
        await db.execute(
            text(
                "DELETE FROM vault_cluster_nodes "
                "WHERE source_ip << CAST('203.0.113.0/24' AS INET)"
            ),
        )
        await db.execute(
            text(
                "DELETE FROM vault_cluster_config WHERE key IN "
                "('cluster_id', 'cluster_ca_cert')"
            )
        )
        await db.commit()


# -- publish ---------------------------------------------------------------


@pytest.mark.asyncio
async def test_publish_writes_shared_and_recipient_rows(
    cluster_identity, master_password
):
    """A live peer with a rekey_pub gets a sealed row + a verifiable shared row."""
    peer_priv = PrivateKey.generate()
    peer_pub = bytes(peer_priv.public_key.encode())
    async with async_session() as db:
        await _insert_node(db, "peer-A", peer_pub)
        await db.commit()
        bundle = await _real_bundle(db, master_password)
        written = await publish_envelope(db, bytearray(bundle), epoch=7)

    assert written == 1
    async with async_session() as db:
        assert sorted(await _envelope_rows(db, 7)) == [SHARED_ROW_UUID, "peer-A"]
        shared = (
            await db.execute(
                text(
                    "SELECT blob, sig, signer_cert FROM vault_rekey_envelope "
                    "WHERE key_epoch = 7 AND node_uuid = :u"
                ),
                {"u": SHARED_ROW_UUID},
            )
        ).fetchone()
        node = (
            await db.execute(
                text(
                    "SELECT wrapped_k FROM vault_rekey_envelope "
                    "WHERE key_epoch = 7 AND node_uuid = 'peer-A'"
                )
            )
        ).fetchone()

    # Origin auth : the on-disk signer cert's pubkey verifies the signature.
    cert = x509.load_pem_x509_certificate(shared.signer_cert.encode("ascii"))
    cert.public_key().verify(
        bytes(shared.sig), _signed_digest(_CLUSTER_ID, 7, bytes(shared.blob))
    )
    # Possession : the peer's private key opens K, K decrypts the blob -> bundle.
    k = SealedBox(peer_priv).decrypt(bytes(node.wrapped_k))
    blob = bytes(shared.blob)
    recovered = AESGCM(k).decrypt(blob[:12], blob[12:], _aad(_CLUSTER_ID, 7))
    assert recovered == bytes(bundle)


@pytest.mark.asyncio
async def test_publish_excludes_self_evicted_revoked(cluster_identity, master_password):
    self_uuid = cluster_identity["node_uuid"]
    good = PrivateKey.generate()
    async with async_session() as db:
        await _insert_node(
            db, self_uuid, bytes(PrivateKey.generate().public_key.encode())
        )
        await _insert_node(
            db,
            "peer-evicted",
            bytes(PrivateKey.generate().public_key.encode()),
            state="evicted",
        )
        await _insert_node(db, "peer-good", bytes(good.public_key.encode()))
        # revoke a 4th live peer
        await _insert_node(
            db, "peer-revoked", bytes(PrivateKey.generate().public_key.encode())
        )
        await _set(db, "vault_cluster_config", "revoked_node_uuids", '["peer-revoked"]')
        await db.commit()
        written = await publish_envelope(
            db, await _real_bundle(db, master_password), epoch=3
        )

    assert written == 1  # only peer-good
    async with async_session() as db:
        assert sorted(await _envelope_rows(db, 3)) == [SHARED_ROW_UUID, "peer-good"]
    async with async_session() as db:
        await _set(db, "vault_cluster_config", "revoked_node_uuids", "[]")
        await db.commit()


@pytest.mark.asyncio
async def test_publish_keeps_self_when_follower_rotates(
    cluster_identity, master_password
):
    """a rotation that landed on a FOLLOWER leaves the host's master
    (same node_uuid) holding the OLD generation. publish_envelope must KEEP self
    in the recipient set (rotator_is_master=False) so that master rolls forward
    -- the historical unconditional self-exclusion stranded the rotating host
    (no envelope -> _rekey_roll_forward_body finds nothing -> fence quarantine).
    """
    self_uuid = cluster_identity["node_uuid"]
    self_priv = PrivateKey.generate()
    async with async_session() as db:
        # self is the ONLY node : with the old exclusion this would write 0 rows.
        await _insert_node(
            db, self_uuid, bytes(self_priv.public_key.encode()), ip=_TEST_IP
        )
        await db.commit()
        bundle = await _real_bundle(db, master_password)
        written = await publish_envelope(
            db, bytearray(bundle), epoch=8, rotator_is_master=False
        )

    assert written == 1  # self kept as a recipient
    async with async_session() as db:
        assert sorted(await _envelope_rows(db, 8)) == [SHARED_ROW_UUID, self_uuid]
        node = (
            await db.execute(
                text(
                    "SELECT wrapped_k FROM vault_rekey_envelope "
                    "WHERE key_epoch = 8 AND node_uuid = :u"
                ),
                {"u": self_uuid},
            )
        ).fetchone()
    # The host master opens its own envelope -> it would roll forward to the new
    # generation instead of stranding.
    k = SealedBox(self_priv).decrypt(bytes(node.wrapped_k))
    assert len(k) == 32


@pytest.mark.asyncio
async def test_publish_supersedes_older_epochs(cluster_identity, master_password):
    peer_pub = bytes(PrivateKey.generate().public_key.encode())
    async with async_session() as db:
        await _insert_node(db, "peer-A", peer_pub)
        await db.commit()
        await publish_envelope(db, await _real_bundle(db, master_password), epoch=5)
        async with async_session() as db2:
            assert await _envelope_rows(db2, 5)  # epoch 5 present
        await publish_envelope(db, await _real_bundle(db, master_password), epoch=6)

    async with async_session() as db:
        assert await _envelope_rows(db, 5) == []  # superseded
        assert sorted(await _envelope_rows(db, 6)) == [SHARED_ROW_UUID, "peer-A"]


@pytest.mark.asyncio
async def test_publish_skips_when_no_cluster_id(cluster_identity, master_password):
    async with async_session() as db:
        await db.execute(
            text("DELETE FROM vault_cluster_config WHERE key = 'cluster_id'")
        )
        await _insert_node(
            db, "peer-A", bytes(PrivateKey.generate().public_key.encode())
        )
        await db.commit()
        written = await publish_envelope(
            db, await _real_bundle(db, master_password), epoch=2
        )
    assert written == 0
    async with async_session() as db:
        assert await _envelope_rows(db, 2) == []


# -- consume ---------------------------------------------------------------


@pytest.mark.asyncio
async def test_consume_returns_bundle_on_valid_envelope(
    cluster_identity, master_password
):
    """End-to-end : a verified envelope yields the exact bundle."""
    vpub = vault.ensure_rekey_keypair()
    async with async_session() as db:
        bundle = await _real_bundle(db, master_password)
        shared, node = _craft_rows(
            9,
            "me-peer",
            vpub,
            bundle,
            cluster_identity["signer_key"],
            cluster_identity["signer_cert_pem"],
        )
        await _set_db_epoch(db, 9)
        await _write_rows(db, shared, node)
        await db.commit()
    vault.set_key_epoch(8)  # we lag by one generation

    async with async_session() as db:
        out = await consume_envelope(db, "me-peer")
    assert out is not None
    assert bytes(out) == bytes(bundle)


@pytest.mark.asyncio
async def test_consume_none_when_already_current(cluster_identity, master_password):
    vpub = vault.ensure_rekey_keypair()
    async with async_session() as db:
        bundle = await _real_bundle(db, master_password)
        shared, node = _craft_rows(
            4,
            "me-peer",
            vpub,
            bundle,
            cluster_identity["signer_key"],
            cluster_identity["signer_cert_pem"],
        )
        await _set_db_epoch(db, 4)
        await _write_rows(db, shared, node)
        await db.commit()
    vault.set_key_epoch(4)  # already current -- nothing to roll
    async with async_session() as db:
        assert await consume_envelope(db, "me-peer") is None


@pytest.mark.asyncio
async def test_consume_none_when_no_row(cluster_identity):
    async with async_session() as db:
        await _set_db_epoch(db, 11)
        await db.commit()
    vault.set_key_epoch(10)
    async with async_session() as db:
        assert await consume_envelope(db, "me-peer") is None  # fence will quarantine


@pytest.mark.asyncio
async def test_consume_none_when_sig_null(cluster_identity, master_password):
    """A DB-write attacker crafts a shared row with blob present but sig +
    signer_cert NULL. consume must fail closed (None -> fence), not raise out
    of bytes(shared.sig) (which used to escape uncaught)."""
    vpub = vault.ensure_rekey_keypair()
    async with async_session() as db:
        bundle = await _real_bundle(db, master_password)
        shared, node = _craft_rows(
            13,
            "me-peer",
            vpub,
            bundle,
            cluster_identity["signer_key"],
            cluster_identity["signer_cert_pem"],
        )
        await _set_db_epoch(db, 13)
        await db.execute(
            text(
                "INSERT INTO vault_rekey_envelope "
                "(key_epoch, node_uuid, blob, sig, signer_cert) "
                "VALUES (:e, :u, :blob, NULL, NULL)"
            ),
            {"e": 13, "u": SHARED_ROW_UUID, "blob": shared["blob"]},
        )
        await db.execute(
            text(
                "INSERT INTO vault_rekey_envelope (key_epoch, node_uuid, wrapped_k) "
                "VALUES (:e, :u, :w)"
            ),
            node,
        )
        await db.commit()
    vault.set_key_epoch(12)
    async with async_session() as db:
        assert await consume_envelope(db, "me-peer") is None


@pytest.mark.asyncio
async def test_consume_rejects_forged_signature(cluster_identity, master_password):
    """A DB-write attacker crafts a blob (and could match master_check) but
    cannot forge the master's signature -> rejected (invariant I2 origin auth)."""
    vpub = vault.ensure_rekey_keypair()
    forged_key = Ed25519PrivateKey.generate()  # not the CA-signed identity
    async with async_session() as db:
        bundle = await _real_bundle(db, master_password)
        # Sign with the foreign key, but present the REAL CA-signed cert :
        # the signature will not verify against that cert's pubkey.
        shared, node = _craft_rows(
            6,
            "me-peer",
            vpub,
            bundle,
            forged_key,
            cluster_identity["signer_cert_pem"],
        )
        await _set_db_epoch(db, 6)
        await _write_rows(db, shared, node)
        await db.commit()
    vault.set_key_epoch(5)
    async with async_session() as db:
        assert await consume_envelope(db, "me-peer") is None


@pytest.mark.asyncio
async def test_consume_rejects_unca_signed_cert(cluster_identity, master_password):
    """A self-signed (non-CA) signer cert is rejected even if its own sig is
    internally consistent."""
    rogue_key = Ed25519PrivateKey.generate()
    rogue_cert, rogue_keypem, _ = cluster_ca.mint_cluster_ca(
        common_name="rogue", validity_days=30
    )
    rogue_signer = cluster_ca.parse_key(rogue_keypem)
    vpub = vault.ensure_rekey_keypair()
    async with async_session() as db:
        bundle = await _real_bundle(db, master_password)
        shared, node = _craft_rows(6, "me-peer", vpub, bundle, rogue_signer, rogue_cert)
        await _set_db_epoch(db, 6)
        await _write_rows(db, shared, node)
        await db.commit()
    vault.set_key_epoch(5)
    async with async_session() as db:
        assert await consume_envelope(db, "me-peer") is None
    del rogue_key


@pytest.mark.asyncio
async def test_consume_rejects_wrong_recipient(cluster_identity, master_password):
    """K sealed to a different node's pubkey cannot be opened -> rejected."""
    vault.ensure_rekey_keypair()
    other_pub = bytes(PrivateKey.generate().public_key.encode())  # not ours
    async with async_session() as db:
        bundle = await _real_bundle(db, master_password)
        shared, node = _craft_rows(
            6,
            "me-peer",
            other_pub,
            bundle,
            cluster_identity["signer_key"],
            cluster_identity["signer_cert_pem"],
        )
        await _set_db_epoch(db, 6)
        await _write_rows(db, shared, node)
        await db.commit()
    vault.set_key_epoch(5)
    async with async_session() as db:
        assert await consume_envelope(db, "me-peer") is None


@pytest.mark.asyncio
async def test_consume_rejects_master_check_mismatch(cluster_identity):
    """Valid sig + valid recipient but a bundle whose hmac_key does not match
    the DB master_check -> rejected (belt-and-braces self-consistency)."""
    vpub = vault.ensure_rekey_keypair()
    garbage = bytearray(os.urandom(128))  # hmac_key won't match master_check
    async with async_session() as db:
        shared, node = _craft_rows(
            6,
            "me-peer",
            vpub,
            garbage,
            cluster_identity["signer_key"],
            cluster_identity["signer_cert_pem"],
        )
        await _set_db_epoch(db, 6)
        await _write_rows(db, shared, node)
        await db.commit()
    vault.set_key_epoch(5)
    async with async_session() as db:
        assert await consume_envelope(db, "me-peer") is None


# -- roll-forward adoption (heartbeat body) --------------------------------


@pytest.mark.asyncio
async def test_roll_forward_adopts_and_tears_down_row(
    cluster_identity, master_password
):
    """_rekey_roll_forward_body adopts the bundle in place, advances the
    in-RAM epoch, and DELETEs its own envelope row."""
    node_uuid = cluster_identity["node_uuid"]
    vpub = vault.ensure_rekey_keypair()  # fix the pub we seal to
    async with async_session() as db:
        bundle = await _real_bundle(db, master_password)
        await _insert_node(db, node_uuid, vpub, ip=_TEST_IP)
        shared, node = _craft_rows(
            12,
            node_uuid,
            vpub,
            bundle,
            cluster_identity["signer_key"],
            cluster_identity["signer_cert_pem"],
        )
        await _set_db_epoch(db, 12)
        await _write_rows(db, shared, node)
        await db.commit()
    vault.set_key_epoch(11)  # lag by one

    # Provision the audit identity first so we can prove the roll-forward
    # (seal() -> unseal()) RELOADS it rather than leaving the node on hmac.
    from api.app.audit_identity import ensure_audit_chain_identity

    async with async_session() as db:
        await ensure_audit_chain_identity(db)
    assert vault.has_audit_identity

    async with async_session() as db:
        result = await _rekey_roll_forward_body(db, node_uuid)

    assert result == "rolled_forward"
    assert vault.key_epoch == 12
    # seal() during roll-forward dropped the signer; the reload restored it, so
    # the node keeps writing ed25519 (not hmac_fallback) after rolling forward.
    assert vault.has_audit_identity
    async with async_session() as db:
        # Per-row teardown : our row is gone (shared row may remain for the reaper).
        mine = (
            await db.execute(
                text(
                    "SELECT 1 FROM vault_rekey_envelope "
                    "WHERE key_epoch = 12 AND node_uuid = :u"
                ),
                {"u": node_uuid},
            )
        ).fetchone()
        assert mine is None


@pytest.mark.asyncio
async def test_roll_forward_noop_when_no_envelope(cluster_identity):
    """No envelope row -> body returns None (the fence then quarantines)."""
    node_uuid = cluster_identity["node_uuid"]
    vault.ensure_rekey_keypair()
    async with async_session() as db:
        await _insert_node(db, node_uuid, vault.rekey_public_key, ip=_TEST_IP)
        await _set_db_epoch(db, 20)
        await db.commit()
    vault.set_key_epoch(19)
    async with async_session() as db:
        assert await _rekey_roll_forward_body(db, node_uuid) is None


# -- red-timing reconciler (primary re-seals for behind peers) --------------


@pytest.mark.asyncio
async def test_republish_reseals_for_behind_quarantined_peer(
    cluster_identity, master_password
):
    """A peer that quarantined behind (published its rekey_pub only after the
    one-shot publish, so it has no envelope row) gets a fresh current-epoch row
    when the primary re-seals -- it can then roll forward without waiting for
    the next rotation (the D3/SH red-timing fix)."""
    self_uuid = cluster_identity["node_uuid"]
    vpub = vault.ensure_rekey_keypair()
    peer_pub = bytes(PrivateKey.generate().public_key.encode())
    async with async_session() as db:
        await _insert_node(db, self_uuid, vpub, state="primary", ip=_TEST_IP)
        await _insert_node(db, "peer-behind", peer_pub, state="quarantined")
        await _set_db_epoch(db, 5)
        await db.commit()
    vault.set_key_epoch(5)  # primary is current

    async with async_session() as db:
        assert "peer-behind" not in await _envelope_rows(db, 5)  # the gap
        sealed = await _rekey_republish_body(db, self_uuid)

    assert sealed == 1
    async with async_session() as db:
        assert sorted(await _envelope_rows(db, 5)) == [SHARED_ROW_UUID, "peer-behind"]


@pytest.mark.asyncio
async def test_republish_noop_when_no_behind_peer(cluster_identity, master_password):
    """Converged cluster (peer secondary, not quarantined) -> no re-seal, no churn."""
    self_uuid = cluster_identity["node_uuid"]
    vpub = vault.ensure_rekey_keypair()
    async with async_session() as db:
        await _insert_node(db, self_uuid, vpub, state="primary", ip=_TEST_IP)
        await _insert_node(
            db,
            "peer-ok",
            bytes(PrivateKey.generate().public_key.encode()),
            state="secondary",
        )
        await _set_db_epoch(db, 5)
        await db.commit()
    vault.set_key_epoch(5)
    async with async_session() as db:
        assert await _rekey_republish_body(db, self_uuid) == 0
        assert await _envelope_rows(db, 5) == []


@pytest.mark.asyncio
async def test_republish_noop_when_not_primary(cluster_identity, master_password):
    """Only the primary reconciles -- a secondary master does not re-seal even
    with a behind peer (single-owner, no thundering herd)."""
    self_uuid = cluster_identity["node_uuid"]
    vpub = vault.ensure_rekey_keypair()
    async with async_session() as db:
        await _insert_node(db, self_uuid, vpub, state="secondary", ip=_TEST_IP)
        await _insert_node(
            db,
            "peer-behind",
            bytes(PrivateKey.generate().public_key.encode()),
            state="quarantined",
        )
        await _set_db_epoch(db, 5)
        await db.commit()
    vault.set_key_epoch(5)
    async with async_session() as db:
        assert await _rekey_republish_body(db, self_uuid) == 0
        assert await _envelope_rows(db, 5) == []
