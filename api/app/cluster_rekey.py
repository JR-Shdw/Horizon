# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Signed, per-node sealed-box rekey envelope.

S1 (key_epoch fence) made a multi-host rotation observably-safe : a peer whose
in-RAM keys lag the rotated generation quarantines itself out of ``/readiness``
instead of serving 500s. But recovery was manual (operator re-unseal). This
module is the S2 roll-forward : after a NON-emergency rotation the master
publishes a temporary, signed, per-recipient envelope so live-but-stale peers
adopt the new generation automatically -- no operator action, no plaintext key
on the wire, and nothing recoverable from the DB alone.

Two security invariants make this sound (see shared/plan-ha-rekey-envelope.md) :

  I1  NEVER AN UNENCRYPTED KEY IN TRANSIT OR AT REST. The new key bundle exists
      only as (a) ciphertext under an ephemeral content key K (the ``blob`` at
      rest), (b) ciphertext sealed to a node's X25519 pubkey (per-peer
      ``wrapped_k``), or (c) live in one node's mlock'd RAM after local decrypt.

  I2  REAL 2FA WITH STRONG INDEPENDENCE. Adopting the new keys needs TWO secrets
      held by two parties : the recipient's X25519 private key (possession,
      RAM-only on that node) opens K, AND a valid Ed25519 signature from the
      rotating master -- verified against the cluster CA -- proves origin. A
      DB-write attacker can neither READ (no privkey) nor INJECT (no signature)
      keys. Dropping the signature collapses I2 -> DB-write becomes key
      substitution, so the signature is non-negotiable.

The envelope wraps the 160-byte sub-key bundle
``hmac||dek||audit||ha_wrap||pki_wrap``
(exactly :meth:`VaultState.export_subkeys_for_shamir` produces and
:meth:`VaultState.unseal` consumes), so it is rotation-type agnostic -- one path
covers ``rotate-password`` and ``rotate-dek-key`` alike, mirroring how keys
already cross hosts during Shamir failover.

This module is pure crypto + DB : :func:`publish_envelope` (master) writes rows,
:func:`consume_envelope` (peer) verifies and returns the validated bundle. The
in-RAM adoption (seal/unseal + Shamir re-split + follower RPC refresh) lives in
``cluster_ha_loops`` so this module does not import ``cluster_setup`` (no cycle).
"""

from __future__ import annotations

import hashlib
import logging
import os
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from rhorizon_crypto import rekey_seal, secure_zero
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from . import cluster_ca, cluster_cert, cluster_membership
from .config import settings
from .crypto import hmac_token
from .vault_state import vault

log = logging.getLogger("rhorizon.cluster_rekey")

# Shared-row sentinel : the single row per epoch that carries the bulk blob +
# Ed25519 signature + signer cert. Per-recipient rows use real node_uuids, none
# of which can be "*" (UUIDs are hex+dashes), so there is no collision.
SHARED_ROW_UUID = "*"

BUNDLE_LEN = 160  # hmac(32) || dek(32) || audit(32) || ha_wrap(32) || pki_wrap(32)
_AESGCM_NONCE_LEN = 12


def _aad(cluster_id: str, epoch: int) -> bytes:
    """Associated data binding the blob to one cluster + one generation.

    Binding ``cluster_id`` stops a blob from being replayed into a different
    cluster ; binding ``epoch`` stops a rollback replay of an older generation.
    """
    return f"vault-rekey:{cluster_id}:{epoch}".encode()


def _signed_digest(cluster_id: str, epoch: int, blob: bytes) -> bytes:
    """SHA-512 over (cluster_id || epoch || blob) -- the Ed25519 signed message.

    Same cluster_id/epoch binding as the AAD : the signature attests *this*
    blob, for *this* cluster, at *this* generation. Ed25519 hashes internally,
    but we sign the digest so the signed message stays a fixed 64 bytes.
    """
    h = hashlib.sha512()
    h.update(f"vault-rekey:{cluster_id}:{epoch}:".encode())
    h.update(blob)
    return h.digest()


async def _read_config(db: AsyncSession, table: str, key: str) -> str | None:
    row = (
        await db.execute(
            text(f"SELECT value FROM {table} WHERE key = :k"),  # noqa: S608 (table is a literal)
            {"k": key},
        )
    ).fetchone()
    return row.value if row else None


# -- master side -----------------------------------------------------------


async def publish_envelope(
    db: AsyncSession,
    bundle: bytearray,
    epoch: int,
    rotator_is_master: bool = True,
) -> int:
    """Seal ``bundle`` to every live peer and write the epoch's envelope rows.

    Called AFTER the rotation has committed (its own follow-up txn), NON-
    emergency only. ``bundle`` is the new generation's 160-byte
    ``hmac||dek||audit||ha_wrap`` ; the caller hands ownership over and this
    function ``secure_zero``'s it before returning.

    ``rotator_is_master`` -- whether the worker running this rotation is its
    host's key-holding master. ``rotate_password`` runs in whichever uvicorn
    worker the routing mesh picked, NOT necessarily the master. When the
    rotator IS the master, ``VaultState.unseal`` already pushed the new sub-
    keys into the running RPC listener (``set_subkeys``), so this host is
    current and is excluded from the recipient set (the historical behaviour).
    When the rotator is a FOLLOWER, the host's master process (a different PID,
    sharing this node's ``node_uuid``) was NOT refreshed and still serves the
    pre-rotation generation ; it MUST receive a roll-forward envelope like any
    other stale node, so ``self`` is kept in the recipient set. Omitting it
    (the old unconditional behaviour) stranded the rotating host : no envelope
    -> ``_rekey_roll_forward_body`` finds nothing -> the fence quarantines the
    whole host until an operator re-unseals it.

    Steps (all in one committed txn) :
      1. Supersede : DELETE every envelope row for ``key_epoch < epoch`` -- only
         the current generation's envelope may exist at rest (forward secrecy).
      2. Build K (ephemeral 32B), ``blob = AESGCM(K, bundle, AAD)``, and the
         Ed25519 ``sig`` over ``H(cluster_id||epoch||blob)`` using this node's
         CA-signed mTLS identity key.
      3. Write the shared row ('*') with blob+sig+signer_cert.
      4. For each non-evicted, non-revoked peer that has published a rekey_pub :
         ``wrapped_k = crypto_box_seal(K, peer_pub)`` and a per-node row.

    Returns the number of per-recipient rows written (0 if not an HA cluster,
    no cert on disk, or no eligible peers). Best-effort and self-contained : on
    any failure it rolls back its own txn and returns 0, because a missing
    envelope degrades cleanly to the S1 fence (peers quarantine) -- it must
    never compromise the rotation that already committed.
    """
    try:
        if len(bundle) != BUNDLE_LEN:
            log.error(
                "publish_envelope: bundle is %d bytes, expected %d",
                len(bundle),
                BUNDLE_LEN,
            )
            return 0

        cluster_id = await _read_config(db, "vault_cluster_config", "cluster_id")
        if not cluster_id:
            # Not an initialised HA cluster -- nothing to propagate to.
            return 0

        cert_pair = cluster_cert.load_cluster_cert(
            settings.cluster_cert_path, settings.cluster_cert_key_path
        )
        if cert_pair is None:
            log.warning(
                "publish_envelope: no cluster cert on disk -- skipping envelope"
            )
            return 0
        signer_cert_pem, signer_key_pem = cert_pair
        signer_key = cluster_ca.parse_key(signer_key_pem)

        # Eligible recipients : live members with a published rekey_pub, minus
        # evicted and revoked nodes. ``self`` (this node_uuid) is excluded ONLY
        # when the rotator is the master -- then the host's RPC listener was
        # already refreshed in-place and is current. When a follower rotated,
        # the host's master is stale and shares this node_uuid, so we KEEP self
        # in the set or it would be stranded (no envelope -> fence quarantine).
        # Omitting a node EXCLUDES it -- it falls back to the fence.
        from .node_uuid import get_node_uuid

        self_uuid = get_node_uuid()
        keep_self = not rotator_is_master  # follower rotation : host master is stale
        revoked = await cluster_membership.read_revoked_uuids(db)
        rows = (
            await db.execute(
                text(
                    "SELECT node_uuid, rekey_pub FROM vault_cluster_nodes "
                    "WHERE rekey_pub IS NOT NULL AND ha_state != 'evicted'"
                )
            )
        ).fetchall()
        recipients = [
            (r.node_uuid, bytes(r.rekey_pub))
            for r in rows
            if r.node_uuid not in revoked and (keep_self or r.node_uuid != self_uuid)
        ]

        # 1. Supersede older generations.
        await db.execute(
            text("DELETE FROM vault_rekey_envelope WHERE key_epoch < :e"),
            {"e": epoch},
        )

        if not recipients:
            # No peer to roll forward : still drop stale rows, commit, done.
            await db.commit()
            return 0

        # 2. Ephemeral content key + bulk wrap + origin signature.
        k = bytearray(os.urandom(32))
        try:
            nonce = os.urandom(_AESGCM_NONCE_LEN)
            ct = AESGCM(bytes(k)).encrypt(nonce, bytes(bundle), _aad(cluster_id, epoch))
            blob = nonce + ct
            sig = signer_key.sign(_signed_digest(cluster_id, epoch, blob))

            # 3. Shared row (upsert so a re-published epoch is idempotent).
            await db.execute(
                text(
                    "INSERT INTO vault_rekey_envelope "
                    "(key_epoch, node_uuid, blob, sig, signer_cert) "
                    "VALUES (:e, :u, :blob, :sig, :cert) "
                    "ON CONFLICT (key_epoch, node_uuid) DO UPDATE SET "
                    "blob = EXCLUDED.blob, sig = EXCLUDED.sig, "
                    "signer_cert = EXCLUDED.signer_cert, created_at = NOW()"
                ),
                {
                    "e": epoch,
                    "u": SHARED_ROW_UUID,
                    "blob": blob,
                    "sig": sig,
                    "cert": signer_cert_pem.decode("ascii"),
                },
            )

            # 4. Per-recipient sealed boxes.
            written = 0
            for uuid, pub in recipients:
                try:
                    wrapped = bytes(rekey_seal(pub, k))
                except Exception:
                    log.warning(
                        "publish_envelope: bad rekey_pub for %s -- skipping", uuid
                    )
                    continue
                await db.execute(
                    text(
                        "INSERT INTO vault_rekey_envelope "
                        "(key_epoch, node_uuid, wrapped_k) VALUES (:e, :u, :w) "
                        "ON CONFLICT (key_epoch, node_uuid) DO UPDATE SET "
                        "wrapped_k = EXCLUDED.wrapped_k, created_at = NOW()"
                    ),
                    {"e": epoch, "u": uuid, "w": wrapped},
                )
                written += 1
        finally:
            secure_zero(k)

        await db.commit()
        log.info(
            "publish_envelope: epoch=%d sealed to %d/%d recipients",
            epoch,
            written,
            len(recipients),
        )
        return written
    except Exception:
        log.warning(
            "publish_envelope failed -- peers fall back to fence", exc_info=True
        )
        try:
            await db.rollback()
        except Exception:
            pass
        return 0
    finally:
        secure_zero(bundle)


# -- peer side -------------------------------------------------------------


def _verify_signer_cert(
    cert_pem: str, ca_cert_pem: bytes, prev_ca_cert_pem: bytes | None
) -> Ed25519PublicKey:
    """Validate the signer cert against the cluster CA ; return its public key.

    Reuses the mTLS dual-CA verifier (current CA first, prev CA during a
    rotation grace window) so envelope origin-auth survives a CA rotation
    exactly like client-cert auth does. Also enforces the cert validity window.
    Raises on any failure -- the caller treats a raise as "reject, do not adopt"
    (the fence then quarantines).
    """
    from . import cluster_mtls

    cert = x509.load_pem_x509_certificate(cert_pem.encode("ascii"))
    now = datetime.now(timezone.utc)
    if not (cert.not_valid_before_utc <= now <= cert.not_valid_after_utc):
        raise ValueError("signer cert outside validity window")
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
    prev_ca = (
        x509.load_pem_x509_certificate(prev_ca_cert_pem) if prev_ca_cert_pem else None
    )
    # Raises MtlsBadSignatureError if neither CA signed the cert.
    cluster_mtls._verify_signature_dual(cert, ca_cert, prev_ca)
    return cert.public_key()


async def consume_envelope(db: AsyncSession, my_uuid: str) -> bytearray | None:
    """Open + verify this node's envelope for the current DB epoch.

    Peer-side. Returns the validated 128-byte sub-key bundle (a bytearray the
    caller MUST adopt then ``secure_zero``), or ``None`` when there is nothing
    to do or the envelope must be rejected -- in which case the S1 fence
    quarantines the node. Does NOT mutate vault state : verification is fully
    separated from adoption (the caller, ``cluster_ha_loops``, performs the
    seal/unseal + Shamir re-split + row teardown only on a non-None return).

    Rejection (returns None, fence handles) on : no envelope row for this node
    at the current epoch (excluded / emergency / sealed-at-rotation), missing
    shared row, sealed box that does not open, signer cert not CA-signed,
    invalid signature, or a master_check self-consistency mismatch.
    """
    from .key_epoch import get_key_epoch

    db_epoch = await get_key_epoch(db)  # coerces a missing/corrupt row to 0
    local = vault.key_epoch
    if local is None or local >= db_epoch:
        return None  # unknown generation, or already current -- nothing to roll

    shared = (
        await db.execute(
            text(
                "SELECT blob, sig, signer_cert FROM vault_rekey_envelope "
                "WHERE key_epoch = :e AND node_uuid = :u"
            ),
            {"e": db_epoch, "u": SHARED_ROW_UUID},
        )
    ).fetchone()
    mine = (
        await db.execute(
            text(
                "SELECT wrapped_k FROM vault_rekey_envelope "
                "WHERE key_epoch = :e AND node_uuid = :u"
            ),
            {"e": db_epoch, "u": my_uuid},
        )
    ).fetchone()
    # Fail closed on a partial shared row (e.g. blob set, sig NULL): guard every
    # field consumed below so bytes(shared.sig) can't raise out (DB-write attacker).
    if (
        shared is None
        or mine is None
        or shared.blob is None
        or shared.sig is None
        or shared.signer_cert is None
        or mine.wrapped_k is None
    ):
        log.warning(
            "consume_envelope: no/partial envelope for node=%s epoch=%d -- fencing",
            my_uuid,
            db_epoch,
        )
        return None

    cluster_id = await _read_config(db, "vault_cluster_config", "cluster_id")
    ca_cert_pem = await _read_config(db, "vault_cluster_config", "cluster_ca_cert")
    if not cluster_id or not ca_cert_pem:
        log.error("consume_envelope: cluster_id / CA cert missing -- cannot verify")
        return None
    prev_ca_cert_pem = await cluster_ca.load_cluster_ca_prev_cert(db)

    blob = bytes(shared.blob)
    sig = bytes(shared.sig)

    # 1. Origin authentication FIRST (I2) -- verify the signature against the CA
    #    before trusting anything. A DB-write attacker without the master key
    #    cannot forge this.
    try:
        signer_pub = _verify_signer_cert(
            shared.signer_cert, ca_cert_pem.encode("ascii"), prev_ca_cert_pem
        )
        signer_pub.verify(sig, _signed_digest(cluster_id, db_epoch, blob))
    except Exception as exc:
        log.error(
            "consume_envelope: ORIGIN AUTH FAILED for epoch=%d (%s) -- REJECTING",
            db_epoch,
            type(exc).__name__,
        )
        return None

    # 2. Possession factor (I2) -- open the sealed K with our RAM-only privkey.
    k = None
    bundle = None
    try:
        k = vault.rekey_seal_open(bytes(mine.wrapped_k))
        # 3. Recover the bundle under K (AAD re-binds cluster_id + epoch).
        plaintext = AESGCM(bytes(k)).decrypt(
            blob[:_AESGCM_NONCE_LEN],
            blob[_AESGCM_NONCE_LEN:],
            _aad(cluster_id, db_epoch),
        )
        bundle = bytearray(plaintext)
        if len(bundle) != BUNDLE_LEN:
            raise ValueError(f"bundle is {len(bundle)} bytes, expected {BUNDLE_LEN}")

        # 4. Belt-and-braces self-consistency : the recovered hmac_key must
        #    reproduce the DB master_check. Catches a mismatched generation even
        #    if everything above somehow verified.
        master_check = await _read_config(db, "vault_config", "master_check")
        if master_check is not None:
            if hmac_token(bytes(bundle[:32]), "master-check-value") != master_check:
                raise ValueError("master_check mismatch -- recovered keys are wrong")
    except Exception as exc:
        log.error(
            "consume_envelope: key recovery failed for epoch=%d (%s) -- REJECTING",
            db_epoch,
            type(exc).__name__,
        )
        if bundle is not None:
            secure_zero(bundle)
        return None
    finally:
        if k is not None:
            secure_zero(k)

    log.warning(
        "consume_envelope: node=%s rolling forward %d -> %d (envelope verified)",
        my_uuid,
        local,
        db_epoch,
    )
    return bundle


async def delete_consumed_row(db: AsyncSession, my_uuid: str, epoch: int) -> None:
    """Per-row teardown : DELETE this node's consumed envelope row.

    Called by the adopter in the SAME committed txn as the in-RAM epoch flip
    (invariant : a node never needs its row twice). The shared row + any
    straggler per-node rows are reaped at TTL or superseded by the next
    rotation -- a converged cluster leaves the table EMPTY.
    """
    await db.execute(
        text(
            "DELETE FROM vault_rekey_envelope WHERE key_epoch = :e AND node_uuid = :u"
        ),
        {"e": epoch, "u": my_uuid},
    )
