# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Audit chain Ed25519 identity -- provisioning + at-rest custody.

The audit chain is signed with a per-node Ed25519 identity (replacing the
master-derived symmetric audit_key). Custody: the 32-byte seed is stored in
``vault_config`` encrypted at rest under the CURRENT dek_key, loaded into a Rust
``AuditSigner`` (mlock'd, zeroize on Drop) at unseal, dropped at seal. The PUBLIC
key + signer fingerprint live cleartext in ``vault_audit_signer_certs`` so
``/audit/verify`` needs no secret (works sealed) and a read-only auditor cannot
forge.

Only the master holds dek_key, so only it can decrypt the seed and sign locally;
followers delegate ``audit_sign_identity`` over RPC, like the symmetric
``audit_sign`` path. On master rotation the seed envelope is re-wrapped
old->new dek so the identity survives rotation unchanged (the key itself does
not rotate). Cert issuance is CA-signed in an HA cluster, self-signed
standalone; the bare public key alone is enough to sign + verify.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.x509.oid import NameOID
from rhorizon_crypto import secure_zero
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from .cluster_rpc import CustodianRpcClient
from .vault_state import VaultSealedError, vault

log = logging.getLogger("rhorizon.audit_identity")

_SEED_KEY = "audit_identity_seed_enc"  # vault_config: AESGCM(dek_key) nonce||ct
_PUB_KEY = "audit_identity_pub"  # vault_config: raw 32-byte pubkey hex


def fingerprint(public_key: bytes) -> str:
    """Signer fingerprint = SHA-256 hex of the raw Ed25519 public key.

    Matches ``vault_state.audit_identity_fpr`` and the ``vault_audit.signer_fpr``
    tag / ``vault_audit_signer_certs.fingerprint`` key.
    """
    return hashlib.sha256(public_key).hexdigest()


async def resolve_signer_fpr(db: AsyncSession) -> str | None:
    """Resolve the cluster's audit signer fingerprint for this node.

    The audit identity is a single cluster-wide key whose PUBLIC half lives
    cleartext in the SHARED Patroni ``vault_config`` (``audit_identity_pub``), so
    EVERY node -- master or follower -- can derive the fingerprint and tag its
    rows uniformly. Only the master can SIGN (it holds dek_key -> the loaded
    signer); followers delegate the signature over RPC but still need this fpr to
    tag the row. Returns None only when no identity has been provisioned yet, in
    which case ``log_action`` keeps the hmac chain.

    Master path is local + free. Follower path reads the public key once and
    caches it on ``vault`` (the identity is stable across master/dek rotation;
    the cache is cleared at seal()).
    """
    if vault.has_audit_identity:
        return vault.audit_identity_fpr
    cached = getattr(vault, "_cluster_audit_fpr", None)
    if cached is not None:
        return cached
    row = (
        await db.execute(
            text("SELECT value FROM vault_config WHERE key = :k"), {"k": _PUB_KEY}
        )
    ).fetchone()
    if row is None:
        return None
    fpr = fingerprint(bytes.fromhex(row.value))
    vault._cluster_audit_fpr = fpr
    return fpr


async def rewrap_seed_for_rotation(db: AsyncSession, old_aesgcm, new_aesgcm) -> bool:
    """Re-wrap the at-rest audit identity seed old_dek -> new_dek.

    The identity key itself does NOT rotate -- only its at-rest envelope moves
    to the new dek_key, so the NEXT unseal can still decrypt + load it. The live
    in-RAM signer is untouched (it keeps signing across the rotation re-unseal),
    so this is purely about not orphaning the seed blob at rest. Mirrors the DEK
    / 2FA re-wrap in rotate_password / rotate_dek_key and runs in the same txn.
    ``DekCipher`` performs the rewrap and zeroization entirely in Rust. No-op
    (returns False) when no seed is stored. Wrap format is ``nonce(12) || ct``,
    no AAD.
    """
    row = (
        await db.execute(
            text("SELECT value FROM vault_config WHERE key = :k"), {"k": _SEED_KEY}
        )
    ).fetchone()
    if row is None:
        return False
    blob = bytes.fromhex(row.value)
    # DekCipher performs decrypt -> encrypt -> zeroize entirely in Rust.
    new_blob = bytes(old_aesgcm.rewrap_to(new_aesgcm, blob))
    await db.execute(
        text("UPDATE vault_config SET value = :v WHERE key = :k"),
        {"v": new_blob.hex(), "k": _SEED_KEY},
    )
    log.info("audit_identity: seed re-wrapped for dek rotation")
    return True


async def register_signer(
    db: AsyncSession,
    public_key: bytes,
    *,
    cert_pem: str | None = None,
    node_uuid: str | None = None,
) -> str:
    """Upsert a signer's PUBLIC key (and cert when issued) into the registry.

    Append-only by fingerprint: re-registering the same key is a no-op on the
    public_key, and fills in cert_pem/node_uuid if they arrive later.
    Returns the fingerprint.
    """
    fpr = fingerprint(public_key)
    await db.execute(
        text("""
            INSERT INTO vault_audit_signer_certs
                (fingerprint, public_key, cert_pem, node_uuid)
            VALUES (:fpr, :pk, :cert, :uuid)
            ON CONFLICT (fingerprint) DO UPDATE SET
                cert_pem = COALESCE(
                    EXCLUDED.cert_pem, vault_audit_signer_certs.cert_pem),
                node_uuid = COALESCE(
                    EXCLUDED.node_uuid, vault_audit_signer_certs.node_uuid)
        """),
        {"fpr": fpr, "pk": public_key, "cert": cert_pem, "uuid": node_uuid},
    )
    return fpr


async def load_audit_identity_into_ram(db: AsyncSession) -> bool:
    """Load the stored seed into a Rust AuditSigner. Returns True if installed.

    Master-side: requires dek_key in RAM (``vault.aesgcm``). A follower (no
    dek_key) returns False and delegates signing via RPC. A missing row is the
    normal pre-provision state and is not an error.
    """
    if vault.sealed:
        raise VaultSealedError()
    external_custodian = isinstance(
        getattr(vault, "_rpc_client", None), CustodianRpcClient
    )
    if vault.aesgcm is None and not external_custodian:
        # Follower: no dek_key locally; signing is delegated to the master.
        return False
    row = (
        await db.execute(
            text("SELECT value FROM vault_config WHERE key = :k"),
            {"k": _SEED_KEY},
        )
    ).fetchone()
    if row is None:
        log.info("audit_identity: no seed in vault_config (pre-provision)")
        return False
    if external_custodian:
        public_row = (
            await db.execute(
                text("SELECT value FROM vault_config WHERE key = :k"),
                {"k": _PUB_KEY},
            )
        ).fetchone()
        if public_row is None:
            log.error("audit_identity: seed exists without its public identity")
            return False
        try:
            expected_public_key = bytes.fromhex(public_row.value)
            result = await vault._call_rpc(
                "install_audit_identity",
                {
                    "wrapped_seed": bytes.fromhex(row.value).hex(),
                    "expected_public_key": expected_public_key.hex(),
                },
            )
            installed_public_key = bytes.fromhex(result["public_key"])
            if not hmac.compare_digest(installed_public_key, expected_public_key):
                raise ValueError("custodian returned a different audit public key")
        except Exception as exc:
            log.error("audit_identity: Rust custodian install failed (%s)", exc)
            return False
        vault._cluster_audit_fpr = fingerprint(expected_public_key)
        log.info(
            "audit_identity: loaded into Rust custodian (fpr=%s)",
            vault._cluster_audit_fpr,
        )
        return True
    try:
        # Ciphertext crosses into Rust; the clear seed does not cross back.
        signer = vault.aesgcm.load_audit_signer(bytes.fromhex(row.value))
    except Exception as exc:
        log.error("audit_identity: seed decrypt failed (%s)", exc)
        return False
    vault.install_audit_signer(signer)
    log.info("audit_identity: loaded into RAM (fpr=%s)", vault.audit_identity_fpr)
    return True


async def ensure_audit_identity(db: AsyncSession) -> bytes | None:
    """Ensure an audit identity exists, is registered, and is loaded into RAM.

    If a seed is already stored, just load it. Otherwise generate a fresh
    Ed25519 identity, store the seed (wrapped under dek_key) + the public key,
    register the public key, and load. Master-side only. Returns the public key,
    or None on a follower / sealed vault.

    NOTE: cert issuance (CA-signed HA / self-signed standalone) is layered on
    via ``register_signer(cert_pem=...)``; the bare public key is sufficient
    for signing + verification.
    """
    if vault.sealed:
        return None
    external_custodian = isinstance(
        getattr(vault, "_rpc_client", None), CustodianRpcClient
    )
    if external_custodian:
        # Only one API worker may decide that the shared identity is absent.
        # The transaction lock is released by the persist commit below.
        await db.execute(
            text(
                "SELECT pg_advisory_xact_lock("
                "hashtext('rhorizon:audit_identity:provision'))"
            )
        )
    existing = (
        await db.execute(
            text("SELECT value FROM vault_config WHERE key = :k"),
            {"k": _PUB_KEY},
        )
    ).fetchone()
    if existing is not None:
        loaded = await load_audit_identity_into_ram(db)
        if external_custodian and not loaded:
            raise RuntimeError("persisted audit identity was not installed")
        return bytes.fromhex(existing.value)

    if external_custodian:
        generated = await vault._call_rpc("generate_audit_identity", {})
        try:
            seed_blob = bytes.fromhex(generated["wrapped_seed"])
            pub = bytes.fromhex(generated["public_key"])
        except (KeyError, TypeError, ValueError) as exc:
            raise RuntimeError("custodian returned an invalid audit identity") from exc
        if len(seed_blob) != 60 or len(pub) != 32:
            raise RuntimeError("custodian returned an invalid audit identity")
    else:
        if vault.aesgcm is None:
            return None

        # Generation, at-rest wrapping, and signer construction all happen in Rust.
        # Python receives only the locked signer object, ciphertext, and public key.
        signer, seed_blob, pub = vault.aesgcm.generate_audit_identity()
        seed_blob = bytes(seed_blob)
        pub = bytes(pub)
    await db.execute(
        text("""
            INSERT INTO vault_config (key, value) VALUES (:k, :v)
            ON CONFLICT (key) DO UPDATE SET value = :v
        """),
        {"k": _SEED_KEY, "v": seed_blob.hex()},
    )
    await db.execute(
        text("""
            INSERT INTO vault_config (key, value) VALUES (:k, :v)
            ON CONFLICT (key) DO UPDATE SET value = :v
        """),
        {"k": _PUB_KEY, "v": pub.hex()},
    )
    await register_signer(db, pub)
    await db.commit()
    if external_custodian:
        if not await load_audit_identity_into_ram(db):
            raise RuntimeError("persisted audit identity was not installed")
    else:
        vault.install_audit_signer(signer)
    log.info("audit_identity: provisioned + loaded (fpr=%s)", fingerprint(pub))
    return pub


# --- cert issuance + unseal/init bootstrap ------------------------------------
# The audit chain VERIFY path reads the raw public key from the registry, not
# the cert -- so a cert is provenance (which node, which CA, rotation lineage),
# not a verification dependency. We still issue one: CA-signed when the node is
# in an HA cluster (trust root = cluster CA), self-signed in standalone (the node
# is its own root). Long validity: the chain must stay attributable across the
# audit retention horizon (up to 10y), and the identity key does not rotate on
# master rotation.

_CERT_VALIDITY_DAYS = 3650


# Ed25519 AlgorithmIdentifier (RFC 8410): SEQUENCE { OID 1.3.101.112 }, absent
# params. Used both as the TBS `signature` field and the outer signatureAlgorithm.
_ED25519_ALG_ID = bytes.fromhex("300506032b6570")


def _cert_builder(audit_pub: bytes, node_uuid: str, *, issuer: x509.Name):
    """X.509 builder certifying ``audit_pub`` (CN=node_uuid), unsigned.

    KeyUsage = digital_signature + content_commitment (non-repudiation) -- this
    key signs audit entries, nothing else. The TBS depends only on these fields
    (subject/issuer/validity/pubkey/extensions), never on the signing private
    key, so the self-sign path can extract its bytes via a throwaway key.
    """
    pubkey = Ed25519PublicKey.from_public_bytes(audit_pub)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, node_uuid)])
    now = datetime.now(timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(pubkey)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=_CERT_VALIDITY_DAYS))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(pubkey), critical=False
        )
    )


def _build_audit_cert(
    audit_pub: bytes,
    node_uuid: str,
    *,
    issuer: x509.Name,
    signing_key: Ed25519PrivateKey,
) -> bytes:
    """Build a CA-signed X.509 cert certifying ``audit_pub``, PEM bytes.

    ``signing_key`` is the cluster CA key (issuer = CA subject), which lives in
    Python legitimately. The standalone self-sign path does NOT use this -- it
    signs in Rust so the audit seed never enters Python (see
    :func:`_self_sign_audit_cert`).
    """
    # Ed25519 ignores the hash parameter ; cryptography requires None.
    cert = _cert_builder(audit_pub, node_uuid, issuer=issuer).sign(
        private_key=signing_key, algorithm=None
    )
    return cert.public_bytes(serialization.Encoding.PEM)


def _der_len(n: int) -> bytes:
    """DER length octets for a content of length n (definite form)."""
    if n < 0x80:
        return bytes([n])
    body = []
    while n:
        body.append(n & 0xFF)
        n >>= 8
    body.reverse()
    return bytes([0x80 | len(body)]) + bytes(body)


def _der_tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(content)) + content


def _assemble_ed25519_cert(tbs: bytes, sig: bytes) -> bytes:
    """Reassemble an X.509 Certificate from a TBS (DER) + an external Ed25519 sig.

    Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature }.
    For Ed25519 the signature is a BIT STRING (0 unused bits || 64 raw bytes).
    Round-trips through ``cryptography`` to validate the DER and emit canonical
    PEM -- a malformed assembly raises here rather than persisting garbage.
    """
    if len(sig) != 64:
        raise ValueError(f"Ed25519 signature must be 64 bytes, got {len(sig)}")
    sig_bitstring = _der_tlv(0x03, b"\x00" + sig)
    cert_der = _der_tlv(0x30, tbs + _ED25519_ALG_ID + sig_bitstring)
    return x509.load_der_x509_certificate(cert_der).public_bytes(
        serialization.Encoding.PEM
    )


async def _self_sign_audit_cert(pub: bytes, node_uuid: str) -> bytes | None:
    """Self-sign the standalone audit cert WITHOUT the seed leaving Rust (A1).

    The TBSCertificate is assembled in Python (issuer == subject; its bytes do
    not depend on the signing private key, so a throwaway Ed25519 key yields the
    exact DER the audit key would). The mlock'd Rust ``AuditSigner`` signs the
    raw TBS, and the X.509 cert is reassembled from (tbs, sig). The cert is
    provenance-only -- ``/audit/verify`` reads the bare pubkey -- so issuing it
    this way costs nothing and closes the last seed-in-Python custody gap.

    Returns None (cert backfilled on a later unseal) if the master has no signer
    loaded or the resulting signature fails to verify.
    """
    if not getattr(vault, "can_audit_sign_raw", vault.has_audit_identity):
        return None
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, node_uuid)])
    throwaway = Ed25519PrivateKey.generate()
    tbs = (
        _cert_builder(pub, node_uuid, issuer=subject)
        .sign(private_key=throwaway, algorithm=None)
        .tbs_certificate_bytes
    )
    try:
        sig = await vault.audit_sign_raw(tbs)
    except Exception as exc:
        log.error("audit_identity: Rust self-sign failed for cert issuance (%s)", exc)
        return None
    # Defence in depth: self-signed, so the subject pubkey IS the signer. Verify
    # before persisting -- a bad signature must never reach the registry.
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, tbs)
    except Exception as exc:
        log.error("audit_identity: self-signed cert failed verify, refusing (%s)", exc)
        return None
    return _assemble_ed25519_cert(tbs, sig)


def _resolve_node_uuid(node_uuid: str | None) -> str:
    if node_uuid:
        return node_uuid
    try:
        from .node_uuid import get_node_uuid

        return get_node_uuid()
    except Exception:
        return "standalone"


async def _issue_audit_cert(
    db: AsyncSession, *, pub: bytes, node_uuid: str
) -> bytes | None:
    """Issue a cert over the audit pubkey -- CA-signed (HA) or self-signed.

    Returns PEM bytes, or None if standalone self-sign is needed but the seed
    cannot be decrypted (the bare pubkey is already registered + usable).
    """
    from . import cluster_ca

    ca = None
    try:
        ca = await cluster_ca.load_cluster_ca(db)
    except Exception:
        ca = None
    if ca is not None:
        ca_cert_pem, ca_key_pem = ca
        ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
        try:
            ca_key = serialization.load_pem_private_key(ca_key_pem, password=None)
        finally:
            secure_zero(ca_key_pem)
        return _build_audit_cert(
            pub, node_uuid, issuer=ca_cert.subject, signing_key=ca_key
        )
    # Standalone: self-sign in Rust so the seed never enters Python (A1).
    return await _self_sign_audit_cert(pub, node_uuid)


async def ensure_audit_chain_identity(
    db: AsyncSession, *, node_uuid: str | None = None
) -> str | None:
    """Master-side bootstrap of the Ed25519 audit chain.

    Provisions + loads the per-node audit identity -- which is what FLIPS new
    audit entries from the legacy HMAC chain to ed25519 (``has_audit_identity``
    gates ``log_action``) -- then certifies its public key in the signer
    registry: CA-signed in an HA cluster, self-signed in standalone. Fills
    ``cert_pem`` for an identity registered bare by an earlier unseal.

    Idempotent: an already-loaded + certified identity is a no-op. Master-side
    only; returns the signer fingerprint, or None on a follower / sealed vault.
    Call sites wrap this best-effort -- a failure leaves the legacy hmac chain
    in place rather than blocking unseal.
    """
    pub = await ensure_audit_identity(db)
    if pub is None:
        return None
    fpr = fingerprint(pub)
    row = (
        await db.execute(
            text(
                "SELECT cert_pem FROM vault_audit_signer_certs WHERE fingerprint = :f"
            ),
            {"f": fpr},
        )
    ).fetchone()
    if row is not None and row.cert_pem:
        return fpr  # already certified
    nid = _resolve_node_uuid(node_uuid)
    cert_pem = await _issue_audit_cert(db, pub=pub, node_uuid=nid)
    if cert_pem is None:
        # Verify reads the raw public key, not the cert, so signing + verify
        # already work; cert backfill retries on the next unseal.
        return fpr
    await register_signer(db, pub, cert_pem=cert_pem.decode("ascii"), node_uuid=nid)
    await db.commit()
    log.info("audit_identity: certified (fpr=%s, node=%s)", fpr, nid)
    return fpr
