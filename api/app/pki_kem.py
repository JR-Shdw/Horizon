# SPDX-License-Identifier: AGPL-3.0-or-later
"""Hybrid KEM (X25519 + ML-KEM-768) glue for the PKI engine.

The classical X25519 leg is done with ``cryptography`` (OpenSSL) -- the same
audited library the ed25519 CA path uses -- NOT a new Rust crate. The ML-KEM leg
reuses the Cut-1 ``rhorizon_crypto`` bindings, and the two leg shared secrets are
folded into one by the Rust ``hybrid_kdf`` HKDF-SHA512 combiner. This module only
composes those KAT-gated primitives; it invents no cryptography of its own.

Custody: the recipient's long-term X25519 + ML-KEM private keys are generated at
issue time, returned ONCE in the leaf PEM, and never stored server-side (same
posture as the pure-ML-KEM Cut 1). encaps is sender-side (public-only); decaps is
recipient-side (holds the returned key). The server itself never encaps/decaps.
"""

from __future__ import annotations

import rhorizon_crypto as rc
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from . import pki_asn1

# Hybrid construction identifiers.
HYBRID_ALGORITHM = "x25519-ml-kem-768"  # subject_key_algorithm (has its own OID)
HYBRID_MODE = "x25519-ml-kem"  # kem_mode value stored / returned
MLKEM_LEG = "ml-kem-768"
# Combiner label = the construction id, so a different parameter set (or a future
# leg swap) domain-separates. Fed to hybrid_kdf as `info = SHA512(label||cts||pks)`.
HYBRID_LABEL = HYBRID_ALGORITHM.encode()


def gen_x25519_keypair() -> tuple[bytes, bytes]:
    """Fresh X25519 keypair -> (raw_public_key 32 B, PKCS8 PEM private key).

    The raw public key becomes one leg of the hybrid subject key; the PKCS8 PEM
    is one block of the return-once leaf private key. OpenSSL keygen.
    """
    priv = X25519PrivateKey.generate()
    raw_pub = priv.public_key().public_bytes_raw()
    pkcs8 = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return raw_pub, pkcs8


def hybrid_encaps(x25519_pub: bytes, mlkem_ek: bytes) -> tuple[bytearray, bytes, bytes]:
    """Encapsulate against a hybrid subject key (sender side, public-only).

    Returns ``(shared_secret 32 B, ct_x25519 32 B, ct_mlkem)``. The X25519 leg is
    an ephemeral DH: ``ct_x25519`` is the ephemeral public key, ``ss_x25519`` is
    DH(ephemeral, recipient_static). The recipient recovers the identical secret
    via :func:`hybrid_decaps`. The caller must wipe the returned shared secret.
    """
    eph = X25519PrivateKey.generate()
    ct_x25519 = eph.public_key().public_bytes_raw()
    ss_x25519 = eph.exchange(X25519PublicKey.from_public_bytes(x25519_pub))
    ss_mlkem, ct_mlkem = rc.mlkem_encaps(mlkem_ek)
    try:
        shared = rc.hybrid_kdf(
            ss_x25519,
            ss_mlkem,
            ct_x25519,
            ct_mlkem,
            x25519_pub,
            mlkem_ek,
            HYBRID_LABEL,
        )
    finally:
        rc.secure_zero(ss_mlkem)
    return shared, ct_x25519, ct_mlkem


def hybrid_decaps(
    x25519_priv: X25519PrivateKey,
    mlkem_dk: bytes | bytearray,
    x25519_pub: bytes,
    mlkem_ek: bytes,
    ct_x25519: bytes,
    ct_mlkem: bytes,
) -> bytearray:
    """Decapsulate a hybrid ciphertext (recipient side, needs the returned keys).

    ``x25519_pub`` / ``mlkem_ek`` are the recipient's own STATIC public keys (from
    the cert subject) -- they bind the KDF transcript and must match what the
    sender used. ML-KEM implicit rejection means a tampered ``ct_mlkem`` yields a
    deterministic pseudo-random secret (never an error), so the parties simply
    disagree, which surfaces when the derived key is used. The caller must wipe
    the returned shared secret.
    """
    ss_x25519 = x25519_priv.exchange(X25519PublicKey.from_public_bytes(ct_x25519))
    ss_mlkem = rc.mlkem_decaps(mlkem_dk, ct_mlkem)
    try:
        return rc.hybrid_kdf(
            ss_x25519,
            ss_mlkem,
            ct_x25519,
            ct_mlkem,
            x25519_pub,
            mlkem_ek,
            HYBRID_LABEL,
        )
    finally:
        rc.secure_zero(ss_mlkem)


def split_hybrid_subject_key(subject_bitstring: bytes) -> tuple[bytes, bytes]:
    """Split a hybrid subject key (SEQUENCE OF BIT STRING) -> (x25519_pub, mlkem_pub).

    ``subject_bitstring`` is the subjectPublicKey BIT STRING content from
    :func:`pki_asn1.extract_subject_pubkey`. Leg order is fixed (X25519 first).
    """
    legs = pki_asn1.split_seq_of_bitstrings(subject_bitstring)
    if len(legs) != 2:
        raise ValueError(f"hybrid subject key must have 2 legs, got {len(legs)}")
    return legs[0], legs[1]


def _split_pem_blocks(pem: bytes) -> list[bytes]:
    marker = b"-----END PRIVATE KEY-----"
    blocks: list[bytes] = []
    idx = 0
    while True:
        end = pem.find(marker, idx)
        if end == -1:
            break
        end += len(marker)
        blocks.append(pem[idx:end].lstrip())
        idx = end
    return blocks


def load_hybrid_private_pem(pem: bytes) -> tuple[X25519PrivateKey, bytes]:
    """Parse a return-once hybrid leaf PEM -> (X25519PrivateKey, mlkem_dk bytes).

    Inverse of :func:`pki_asn1.hybrid_kem_private_key_pem`: block 0 = X25519 PKCS8,
    block 1 = ML-KEM expandedKey PKCS8.
    """
    blocks = _split_pem_blocks(pem)
    if len(blocks) != 2:
        raise ValueError(f"hybrid private PEM must have 2 blocks, got {len(blocks)}")
    x25519_priv = serialization.load_pem_private_key(blocks[0], password=None)
    if not isinstance(x25519_priv, X25519PrivateKey):
        raise ValueError("first hybrid PEM block is not an X25519 private key")
    mlkem_dk = pki_asn1.mlkem_dk_from_pem(blocks[1])
    return x25519_priv, mlkem_dk
