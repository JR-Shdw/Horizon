# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""PKI engine CA: mint / load / sign-leaf / rotate a dedicated issuing CA.

Separate from the cluster CA (own wrap key, tables, AAD). Algorithm selectable
per CA: ed25519 (via cryptography) or ml-dsa-65 (FIPS 204, signed by the Rust
MlDsaSigner with the cert DER hand-assembled by pki_asn1; pure Rust, no OpenSSL
3.5+). CA key wrapped at rest under pki_wrap_key (AAD vault-pki:ca_key) via
vault.pki_wrap_encrypt -- followers delegate to master; rotation re-wraps.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from hashlib import sha256

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.x509.oid import NameOID
from rhorizon_crypto import (
    DekCipher,
    MlDsaSigner,
    MlKemKeypair,
    secure_zero,
    verify_ml_dsa,
)
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from . import pki_asn1, pki_kem
from .key_epoch import require_generation_current
from .vault_state import VaultSealedError, vault

log = logging.getLogger("rhorizon")

_CONFIG_KEY_CERT = "pki_ca_cert"
_CONFIG_KEY_KEY = "pki_ca_key"  # wrapped private material (ed25519 PEM | ml-dsa sk)
_CONFIG_KEY_PUB = "pki_ca_pub"  # ml-dsa public key hex (absent for ed25519)
_CONFIG_KEY_ALG = "pki_ca_algorithm"
_CONFIG_KEY_CN = "pki_ca_cn"  # CA subject CN, = leaf issuer CN
_CONFIG_KEY_CERT_PREV = "pki_ca_cert_prev"
_CONFIG_KEY_ROTATED_AT = "pki_ca_rotated_at"
# AAD is namespace-free: the per-namespace binding is the row key suffix
# (pki_ca_*:<namespace>), and a DB-write attacker who could swap a wrapped key
# could swap the whole CA row anyway. Keeping it namespace-free makes the
# legacy singleton -> ':default' migration a pure key rename (no re-wrap).
_AAD = b"vault-pki:ca_key"

DEFAULT_NAMESPACE = "default"


def _nk(base: str, namespace: str) -> str:
    """Namespace-scoped config key: ``<base>:<namespace>``. One CA per namespace."""
    return f"{base}:{namespace}"


_DEFAULT_CN = "rhorizon-pki"
_DEFAULT_VALIDITY_DAYS = 365 * 10
# ed25519 (classical) + ml-dsa-65 (PQ, NIST level 3) + ed25519-mldsa65 (composite
# hybrid: both required to verify, ANSSI sec 3.2). ml-dsa-87 (level 5) needs a
# separate Rust signer (fips204::ml_dsa_87) -- a follow-up.
COMPOSITE_ALGORITHM = "ed25519-mldsa65"
ALGORITHMS = ("ed25519", "ml-dsa-65", COMPOSITE_ALGORITHM)


class PkiError(Exception):
    pass


def _ed25519_pub_raw(key: Ed25519PrivateKey) -> bytes:
    """Raw 32-byte Ed25519 public key (the composite BIT STRING component)."""
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def _ed25519_pkcs8_pem(key: Ed25519PrivateKey) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _mldsa_signer_from_seed(seed: bytes | bytearray) -> MlDsaSigner:
    if isinstance(seed, bytearray):
        return MlDsaSigner.from_seed_bytearray(seed)
    return MlDsaSigner.from_seed(seed)


def _pack_composite_key(
    ed25519_pkcs8_pem: bytes, mldsa_seed: bytes | bytearray
) -> bytearray:
    """At-rest composite CA private blob: len(ed PEM) || ed PEM || 32B ml-dsa seed.

    Wrapped as opaque bytes by set_pki_ca -> _wrap; rewrap/rotate re-wrap it
    unchanged (they never parse the blob).
    """
    blob = bytearray(len(ed25519_pkcs8_pem).to_bytes(4, "big"))
    blob.extend(ed25519_pkcs8_pem)
    blob.extend(mldsa_seed)
    return blob


def _unpack_composite_key(
    blob: bytes | bytearray,
) -> tuple[bytearray, bytearray]:
    n = int.from_bytes(blob[:4], "big")
    return bytearray(blob[4 : 4 + n]), bytearray(blob[4 + n :])


def compute_fingerprint(cert_pem: bytes) -> str:
    """Lowercase hex SHA-256 of the DER form of a PEM cert (any algorithm)."""
    return sha256(pki_asn1.pem_to_der(cert_pem)).hexdigest()


# --- mint -------------------------------------------------------------------


def mint_pki_ca(
    algorithm: str = "ed25519",
    common_name: str = _DEFAULT_CN,
    validity_days: int = _DEFAULT_VALIDITY_DAYS,
) -> tuple[bytes, bytes | bytearray, str | None, str]:
    """Generate a fresh self-signed PKI CA.

    Returns (cert_pem, key_blob, pub_hex, fingerprint). key_blob is the sensitive
    private material (ed25519 PKCS8 PEM, or the 32-byte ML-DSA seed) the caller
    MUST wrap via set_pki_ca. pub_hex is the ML-DSA public key hex (None for
    ed25519, derivable from the key).
    """
    if algorithm not in ALGORITHMS:
        raise PkiError(f"unknown algorithm {algorithm!r}; pick one of {ALGORITHMS}")
    now = datetime.now(timezone.utc)
    nb, na = now - timedelta(minutes=5), now + timedelta(days=validity_days)

    if algorithm == "ed25519":
        priv = Ed25519PrivateKey.generate()
        pub = priv.public_key()
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(pub)
            .serial_number(x509.random_serial_number())
            .not_valid_before(nb)
            .not_valid_after(na)
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(pub), critical=False
            )
            .sign(private_key=priv, algorithm=None)
        )
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_blob = priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return cert_pem, key_blob, None, compute_fingerprint(cert_pem)

    if algorithm == COMPOSITE_ALGORITHM:
        # Composite Ed25519 + ML-DSA-65: both keys self-sign the SAME TBS bytes;
        # verify requires BOTH (ANSSI sec 3.2). ed25519 goes through build_cert
        # (not CertificateBuilder) so the two signatures cover identical bytes.
        ed = Ed25519PrivateKey.generate()
        signer = MlDsaSigner.generate()
        ed_pub, mldsa_pub = _ed25519_pub_raw(ed), bytes(signer.public_key())
        cpv = pki_asn1.composite_public_value([ed_pub, mldsa_pub])

        def _sign(tbs: bytes) -> bytes:
            return pki_asn1.composite_signature_value(
                [ed.sign(tbs), bytes(signer.sign_raw(tbs))]
            )

        cert_pem, fpr = pki_asn1.build_cert(
            subject_key_algorithm=algorithm,
            signature_algorithm=algorithm,
            sign=_sign,
            serial=x509.random_serial_number(),
            subject_cn=common_name,
            issuer_cn=common_name,
            not_before=nb,
            not_after=na,
            subject_public_key=cpv,
            issuer_public_key=cpv,
            is_ca=True,
            path_len=0,
        )
        seed = signer.seed()
        try:
            key_blob = _pack_composite_key(_ed25519_pkcs8_pem(ed), seed)
        finally:
            secure_zero(seed)
        return cert_pem, key_blob, mldsa_pub.hex(), fpr

    # ML-DSA: sign in Rust, assemble the cert DER in pki_asn1. The at-rest key
    # material is the 32-byte FIPS 204 seed (deterministic keygen), not the
    # expanded key -- smaller, and the seed form OpenSSL/RFC 9881 expect.
    signer = MlDsaSigner.generate()
    pub = bytes(signer.public_key())
    seed = signer.seed()
    cert_pem, fpr = pki_asn1.build_cert(
        subject_key_algorithm=algorithm,
        signature_algorithm=algorithm,
        sign=lambda tbs: bytes(signer.sign_raw(tbs)),
        serial=x509.random_serial_number(),
        subject_cn=common_name,
        issuer_cn=common_name,
        not_before=nb,
        not_after=na,
        subject_public_key=pub,
        issuer_public_key=pub,
        is_ca=True,
        path_len=0,
    )
    return cert_pem, seed, pub.hex(), fpr


# --- persistence ------------------------------------------------------------


async def _wrap(blob: bytes | bytearray) -> bytes:
    return await vault.pki_wrap_encrypt(blob, _AAD)


async def _unwrap(wrapped: bytes) -> bytearray:
    return await vault.pki_wrap_decrypt(bytes(wrapped), _AAD)


async def _set_row(session: AsyncSession, key: str, value: str) -> None:
    await session.execute(
        text(
            "INSERT INTO vault_pki_config (key, value) VALUES (:k, :v) "
            "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value"
        ),
        {"k": key, "v": value},
    )


async def set_pki_ca(
    session: AsyncSession,
    namespace: str,
    cert_pem: bytes,
    key_blob: bytes | bytearray,
    pub_hex: str | None,
    algorithm: str,
    common_name: str,
) -> None:
    """Persist a freshly minted CA for ``namespace`` (private key wrapped)."""
    try:
        if vault.sealed:
            raise VaultSealedError()
        await require_generation_current(session, vault)
        wrapped = await _wrap(key_blob)
        await _set_row(
            session, _nk(_CONFIG_KEY_CERT, namespace), cert_pem.decode("ascii")
        )
        await _set_row(session, _nk(_CONFIG_KEY_KEY, namespace), wrapped.hex())
        await _set_row(session, _nk(_CONFIG_KEY_ALG, namespace), algorithm)
        await _set_row(session, _nk(_CONFIG_KEY_CN, namespace), common_name)
        if pub_hex is not None:
            await _set_row(session, _nk(_CONFIG_KEY_PUB, namespace), pub_hex)
        log.info("pki_ca: persisted %s CA for namespace %s", algorithm, namespace)
    finally:
        if isinstance(key_blob, bytearray):
            secure_zero(key_blob)


async def load_pki_ca(
    session: AsyncSession, namespace: str
) -> tuple[bytes, bytearray, str | None, str, str] | None:
    """Return ``(cert_pem, key_blob, pub_hex, algorithm, cn)`` for ``namespace``
    or None.

    The plaintext key material only leaves Rust+AES-GCM at sign time. The caller
    must wipe the returned bytearray with ``secure_zero`` immediately after use.
    """
    if vault.sealed:
        raise VaultSealedError()
    rows = (
        await session.execute(
            text(
                "SELECT key, value FROM vault_pki_config WHERE key IN "
                "(:c, :k, :p, :a, :n)"
            ),
            {
                "c": _nk(_CONFIG_KEY_CERT, namespace),
                "k": _nk(_CONFIG_KEY_KEY, namespace),
                "p": _nk(_CONFIG_KEY_PUB, namespace),
                "a": _nk(_CONFIG_KEY_ALG, namespace),
                "n": _nk(_CONFIG_KEY_CN, namespace),
            },
        )
    ).fetchall()
    by = {r.key: r.value for r in rows}
    cert_pem = by.get(_nk(_CONFIG_KEY_CERT, namespace))
    key_blob = by.get(_nk(_CONFIG_KEY_KEY, namespace))
    algorithm = by.get(_nk(_CONFIG_KEY_ALG, namespace))
    cn = by.get(_nk(_CONFIG_KEY_CN, namespace))
    if cert_pem is None or key_blob is None or algorithm is None:
        return None
    plain = await _unwrap(bytes.fromhex(key_blob))
    pub_hex = by.get(_nk(_CONFIG_KEY_PUB, namespace))
    return cert_pem.encode("ascii"), plain, pub_hex, algorithm, cn or _DEFAULT_CN


async def is_initialised(session: AsyncSession, namespace: str) -> bool:
    row = (
        await session.execute(
            text("SELECT COUNT(*) AS n FROM vault_pki_config WHERE key IN (:c, :k)"),
            {
                "c": _nk(_CONFIG_KEY_CERT, namespace),
                "k": _nk(_CONFIG_KEY_KEY, namespace),
            },
        )
    ).fetchone()
    return int(row.n) == 2


async def list_ca_namespaces(session: AsyncSession) -> list[str]:
    """Namespaces that have an initialised CA (sorted)."""
    prefix = _CONFIG_KEY_CERT + ":"
    rows = (
        await session.execute(
            text("SELECT key FROM vault_pki_config WHERE key LIKE :p"),
            {"p": prefix + "%"},
        )
    ).fetchall()
    return sorted(r.key[len(prefix) :] for r in rows)


# --- sign leaf --------------------------------------------------------------


def _ca_signer(algorithm: str, ca_key_blob: bytes, ca_pub_hex: str | None):
    """Build ``(sign_fn, issuer_public_key)`` for a CA of the given signature algo.

    ``sign_fn(tbs)`` returns the raw signature bytes under ``algorithm`` (ed25519
    64 B, ML-DSA SIG_LEN, or a composite SEQUENCE OF BIT STRING), self-checking
    every component before returning so a bad signature never reaches a relying
    party. ``issuer_public_key`` is the CA subject-key bytes used for the leaf's
    issuer SPKI / AKI (raw ed25519 pub, raw ML-DSA pub, or the composite public
    value). Shared by :func:`sign_leaf_cert` (ML-DSA / composite) and
    :func:`sign_kem_leaf_cert` (all three CA algorithms).
    """
    if algorithm == "ed25519":
        ca_key = serialization.load_pem_private_key(ca_key_blob, password=None)
        if not isinstance(ca_key, Ed25519PrivateKey):
            raise PkiError("PKI CA key is not Ed25519")
        issuer_pub = _ed25519_pub_raw(ca_key)

        def _sign_ed(tbs: bytes) -> bytes:
            sig = ca_key.sign(tbs)
            try:
                ca_key.public_key().verify(sig, tbs)
            except InvalidSignature as exc:
                raise PkiError("ed25519 CA self-check failed signing cert") from exc
            return sig

        return _sign_ed, issuer_pub

    if algorithm == COMPOSITE_ALGORITHM:
        ed_pem, seed = _unpack_composite_key(ca_key_blob)
        try:
            ca_ed = serialization.load_pem_private_key(ed_pem, password=None)
            ca_mldsa = _mldsa_signer_from_seed(seed)
        finally:
            secure_zero(ed_pem)
            secure_zero(seed)
        if not isinstance(ca_ed, Ed25519PrivateKey):
            raise PkiError("composite CA ed25519 component is not Ed25519")
        ca_ed_pub = _ed25519_pub_raw(ca_ed)
        ca_mldsa_pub = (
            bytes.fromhex(ca_pub_hex) if ca_pub_hex else bytes(ca_mldsa.public_key())
        )
        issuer_pub = pki_asn1.composite_public_value([ca_ed_pub, ca_mldsa_pub])

        def _sign_composite(tbs: bytes) -> bytes:
            sig_ed = ca_ed.sign(tbs)
            sig_mldsa = bytes(ca_mldsa.sign_raw(tbs))
            # Defence in depth: BOTH component signatures must verify before the
            # cert is handed out. A single valid signature is a downgrade hole.
            try:
                ca_ed.public_key().verify(sig_ed, tbs)
            except InvalidSignature as exc:
                raise PkiError("composite ed25519 CA self-check failed") from exc
            if not verify_ml_dsa(ca_mldsa_pub, tbs, sig_mldsa):
                raise PkiError("composite ML-DSA CA self-check failed")
            return pki_asn1.composite_signature_value([sig_ed, sig_mldsa])

        return _sign_composite, issuer_pub

    # ML-DSA CA.
    if ca_pub_hex is None:
        raise PkiError("ML-DSA CA missing stored public key")
    ca_pub = bytes.fromhex(ca_pub_hex)
    ca_signer = _mldsa_signer_from_seed(ca_key_blob)

    def _sign_mldsa(tbs: bytes) -> bytes:
        sig = bytes(ca_signer.sign_raw(tbs))
        # Confirm the CA actually signed this TBS before handing the cert out.
        if not verify_ml_dsa(ca_pub, tbs, sig):
            raise PkiError("ML-DSA CA self-check failed signing cert")
        return sig

    return _sign_mldsa, ca_pub


def sign_leaf_cert(
    ca_cert_pem: bytes,
    ca_key_blob: bytes,
    ca_pub_hex: str | None,
    algorithm: str,
    issuer_cn: str,
    *,
    common_name: str,
    san_ips: list[str] | None = None,
    san_dns: list[str] | None = None,
    validity_days: int = 30,
    eku_client: bool = True,
    eku_server: bool = True,
) -> tuple[bytes, bytes, int, datetime]:
    """Issue a leaf cert (server-side keygen).

    Returns (cert_pem, key_pem, serial, not_after) for the registry row. Leaf
    keypair in the CA's algorithm, signed by the CA. ML-DSA rebuilds the CA into
    a Rust MlDsaSigner and self-checks the signature before assembly.
    """
    now = datetime.now(timezone.utc)
    nb, na = now - timedelta(minutes=5), now + timedelta(days=validity_days)
    serial = x509.random_serial_number()
    eku = []
    if eku_server:
        eku.append(pki_asn1.EKU_SERVER_AUTH)
    if eku_client:
        eku.append(pki_asn1.EKU_CLIENT_AUTH)

    if algorithm == "ed25519":
        ca_key = serialization.load_pem_private_key(ca_key_blob, password=None)
        if not isinstance(ca_key, Ed25519PrivateKey):
            raise PkiError("PKI CA key is not Ed25519")
        ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
        leaf = Ed25519PrivateKey.generate()
        leaf_pub = leaf.public_key()
        builder = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
            )
            .issuer_name(ca_cert.subject)
            .public_key(leaf_pub)
            .serial_number(serial)
            .not_valid_before(nb)
            .not_valid_after(na)
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=True,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(leaf_pub), critical=False
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                critical=False,
            )
        )
        san = _san_general_names(san_ips, san_dns)
        if san:
            builder = builder.add_extension(
                x509.SubjectAlternativeName(san), critical=False
            )
        if eku:
            builder = builder.add_extension(
                x509.ExtendedKeyUsage([x509.ObjectIdentifier(o) for o in eku]),
                critical=False,
            )
        cert = builder.sign(private_key=ca_key, algorithm=None)
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = leaf.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return cert_pem, key_pem, serial, na

    if algorithm == COMPOSITE_ALGORITHM:
        sign_fn, issuer_cpv = _ca_signer(algorithm, ca_key_blob, ca_pub_hex)
        leaf_ed = Ed25519PrivateKey.generate()
        leaf_mldsa = MlDsaSigner.generate()
        leaf_cpv = pki_asn1.composite_public_value(
            [_ed25519_pub_raw(leaf_ed), bytes(leaf_mldsa.public_key())]
        )

        cert_pem, _fpr = pki_asn1.build_cert(
            subject_key_algorithm=algorithm,
            signature_algorithm=algorithm,
            sign=sign_fn,
            serial=serial,
            subject_cn=common_name,
            issuer_cn=issuer_cn,
            not_before=nb,
            not_after=na,
            subject_public_key=leaf_cpv,
            issuer_public_key=issuer_cpv,
            is_ca=False,
            san_ips=san_ips,
            san_dns=san_dns,
            eku=eku or None,
        )
        seed = leaf_mldsa.seed()
        try:
            key_pem = pki_asn1.composite_private_key_pem(
                _ed25519_pkcs8_pem(leaf_ed), seed
            )
        finally:
            secure_zero(seed)
        return cert_pem, key_pem, serial, na

    # ML-DSA leaf.
    sign_fn, ca_pub = _ca_signer(algorithm, ca_key_blob, ca_pub_hex)
    leaf_signer = MlDsaSigner.generate()
    leaf_pub = bytes(leaf_signer.public_key())

    cert_pem, _fpr = pki_asn1.build_cert(
        subject_key_algorithm=algorithm,
        signature_algorithm=algorithm,
        sign=sign_fn,
        serial=serial,
        subject_cn=common_name,
        issuer_cn=issuer_cn,
        not_before=nb,
        not_after=na,
        subject_public_key=leaf_pub,
        issuer_public_key=ca_pub,
        is_ca=False,
        san_ips=san_ips,
        san_dns=san_dns,
        eku=eku or None,
    )
    seed = leaf_signer.seed()
    try:
        key_pem = pki_asn1.mldsa_private_key_pem(algorithm, seed)
    finally:
        secure_zero(seed)
    return cert_pem, key_pem, serial, na


def sign_kem_leaf_cert(
    ca_cert_pem: bytes,
    ca_key_blob: bytes,
    ca_pub_hex: str | None,
    ca_algorithm: str,
    issuer_cn: str,
    *,
    common_name: str,
    kem_algorithm: str = "ml-kem-768",
    kem_mode: str = "ml-kem",
    san_ips: list[str] | None = None,
    san_dns: list[str] | None = None,
    validity_days: int = 30,
) -> tuple[bytes, bytes, int, datetime, str]:
    """Issue a KEM leaf cert: a KEM subject key signed by the CA.

    ``kem_mode`` selects the construction:
      - ``"ml-kem"`` (Cut 1): pure ML-KEM subject key.
      - ``"x25519-ml-kem"`` (Cut 2): hybrid X25519 + ML-KEM subject key
        (SEQUENCE OF BIT STRING legs), the ANSSI/BSI-required classical+PQ
        combination.

    The subject key has KeyUsage=keyEncipherment and NO EKU (a KEM key does not do
    serverAuth/clientAuth). It is signed by the CA under ``ca_algorithm``
    (ed25519 / ml-dsa-65 / composite) -- subject key algorithm != signature
    algorithm, the Workstream-2 split. Returns ``(cert_pem, key_pem, serial,
    not_after, subject_algorithm)`` where ``subject_algorithm`` is ``ml-kem-768``
    (pure) or ``x25519-ml-kem-768`` (hybrid). The decapsulation (secret) key PEM
    is returned ONCE for the requester and never stored server-side (no new
    key-custody surface).
    """
    if kem_algorithm not in pki_asn1.KEM_OID:
        raise PkiError(f"unknown KEM algorithm {kem_algorithm!r}")
    if kem_algorithm != "ml-kem-768":
        raise PkiError(f"{kem_algorithm} not wired in this build; use ml-kem-768")
    if kem_mode not in ("ml-kem", pki_kem.HYBRID_MODE):
        raise PkiError(f"unknown kem_mode {kem_mode!r}")
    if ca_algorithm not in ALGORITHMS:
        raise PkiError(f"unknown CA algorithm {ca_algorithm!r}")

    now = datetime.now(timezone.utc)
    nb, na = now - timedelta(minutes=5), now + timedelta(days=validity_days)
    serial = x509.random_serial_number()

    sign_fn, issuer_pub = _ca_signer(ca_algorithm, ca_key_blob, ca_pub_hex)
    mlkem_kp = MlKemKeypair.generate(kem_algorithm)
    mlkem_pub = bytes(mlkem_kp.public_key())

    mlkem_dk = mlkem_kp.secret_key()
    try:
        if kem_mode == pki_kem.HYBRID_MODE:
            subject_algorithm = pki_kem.HYBRID_ALGORITHM
            x25519_pub, x25519_pkcs8 = pki_kem.gen_x25519_keypair()
            # Leg order fixed = combiner domain separator: X25519 first, ML-KEM second.
            subject_public_key = pki_asn1.composite_public_value(
                [x25519_pub, mlkem_pub]
            )
            key_pem = pki_asn1.hybrid_kem_private_key_pem(
                x25519_pkcs8, kem_algorithm, mlkem_dk
            )
        else:
            subject_algorithm = kem_algorithm
            subject_public_key = mlkem_pub
            key_pem = pki_asn1.mlkem_private_key_pem(kem_algorithm, mlkem_dk)
    finally:
        secure_zero(mlkem_dk)

    cert_pem, _fpr = pki_asn1.build_cert(
        subject_key_algorithm=subject_algorithm,
        signature_algorithm=ca_algorithm,
        kem=True,
        sign=sign_fn,
        serial=serial,
        subject_cn=common_name,
        issuer_cn=issuer_cn,
        not_before=nb,
        not_after=na,
        subject_public_key=subject_public_key,
        issuer_public_key=issuer_pub,
        is_ca=False,
        san_ips=san_ips,
        san_dns=san_dns,
    )
    return cert_pem, key_pem, serial, na, subject_algorithm


def composite_component_pubs(cert_pem: bytes) -> tuple[bytes, bytes]:
    """Extract (ed25519_pub, ml-dsa_pub) from a composite cert's subject key."""
    raw = pki_asn1.extract_subject_pubkey(pki_asn1.pem_to_der(cert_pem))
    parts = pki_asn1.split_seq_of_bitstrings(raw)
    if len(parts) != 2:
        raise PkiError("cert subject key is not a 2-component composite")
    return parts[0], parts[1]


def verify_composite_cert(
    cert_pem: bytes, issuer_ed_pub: bytes, issuer_mldsa_pub: bytes
) -> bool:
    """Verify a composite cert's signature against the issuer's component keys.

    Accept iff BOTH the Ed25519 AND the ML-DSA component signatures verify over
    the same TBS (ANSSI sec 3.2). A single valid component is a downgrade hole,
    so this returns False unless both pass. For a self-signed CA the issuer keys
    are the cert's own :func:`composite_component_pubs`.
    """
    tbs, sig = pki_asn1.extract_tbs_and_sig(pki_asn1.pem_to_der(cert_pem))
    parts = pki_asn1.split_seq_of_bitstrings(sig)
    if len(parts) != 2:
        return False
    sig_ed, sig_mldsa = parts
    try:
        Ed25519PublicKey.from_public_bytes(issuer_ed_pub).verify(sig_ed, tbs)
    except (InvalidSignature, ValueError):
        return False
    return bool(verify_ml_dsa(issuer_mldsa_pub, tbs, sig_mldsa))


def _san_general_names(san_ips: list[str] | None, san_dns: list[str] | None) -> list:
    import ipaddress

    names: list = []
    for d in san_dns or []:
        names.append(x509.DNSName(d))
    for ip in san_ips or []:
        names.append(x509.IPAddress(ipaddress.ip_address(ip)))
    return names


# --- rotation ---------------------------------------------------------------


async def rewrap_for_master_rotation(
    session: AsyncSession, old_pki_wrap_key: bytes, new_pki_wrap_key: bytes
) -> bool:
    """Re-wrap EVERY namespace's at-rest CA key under the new pki_wrap_key.

    Master rotation re-derives sub-keys -- the OLD pki_wrap_key can't decrypt
    under the NEW one. Called from /rotate-password BEFORE ``vault.unseal``
    flips state. No-op (False) if no CA exists. Raises on decrypt failure (a
    silent loss of a CA key is worse than a failed rotation).
    """
    rows = (
        await session.execute(
            text("SELECT key, value FROM vault_pki_config WHERE key LIKE :p"),
            {"p": _CONFIG_KEY_KEY + ":%"},
        )
    ).fetchall()
    if not rows:
        return False
    old_cipher = DekCipher(old_pki_wrap_key)
    new_cipher = DekCipher(new_pki_wrap_key)
    try:
        for r in rows:
            wrapped = bytes.fromhex(r.value)
            new_blob = bytes(old_cipher.rewrap_to(new_cipher, wrapped, _AAD)).hex()
            await session.execute(
                text("UPDATE vault_pki_config SET value = :v WHERE key = :k"),
                {"v": new_blob, "k": r.key},
            )
    finally:
        del old_cipher
        del new_cipher
    log.info("pki_ca: re-wrapped %d CA key(s) under new pki_wrap_key", len(rows))
    return True


async def rotate_pki_ca(
    session: AsyncSession,
    namespace: str,
    validity_days: int = _DEFAULT_VALIDITY_DAYS,
) -> tuple[bytes, str]:
    """Mint a new CA for ``namespace``, keep the old cert as
    ``pki_ca_cert_prev:<namespace>`` (grace window).

    In-flight leaves signed by the old CA stay verifiable against the previous
    cert until :func:`drop_pki_ca_prev`. Returns ``(new_cert_pem, fingerprint)``.
    """
    if vault.sealed:
        raise VaultSealedError()
    await require_generation_current(session, vault)
    current = await load_pki_ca(session, namespace)
    if current is None:
        raise PkiError(f"PKI not initialised for namespace {namespace}")
    old_cert_pem, _k, _p, algorithm, cn = current
    secure_zero(_k)

    cert_pem, key_blob, pub_hex, fpr = mint_pki_ca(algorithm, cn, validity_days)
    wrapped = await _wrap(key_blob)
    await _set_row(
        session, _nk(_CONFIG_KEY_CERT_PREV, namespace), old_cert_pem.decode("ascii")
    )
    await _set_row(session, _nk(_CONFIG_KEY_CERT, namespace), cert_pem.decode("ascii"))
    await _set_row(session, _nk(_CONFIG_KEY_KEY, namespace), wrapped.hex())
    await _set_row(
        session,
        _nk(_CONFIG_KEY_ROTATED_AT, namespace),
        datetime.now(timezone.utc).isoformat(),
    )
    if pub_hex is not None:
        await _set_row(session, _nk(_CONFIG_KEY_PUB, namespace), pub_hex)
    log.info(
        "pki_ca: rotated %s CA for namespace %s (grace open)", algorithm, namespace
    )
    return cert_pem, fpr


async def load_pki_ca_prev_cert(session: AsyncSession, namespace: str) -> bytes | None:
    row = (
        await session.execute(
            text("SELECT value FROM vault_pki_config WHERE key = :k"),
            {"k": _nk(_CONFIG_KEY_CERT_PREV, namespace)},
        )
    ).fetchone()
    return row.value.encode("ascii") if row else None


async def drop_pki_ca_prev(session: AsyncSession, namespace: str) -> bool:
    """Close the rotation grace window for ``namespace`` (delete the prev cert)."""
    result = await session.execute(
        text("DELETE FROM vault_pki_config WHERE key = :k"),
        {"k": _nk(_CONFIG_KEY_CERT_PREV, namespace)},
    )
    return result.rowcount > 0
