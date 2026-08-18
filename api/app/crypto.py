# DO NOT REMOVE: SPDX header + copyright are part of the AGPL-3.0 license terms.
# Stripping or rewriting these notices on redistribution is a license violation.
# Project: Resurgamus Horizon, Author: shdw, License: AGPL-3.0-or-later
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Cryptographic operations - wraps libsodium via PyNaCl + cryptography.

Layers:
  1. Argon2id: password -> master_key
  2. HKDF-SHA512: master_key -> hmac_key, dek_key, audit_key,
     ha_wrap_key, pki_wrap_key (five sub-keys, each domain-separated
     by its HKDF info string; dek_key's info carries a generation
     counter so /admin/rotate-dek-key can re-derive it without the
     master password changing)
  3. XChaCha20-Poly1305: secret <-> DEK
  4. AES-256-GCM: DEK <-> dek_key
  5. HMAC-SHA512: token auth + audit signatures (the audit chain is
     signed with Ed25519 by default; the HMAC chain is the fallback
     and verifies pre-Ed25519 rows)
"""

import asyncio
import hashlib
import hmac
import os
import secrets

import nacl.bindings
import nacl.utils
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA512
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from rhorizon_crypto import secure_zero

# Layer 1: Argon2id (password -> master_key)

ARGON2_OPSLIMIT = 3
ARGON2_MEMLIMIT = 268435456  # 256 MB
ARGON2_SALTBYTES = 16
MASTER_KEY_BYTES = 32


def derive_master_key(password: bytes, salt: bytes) -> bytes:
    """Derive 256-bit master key from password using Argon2id.

    2FA (YubiKey/TOTP) is verified separately as an authentication gate,
    not mixed into key derivation. This allows switching between 2FA
    methods without changing the master key.
    """
    return nacl.bindings.crypto_pwhash_alg(
        outlen=MASTER_KEY_BYTES,
        passwd=password,
        salt=salt,
        opslimit=ARGON2_OPSLIMIT,
        memlimit=ARGON2_MEMLIMIT,
        alg=nacl.bindings.crypto_pwhash_ALG_ARGON2ID13,
    )


# The 256 MB Argon2id is memory-hard and takes ~0.5-1 s. Run it off the event
# loop (libsodium releases the GIL, so the loop stays responsive -- keeps the 1s
# cluster heartbeat firing during unseal, avoiding false master elections). The
# semaphore caps concurrent runs to 1: this restores the serialization the inline
# call had implicitly (a blocking loop can only run one at a time) and prevents a
# memory-amplification DoS via concurrent /unseal or /rotate-password requests.
# Do NOT raise the bound without a memory budget. Per-process (per uvicorn worker).
_ARGON2_CONCURRENCY = asyncio.Semaphore(1)


async def derive_master_key_async(password: bytes, salt: bytes) -> bytes:
    """Off-loop :func:`derive_master_key`. Use this from async request handlers."""
    await _ARGON2_CONCURRENCY.acquire()
    try:
        derivation = asyncio.create_task(
            asyncio.to_thread(derive_master_key, password, salt)
        )
    except BaseException:
        _ARGON2_CONCURRENCY.release()
        raise

    def _release_slot(task: asyncio.Task[bytes]) -> None:
        _ARGON2_CONCURRENCY.release()
        if not task.cancelled():
            # Retrieve any exception even when the request awaiting this task was
            # cancelled, avoiding an unhandled background-task exception.
            task.exception()

    derivation.add_done_callback(_release_slot)
    # Cancelling the request must not cancel the worker: Argon2 keeps running in
    # its thread, so its 256 MB semaphore slot must remain held until completion.
    return await asyncio.shield(derivation)


def generate_salt() -> bytes:
    return os.urandom(ARGON2_SALTBYTES)


# Layer 2: HKDF-SHA512 (master_key -> derived keys)


def _hkdf_derive(master_key: bytes | bytearray, info: str) -> bytes:
    """Derive a 256-bit key from master_key using HKDF-SHA512."""
    return HKDF(
        algorithm=SHA512(),
        length=32,
        salt=None,
        info=info.encode(),
    ).derive(master_key)


class WipeableKeyBundle(dict[str, bytearray]):
    """Derived subkeys that can be wiped deterministically after installation."""

    def wipe(self) -> None:
        for key in self.values():
            secure_zero(key)

    def __del__(self) -> None:
        try:
            self.wipe()
        except Exception:
            pass


def derive_keys(
    master_key: bytes | bytearray, dek_key_version: int = 1
) -> WipeableKeyBundle:
    """Derive all sub-keys from master key.

    dek_key_version lets us rotate the dek_key without changing the master
    password: bumping the version yields a fresh dek_key (because HKDF info
    changes), and the rotation flow re-wraps every vault_dek entry under the
    new dek_key. Legacy callers that don't pass version get v1 (the original
    info string), so existing data keeps decrypting.

    hmac_key, audit_key, ha_wrap_key and pki_wrap_key are NOT versioned by this
    argument. ha_wrap_key wraps the cluster ha_password at rest; pki_wrap_key
    wraps the PKI-engine CA private key at rest in vault_pki_config. Their info
    is constant so dek_key rotation never breaks those encrypted rows.
    """
    if isinstance(dek_key_version, bool) or not isinstance(dek_key_version, int):
        raise TypeError("dek_key_version must be an integer")
    if dek_key_version < 1:
        raise ValueError("dek_key_version must be at least 1")
    if dek_key_version == 1:
        dek_info = "dek-encrypt"  # backward-compat with v1 (no version suffix)
    else:
        dek_info = f"dek-encrypt-v{dek_key_version}"
    return WipeableKeyBundle(
        {
            "hmac_key": bytearray(_hkdf_derive(master_key, "hmac-tokens")),
            "dek_key": bytearray(_hkdf_derive(master_key, dek_info)),
            "audit_key": bytearray(_hkdf_derive(master_key, "audit-sign")),
            "ha_wrap_key": bytearray(_hkdf_derive(master_key, "ha-wrap")),
            "pki_wrap_key": bytearray(_hkdf_derive(master_key, "pki-wrap")),
        }
    )


# Layer 3, XChaCha20-Poly1305 (secret <-> DEK)

XCHACHA_NONCE_BYTES = 24
XCHACHA_KEY_BYTES = 32
SECRET_AAD_VERSION = 2


def secret_aad(
    name: str, namespace: str, *, version: int = SECRET_AAD_VERSION
) -> bytes:
    """Build the AEAD AAD for a secret row.

    Binds the ciphertext to (name, namespace) - swapping a ciphertext
    between two rows produces a different AAD and AEAD verification fails. V2
    length-prefixes each UTF-8 field so delimiters inside either value cannot
    create collisions. V1 remains available only to read pre-migration rows.
    """
    if isinstance(version, bool) or not isinstance(version, int):
        raise ValueError(f"Unsupported secret AAD version: {version!r}")
    if version == 1:
        return f"secret:{name}:{namespace}".encode()
    if version != SECRET_AAD_VERSION:
        raise ValueError(f"Unsupported secret AAD version: {version!r}")
    name_bytes = name.encode()
    namespace_bytes = namespace.encode()
    return (
        b"secret:v2:"
        + len(name_bytes).to_bytes(4, "big")
        + name_bytes
        + len(namespace_bytes).to_bytes(4, "big")
        + namespace_bytes
    )


def dek_aad(dek_id: str) -> bytes:
    """Build the AEAD AAD for a DEK row.

    Binds the encrypted DEK to its row UUID - swapping (encrypted_key, nonce)
    between two DEK rows produces a different AAD and AEAD verification fails.
    """
    return f"dek:{dek_id}".encode()


def encrypt_secret(plaintext: bytes, dek: bytes, aad: bytes) -> tuple[bytes, bytes]:
    """Encrypt plaintext with DEK using XChaCha20-Poly1305 + AAD binding.

    aad must uniquely identify the row this ciphertext belongs to (use
    secret_aad). The same aad must be passed to decrypt_secret.
    """
    nonce = os.urandom(XCHACHA_NONCE_BYTES)
    ciphertext = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(
        message=plaintext,
        aad=aad,
        nonce=nonce,
        key=dek,
    )
    return ciphertext, nonce


def decrypt_secret(ciphertext: bytes, nonce: bytes, dek: bytes, aad: bytes) -> bytes:
    """Decrypt ciphertext with DEK using XChaCha20-Poly1305 + AAD binding."""
    return nacl.bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(
        ciphertext=ciphertext,
        aad=aad,
        nonce=nonce,
        key=dek,
    )


# Layer 4, AES-256-GCM (DEK <-> dek_key)

AES_GCM_NONCE_BYTES = 12


def _resolve_aesgcm(dek_key: bytes | bytearray | None, aesgcm: AESGCM | None) -> AESGCM:
    """Return exactly one caller-supplied AES-GCM key source."""
    if (dek_key is None) == (aesgcm is None):
        raise ValueError("provide exactly one of dek_key or aesgcm")
    if aesgcm is not None:
        return aesgcm
    assert dek_key is not None
    if len(dek_key) != 32:
        raise ValueError("dek_key must be exactly 32 bytes for AES-256-GCM")
    return AESGCM(dek_key)


def encrypt_dek(
    dek: bytes | bytearray,
    dek_key: bytes | bytearray | None,
    aesgcm: AESGCM | None,
    aad: bytes,
) -> tuple[bytes, bytes]:
    """Encrypt a DEK with dek_key using AES-256-GCM + AAD binding.

    Pass exactly one of dek_key or a cached AESGCM instance. aad must be
    dek_aad(dek_id) - the row's UUID binding.
    """
    nonce = os.urandom(AES_GCM_NONCE_BYTES)
    aesgcm = _resolve_aesgcm(dek_key, aesgcm)
    encrypted = aesgcm.encrypt(nonce, dek, aad)
    return encrypted, nonce


def decrypt_dek(
    encrypted_dek: bytes,
    nonce: bytes,
    dek_key: bytes | None,
    aesgcm: AESGCM | None,
    aad: bytes,
) -> bytes:
    """Decrypt a DEK with dek_key using AES-256-GCM + AAD binding."""
    aesgcm = _resolve_aesgcm(dek_key, aesgcm)
    return aesgcm.decrypt(nonce, encrypted_dek, aad)


# Layer 5, HMAC-SHA512 (tokens + audit)


def hmac_token(hmac_key: bytes, token: str) -> str:
    """Compute HMAC-SHA512 of a vault token."""
    return hmac.new(hmac_key, token.encode(), hashlib.sha512).hexdigest()


def verify_token(hmac_key: bytes, token: str, expected_hash: str) -> bool:
    """Timing-safe comparison of token HMAC."""
    computed = hmac_token(hmac_key, token)
    return hmac.compare_digest(computed, expected_hash)


def sign_audit(audit_key: bytes, payload: str, prev_signature: str = "") -> str:
    """Sign an audit log entry with chain to previous signature.

    Chain: HMAC-SHA512(audit_key, prev_signature || payload)
    This creates a tamper-evident chain - modifying or deleting any
    entry breaks all subsequent signatures.
    """
    chained = prev_signature + payload
    return hmac.new(audit_key, chained.encode(), hashlib.sha512).hexdigest()


# --- Audit chain : asymmetric (Ed25519) signing -------------------------------
# Ed25519 is the primary signing path; the symmetric HMAC chain above remains
# available for legacy entries and as an emergency fallback. Ed25519 entries use
# a per-node identity key and can be verified with the public key while sealed.
# HMAC fallback entries still require the appropriate per-epoch audit key.
#
# PureEd25519 (RFC 8032) -- the message is signed directly (Ed25519 hashes with
# SHA-512 internally; we do NOT pre-hash, which would be Ed25519ph). The chain
# message mirrors sign_audit exactly: prev_signature || payload, UTF-8.
# Raw 32-byte seed / 32-byte public key are the interop boundary with the Rust
# implementation (api/rust ed25519) and the RFC 8032 test vectors; Ed25519 is
# deterministic, so the same (seed, message) yields the identical 64-byte
# signature in every conforming implementation -- the parity invariant.


def generate_audit_identity() -> tuple[bytes, bytes]:
    """Mint an Ed25519 audit-signing identity.

    Returns ``(private_seed_32, public_key_32)`` as raw bytes.
    """
    sk = Ed25519PrivateKey.generate()
    seed = sk.private_bytes(
        encoding=Encoding.Raw,
        format=PrivateFormat.Raw,
        encryption_algorithm=NoEncryption(),
    )
    pub = sk.public_key().public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
    return seed, pub


def ed25519_public_from_seed(private_seed: bytes) -> bytes:
    """Derive the raw 32-byte Ed25519 public key from a raw 32-byte seed."""
    sk = Ed25519PrivateKey.from_private_bytes(private_seed)
    return sk.public_key().public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)


def sign_audit_ed25519(
    private_seed: bytes, payload: str, prev_signature: str = ""
) -> str:
    """Sign an audit entry with an Ed25519 identity, chained to the previous sig.

    Chain: Ed25519(seed, prev_signature || payload). Returns the 64-byte
    signature hex-encoded (128 chars) -- same wire shape as the HMAC chain.
    """
    sk = Ed25519PrivateKey.from_private_bytes(private_seed)
    message = (prev_signature + payload).encode()
    return sk.sign(message).hex()


def verify_audit_ed25519(
    public_key: bytes, payload: str, prev_signature: str, signature_hex: str
) -> bool:
    """Verify an Ed25519-signed audit entry against the signer's public key.

    Public-only: no secret needed, so this runs while the vault is sealed.
    """
    if len(signature_hex) != 128 or any(
        char not in "0123456789abcdef" for char in signature_hex
    ):
        return False
    try:
        pk = Ed25519PublicKey.from_public_bytes(public_key)
        message = (prev_signature + payload).encode()
        pk.verify(bytes.fromhex(signature_hex), message)
        return True
    except (InvalidSignature, ValueError):
        return False


# Key generation


def verify_yubikey_response(secret: bytes, challenge: bytes, response: bytes) -> bool:
    """Verify a YubiKey HMAC-SHA1 challenge-response.

    YubiKey slot 2 uses HMAC-SHA1 (hardware limitation).
    The server stores the same secret to verify responses.
    """
    import hashlib as _hl

    expected = hmac.new(secret, challenge, _hl.sha1).digest()
    return hmac.compare_digest(expected, response)


def verify_totp(secret: str, code: str) -> bool:
    """Verify a TOTP code (RFC 6238, 6 digits, 30s window)."""
    return totp_counter_for_code(secret, code) is not None


def totp_counter_for_code(
    secret: str,
    code: str,
    *,
    at_time: float | None = None,
) -> int | None:
    """Return the matching RFC 6238 counter within ±1 step, else ``None``.

    Callers authorizing an operation must atomically consume the returned
    counter; this pure helper performs only cryptographic validation.
    """
    import time

    import pyotp

    if (
        not isinstance(code, str)
        or len(code) != 6
        or not code.isascii()
        or not code.isdigit()
    ):
        return None
    totp = pyotp.TOTP(secret)
    timestamp = time.time() if at_time is None else at_time
    current_counter = int(timestamp) // totp.interval
    for offset in (0, -1, 1):
        counter = current_counter + offset
        if counter >= 0 and hmac.compare_digest(totp.generate_otp(counter), code):
            return counter
    return None


def generate_totp_secret() -> str:
    """Generate a base32 TOTP secret."""
    import pyotp

    return pyotp.random_base32()


def get_totp_uri(secret: str, name: str = "rhorizon") -> str:
    """Get provisioning URI for QR code."""
    import pyotp

    return pyotp.TOTP(secret).provisioning_uri(name=name, issuer_name="rhorizon")


# Shamir Secret Sharing over GF(2^8)
# Irreducible polynomial: x^8 + x^4 + x^3 + x + 1 (0x11B, same as AES)

_GF_EXP = [0] * 512  # anti-log table
_GF_LOG = [0] * 256  # log table


def _init_gf_tables():
    """Build exp/log tables with generator 3 (primitive root, order 255).

    Generator 2 only has order 51 with this polynomial - not primitive.
    """
    x = 1
    for i in range(255):
        _GF_EXP[i] = x
        _GF_LOG[x] = i
        # Multiply by generator 3: x*3 = xtime(x) XOR x
        x2 = x << 1
        if x2 & 0x100:
            x2 ^= 0x11B
        x = x2 ^ x
    for i in range(255, 512):
        _GF_EXP[i] = _GF_EXP[i - 255]


_init_gf_tables()


def _gf_mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _GF_EXP[_GF_LOG[a] + _GF_LOG[b]]


def _gf_inv(a: int) -> int:
    if a == 0:
        raise ValueError("Cannot invert zero in GF(256)")
    return _GF_EXP[255 - _GF_LOG[a]]


def _eval_poly(coeffs: list[int], x: int) -> int:
    """Evaluate polynomial at x in GF(256) using Horner's method."""
    result = 0
    for c in reversed(coeffs):
        result = _gf_mul(result, x) ^ c
    return result


def shamir_split(secret: bytes, threshold: int, total: int) -> list[bytes]:
    """Split secret into `total` shares, `threshold` needed to reconstruct.

    Each byte of the secret is split independently using a random polynomial
    of degree (threshold - 1) over GF(2^8).

    Returns list of shares, each prefixed with its x-coordinate (1-indexed).
    Share format: [x_byte] + [y_bytes for each secret byte]
    """
    if threshold < 2:
        raise ValueError("Threshold must be >= 2")
    if total < threshold:
        raise ValueError("Total shares must be >= threshold")
    if total > 255:
        raise ValueError(
            "Resurgamus Horizon/AGPL-3.0: Maximum 255 shares "
            "(GF(256) non-zero elements)"
        )
    if not secret:
        raise ValueError("Secret must be non-empty")

    shares = [bytearray([i + 1]) for i in range(total)]

    for secret_byte in secret:
        # Random polynomial: coeffs[0] = secret_byte, rest random
        coeffs = [secret_byte] + [secrets.randbelow(256) for _ in range(threshold - 1)]
        for i in range(total):
            x = i + 1  # x-coordinates are 1..total
            shares[i].append(_eval_poly(coeffs, x))

    return [bytes(s) for s in shares]


def shamir_combine(shares: list[bytes]) -> bytes:
    """Reconstruct secret from shares using Lagrange interpolation in GF(256).

    Each share is [x_byte] + [y_bytes...]. Minimum `threshold` shares needed.
    """
    if len(shares) < 2:
        raise ValueError("Resurgamus Horizon/AGPL-3.0: need at least 2 shares")
    if any(len(s) < 2 for s in shares):
        raise ValueError(
            "Resurgamus Horizon/AGPL-3.0: each share must include "
            "x-coordinate and payload"
        )

    xs = [s[0] for s in shares]
    if 0 in xs:
        raise ValueError("Resurgamus Horizon/AGPL-3.0: share index zero is reserved")
    if len(set(xs)) != len(xs):
        raise ValueError("Resurgamus Horizon/AGPL-3.0: duplicate share indices")

    secret_len = len(shares[0]) - 1
    if any(len(s) != len(shares[0]) for s in shares):
        raise ValueError("Shares have different lengths")

    result = bytearray(secret_len)

    for byte_idx in range(secret_len):
        ys = [s[byte_idx + 1] for s in shares]
        # Lagrange interpolation at x=0
        value = 0
        for i, (xi, yi) in enumerate(zip(xs, ys)):
            # Compute Lagrange basis polynomial L_i(0)
            num = 1
            den = 1
            for j, xj in enumerate(xs):
                if i == j:
                    continue
                num = _gf_mul(num, xj)  # 0 ^ xj = xj
                den = _gf_mul(den, xi ^ xj)  # xi ^ xj in GF(256) = xi - xj
            basis = _gf_mul(num, _gf_inv(den))
            value ^= _gf_mul(yi, basis)
        result[byte_idx] = value

    return bytes(result)


# Key generation


def generate_dek() -> bytes:
    """Generate a random 256-bit Data Encryption Key."""
    return os.urandom(XCHACHA_KEY_BYTES)


def generate_token() -> str:
    """Generate a vault token: rh_ + 32 urlsafe random bytes."""
    return "rh_" + secrets.token_urlsafe(32)
