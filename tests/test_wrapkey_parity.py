# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""A7 parity: the Rust WrapKey AES-256-GCM + HMAC-SHA512 must agree with the
Python reference (cryptography.AESGCM / hmac stdlib, both OpenSSL-backed).

A KNOWN subkey is injected through the production API (WrapKey.encrypt wraps it
under the random wrap key; the subkey methods decrypt it internally) -- so no
test-only Rust surface is added. HMAC is deterministic -> byte-identical;
AES-GCM uses a random nonce -> interop both directions. Runs in CI via pytest.
"""

import hashlib
import hmac as _hmac
import os

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_decrypt,
    crypto_aead_xchacha20poly1305_ietf_encrypt,
)
from nacl.public import PrivateKey, PublicKey, SealedBox
from rhorizon_crypto import SecureBuffer, WrapKey, rekey_seal, secure_zero


def _wk_with_known_subkey():
    wk = WrapKey()
    subkey = os.urandom(32)
    enc_subkey = bytes(wk.encrypt(subkey))  # wrap the known subkey under wk
    return wk, subkey, enc_subkey


def test_secure_buffer_can_copy_to_wipeable_bytearray():
    secret = os.urandom(32)
    protected = SecureBuffer(secret)

    plaintext = protected.to_bytearray()
    assert isinstance(plaintext, bytearray)
    assert plaintext == secret

    secure_zero(plaintext)
    assert plaintext == b"\x00" * len(secret)


def test_rust_rekey_keypair_opens_pynacl_sealed_box():
    wk = WrapKey()
    public, encrypted_private = wk.generate_rekey_keypair()
    plaintext = os.urandom(32)
    ciphertext = SealedBox(PublicKey(bytes(public))).encrypt(plaintext)

    opened = wk.rekey_seal_open(bytes(encrypted_private), ciphertext)
    assert isinstance(opened, bytearray)
    assert opened == plaintext
    secure_zero(opened)


def test_rust_rekey_seal_opens_with_pynacl_private_key():
    private = PrivateKey.generate()
    plaintext = bytearray(os.urandom(32))
    ciphertext = rekey_seal(bytes(private.public_key), plaintext)

    assert SealedBox(private).decrypt(bytes(ciphertext)) == plaintext
    secure_zero(plaintext)


def test_rust_rekey_open_rejects_tampering():
    wk = WrapKey()
    public, encrypted_private = wk.generate_rekey_keypair()
    ciphertext = bytearray(SealedBox(PublicKey(bytes(public))).encrypt(os.urandom(32)))
    ciphertext[-1] ^= 1

    with pytest.raises(ValueError, match="sealed box open failed"):
        wk.rekey_seal_open(bytes(encrypted_private), bytes(ciphertext))


def test_chained_secret_encrypt_matches_python_primitives():
    wk, dek_key, encrypted_dek_subkey = _wk_with_known_subkey()
    plaintext = os.urandom(117)
    dek_binding = b"dek:row-id"
    secret_binding = b"secret:v2:binding"

    encrypted_dek, dek_nonce, ciphertext, secret_nonce = wk.chained_secret_encrypt(
        encrypted_dek_subkey,
        plaintext,
        dek_binding,
        secret_binding,
    )
    dek = AESGCM(dek_key).decrypt(
        bytes(dek_nonce),
        bytes(encrypted_dek),
        dek_binding,
    )
    opened = crypto_aead_xchacha20poly1305_ietf_decrypt(
        bytes(ciphertext),
        secret_binding,
        bytes(secret_nonce),
        dek,
    )
    assert opened == plaintext


def test_chained_secret_decrypt_opens_python_ciphertext():
    wk, dek_key, encrypted_dek_subkey = _wk_with_known_subkey()
    dek = os.urandom(32)
    dek_nonce = os.urandom(12)
    dek_binding = b"dek:legacy"
    encrypted_dek = AESGCM(dek_key).encrypt(dek_nonce, dek, dek_binding)
    plaintext = os.urandom(73)
    secret_nonce = os.urandom(24)
    secret_binding = b"secret:legacy:name:namespace"
    ciphertext = crypto_aead_xchacha20poly1305_ietf_encrypt(
        plaintext,
        secret_binding,
        secret_nonce,
        dek,
    )

    opened = wk.chained_secret_decrypt(
        encrypted_dek_subkey,
        encrypted_dek,
        dek_nonce,
        dek_binding,
        ciphertext,
        secret_nonce,
        secret_binding,
    )
    assert isinstance(opened, bytearray)
    assert opened == plaintext
    secure_zero(opened)


def test_chained_secret_reencrypt_upgrades_binding_without_plaintext_output():
    wk, dek_key, encrypted_dek_subkey = _wk_with_known_subkey()
    old_dek = os.urandom(32)
    old_dek_nonce = os.urandom(12)
    old_dek_aad = b"dek:old"
    old_encrypted_dek = AESGCM(dek_key).encrypt(
        old_dek_nonce,
        old_dek,
        old_dek_aad,
    )
    plaintext = os.urandom(91)
    old_secret_nonce = os.urandom(24)
    old_secret_aad = b"secret:legacy:ns"
    old_ciphertext = crypto_aead_xchacha20poly1305_ietf_encrypt(
        plaintext,
        old_secret_aad,
        old_secret_nonce,
        old_dek,
    )
    new_dek_aad = b"dek:new"
    new_secret_aad = b"secret:v2:new-binding"

    encrypted_dek, dek_nonce, ciphertext, secret_nonce = wk.chained_secret_reencrypt(
        encrypted_dek_subkey,
        old_encrypted_dek,
        old_dek_nonce,
        old_dek_aad,
        old_ciphertext,
        old_secret_nonce,
        old_secret_aad,
        new_dek_aad,
        new_secret_aad,
    )
    new_dek = AESGCM(dek_key).decrypt(
        bytes(dek_nonce),
        bytes(encrypted_dek),
        new_dek_aad,
    )
    opened = crypto_aead_xchacha20poly1305_ietf_decrypt(
        bytes(ciphertext),
        new_secret_aad,
        bytes(secret_nonce),
        new_dek,
    )
    assert opened == plaintext
    assert new_dek != old_dek


def test_chained_secret_decrypt_rejects_tampering():
    wk, _, encrypted_dek_subkey = _wk_with_known_subkey()
    encrypted_dek, dek_nonce, ciphertext, secret_nonce = wk.chained_secret_encrypt(
        encrypted_dek_subkey,
        b"secret",
        b"dek:aad",
        b"secret:aad",
    )
    tampered = bytearray(ciphertext)
    tampered[-1] ^= 1

    with pytest.raises(ValueError, match="Secret decryption failed"):
        wk.chained_secret_decrypt(
            encrypted_dek_subkey,
            encrypted_dek,
            dek_nonce,
            b"dek:aad",
            bytes(tampered),
            secret_nonce,
            b"secret:aad",
        )


@pytest.mark.parametrize("msglen", [0, 1, 32, 117, 1024])
def test_hmac_sha512_byte_identical(msglen):
    wk, subkey, enc_subkey = _wk_with_known_subkey()
    msg = os.urandom(msglen)
    rust = bytes(wk.hmac_sha512(enc_subkey, msg))
    py = _hmac.new(subkey, msg, hashlib.sha512).digest()
    assert rust == py and len(rust) == 64


def test_hmac_sha512_known_answer():
    # KAT-style: fixed subkey + message through both impls.
    wk = WrapKey()
    subkey = b"Jefe".ljust(32, b"\x00")
    enc_subkey = bytes(wk.encrypt(subkey))
    msg = b"what do ya want for nothing?"
    assert (
        bytes(wk.hmac_sha512(enc_subkey, msg))
        == _hmac.new(subkey, msg, hashlib.sha512).digest()
    )


@pytest.mark.parametrize("ptlen,aadlen", [(0, 0), (16, 0), (32, 13), (200, 64)])
def test_aesgcm_rust_encrypt_python_decrypt(ptlen, aadlen):
    wk, subkey, enc_subkey = _wk_with_known_subkey()
    pt, aad = os.urandom(ptlen), os.urandom(aadlen)
    blob = bytes(wk.aesgcm_subkey_encrypt(enc_subkey, pt, aad))
    assert AESGCM(subkey).decrypt(blob[:12], blob[12:], aad) == pt


@pytest.mark.parametrize("ptlen,aadlen", [(0, 0), (16, 0), (32, 13), (200, 64)])
def test_aesgcm_python_encrypt_rust_decrypt(ptlen, aadlen):
    wk, subkey, enc_subkey = _wk_with_known_subkey()
    pt, aad = os.urandom(ptlen), os.urandom(aadlen)
    nonce = os.urandom(12)
    ct = AESGCM(subkey).encrypt(nonce, pt, aad)
    plaintext = wk.aesgcm_subkey_decrypt(enc_subkey, nonce + ct, aad)
    try:
        assert isinstance(plaintext, bytearray)
        assert plaintext == pt
    finally:
        secure_zero(plaintext)


def test_aesgcm_tamper_rejected_by_both():
    wk, subkey, enc_subkey = _wk_with_known_subkey()
    pt, aad = os.urandom(32), os.urandom(8)
    blob = bytearray(wk.aesgcm_subkey_encrypt(enc_subkey, pt, aad))
    blob[-1] ^= 1  # flip a tag bit
    with pytest.raises(Exception):
        wk.aesgcm_subkey_decrypt(enc_subkey, bytes(blob), aad)
    with pytest.raises(Exception):
        AESGCM(subkey).decrypt(bytes(blob[:12]), bytes(blob[12:]), aad)


def test_aad_mismatch_rejected_by_both():
    wk, subkey, enc_subkey = _wk_with_known_subkey()
    pt = os.urandom(32)
    blob = bytes(wk.aesgcm_subkey_encrypt(enc_subkey, pt, b"aad-A"))
    with pytest.raises(Exception):
        wk.aesgcm_subkey_decrypt(enc_subkey, blob, b"aad-B")
    with pytest.raises(Exception):
        AESGCM(subkey).decrypt(blob[:12], blob[12:], b"aad-B")
