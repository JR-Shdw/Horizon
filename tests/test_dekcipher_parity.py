# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""DekCipher parity: the Rust mlock'd dek_key cipher must be a byte-exact
drop-in for cryptography.AESGCM (external nonce, tag-appended ciphertext,
aad=None == empty aad). This is what lets it replace the AESGCM(dek_key)
session cache without re-encrypting any existing DEK. Runs in CI via pytest.
"""

import os

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from rhorizon_crypto import DekCipher, secure_zero


def test_dekcipher_accepts_mutable_key_buffer():
    key = bytearray(os.urandom(32))
    plaintext = bytearray(os.urandom(32))
    try:
        cipher = DekCipher(key)
        nonce = os.urandom(12)
        ciphertext = cipher.encrypt(nonce, plaintext, b"mutable-input")
        assert (
            AESGCM(bytes(key)).decrypt(nonce, ciphertext, b"mutable-input") == plaintext
        )
    finally:
        secure_zero(key)
        secure_zero(plaintext)
    assert key == bytearray(32)
    assert plaintext == bytearray(32)


@pytest.mark.parametrize(
    "ptlen,aadlen", [(0, 0), (16, 0), (32, 7), (48, 13), (300, 64)]
)
def test_dekcipher_rust_encrypt_python_decrypt(ptlen, aadlen):
    key, nonce = os.urandom(32), os.urandom(12)
    pt, aad = os.urandom(ptlen), os.urandom(aadlen)
    ct = bytes(DekCipher(key).encrypt(nonce, pt, aad))
    assert AESGCM(key).decrypt(nonce, ct, aad) == pt


@pytest.mark.parametrize(
    "ptlen,aadlen", [(0, 0), (16, 0), (32, 7), (48, 13), (300, 64)]
)
def test_dekcipher_python_encrypt_rust_decrypt(ptlen, aadlen):
    key, nonce = os.urandom(32), os.urandom(12)
    pt, aad = os.urandom(ptlen), os.urandom(aadlen)
    ct = AESGCM(key).encrypt(nonce, pt, aad)
    assert bytes(DekCipher(key).decrypt(nonce, ct, aad)) == pt


def test_dekcipher_sensitive_decrypt_returns_mutable_buffer():
    key, nonce, plaintext = os.urandom(32), os.urandom(12), os.urandom(32)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)

    recovered = DekCipher(key).decrypt_bytearray(nonce, ciphertext, None)
    try:
        assert isinstance(recovered, bytearray)
        assert recovered == plaintext
    finally:
        secure_zero(recovered)


def test_dekcipher_none_aad_matches_aesgcm_none():
    # The DEK / audit-seed code calls .encrypt(nonce, data, None) -- None must
    # behave exactly like AESGCM's None (empty AAD), so existing rows decrypt.
    key, nonce, pt = os.urandom(32), os.urandom(12), os.urandom(48)
    assert (
        AESGCM(key).decrypt(nonce, bytes(DekCipher(key).encrypt(nonce, pt, None)), None)
        == pt
    )
    assert (
        bytes(DekCipher(key).decrypt(nonce, AESGCM(key).encrypt(nonce, pt, None), None))
        == pt
    )
    # None and b"" are interchangeable (matches AESGCM semantics).
    ct_none = bytes(DekCipher(key).encrypt(nonce, pt, None))
    assert bytes(DekCipher(key).decrypt(nonce, ct_none, b"")) == pt


def test_dekcipher_tamper_and_aad_mismatch_rejected():
    key, nonce, pt = os.urandom(32), os.urandom(12), os.urandom(32)
    ct = bytearray(DekCipher(key).encrypt(nonce, pt, b"dek:1"))
    ct[-1] ^= 1
    with pytest.raises(Exception):
        DekCipher(key).decrypt(nonce, bytes(ct), b"dek:1")
    good = bytes(DekCipher(key).encrypt(nonce, pt, b"dek:1"))
    with pytest.raises(Exception):
        DekCipher(key).decrypt(nonce, good, b"dek:2")  # wrong AAD


def test_dekcipher_rejects_bad_key_and_nonce_len():
    with pytest.raises(ValueError):
        DekCipher(os.urandom(31))
    with pytest.raises(ValueError):
        DekCipher(os.urandom(32)).encrypt(os.urandom(11), b"x", None)
