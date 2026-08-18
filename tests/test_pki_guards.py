# SPDX-License-Identifier: AGPL-3.0-or-later
"""pki_ca input guards: reject bad algorithm / wrong CA key type / missing pub.

Pure functions, no DB. These are the issuance-time defenses (a malformed CA must
never produce a leaf), so they are worth pinning even though each is one branch.
"""

import pytest
from api.app import pki_ca
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from rhorizon_crypto import (
    MlDsaSigner,
    MlKemKeypair,
    mlkem_decaps,
    mlkem_encaps,
    secure_zero,
)


def test_mint_pki_ca_rejects_unknown_algorithm():
    with pytest.raises(pki_ca.PkiError):
        pki_ca.mint_pki_ca(algorithm="bogus")


def test_sign_leaf_rejects_non_ed25519_ca_key():
    ca_cert, _key, _pub, _fpr = pki_ca.mint_pki_ca("ed25519")
    ec_pem = ec.generate_private_key(ec.SECP256R1()).private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    with pytest.raises(pki_ca.PkiError, match="not Ed25519"):
        pki_ca.sign_leaf_cert(
            ca_cert, ec_pem, None, "ed25519", "ca", common_name="leaf"
        )


def test_sign_leaf_mldsa_requires_stored_pub():
    with pytest.raises(pki_ca.PkiError, match="missing stored public key"):
        pki_ca.sign_leaf_cert(b"x", b"x", None, "ml-dsa-65", "ca", common_name="leaf")


def test_mldsa_seed_export_is_wipeable():
    seed = MlDsaSigner.generate().seed()
    assert isinstance(seed, bytearray)
    assert len(seed) == 32
    secure_zero(seed)
    assert seed == bytearray(32)


def test_mlkem_secret_key_export_is_wipeable():
    keypair = MlKemKeypair.generate()
    secret_key = keypair.secret_key()
    assert isinstance(secret_key, bytearray)
    assert len(secret_key) == 2400

    sender_secret, ciphertext = mlkem_encaps(keypair.public_key())
    receiver_secret = mlkem_decaps(secret_key, ciphertext)
    assert isinstance(sender_secret, bytearray)
    assert isinstance(receiver_secret, bytearray)
    assert sender_secret == receiver_secret

    secure_zero(sender_secret)
    secure_zero(receiver_secret)
    secure_zero(secret_key)
    assert sender_secret == bytearray(32)
    assert receiver_secret == bytearray(32)
    assert secret_key == bytearray(2400)


@pytest.mark.asyncio
async def test_set_pki_ca_wipes_mutable_blob_on_wrap_error(monkeypatch):
    class UnsealedVault:
        sealed = False

    async def generation_is_current(_session, _vault):
        return None

    async def wrap_fails(_blob):
        raise RuntimeError("injected wrap failure")

    monkeypatch.setattr(pki_ca, "vault", UnsealedVault())
    monkeypatch.setattr(pki_ca, "require_generation_current", generation_is_current)
    monkeypatch.setattr(pki_ca, "_wrap", wrap_fails)
    key_blob = bytearray(b"sensitive CA key")

    with pytest.raises(RuntimeError, match="injected wrap failure"):
        await pki_ca.set_pki_ca(
            object(), "default", b"cert", key_blob, None, "ml-dsa-65", "ca"
        )

    assert key_blob == bytearray(len(key_blob))
