# SPDX-License-Identifier: AGPL-3.0-or-later
"""S2 -- Python <-> Rust Ed25519 parity gate.

Ed25519 (RFC 8032) is deterministic: a conforming signer produces the SAME
64-byte signature for a given (seed, message). This test proves the Python
reference (api/app/crypto.py) and the Rust impl (rhorizon_crypto.AuditSigner)
never diverge -- byte-equal signatures, byte-equal public keys, and each side's
signatures verify under the other. If this fails, the two implementations have
drifted and the audit chain would verify differently depending on which signer
wrote the entry. HARD GATE.
"""

import os
import random

import pytest
from api.app.crypto import (
    ed25519_public_from_seed,
    sign_audit_ed25519,
    verify_audit_ed25519,
)

# Hard dependency: the Rust extension is always present in this project
# . Skip cleanly only if someone runs the suite without building it.
rc = pytest.importorskip("rhorizon_crypto")


def _rust_sign(seed: bytes, payload: str, prev: str = "") -> str:
    return rc.AuditSigner.from_seed(seed).sign(payload, prev)


def _rust_pub(seed: bytes) -> bytes:
    return rc.AuditSigner.from_seed(seed).public_key()


# A spread of payload / prev_signature shapes the audit chain actually produces:
# empty, the real "actor|action|target|detail_json" shape, unicode in detail,
# long binary-ish payloads, and a realistic 128-hex prev_signature link.
_MESSAGES = [
    ("", ""),
    ("root|create_token|mcp-bot|{}", ""),
    ("root|create_secret|db|{}", "a" * 128),
    ('op|rotate_password|None|{"_critical": true}', "f3" * 64),
    ("user|delete_secret|prod/api-key|{}", "0" * 128),
    ('acct|login|None|{"note": "élève café - 漢字"}', "deadbeef" * 16),
    ("x" * 4000 + "|read|t|{}", "9" * 128),  # long payload
]


def test_rfc_anchor_both_impls_agree():
    """Both impls reproduce the RFC 8032 TEST 1 signature -- and equal each other."""
    seed = bytes.fromhex(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
    )
    rfc_sig = (
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555f"
        "b8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    )
    py = sign_audit_ed25519(seed, payload="", prev_signature="")
    rust = _rust_sign(seed, "", "")
    assert py == rfc_sig
    assert rust == rfc_sig
    assert py == rust


def test_signature_and_pubkey_parity():
    """Byte-identical signatures + public keys across 256 random seeds/messages."""
    rng = random.Random(0xA17D17)  # fixed seed -> reproducible failures
    for i in range(256):
        seed = os.urandom(32)
        # public key parity
        assert ed25519_public_from_seed(seed) == _rust_pub(seed)
        # signature parity over a varied message
        if i < len(_MESSAGES):
            payload, prev = _MESSAGES[i]
        else:
            n = rng.randint(0, 200)
            payload = "".join(chr(rng.randint(32, 0x2E7F)) for _ in range(n))
            prev = rng.choice(["", "a" * 128, os.urandom(32).hex()])
        py = sign_audit_ed25519(seed, payload=payload, prev_signature=prev)
        rust = _rust_sign(seed, payload, prev)
        assert py == rust, f"divergence at i={i}: payload={payload!r} prev={prev!r}"


def test_cross_verification():
    """Each impl verifies the other's signatures; tampering fails on both."""
    for payload, prev in _MESSAGES:
        seed = os.urandom(32)
        pub_py = ed25519_public_from_seed(seed)
        pub_rust = _rust_pub(seed)
        assert pub_py == pub_rust
        sig_py = sign_audit_ed25519(seed, payload=payload, prev_signature=prev)
        sig_rust = _rust_sign(seed, payload, prev)
        assert sig_py == sig_rust
        # Cross-verify both signatures with both verifiers.
        for sig in (sig_py, sig_rust):
            assert verify_audit_ed25519(pub_py, payload, prev, sig) is True
            assert rc.ed25519_audit_verify(pub_rust, payload, prev, sig) is True
        # Tamper: flip one signature nibble -> both verifiers reject.
        bad = ("f" if sig_py[0] != "f" else "0") + sig_py[1:]
        assert verify_audit_ed25519(pub_py, payload, prev, bad) is False
        assert rc.ed25519_audit_verify(pub_rust, payload, prev, bad) is False
        # Tamper: change the chain link -> both reject.
        other_prev = prev + "00" if prev != "" else "00"
        assert verify_audit_ed25519(pub_py, payload, other_prev, sig_py) is False
        assert rc.ed25519_audit_verify(pub_rust, payload, other_prev, sig_rust) is False


def test_sign_raw_parity():
    """Rust ``sign_raw`` byte-matches the Python Ed25519 reference over raw bytes.

    This is the A1 cert-self-sign primitive: the seed stays mlock'd in Rust while
    Python only assembles the cert. Determinism (RFC 8032) means a conforming
    signer yields the identical 64-byte signature, and the signature must verify
    under the matching public key. HARD GATE alongside the chain-sign parity.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )

    rng = random.Random(0x51602A)
    for _ in range(64):
        seed = os.urandom(32)
        msg = os.urandom(rng.randint(0, 512))  # raw bytes, not a UTF-8 payload
        py_sig = Ed25519PrivateKey.from_private_bytes(seed).sign(msg)
        rust_sig = bytes(rc.AuditSigner.from_seed(seed).sign_raw(msg))
        assert rust_sig == py_sig, f"sign_raw divergence on {len(msg)}-byte message"
        # The Rust signature verifies under the signer's own public key.
        pub = bytes(rc.AuditSigner.from_seed(seed).public_key())
        Ed25519PublicKey.from_public_bytes(pub).verify(rust_sig, msg)


def test_malformed_inputs_parity():
    """Both verifiers return False (never raise) on malformed signature/key."""
    seed = os.urandom(32)
    pub = ed25519_public_from_seed(seed)
    for bad_sig in ("", "zz", "ab", "00" * 63, "00" * 65):
        assert verify_audit_ed25519(pub, "p", "", bad_sig) is False
        assert rc.ed25519_audit_verify(pub, "p", "", bad_sig) is False
    for bad_key in (b"", b"\x00" * 8, b"\x00" * 31, b"\x00" * 33):
        sig = sign_audit_ed25519(seed, payload="p", prev_signature="")
        assert verify_audit_ed25519(bad_key, "p", "", sig) is False
        assert rc.ed25519_audit_verify(bad_key, "p", "", sig) is False
