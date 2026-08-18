# SPDX-License-Identifier: AGPL-3.0-or-later
"""S0 -- Python Ed25519 audit-signing primitive.

Anchors the primitive to the RFC 8032 section 7.1 test vectors (so it matches
the standard, not just itself) and exercises the chain semantics the audit log
relies on. This Python impl is the REFERENCE the Rust impl (api/rust) must match
bit-for-bit -- Ed25519 is deterministic, so the same (seed, message) yields the
same 64-byte signature in every conforming implementation (proven in the parity
gate, test_audit_ed25519_parity.py, once the Rust side lands).
"""

from api.app.crypto import (
    ed25519_public_from_seed,
    generate_audit_identity,
    sign_audit_ed25519,
    verify_audit_ed25519,
)

# RFC 8032 section 7.1 -- Ed25519 test vectors. `msg` is expressed as a str so it
# routes through the same payload API the audit chain uses (empty + single byte
# 0x72='r' are the vectors representable as UTF-8 payloads).
RFC8032 = [
    {
        "seed": "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "pub": "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "msg": "",
        "sig": (
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e0652249"
            "01555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe2465514143"
            "8e7a100b"
        ),
    },
    {
        "seed": "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "pub": "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "msg": "r",  # 0x72
        "sig": (
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb"
            "69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d2916"
            "12bb0c00"
        ),
    },
]


def test_rfc8032_public_key_derivation():
    """Public key derived from each RFC seed matches the published value."""
    for v in RFC8032:
        seed = bytes.fromhex(v["seed"])
        assert ed25519_public_from_seed(seed).hex() == v["pub"]


def test_rfc8032_signatures():
    """sign_audit_ed25519 reproduces the RFC 8032 published signatures.

    prev_signature="" so the chain message is exactly the RFC message; payload
    carries the vector's message bytes.
    """
    for v in RFC8032:
        seed = bytes.fromhex(v["seed"])
        assert sign_audit_ed25519(seed, payload=v["msg"], prev_signature="") == v["sig"]


def test_rfc8032_verify():
    """The public-key verify accepts the RFC signatures and rejects tampering."""
    for v in RFC8032:
        pub = bytes.fromhex(v["pub"])
        assert verify_audit_ed25519(pub, v["msg"], "", v["sig"]) is True
        # Flip one signature nibble -> reject.
        bad = ("f" if v["sig"][0] != "f" else "0") + v["sig"][1:]
        assert verify_audit_ed25519(pub, v["msg"], "", bad) is False
        # Wrong message -> reject.
        assert verify_audit_ed25519(pub, v["msg"] + "x", "", v["sig"]) is False


def test_roundtrip_and_identity():
    """A freshly minted identity signs and self-verifies; pubkey is consistent."""
    seed, pub = generate_audit_identity()
    assert len(seed) == 32 and len(pub) == 32
    assert ed25519_public_from_seed(seed) == pub
    sig = sign_audit_ed25519(seed, payload="root|create_token|t|{}", prev_signature="")
    assert verify_audit_ed25519(pub, "root|create_token|t|{}", "", sig) is True


def test_chain_binding():
    """prev_signature is bound into the signature -- the chain is tamper-evident."""
    seed, pub = generate_audit_identity()
    payload = "root|create_secret|db|{}"
    prev = "a" * 128
    sig = sign_audit_ed25519(seed, payload, prev_signature=prev)
    # Correct prev verifies; a different prev (broken link) does not.
    assert verify_audit_ed25519(pub, payload, prev, sig) is True
    assert verify_audit_ed25519(pub, payload, "b" * 128, sig) is False
    # Changing prev changes the signature (no reuse across links).
    assert sign_audit_ed25519(seed, payload, prev_signature="b" * 128) != sig


def test_wrong_signer_rejected():
    """A signature from one identity does not verify under another's pubkey."""
    seed_a, _ = generate_audit_identity()
    _, pub_b = generate_audit_identity()
    sig = sign_audit_ed25519(seed_a, payload="x|y||{}", prev_signature="")
    assert verify_audit_ed25519(pub_b, "x|y||{}", "", sig) is False


def test_malformed_inputs_return_false():
    """Garbage signature / wrong-length key verify False, never raise."""
    _, pub = generate_audit_identity()
    assert verify_audit_ed25519(pub, "p", "", "zz") is False  # non-hex
    assert verify_audit_ed25519(pub, "p", "", "ab") is False  # too short
    assert verify_audit_ed25519(b"\x00" * 8, "p", "", "00" * 64) is False  # bad key len


def test_noncanonical_signature_hex_returns_false():
    vector = RFC8032[0]
    public_key = bytes.fromhex(vector["pub"])
    signature = vector["sig"]
    uppercase = signature.upper()
    spaced = f"{signature[:2]} {signature[2:]}"

    assert bytes.fromhex(uppercase) == bytes.fromhex(signature)
    assert bytes.fromhex(spaced) == bytes.fromhex(signature)
    assert verify_audit_ed25519(public_key, vector["msg"], "", uppercase) is False
    assert verify_audit_ed25519(public_key, vector["msg"], "", spaced) is False
