# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""PKI secrets engine: lifecycle (ed25519 + ML-DSA), PQ conformance, namespaces.

The ML-DSA path is verified against the Rust verify_ml_dsa (cryptography <49
can't parse ML-DSA X.509); ed25519 is verified via cryptography directly.
"""

import json

import pytest
import rhorizon_crypto as rc
from api.app import pki_asn1, pki_kem
from api.app.crypto import generate_token
from api.app.database import async_session
from api.app.vault_state import vault
from cryptography import x509
from sqlalchemy import text

PKI = "/api/v1/vault/pki"
# id-ml-dsa-65 (2.16.840.1.101.3.4.3.18) encoded as a DER OID TLV.
_ML_DSA_65_OID_DER = bytes.fromhex("0609608648016503040312")


async def _make_token(name: str, perms: dict) -> str:
    raw = generate_token()
    token_hash = await vault.hmac_sha512_hex(raw)
    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_tokens WHERE name = :n"), {"n": name})
        await db.execute(
            text(
                "INSERT INTO vault_tokens (name, token_hash, permissions, created_by) "
                "VALUES (:n, :h, CAST(:p AS jsonb), 'test')"
            ),
            {"n": name, "h": token_hash, "p": json.dumps(perms)},
        )
        await db.commit()
    return raw


async def _reset_pki():
    async with async_session() as db:
        await db.execute(text("DELETE FROM vault_pki_config"))
        await db.execute(text("DELETE FROM vault_pki_certs"))
        await db.commit()


@pytest.mark.asyncio
@pytest.mark.parametrize("algorithm", ["ed25519", "ml-dsa-65", "ed25519-mldsa65"])
async def test_pki_lifecycle(client, master_password, admin_token, algorithm):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    await _reset_pki()
    h = {"Authorization": f"Bearer {admin_token}"}

    # init
    r = await client.post(
        f"{PKI}/init",
        json={"algorithm": algorithm, "common_name": "rhorizon-pki"},
        headers=h,
    )
    assert r.status_code == 201, r.text
    assert r.json()["algorithm"] == algorithm
    ca_fpr = r.json()["fingerprint"]

    # second init -> 409
    r = await client.post(f"{PKI}/init", json={"algorithm": algorithm}, headers=h)
    assert r.status_code == 409

    # GET /ca
    r = await client.get(f"{PKI}/ca", headers=h)
    assert r.status_code == 200
    ca_pem = r.json()["certificate"].encode()
    assert r.json()["fingerprint"] == ca_fpr

    # issue a leaf
    r = await client.post(
        f"{PKI}/issue",
        json={
            "common_name": "svc.internal",
            "san_ips": ["10.0.0.1"],
            "san_dns": ["svc.internal"],
            "ttl_days": 30,
        },
        headers=h,
    )
    assert r.status_code == 201, r.text
    body = r.json()
    serial = body["serial"]
    leaf_pem = body["certificate"].encode()
    assert "BEGIN PRIVATE KEY" in body["private_key"] or "BEGIN " in body["private_key"]
    assert body["algorithm"] == algorithm

    # the leaf verifies under the CA
    if algorithm == "ed25519":
        ca = x509.load_pem_x509_certificate(ca_pem)
        leaf = x509.load_pem_x509_certificate(leaf_pem)
        ca.public_key().verify(leaf.signature, leaf.tbs_certificate_bytes)
        san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        assert "svc.internal" in san.get_values_for_type(x509.DNSName)
    elif algorithm == "ed25519-mldsa65":
        # Composite: accept iff BOTH the ed25519 AND the ml-dsa signatures verify.
        from api.app import pki_ca

        ca_ed_pub, ca_mldsa_pub = pki_ca.composite_component_pubs(ca_pem)
        assert pki_ca.verify_composite_cert(leaf_pem, ca_ed_pub, ca_mldsa_pub)
        assert pki_asn1._oid(
            pki_asn1.COMPOSITE_OID["ed25519-mldsa65"]
        ) in pki_asn1.pem_to_der(leaf_pem)
        led, lml = pki_ca.composite_component_pubs(leaf_pem)
        assert len(led) == 32 and len(lml) == 1952
        # the bare ml-dsa OID must NOT appear as the cert's signatureAlgorithm
        # (it is a composite cert, signed under the composite OID)
    else:
        async with async_session() as db:
            row = (
                await db.execute(
                    text(
                        "SELECT value FROM vault_pki_config "
                        "WHERE key = 'pki_ca_pub:default'"
                    )
                )
            ).fetchone()
        ca_pub = bytes.fromhex(row.value)
        tbs, sig = pki_asn1.extract_tbs_and_sig(pki_asn1.pem_to_der(leaf_pem))
        assert rc.verify_ml_dsa(ca_pub, tbs, sig)
        assert _ML_DSA_65_OID_DER in pki_asn1.pem_to_der(leaf_pem)

    # list shows the cert
    r = await client.get(f"{PKI}/certs", headers=h)
    assert r.status_code == 200
    items = {c["serial"]: c for c in r.json()["items"]}
    assert serial in items
    assert items[serial]["revoked_at"] is None

    # revoke
    r = await client.post(
        f"{PKI}/revoke", json={"serial": serial, "reason": "test"}, headers=h
    )
    assert r.status_code == 200
    assert r.json()["advisory"] is True  # record-only revocation, no CRL/OCSP
    r = await client.get(f"{PKI}/certs", headers=h)
    revoked = {c["serial"]: c for c in r.json()["items"]}[serial]
    assert revoked["revoked_at"] is not None
    assert revoked["revocation_reason"] == "test"

    # rotate -> old cert kept as previous (grace window)
    r = await client.post(f"{PKI}/rotate", json={}, headers=h)
    assert r.status_code == 200
    new_fpr = r.json()["fingerprint"]
    assert new_fpr != ca_fpr
    r = await client.get(f"{PKI}/ca", headers=h)
    assert r.json()["fingerprint"] == new_fpr
    assert "previous_certificate" in r.json()


def test_kem_helper_guards():
    """Pure-unit: the KEM helpers reject bad algorithms / malformed inputs.

    Covers the input-validation branches of mlkem_private_key_pem and
    sign_kem_leaf_cert (and the ed25519 CA-key type check in _ca_signer) without
    an HTTP/DB round-trip.
    """
    import pytest as _pytest
    from api.app import pki_ca
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    # mlkem_private_key_pem: not an ML-KEM algorithm, and wrong decaps-key length.
    with _pytest.raises(ValueError, match="not an ML-KEM"):
        pki_asn1.mlkem_private_key_pem("ed25519", b"\x00" * 2400)
    with _pytest.raises(ValueError, match="2400 bytes"):
        pki_asn1.mlkem_private_key_pem("ml-kem-768", b"\x00" * 10)

    # sign_kem_leaf_cert: unknown KEM set, and unknown CA signature algorithm.
    with _pytest.raises(pki_ca.PkiError, match="unknown KEM algorithm"):
        pki_ca.sign_kem_leaf_cert(
            b"", b"", None, "ed25519", "ca", common_name="x", kem_algorithm="bogus"
        )
    with _pytest.raises(pki_ca.PkiError, match="unknown CA algorithm"):
        pki_ca.sign_kem_leaf_cert(b"", b"", None, "rsa-2048", "ca", common_name="x")

    # _ca_signer: an ed25519 CA slot loaded with a non-Ed25519 key is rejected.
    ec_pem = ec.generate_private_key(ec.SECP256R1()).private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with _pytest.raises(pki_ca.PkiError, match="not Ed25519"):
        pki_ca._ca_signer("ed25519", ec_pem, None)


def test_composite_signature_downgrade_resistance():
    """A composite cert is rejected if EITHER component signature is tampered.

    Pure-unit (no HTTP/DB): tamper the ed25519 leg, then the ml-dsa leg, in an
    otherwise valid leaf and confirm verify_composite_cert() returns False for
    each. A single valid component must never be accepted (ANSSI sec 3.2).
    """
    from api.app import pki_ca

    ca_pem, ca_blob, ca_pub_hex, _fpr = pki_ca.mint_pki_ca(
        "ed25519-mldsa65", "dt-ca", 3650
    )
    ca_ed_pub, ca_mldsa_pub = pki_ca.composite_component_pubs(ca_pem)
    leaf_pem, _key, _serial, _na = pki_ca.sign_leaf_cert(
        ca_pem, ca_blob, ca_pub_hex, "ed25519-mldsa65", "dt-ca", common_name="leaf"
    )
    assert pki_ca.verify_composite_cert(leaf_pem, ca_ed_pub, ca_mldsa_pub)

    der = pki_asn1.pem_to_der(leaf_pem)
    tbs, sigval = pki_asn1.extract_tbs_and_sig(der)
    sig_ed, sig_mldsa = pki_asn1.split_seq_of_bitstrings(sigval)

    def _rebuild(new_ed: bytes, new_mldsa: bytes) -> bytes:
        bad = pki_asn1.assemble_cert(
            "ed25519-mldsa65",
            tbs,
            pki_asn1.composite_signature_value([new_ed, new_mldsa]),
        )
        return pki_asn1.der_to_pem(bad)

    bad_ed = bytes([sig_ed[0] ^ 0xFF]) + sig_ed[1:]
    assert not pki_ca.verify_composite_cert(
        _rebuild(bad_ed, sig_mldsa), ca_ed_pub, ca_mldsa_pub
    ), "tampered ed25519 leg must be rejected"

    bad_mldsa = bytes([sig_mldsa[0] ^ 0xFF]) + sig_mldsa[1:]
    assert not pki_ca.verify_composite_cert(
        _rebuild(sig_ed, bad_mldsa), ca_ed_pub, ca_mldsa_pub
    ), "tampered ml-dsa leg must be rejected"


def test_kem_cert_subject_signature_split():
    """A cert can carry a KEM subject key signed by a different (CA) algorithm.

    Workstream-2 groundwork: subject SPKI = ML-KEM-768, signatureAlgorithm =
    ml-dsa-65, KeyUsage=keyEncipherment, no EKU. No KEM crate yet -- the subject
    key is opaque bytes; only the DER structure + the CA signature are exercised.
    """
    import datetime as _dt

    from api.app import pki_asn1

    now = _dt.datetime.now(_dt.timezone.utc)
    ca = rc.MlDsaSigner.generate()
    ca_pub = bytes(ca.public_key())
    kem_pub = b"\x77" * pki_asn1.KEM_PUB_LEN["ml-kem-768"]

    def _sign(tbs: bytes) -> bytes:
        sig = bytes(ca.sign_raw(tbs))
        assert rc.verify_ml_dsa(ca_pub, tbs, sig)
        return sig

    pem, _fpr = pki_asn1.build_cert(
        subject_key_algorithm="ml-kem-768",
        signature_algorithm="ml-dsa-65",
        kem=True,
        sign=_sign,
        serial=7,
        subject_cn="kem-leaf",
        issuer_cn="ca",
        not_before=now - _dt.timedelta(minutes=5),
        not_after=now + _dt.timedelta(days=30),
        subject_public_key=kem_pub,
        issuer_public_key=ca_pub,
        is_ca=False,
    )
    der = pki_asn1.pem_to_der(pem)
    # subject SPKI carries the ML-KEM OID + the KEM pubkey; the outer
    # signatureAlgorithm is the CA's ml-dsa-65 (two distinct algorithm ids)
    assert pki_asn1._oid(pki_asn1.KEM_OID["ml-kem-768"]) in der
    assert pki_asn1.extract_subject_pubkey(der) == kem_pub
    tbs, sig = pki_asn1.extract_tbs_and_sig(der)
    assert rc.verify_ml_dsa(ca_pub, tbs, sig)
    # KeyUsage=keyEncipherment (bit 2 -> 05 20), and NO EKU on a KEM cert
    assert bytes([0x03, 0x02, 0x05, 0x20]) in der
    assert pki_asn1._oid("2.5.29.37") not in der


def _dk_from_kem_pem(pem: bytes) -> bytes:
    """Recover the raw ML-KEM decapsulation key from the return-once PKCS8 PEM.

    OneAsymmetricKey { version, algid, privateKey OCTET STRING } where privateKey
    wraps the ML-KEM-PrivateKey expandedKey OCTET STRING (see mlkem_private_key_pem).
    """
    der = pki_asn1.pem_to_der(pem)
    _t, seqc, _ = pki_asn1._read_tlv(der, 0)
    _t, _v, i = pki_asn1._read_tlv(seqc, 0)  # version
    _t, _v, i = pki_asn1._read_tlv(seqc, i)  # algid
    _t, pk_oct, _ = pki_asn1._read_tlv(seqc, i)  # privateKey OCTET STRING
    _t, dk, _ = pki_asn1._read_tlv(pk_oct, 0)  # inner OCTET STRING = expandedKey
    return dk


@pytest.mark.asyncio
@pytest.mark.parametrize("ca_algorithm", ["ed25519", "ml-dsa-65", "ed25519-mldsa65"])
async def test_kem_issue_lifecycle(client, master_password, admin_token, ca_algorithm):
    """Issue an ML-KEM KEM cert under each CA signature algorithm and use it.

    The subject key is ML-KEM-768 (KeyUsage=keyEncipherment, no EKU); the cert is
    signed by the CA. The returned decapsulation key must decapsulate a ciphertext
    encapsulated against the cert's subject key -> the KEM cert is functional.
    """
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    await _reset_pki()
    h = {"Authorization": f"Bearer {admin_token}"}

    r = await client.post(
        f"{PKI}/init",
        json={"algorithm": ca_algorithm, "common_name": "rhorizon-pki"},
        headers=h,
    )
    assert r.status_code == 201, r.text
    ca_pem = (await client.get(f"{PKI}/ca", headers=h)).json()["certificate"].encode()

    r = await client.post(
        f"{PKI}/kem/issue",
        json={
            "common_name": "kem.internal",
            "san_dns": ["kem.internal"],
            "kem_algorithm": "ml-kem-768",
            "ttl_days": 30,
        },
        headers=h,
    )
    assert r.status_code == 201, r.text
    body = r.json()
    serial = body["serial"]
    # response records the CA sig algo + the ML-KEM subject algo + the KEM mode
    assert body["algorithm"] == ca_algorithm
    assert body["subject_algorithm"] == "ml-kem-768"
    assert body["kem_mode"] == "ml-kem"
    assert "BEGIN PRIVATE KEY" in body["private_key"]

    leaf_pem = body["certificate"].encode()
    der = pki_asn1.pem_to_der(leaf_pem)
    # subject key = ML-KEM-768 encaps key; KeyUsage=keyEncipherment; NO EKU
    ek = pki_asn1.extract_subject_pubkey(der)
    assert len(ek) == pki_asn1.KEM_PUB_LEN["ml-kem-768"]
    assert pki_asn1._oid(pki_asn1.KEM_OID["ml-kem-768"]) in der
    assert bytes([0x03, 0x02, 0x05, 0x20]) in der  # keyEncipherment (bit 2)
    assert pki_asn1._oid("2.5.29.37") not in der  # no ExtendedKeyUsage

    # the CA signature over the KEM cert verifies (per CA algorithm)
    from api.app import pki_ca

    tbs, sig = pki_asn1.extract_tbs_and_sig(der)
    if ca_algorithm == "ed25519":
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey,
        )

        ca = x509.load_pem_x509_certificate(ca_pem)
        ca_ed_pub = ca.public_key().public_bytes_raw()
        Ed25519PublicKey.from_public_bytes(ca_ed_pub).verify(sig, tbs)
    elif ca_algorithm == "ed25519-mldsa65":
        ca_ed, ca_ml = pki_ca.composite_component_pubs(ca_pem)
        assert pki_ca.verify_composite_cert(leaf_pem, ca_ed, ca_ml)
    else:
        async with async_session() as db:
            row = (
                await db.execute(
                    text(
                        "SELECT value FROM vault_pki_config "
                        "WHERE key = 'pki_ca_pub:default'"
                    )
                )
            ).fetchone()
        assert rc.verify_ml_dsa(bytes.fromhex(row.value), tbs, sig)

    # the issued keypair works: encaps against the cert ek, decaps with the
    # returned dk -> identical 32-byte shared secret
    dk = _dk_from_kem_pem(body["private_key"].encode())
    ss_send, ct = rc.mlkem_encaps(ek)
    ss_recv = rc.mlkem_decaps(dk, ct)
    assert ss_send == ss_recv and len(ss_recv) == 32

    # /certs surfaces the KEM subject algorithm + mode
    items = {
        c["serial"]: c
        for c in (await client.get(f"{PKI}/certs", headers=h)).json()["items"]
    }
    assert items[serial]["subject_algorithm"] == "ml-kem-768"
    assert items[serial]["kem_mode"] == "ml-kem"
    assert items[serial]["algorithm"] == ca_algorithm


def test_hybrid_kdf_openssl_parity():
    """The live rhorizon_crypto.hybrid_kdf matches an OpenSSL HKDF-SHA512 reference.

    Cross-implementation anchor for the loaded extension (the Rust unit test pins
    the crate; this pins the wheel actually imported by the app). Also asserts the
    frozen KAT vector and the leg-order domain separation.
    """
    import hashlib

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    def openssl_ref(ss_x, ss_m, ct_x, ct_m, pk_x, pk_m, label):
        info = hashlib.sha512(label + ct_x + ct_m + pk_x + pk_m).digest()
        return HKDF(
            algorithm=hashes.SHA512(),
            length=32,
            salt=b"rhorizon-hybrid-kem-v1",
            info=info,
        ).derive(ss_x + ss_m)

    ss_x, ss_m = b"\x11" * 32, b"\x22" * 32
    ct_x, ct_m = b"\x33" * 32, b"\x44" * 1088
    pk_x, pk_m = b"\x55" * 32, b"\x66" * 1184
    label = pki_kem.HYBRID_LABEL

    got = rc.hybrid_kdf(ss_x, ss_m, ct_x, ct_m, pk_x, pk_m, label)
    assert got == openssl_ref(ss_x, ss_m, ct_x, ct_m, pk_x, pk_m, label)
    # frozen KAT (same vector as the Rust hybrid_kdf_openssl_kat test)
    kat = "22766b5730ae6f0d2e16a2261208ca1986731733934ffe2e135b5e0c193c9ebf"
    assert got.hex() == kat
    # leg order is a domain separator: swapping the two shared secrets differs
    assert rc.hybrid_kdf(ss_m, ss_x, ct_x, ct_m, pk_x, pk_m, label) != got
    # wrong-sized fixed leg errors, never silently truncates
    with pytest.raises(ValueError):
        rc.hybrid_kdf(b"\x11" * 8, ss_m, ct_x, ct_m, pk_x, pk_m, label)
    with pytest.raises(ValueError):
        rc.hybrid_kdf(ss_x, ss_m, ct_x, ct_m[:-1], pk_x, pk_m, label)
    with pytest.raises(ValueError):
        rc.hybrid_kdf(ss_x, ss_m, ct_x, ct_m, pk_x, pk_m[:-1], label)
    with pytest.raises(ValueError):
        rc.hybrid_kdf(ss_x, ss_m, ct_x, ct_m, pk_x, pk_m, b"other")


@pytest.mark.asyncio
@pytest.mark.parametrize("ca_algorithm", ["ed25519", "ml-dsa-65", "ed25519-mldsa65"])
async def test_hybrid_kem_issue_lifecycle(
    client, master_password, admin_token, ca_algorithm
):
    """Issue a HYBRID X25519+ML-KEM KEM cert under each CA algo and use it.

    Subject key = SEQUENCE(2) OF BIT STRING (X25519 pub, ML-KEM-768 pub),
    KeyUsage=keyEncipherment, no EKU, signed by the CA. The returned two-block
    private key must decapsulate a ciphertext encapsulated against the cert's
    hybrid subject key -> the whole classical+PQ path is functional end to end.
    """
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    await _reset_pki()
    h = {"Authorization": f"Bearer {admin_token}"}

    r = await client.post(
        f"{PKI}/init",
        json={"algorithm": ca_algorithm, "common_name": "rhorizon-pki"},
        headers=h,
    )
    assert r.status_code == 201, r.text
    ca_pem = (await client.get(f"{PKI}/ca", headers=h)).json()["certificate"].encode()

    r = await client.post(
        f"{PKI}/kem/issue",
        json={
            "common_name": "hybrid.internal",
            "san_dns": ["hybrid.internal"],
            "kem_algorithm": "ml-kem-768",
            "kem_mode": "x25519-ml-kem",
            "ttl_days": 30,
        },
        headers=h,
    )
    assert r.status_code == 201, r.text
    body = r.json()
    serial = body["serial"]
    assert body["algorithm"] == ca_algorithm
    assert body["subject_algorithm"] == "x25519-ml-kem-768"
    assert body["kem_mode"] == "x25519-ml-kem"
    # two return-once private key blocks: X25519 PKCS8 + ML-KEM expandedKey
    assert body["private_key"].count("BEGIN PRIVATE KEY") == 2

    leaf_pem = body["certificate"].encode()
    der = pki_asn1.pem_to_der(leaf_pem)
    # subject key = hybrid SEQUENCE OF BIT STRING; split into the two legs
    subject = pki_asn1.extract_subject_pubkey(der)
    x25519_pub, mlkem_ek = pki_kem.split_hybrid_subject_key(subject)
    assert len(x25519_pub) == 32
    assert len(mlkem_ek) == pki_asn1.KEM_PUB_LEN["ml-kem-768"]
    # hybrid subject algorithm OID present; ML-KEM leg OID NOT at the subject level
    # (it is opaque inside the composite BIT STRING, not an AlgorithmIdentifier)
    assert pki_asn1._oid(pki_asn1.HYBRID_KEM_OID["x25519-ml-kem-768"]) in der
    assert bytes([0x03, 0x02, 0x05, 0x20]) in der  # keyEncipherment (bit 2)
    assert pki_asn1._oid("2.5.29.37") not in der  # no ExtendedKeyUsage

    # CA signature over the hybrid KEM cert verifies (per CA algorithm)
    from api.app import pki_ca

    tbs, sig = pki_asn1.extract_tbs_and_sig(der)
    if ca_algorithm == "ed25519":
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey,
        )

        ca = x509.load_pem_x509_certificate(ca_pem)
        ca_ed_pub = ca.public_key().public_bytes_raw()
        Ed25519PublicKey.from_public_bytes(ca_ed_pub).verify(sig, tbs)
    elif ca_algorithm == "ed25519-mldsa65":
        ca_ed, ca_ml = pki_ca.composite_component_pubs(ca_pem)
        assert pki_ca.verify_composite_cert(leaf_pem, ca_ed, ca_ml)
    else:
        async with async_session() as db:
            row = (
                await db.execute(
                    text(
                        "SELECT value FROM vault_pki_config "
                        "WHERE key = 'pki_ca_pub:default'"
                    )
                )
            ).fetchone()
        assert rc.verify_ml_dsa(bytes.fromhex(row.value), tbs, sig)

    # end-to-end hybrid KEM: encaps against the cert legs, decaps with the two
    # returned private keys -> identical 32-byte combined shared secret
    x25519_priv, mlkem_dk = pki_kem.load_hybrid_private_pem(
        body["private_key"].encode()
    )
    ss_send, ct_x, ct_m = pki_kem.hybrid_encaps(x25519_pub, mlkem_ek)
    ss_recv = pki_kem.hybrid_decaps(
        x25519_priv, mlkem_dk, x25519_pub, mlkem_ek, ct_x, ct_m
    )
    assert isinstance(ss_send, bytearray)
    assert isinstance(ss_recv, bytearray)
    assert ss_send == ss_recv and len(ss_recv) == 32
    # tampering EITHER leg's ciphertext breaks agreement (both legs are bound)
    bad_x = bytearray(ct_x)
    bad_x[0] ^= 0x01
    bad_x_secret = pki_kem.hybrid_decaps(
        x25519_priv, mlkem_dk, x25519_pub, mlkem_ek, bytes(bad_x), ct_m
    )
    assert bad_x_secret != ss_recv
    bad_m = bytearray(ct_m)
    bad_m[0] ^= 0x01
    bad_m_secret = pki_kem.hybrid_decaps(
        x25519_priv, mlkem_dk, x25519_pub, mlkem_ek, ct_x, bytes(bad_m)
    )
    assert bad_m_secret != ss_recv
    for secret in (ss_send, ss_recv, bad_x_secret, bad_m_secret):
        rc.secure_zero(secret)

    # /certs surfaces the hybrid subject algorithm + mode
    items = {
        c["serial"]: c
        for c in (await client.get(f"{PKI}/certs", headers=h)).json()["items"]
    }
    assert items[serial]["subject_algorithm"] == "x25519-ml-kem-768"
    assert items[serial]["kem_mode"] == "x25519-ml-kem"
    assert items[serial]["algorithm"] == ca_algorithm


@pytest.mark.asyncio
async def test_kem_issue_unsupported_algorithm_rejected(
    client, master_password, admin_token
):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    await _reset_pki()
    h = {"Authorization": f"Bearer {admin_token}"}
    await client.post(f"{PKI}/init", json={"algorithm": "ed25519"}, headers=h)
    r = await client.post(
        f"{PKI}/kem/issue",
        json={"common_name": "kem.x", "kem_algorithm": "ml-kem-1024"},
        headers=h,
    )
    assert r.status_code == 400
    assert "ml-kem-768" in r.text


@pytest.mark.asyncio
async def test_kem_issue_before_init_404(client, master_password, admin_token):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    await _reset_pki()
    r = await client.post(
        f"{PKI}/kem/issue",
        json={"common_name": "kem.x"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_pki_unknown_algorithm_rejected(client, master_password, admin_token):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    await _reset_pki()
    r = await client.post(
        f"{PKI}/init",
        json={"algorithm": "rsa-2048"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_pki_issue_before_init_404(client, master_password, admin_token):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    await _reset_pki()
    r = await client.post(
        f"{PKI}/issue",
        json={"common_name": "x"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_pki_namespace_isolation(client, master_password, admin_token):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    await _reset_pki()
    h = {"Authorization": f"Bearer {admin_token}"}
    # each namespace gets its own CA (admin)
    await client.post(f"{PKI}/init", json={"algorithm": "ed25519"}, headers=h)
    await client.post(
        f"{PKI}/init", json={"algorithm": "ed25519", "namespace": "ns-a"}, headers=h
    )

    scoped = await _make_token(
        "pki-scoped-a", {"secrets": "rw", "namespaces": ["ns-a"]}
    )
    # issue into a namespace the token is NOT scoped to -> 403
    r = await client.post(
        f"{PKI}/issue",
        json={"common_name": "x", "namespace": "ns-b"},
        headers={"Authorization": f"Bearer {scoped}"},
    )
    assert r.status_code == 403
    # issue into the allowed namespace (which has its own CA) -> 201
    r = await client.post(
        f"{PKI}/issue",
        json={"common_name": "x", "namespace": "ns-a"},
        headers={"Authorization": f"Bearer {scoped}"},
    )
    assert r.status_code == 201, r.text


@pytest.mark.asyncio
async def test_pki_per_namespace_cas(client, master_password, admin_token):
    """Two namespaces get independent CAs (own algorithm + fingerprint)."""
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    await _reset_pki()
    h = {"Authorization": f"Bearer {admin_token}"}

    r = await client.post(
        f"{PKI}/init", json={"algorithm": "ed25519", "namespace": "team-a"}, headers=h
    )
    fpr_a = r.json()["fingerprint"]
    r = await client.post(
        f"{PKI}/init", json={"algorithm": "ml-dsa-65", "namespace": "team-b"}, headers=h
    )
    fpr_b = r.json()["fingerprint"]
    assert fpr_a != fpr_b

    # both CAs are listed
    r = await client.get(f"{PKI}/cas", headers=h)
    assert set(r.json()["namespaces"]) >= {"team-a", "team-b"}

    # each namespace serves its own CA + algorithm
    a = (await client.get(f"{PKI}/ca?namespace=team-a", headers=h)).json()
    b = (await client.get(f"{PKI}/ca?namespace=team-b", headers=h)).json()
    assert a["algorithm"] == "ed25519" and a["fingerprint"] == fpr_a
    assert b["algorithm"] == "ml-dsa-65" and b["fingerprint"] == fpr_b

    # issuing into a namespace without a CA -> 404
    r = await client.post(
        f"{PKI}/issue", json={"common_name": "x", "namespace": "team-c"}, headers=h
    )
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_pki_san_field_validation(client, master_password, admin_token):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    await _reset_pki()
    h = {"Authorization": f"Bearer {admin_token}"}
    await client.post(f"{PKI}/init", json={"algorithm": "ed25519"}, headers=h)

    # an IP in san_dns is rejected (422) -- it belongs in san_ips
    r = await client.post(
        f"{PKI}/issue",
        json={"common_name": "svc", "san_dns": ["192.168.10.1"]},
        headers=h,
    )
    assert r.status_code == 422
    # a non-IP in san_ips is rejected
    r = await client.post(
        f"{PKI}/issue", json={"common_name": "svc", "san_ips": ["not-an-ip"]}, headers=h
    )
    assert r.status_code == 422
    # correct placement is accepted
    r = await client.post(
        f"{PKI}/issue",
        json={
            "common_name": "svc",
            "san_dns": ["svc.internal"],
            "san_ips": ["192.168.10.1"],
        },
        headers=h,
    )
    assert r.status_code == 201, r.text
