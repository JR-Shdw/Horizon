# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
"""Minimal DER X.509 builder for ML-DSA (FIPS 204) certs.

cryptography <49 can't build ML-DSA SPKI/signatures, so the PQ CA hand-rolls the
TBSCertificate + Certificate + seed-form PKCS8 here (ed25519 goes through
cryptography). Narrow scope: CN names, UTCTime, basicConstraints/keyUsage/SAN/
EKU/SKI/AKI. The signing key never enters -- caller passes a sign(tbs)->sig
callback. OIDs id-ml-dsa-65/87 (RFC 9881); no AlgorithmIdentifier params.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime
from hashlib import sha1, sha256
from typing import Callable

ML_DSA_OID = {
    "ml-dsa-65": "2.16.840.1.101.3.4.3.18",
    "ml-dsa-87": "2.16.840.1.101.3.4.3.19",
}
PUB_LEN = {"ml-dsa-65": 1952, "ml-dsa-87": 2592}
SIG_LEN = {"ml-dsa-65": 3309, "ml-dsa-87": 4627}

# Ed25519 SPKI/PKCS8 OID (RFC 8410). Used as a composite component.
_OID_ED25519 = "1.3.101.112"

# Composite (hybrid) signature algorithms: classical + PQ, both required to
# verify (ANSSI sec 3.2 concatenation combiner, EUF-CMA). The public key and
# signature are draft-ietf-lamps-pq-composite-sigs shaped -- each a
# SEQUENCE SIZE (2) OF BIT STRING -- but the algorithm OID lives under a PRIVATE
# arc for now (in-house interop only; NOT interoperable with external X.509
# tooling). Swap to the draft's assigned id-MLDSA65-Ed25519 OID once it is an RFC.
# 1.3.6.1.4.1.62841 is a placeholder rhorizon private experimental PEN.
COMPOSITE_OID = {
    "ed25519-mldsa65": "1.3.6.1.4.1.62841.2.1",
}
# Component algorithms of each composite, in the fixed order they appear in the
# CompositePublicKey / CompositeSignatureValue SEQUENCE. The order IS the domain
# separator between legs -- never reorder.
COMPOSITE_COMPONENTS = {
    "ed25519-mldsa65": ("ed25519", "ml-dsa-65"),
}

# KEM subject-key algorithms (NIST CSOR OIDs, FIPS 203 for ML-KEM). A KEM cert
# carries one of these as its SUBJECT key (KeyUsage keyEncipherment) and is
# SIGNED by an ed25519 / ml-dsa-65 / composite CA -- subject algo != signature
# algo, unlike the ML-DSA/composite certs where they coincide.
KEM_OID = {
    "ml-kem-512": "2.16.840.1.101.3.4.4.1",
    "ml-kem-768": "2.16.840.1.101.3.4.4.2",
    "ml-kem-1024": "2.16.840.1.101.3.4.4.3",
}
KEM_PUB_LEN = {"ml-kem-512": 800, "ml-kem-768": 1184, "ml-kem-1024": 1568}

# Hybrid KEM subject-key algorithms: a CLASSICAL KEM leg (X25519) combined with a
# PQ KEM leg (ML-KEM) via an HKDF-SHA512 combiner. This is the ANSSI/BSI-required
# hybridation for the confidentiality axis -- the pure-ML-KEM KEM certs (KEM_OID)
# are PQ but NOT hybrid. The subject public key is a SEQUENCE SIZE (2) OF BIT
# STRING (x25519_pub, mlkem_pub) -- same shape as CompositePublicKey; the leg
# ORDER is the combiner's domain separator, never reorder. The OID lives under a
# PRIVATE arc (62841.3.x = hybrid-KEM branch, sibling of the 62841.2.x composite
# signatures) -- in-house interop only, swap to draft-ietf-lamps-pq-composite-kem's
# assigned OID once it is an RFC.
HYBRID_KEM_OID = {
    "x25519-ml-kem-768": "1.3.6.1.4.1.62841.3.1",
}
# Component (leg) algorithms of each hybrid KEM, in the fixed SEQUENCE order.
HYBRID_KEM_COMPONENTS = {
    "x25519-ml-kem-768": ("x25519", "ml-kem-768"),
}
_X25519_PUB_LEN = 32

# Signature algorithms usable for the outer signatureAlgorithm (a CA signs with
# one of these). ed25519 has a bare OID + no fixed SIG_LEN here (64 B, checked by
# the caller's signer); ml-dsa-65/87 are length-checked; composite is a
# SEQUENCE OF BIT STRING (no fixed length).
_ED25519_SIG = "ed25519"


def is_composite(algorithm: str) -> bool:
    return algorithm in COMPOSITE_OID


def is_hybrid_kem(algorithm: str) -> bool:
    return algorithm in HYBRID_KEM_OID


def _oid_for(algorithm: str) -> str:
    if algorithm in COMPOSITE_OID:
        return COMPOSITE_OID[algorithm]
    if algorithm in HYBRID_KEM_OID:
        return HYBRID_KEM_OID[algorithm]
    if algorithm in ML_DSA_OID:
        return ML_DSA_OID[algorithm]
    if algorithm in KEM_OID:
        return KEM_OID[algorithm]
    if algorithm == _ED25519_SIG:
        return _OID_ED25519
    raise KeyError(f"unknown algorithm OID: {algorithm!r}")


_OID_CN = "2.5.4.3"
_OID_BASIC_CONSTRAINTS = "2.5.29.19"
_OID_KEY_USAGE = "2.5.29.15"
_OID_SAN = "2.5.29.17"
_OID_EKU = "2.5.29.37"
_OID_SKI = "2.5.29.14"
_OID_AKI = "2.5.29.35"
EKU_SERVER_AUTH = "1.3.6.1.5.5.7.3.1"
EKU_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"


# --- DER primitives ---------------------------------------------------------


def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = []
    while n:
        body.append(n & 0xFF)
        n >>= 8
    body.reverse()
    return bytes([0x80 | len(body)]) + bytes(body)


def _tlv(tag: int, content: bytes | bytearray) -> bytes:
    return b"".join((bytes([tag]), _der_len(len(content)), content))


def _seq(*items: bytes) -> bytes:
    return _tlv(0x30, b"".join(items))


def _set(*items: bytes) -> bytes:
    return _tlv(0x31, b"".join(items))


def _int(n: int) -> bytes:
    if n == 0:
        return _tlv(0x02, b"\x00")
    body = []
    while n:
        body.append(n & 0xFF)
        n >>= 8
    body.reverse()
    if body[0] & 0x80:  # avoid being read as negative
        body.insert(0, 0x00)
    return _tlv(0x02, bytes(body))


def _oid(dotted: str) -> bytes:
    parts = [int(p) for p in dotted.split(".")]
    first = 40 * parts[0] + parts[1]
    out = [first]
    for p in parts[2:]:
        if p < 0x80:
            out.append(p)
            continue
        stack = [p & 0x7F]
        p >>= 7
        while p:
            stack.append((p & 0x7F) | 0x80)
            p >>= 7
        out.extend(reversed(stack))
    return _tlv(0x06, bytes(out))


def _bitstring(data: bytes) -> bytes:
    return _tlv(0x03, b"\x00" + data)


def _octet(data: bytes | bytearray) -> bytes:
    return _tlv(0x04, data)


def _utf8(s: str) -> bytes:
    return _tlv(0x0C, s.encode("utf-8"))


def _bool(b: bool) -> bytes:
    return _tlv(0x01, b"\xff" if b else b"\x00")


def _x509_time(dt: datetime) -> bytes:
    # RFC 5280 Time CHOICE: UTCTime (0x17, 2-digit year) through 2049,
    # GeneralizedTime (0x18, 4-digit year) from 2050 on.
    if dt.year < 2050:
        return _tlv(0x17, dt.strftime("%y%m%d%H%M%SZ").encode("ascii"))
    return _tlv(0x18, dt.strftime("%Y%m%d%H%M%SZ").encode("ascii"))


def _ctx(tag_num: int, content: bytes, *, constructed: bool = True) -> bytes:
    return _tlv((0xA0 if constructed else 0x80) | tag_num, content)


# --- X.509 structure --------------------------------------------------------


def _name(cn: str) -> bytes:
    return _seq(_set(_seq(_oid(_OID_CN), _utf8(cn))))


def _algid(algorithm: str) -> bytes:
    # AlgorithmIdentifier: SEQUENCE { OID } -- no parameters (RFC 9881 for ML-DSA,
    # FIPS 203 for ML-KEM, RFC 8410 for ed25519; composite OIDs also no params).
    return _seq(_oid(_oid_for(algorithm)))


def spki(algorithm: str, public_key: bytes) -> bytes:
    """SubjectPublicKeyInfo for an ML-DSA / ML-KEM / ed25519 / composite key.

    Length is checked where fixed (ML-DSA, ML-KEM, ed25519). For composite,
    ``public_key`` is the CompositePublicKey DER (SEQUENCE OF BIT STRING) -- no
    fixed length, so the check is skipped.
    """
    expected = None
    if algorithm in PUB_LEN:
        expected = PUB_LEN[algorithm]
    elif algorithm in KEM_PUB_LEN:
        expected = KEM_PUB_LEN[algorithm]
    elif algorithm == _ED25519_SIG:
        expected = 32
    if expected is not None and len(public_key) != expected:
        raise ValueError(
            f"{algorithm} public key must be {expected} bytes, got {len(public_key)}"
        )
    return _seq(_algid(algorithm), _bitstring(public_key))


def composite_public_value(component_pubs: list[bytes]) -> bytes:
    """CompositePublicKey ::= SEQUENCE SIZE (2) OF BIT STRING (raw component keys).

    Order is fixed by COMPOSITE_COMPONENTS -- caller passes pubs in that order.
    """
    return _seq(*[_bitstring(p) for p in component_pubs])


def composite_signature_value(component_sigs: list[bytes]) -> bytes:
    """CompositeSignatureValue ::= SEQUENCE SIZE (2) OF BIT STRING (raw sigs)."""
    return _seq(*[_bitstring(s) for s in component_sigs])


def split_seq_of_bitstrings(der: bytes) -> list[bytes]:
    """Parse a SEQUENCE OF BIT STRING back into raw component byte strings.

    Inverse of :func:`composite_public_value` / :func:`composite_signature_value`.
    Drops each BIT STRING's leading unused-bits octet (always 0 here).
    """
    tag, content, _ = _read_tlv(der, 0)
    if tag != 0x30:
        raise ValueError("expected SEQUENCE")
    out: list[bytes] = []
    i = 0
    while i < len(content):
        btag, bcontent, i = _read_tlv(content, i)
        if btag != 0x03:
            raise ValueError("expected BIT STRING inside composite SEQUENCE")
        out.append(bcontent[1:])  # drop the unused-bits octet
    return out


def _extension(oid: str, critical: bool, value_der: bytes) -> bytes:
    items = [_oid(oid)]
    if critical:
        items.append(_bool(True))
    items.append(_octet(value_der))
    return _seq(*items)


def _ext_basic_constraints(ca: bool, path_len: int | None) -> bytes:
    items = []
    if ca:
        items.append(_bool(True))  # cA DEFAULT FALSE -> emit only when True
    if path_len is not None:
        items.append(_int(path_len))
    return _extension(_OID_BASIC_CONSTRAINTS, True, _seq(*items))


def _ext_key_usage(bit_positions: list[int]) -> bytes:
    # KeyUsage BIT STRING, bit 0 = MSB of the first content octet.
    if not bit_positions:
        raise ValueError("keyUsage needs at least one bit")
    top = max(bit_positions)
    nbytes = top // 8 + 1
    buf = bytearray(nbytes)
    for b in bit_positions:
        buf[b // 8] |= 0x80 >> (b % 8)
    unused = 8 - (top % 8 + 1)
    value = _tlv(0x03, bytes([unused]) + bytes(buf))
    return _extension(_OID_KEY_USAGE, True, value)


def _general_name_ip(addr: str) -> bytes:
    packed = ipaddress.ip_address(addr).packed  # 4 (v4) or 16 (v6) bytes
    return _tlv(0x87, packed)  # iPAddress [7] IMPLICIT OCTET STRING


def _general_name_dns(name: str) -> bytes:
    return _tlv(0x82, name.encode("ascii"))  # dNSName [2] IMPLICIT IA5String


def _ext_san(san_ips: list[str], san_dns: list[str]) -> bytes:
    gns = [_general_name_dns(d) for d in san_dns]
    gns += [_general_name_ip(ip) for ip in san_ips]
    # SAN is non-critical when the subject DN carries a CN (our case).
    return _extension(_OID_SAN, False, _seq(*gns))


def _ext_eku(oids: list[str]) -> bytes:
    return _extension(_OID_EKU, False, _seq(*[_oid(o) for o in oids]))


def _ext_ski(public_key: bytes) -> bytes:
    # RFC 5280 method 1: SHA-1 of the public key as an identifier, not a
    # security hash (usedforsecurity=False -> not a collision-sensitive use).
    keyid = sha1(public_key, usedforsecurity=False).digest()
    return _extension(_OID_SKI, False, _octet(keyid))


def _ext_aki(issuer_public_key: bytes) -> bytes:
    keyid = sha1(issuer_public_key, usedforsecurity=False).digest()
    # AuthorityKeyIdentifier ::= SEQUENCE { keyIdentifier [0] OCTET STRING }
    return _extension(_OID_AKI, False, _seq(_ctx(0, keyid, constructed=False)))


def build_tbs(
    *,
    serial: int,
    subject_cn: str,
    issuer_cn: str,
    not_before: datetime,
    not_after: datetime,
    subject_public_key: bytes,
    issuer_public_key: bytes,
    is_ca: bool,
    subject_key_algorithm: str,
    signature_algorithm: str,
    kem: bool = False,
    path_len: int | None = None,
    san_ips: list[str] | None = None,
    san_dns: list[str] | None = None,
    eku: list[str] | None = None,
) -> bytes:
    """Assemble a v3 TBSCertificate DER.

    The subject SPKI uses ``subject_key_algorithm``; the inner signature
    AlgorithmIdentifier uses ``signature_algorithm``. They coincide for ML-DSA /
    composite certs and differ for KEM certs (subject = ML-KEM, signature = the
    CA's). ``kem=True`` sets KeyUsage=keyEncipherment and drops EKU (a KEM leaf
    does not do serverAuth/clientAuth). The signing key is NOT referenced here --
    the caller signs this DER and reassembles via :func:`assemble_cert`.
    """
    ska, sga = subject_key_algorithm, signature_algorithm
    if kem:
        ku = _ext_key_usage([2])  # keyEncipherment
        eku = None
    elif is_ca:
        ku = _ext_key_usage([0, 5, 6])  # digitalSignature, keyCertSign, cRLSign
    else:
        ku = _ext_key_usage([0, 4])  # digitalSignature, keyAgreement

    exts = [_ext_basic_constraints(is_ca, path_len), ku, _ext_ski(subject_public_key)]
    if not is_ca:
        exts.append(_ext_aki(issuer_public_key))
    if san_ips or san_dns:
        exts.append(_ext_san(san_ips or [], san_dns or []))
    if eku:
        exts.append(_ext_eku(eku))

    return _seq(
        _ctx(0, _int(2)),  # version [0] EXPLICIT v3 (== 2)
        _int(serial),
        _algid(sga),  # signature AlgorithmIdentifier
        _name(issuer_cn),
        _seq(_x509_time(not_before), _x509_time(not_after)),
        _name(subject_cn),
        spki(ska, subject_public_key),
        _ctx(3, _seq(*exts)),  # extensions [3] EXPLICIT
    )


def assemble_cert(signature_algorithm: str, tbs: bytes, signature: bytes) -> bytes:
    """Certificate DER from (tbs, signature) under ``signature_algorithm``.

    Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature }.
    The ML-DSA fixed-length check applies only to ML-DSA signatures; composite
    (SEQUENCE OF BIT STRING) and ed25519 (64 B, caller-checked) skip it.
    """
    exp = SIG_LEN.get(signature_algorithm)
    if exp is not None and len(signature) != exp:
        raise ValueError(
            f"{signature_algorithm} signature must be {exp} bytes, got {len(signature)}"
        )
    return _seq(tbs, _algid(signature_algorithm), _bitstring(signature))


def mldsa_private_key_pem(algorithm: str, seed: bytes | bytearray) -> bytes:
    """PKCS8 (OneAsymmetricKey) PEM for an ML-DSA private key, seed form.

    RFC 9881 / OpenSSL: privateKey OCTET STRING wraps the ML-DSA-PrivateKey
    CHOICE ``seed [0] OCTET STRING (SIZE(32))`` -- the [0] is IMPLICIT, so the
    content is one context-primitive TLV (tag 0x80, len 32, the 32-byte FIPS 204
    keygen seed). This is the encoding OpenSSL 3.5+/cryptography>=49 emit + load,
    so issued ML-DSA keys are interoperable. Returned once on issue.
    """
    if len(seed) != 32:
        raise ValueError(f"ML-DSA seed must be 32 bytes, got {len(seed)}")
    choice = _tlv(0x80, seed)  # seed [0] IMPLICIT OCTET STRING
    pki = _seq(_int(0), _algid(algorithm), _octet(choice))
    import base64

    b64 = base64.encodebytes(pki).replace(b"\n", b"")
    lines = b"\n".join(b64[i : i + 64] for i in range(0, len(b64), 64))
    return b"-----BEGIN PRIVATE KEY-----\n" + lines + b"\n-----END PRIVATE KEY-----\n"


def mlkem_private_key_pem(algorithm: str, dk: bytes | bytearray) -> bytes:
    """PKCS8 (OneAsymmetricKey) PEM for an ML-KEM decapsulation key, expanded form.

    draft-ietf-lamps-kyber-certificates:
    ``ML-KEM-PrivateKey ::= CHOICE { seed [0] OCTET STRING, expandedKey OCTET
    STRING, both SEQUENCE {...} }``. We hold the FIPS 203 expanded decapsulation
    key (DK_LEN bytes), not the 64-byte seed, so we emit the ``expandedKey``
    alternative: the privateKey OCTET STRING wraps one OCTET STRING(dk). Mirrors
    :func:`mldsa_private_key_pem` (which uses the ``seed [0]`` alternative). This
    is the return-once leaf secret -- shown once on issue, never stored. In-house
    interop (swappable to the draft's assigned encoding when it becomes an RFC).
    """
    if algorithm not in KEM_OID:
        raise ValueError(f"not an ML-KEM algorithm: {algorithm!r}")
    # FIPS 203 expanded decapsulation-key sizes (guard a wrong-variant blob).
    dk_len = {"ml-kem-512": 1632, "ml-kem-768": 2400, "ml-kem-1024": 3168}[algorithm]
    if len(dk) != dk_len:
        raise ValueError(
            f"{algorithm} decaps key must be {dk_len} bytes, got {len(dk)}"
        )
    choice = _octet(dk)  # ML-KEM-PrivateKey ::= expandedKey OCTET STRING
    pki = _seq(_int(0), _algid(algorithm), _octet(choice))
    import base64

    b64 = base64.encodebytes(pki).replace(b"\n", b"")
    lines = b"\n".join(b64[i : i + 64] for i in range(0, len(b64), 64))
    return b"-----BEGIN PRIVATE KEY-----\n" + lines + b"\n-----END PRIVATE KEY-----\n"


def mlkem_dk_from_pem(pem: bytes) -> bytes:
    """Recover the raw ML-KEM decapsulation key from a return-once PKCS8 PEM.

    Inverse of :func:`mlkem_private_key_pem`. OneAsymmetricKey
    ``{ version, algid, privateKey OCTET STRING }`` where privateKey wraps the
    ML-KEM-PrivateKey expandedKey OCTET STRING. Parses the FIRST PEM block found.
    """
    der = pem_to_der(pem)
    _t, seqc, _ = _read_tlv(der, 0)
    _t, _v, i = _read_tlv(seqc, 0)  # version
    _t, _v, i = _read_tlv(seqc, i)  # algid
    _t, pk_oct, _ = _read_tlv(seqc, i)  # privateKey OCTET STRING
    _t, dk, _ = _read_tlv(pk_oct, 0)  # inner OCTET STRING = expandedKey
    return dk


def composite_private_key_pem(
    ed25519_pkcs8_pem: bytes, mldsa_seed: bytes | bytearray
) -> bytes:
    """Return-once composite private key: two standard PKCS8 PEM blocks.

    The ed25519 block (from cryptography's PKCS8 serializer) followed by the
    seed-form ML-DSA block (:func:`mldsa_private_key_pem`). Each block is
    independently loadable by standard tooling -- we do not invent a composite
    PKCS8 OID. Returned once on issue, never stored.
    """
    ed = ed25519_pkcs8_pem
    if not ed.endswith(b"\n"):
        ed += b"\n"
    return ed + mldsa_private_key_pem("ml-dsa-65", mldsa_seed)


def hybrid_kem_private_key_pem(
    x25519_pkcs8_pem: bytes, mlkem_algorithm: str, mlkem_dk: bytes | bytearray
) -> bytes:
    """Return-once hybrid KEM private key: two standard PKCS8 PEM blocks.

    The X25519 block (from cryptography's PKCS8 serializer, RFC 8410) followed by
    the ML-KEM expandedKey block (:func:`mlkem_private_key_pem`). Each block is
    independently loadable -- we do not invent a composite PKCS8 OID. The leg
    order (X25519 first) matches the subject public key and the combiner's domain
    separator. Shown once on issue, never stored.
    """
    x = x25519_pkcs8_pem
    if not x.endswith(b"\n"):
        x += b"\n"
    return x + mlkem_private_key_pem(mlkem_algorithm, mlkem_dk)


def der_to_pem(der: bytes) -> bytes:
    import base64

    b64 = base64.encodebytes(der).replace(b"\n", b"")
    lines = b"\n".join(b64[i : i + 64] for i in range(0, len(b64), 64))
    return b"-----BEGIN CERTIFICATE-----\n" + lines + b"\n-----END CERTIFICATE-----\n"


def pem_to_der(pem: bytes) -> bytes:
    import base64

    body = b"".join(
        line for line in pem.splitlines() if line and not line.startswith(b"-----")
    )
    return base64.b64decode(body)


def fingerprint(cert_der: bytes) -> str:
    """Lowercase hex SHA-256 of the cert DER (trust-anchor identity)."""
    return sha256(cert_der).hexdigest()


def _read_tlv(b: bytes, i: int) -> tuple[int, bytes, int]:
    """Read one DER TLV at offset i. Returns (tag, content, next_offset)."""
    tag = b[i]
    length = b[i + 1]
    off = 2
    if length & 0x80:
        nb = length & 0x7F
        length = int.from_bytes(b[i + 2 : i + 2 + nb], "big")
        off = 2 + nb
    return tag, b[i + off : i + off + length], i + off + length


def extract_tbs_and_sig(cert_der: bytes) -> tuple[bytes, bytes]:
    """Return (tbs_der, signature) from a Certificate DER.

    Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature }.
    Lets a verifier check an ML-DSA cert's signature via ``verify_ml_dsa`` even
    where cryptography (<49) can't parse it (CA self-check, tests).
    """
    _tag, content, _ = _read_tlv(cert_der, 0)  # outer SEQUENCE content
    _ttag, _tc, j = _read_tlv(content, 0)  # tbsCertificate (whole TLV is content[:j])
    tbs = content[:j]
    _atag, _ac, k = _read_tlv(content, j)  # signatureAlgorithm
    _btag, bit_content, _ = _read_tlv(content, k)  # signature BIT STRING
    return tbs, bit_content[1:]  # drop the unused-bits octet


def extract_subject_pubkey(cert_der: bytes) -> bytes:
    """Return the subjectPublicKeyInfo BIT STRING content (unused-bits octet
    dropped) from a Certificate DER.

    For a composite cert this is the CompositePublicKey DER
    (SEQUENCE OF BIT STRING) -- feed it to :func:`split_seq_of_bitstrings`.
    Assumes the v3 layout emitted by :func:`build_tbs` (version [0] always
    present): tbs elements are version, serial, sigAlg, issuer, validity,
    subject, subjectPublicKeyInfo, [3] extensions.
    """
    _tag, cert_content, _ = _read_tlv(cert_der, 0)  # Certificate SEQUENCE
    _ttag, tbs_content, _ = _read_tlv(cert_content, 0)  # tbsCertificate content
    i = 0
    for _ in range(6):  # skip version..subject (6 elements)
        _t, _c, i = _read_tlv(tbs_content, i)
    _stag, spki_content, _ = _read_tlv(tbs_content, i)  # subjectPublicKeyInfo
    _atag, _ac, j = _read_tlv(spki_content, 0)  # AlgorithmIdentifier
    _btag, bit_content, _ = _read_tlv(spki_content, j)  # subjectPublicKey BIT STRING
    return bit_content[1:]


def build_cert(
    *,
    sign: Callable[[bytes], bytes],
    subject_key_algorithm: str,
    signature_algorithm: str,
    kem: bool = False,
    **tbs_kwargs,
) -> tuple[bytes, str]:
    """Build + sign a cert. Returns ``(pem, fingerprint_hex)``.

    ``subject_key_algorithm`` == ``signature_algorithm`` for ML-DSA/composite
    certs; they differ for a KEM cert (subject = ML-KEM, signature = the CA's).
    ``sign`` takes the TBS DER and returns the raw signature bytes under
    ``signature_algorithm``, over the TBS verbatim (matching how the cert is
    later verified).
    """
    tbs = build_tbs(
        subject_key_algorithm=subject_key_algorithm,
        signature_algorithm=signature_algorithm,
        kem=kem,
        **tbs_kwargs,
    )
    sig = sign(tbs)
    der = assemble_cert(signature_algorithm, tbs, sig)
    return der_to_pem(der), fingerprint(der)
