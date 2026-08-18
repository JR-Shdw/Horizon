# Hybrid KEM certificates (X25519 + ML-KEM-768)

This document specifies the hybrid KEM certificate format rhorizon issues under
`kem_mode=x25519-ml-kem` and shows how a holder recovers a shared secret. It is
the confidentiality-axis companion to the composite *signature* certs described
in [PKI.md](PKI.md). For the "why hybrid" rationale (ANSSI/BSI mandate,
harvest-now-decrypt-later) see the [Hybrid KEM certificates](PKI.md#hybrid-kem-certificates-x25519-ml-kem-768)
section of PKI.md.

## Why two legs

A hybrid KEM combines a **classical** key-establishment mechanism (X25519, an
elliptic-curve Diffie-Hellman) with a **post-quantum** one (ML-KEM-768, FIPS 203).
The derived secret stays secure as long as *at least one* leg is unbroken:

- if a quantum computer breaks X25519, the ML-KEM leg still protects the secret;
- if a flaw is found in the young ML-KEM code (or the standard), the classical
  X25519 leg still protects it.

ANSSI and BSI both **require** this combination for the confidentiality axis;
pure ML-KEM (`kem_mode=ml-kem`) is post-quantum but not hybrid and does not meet
that bar on its own.

## Certificate shape

A hybrid KEM cert is an ordinary X.509 v3 certificate whose **subject public
key** is the hybrid key and whose **signature** is produced by the namespace CA
under its own algorithm (`ed25519`, `ml-dsa-65`, or `ed25519-mldsa65`). Subject
algorithm != signature algorithm — the Workstream-2 split.

```
subjectPublicKeyInfo
  AlgorithmIdentifier  OID 1.3.6.1.4.1.62841.3.1   -- x25519-ml-kem-768 (private arc)
  subjectPublicKey BIT STRING
    SEQUENCE SIZE (2) OF BIT STRING
      BIT STRING  x25519_pub    (32 bytes)         -- leg 0 (classical)
      BIT STRING  mlkem768_pub  (1184 bytes)       -- leg 1 (post-quantum)
KeyUsage         keyEncipherment (bit 2), critical
ExtendedKeyUsage absent  -- a KEM key does not do serverAuth/clientAuth
```

- **Leg order is fixed** (X25519 first, ML-KEM second) and is part of the
  combiner's domain separation — never reorder.
- The OID is a **private-arc placeholder** (`62841.3.x` = hybrid-KEM branch),
  swappable to `draft-ietf-lamps-pq-composite-kem`'s assigned OID once it is an
  RFC. These certs are in-house interop only; general X.509 tooling will not
  parse the composite subject key.

### Return-once private key

On issue, the response `private_key` field carries **two** standard PKCS8 PEM
blocks, shown once and never stored server-side:

```
-----BEGIN PRIVATE KEY-----      <- X25519 (RFC 8410)
...
-----END PRIVATE KEY-----
-----BEGIN PRIVATE KEY-----      <- ML-KEM-768 expandedKey (FIPS 203)
...
-----END PRIVATE KEY-----
```

Each block is independently loadable (no invented composite PKCS8 OID). The
X25519 block loads with any RFC 8410 tool; the ML-KEM block is the FIPS 203
`expandedKey` form (in-house until the LAMPS drafts assign an encoding).

## The combiner

Both parties derive the same 32-byte shared secret from the two leg secrets:

```
IKM  = ss_x25519 || ss_mlkem                       (x25519 leg FIRST = domain separator)
salt = "rhorizon-hybrid-kem-v1"
info = SHA512( label || ct_x25519 || ct_mlkem || pk_x25519 || pk_mlkem )
ss   = HKDF-Expand( HKDF-Extract(salt, IKM), info, 32 )     -- HKDF-SHA512
```

- `label` = `"x25519-ml-kem-768"` (the construction id; a different parameter set
  or a future leg change gets a fresh label so secrets never collide).
- `pk_x25519` / `pk_mlkem` are the **recipient's static** public keys (the cert
  subject legs). `ct_x25519` is the sender's ephemeral X25519 public key;
  `ct_mlkem` is the ML-KEM ciphertext.
- Binding both ciphertexts and both public keys into `info` gives
  re-encapsulation / transcript resistance (ETSI TS 103 744 /
  Giacon-Heuer-Poettering shape). The salt is version-suffixed so the whole
  construction is replaceable atomically.

The combiner is the only new cryptographic step and it runs in the Rust
extension (`rhorizon_crypto.hybrid_kdf`), gated by a known-answer test whose
expected value is computed independently by OpenSSL's HKDF-SHA512 — a genuine
cross-implementation KAT, plus a Python-side parity test against the live wheel.
The X25519 leg (keygen/DH/PKCS8) is OpenSSL via `cryptography`; ML-KEM is
`fips203`. No home-made primitive.

## Encapsulate / decapsulate

Sender (has the cert; public-only, needs no secret):

```
ephemeral X25519 keypair (eph_sk, ct_x25519)
ss_x25519 = X25519(eph_sk, pk_x25519)              # DH with recipient static leg
ss_mlkem, ct_mlkem = ML-KEM-768.Encaps(pk_mlkem)
ss = hybrid_kdf(ss_x25519, ss_mlkem, ct_x25519, ct_mlkem, pk_x25519, pk_mlkem, label)
# transmit (ct_x25519, ct_mlkem) to the recipient
```

Recipient (holds the return-once private key + its own cert):

```
ss_x25519 = X25519(x25519_sk, ct_x25519)           # same DH value
ss_mlkem  = ML-KEM-768.Decaps(mlkem_dk, ct_mlkem)
ss = hybrid_kdf(ss_x25519, ss_mlkem, ct_x25519, ct_mlkem, pk_x25519, pk_mlkem, label)
```

Both sides compute the identical `ss`. ML-KEM's implicit rejection means a
tampered `ct_mlkem` yields a deterministic pseudo-random `ss_mlkem` (never an
error), so a manipulated ciphertext simply makes the two parties disagree — which
surfaces the first time the derived key is used.

### Python helper

`api/app/pki_kem.py` composes the primitives:

```python
from api.app import pki_asn1, pki_kem

# --- sender: parse the cert subject into its two legs, then encapsulate
subject = pki_asn1.extract_subject_pubkey(pki_asn1.pem_to_der(cert_pem))
x25519_pub, mlkem_ek = pki_kem.split_hybrid_subject_key(subject)
ss_send, ct_x, ct_m = pki_kem.hybrid_encaps(x25519_pub, mlkem_ek)

# --- recipient: load the two-block private key, then decapsulate
x25519_priv, mlkem_dk = pki_kem.load_hybrid_private_pem(private_key_pem)
ss_recv = pki_kem.hybrid_decaps(
    x25519_priv, mlkem_dk, x25519_pub, mlkem_ek, ct_x, ct_m
)
assert ss_send == ss_recv          # identical 32-byte shared secret
```

## Verifying the CA signature

The hybrid subject key does not change how the CA signature is checked — verify
it with the same in-house verifier as any other leaf of that CA algorithm
(`ed25519` via `cryptography`, `ml-dsa-65` via `verify_ml_dsa`, composite via
`pki_ca.verify_composite_cert`). See [PKI.md](PKI.md#verifying-a-leaf).

## Limits

- Only `x25519-ml-kem-768` is wired (matches the TLS `X25519MLKEM768` set). Other
  ML-KEM parameter sets are known to the ASN.1 layer but rejected by the build.
- In-house interop only until `draft-ietf-lamps-pq-composite-kem` is an RFC; at
  that point swap the private OID + encoding and keep the combiner (or adopt the
  draft's KDF if it diverges) behind a new `HYBRID_KEM_SALT` version.
- A code-based third leg (Classic McEliece) for a BSI/ISO hedge remains a
  deferred, optional Cut 3.
