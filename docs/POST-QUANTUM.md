# Quantum-resistant posture

rhorizon's data-at-rest design uses 256-bit symmetric primitives and
information-theoretic secret sharing. Shor's algorithm does not break those
primitives; Grover's algorithm reduces the brute-force margin of symmetric
keys. Transport prefers a hybrid KEM, while interactive authentication and
certificate signatures remain classical.

Two constraints frame the assessment below:

- **Symmetric cryptography and public-key exchange have different quantum
  margins.** The configured 256-bit symmetric primitives retain an estimated
  128-bit brute-force margin under Grover's algorithm. A hybrid
  key-encapsulation mechanism combines ML-KEM with classical X25519 for TLS
  key exchange.
- **An old protocol version or a classical-only key exchange is a
  harvest-now-decrypt-later risk.** An attacker records the handshake today and
  may decrypt the session if a cryptographically relevant quantum computer
  later breaks its classical exchange. Operators must verify hybrid negotiation
  on each transport path; configured classical fallbacks are not
  quantum-resistant.

## Application primitives (data at rest, internal)

Assessment at the configured key sizes:

| Primitive | Role | Quantum status |
|---|---|---|
| Argon2id | master-key derivation from the password | password strength and KDF cost remain decisive |
| HKDF-SHA512 | sub-key derivation | symmetric construction; not broken by Shor |
| XChaCha20-Poly1305 | secret encryption (secret to DEK), 256-bit | estimated 128-bit brute-force margin under Grover |
| AES-256-GCM | double envelope (DEK to dek_key) | estimated 128-bit brute-force margin under Grover |
| HMAC-SHA512 | token auth | symmetric construction; not broken by Shor |
| HMAC chain | audit tamper-evidence | symmetric construction; no public-key signature dependency |
| Shamir GF(256) | cluster failover shares | information-theoretic if shares remain independent and the threshold is uncompromised |
| HMAC bootstrap (ha_password) | cross-node HA JOIN | symmetric construction; password entropy still matters |
| age passphrase (scrypt + ChaCha20-Poly1305) | encrypted backups | password strength and KDF cost remain decisive |

Stored ciphertext does not depend on a recorded public-key handshake: it uses
AES-256 / XChaCha20 under password-derived key material, and age backups use the
scrypt passphrase recipient rather than an X25519 recipient. Audit authenticity
is currently Ed25519, with HMAC-SHA512 only for legacy/fallback rows; Ed25519 is
not post-quantum and must not be counted as part of the symmetric storage claim.

## Client and perimeter primitives (current)

Concrete versions in the shipped image: OpenSSL 3.5.x, TLS 1.3, PostgreSQL 18,
Go 1.25, rustls with aws-lc-rs.

| Surface | Primitive (current) | Type | Quantum status |
|---|---|---|---|
| UI / client TLS (nginx) | TLS 1.3 `X25519MLKEM768` preferred | hybrid KEM with classical fallback | quantum-resistant only when the hybrid group is negotiated |
| PG to API (asyncpg) | TLS 1.3 `ssl_groups=X25519MLKEM768:...` (PG 18 + OpenSSL 3.5) | hybrid KEM with classical fallback | quantum-resistant only when the hybrid group is negotiated |
| Inter-node HA (cluster mTLS) | hybrid KEM via nginx + ECDSA client cert | KEM hybrid, signature classical | exchange is quantum-resistant when hybrid negotiation succeeds |
| Go connectors (terraform / ESO providers) | `X25519MLKEM768` default (Go 1.25) | hybrid KEM | verify negotiation against the target |
| rh-* Rust agent (fetch/inject/watch) | `X25519MLKEM768` via aws-lc-rs rustls | hybrid KEM | verify negotiation against the target |
| WebAuthn / FIDO2 | ECDSA / EdDSA P-256 | signature | classical (interactive, not harvestable) |

The Rust agent carries plaintext secret values on its hop, so it matters most:
it builds its Rust `reqwest` HTTP client on the aws-lc-rs rustls provider (ring,
the previous provider, has no ML-KEM). Proof is at the wire: `tools/pq-verify.sh [host:port]`
passes only if two independent stacks (OpenSSL 3.5 and aws-lc-rs) both negotiate
`X25519MLKEM768` against the target.

## Symmetric vs asymmetric

| Class | Used for | Examples | Quantum status |
|---|---|---|---|
| Symmetric | data at rest, auth, KDF | AES-256-GCM, XChaCha20, HMAC-SHA512, Argon2id | 256-bit keys retain an estimated 128-bit Grover margin |
| KEM (key exchange) | TLS handshakes | `X25519MLKEM768` (ML-KEM-768 hybrid, FIPS 203) | quantum-resistant when negotiated |
| Signature | TLS certs, WebAuthn | ECDSA / EdDSA P-256 | classical, but auth-only (live MITM, not harvestable) |
| Secret sharing | HA failover | Shamir GF(256) | information-theoretic under its share assumptions |

Only the **KEM** protects against harvest-now-decrypt-later. A classical
signature affects only live MITM forgery, which needs a quantum computer at
handshake time, so a PQ signature on the *transport* handshake would be cosmetic.

## PKI engine signatures (ML-DSA, optional)

The [PKI engine](PKI.md) is the one place a post-quantum *signature* is not
cosmetic: it issues service-identity certificates that may outlive the arrival
of a cryptographically relevant quantum computer, for internal relying parties
you control (so you can require an ML-DSA-aware verifier).

The CA algorithm is selectable per CA: `ed25519` (classical) or `ml-dsa-65`
(ML-DSA, FIPS 204). ML-DSA certs are signed by an in-vault Rust signer
(`fips204`, pure Rust, no OpenSSL 3.5+ dependency, so it works on LibreSSL too)
and are interoperable with OpenSSL 3.5+/`cryptography` 49+. The `fips204` crate
is not yet independently audited, so it is gated by NIST ACVP ML-DSA-65
known-answer vectors and cross-verified against OpenSSL; constant-time posture
is covered in [Side-channels](SIDE-CHANNELS.md).

Selecting ML-DSA removes the classical signature from that issued certificate
chain for relying parties that support it. End-to-end transport resistance
still depends on live negotiation of `X25519MLKEM768`; configured classical
fallbacks remain. This does **not** change cluster mTLS or WebAuthn signatures,
which remain classical.

## Configuration and verification

`frontend/nginx-tls.conf` pins the TLS 1.3 key exchange to the hybrid group:

```
ssl_ecdh_curve X25519MLKEM768:X25519:secp256r1;
```

`X25519MLKEM768` is the IETF hybrid of classical X25519 and ML-KEM-768. Listing
it first makes PQ-capable clients negotiate it; the X25519 / P-256 fallback
keeps older clients working. PostgreSQL 18 mirrors this with
`ssl_groups=X25519MLKEM768:X25519:secp256r1` (set `PG_SSL_GROUPS` in `.env`).

Requirements, all met by the pinned image: OpenSSL 3.5 or newer (exposes
`X25519MLKEM768`; nginx rejects the group at startup on older libssl) and
TLS 1.3 (the hybrid KEM is a TLS 1.3 group; TLS 1.2 falls back to classical
ECDHE).

Verify a live endpoint negotiated the PQ group:

```bash
openssl s_client -connect HOST:8443 -tls1_3 -groups X25519MLKEM768 </dev/null 2>/dev/null \
  | grep -i 'Negotiated TLS1.3 group'
```
