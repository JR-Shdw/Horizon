# Standards & sources

RFCs referenced by Resurgamus Horizon's own source (build artifacts / vendored
TLS libraries excluded). One line each: `RFC NUMBER - topic`.

## Cryptographic primitives & key derivation

- RFC 2104 - HMAC (keyed-hash message authentication)
- RFC 4231 - HMAC-SHA-2 test vectors (HMAC-SHA512 known-answer gate)
- RFC 5869 - HKDF (HMAC-based key derivation function)
- RFC 8439 - ChaCha20 & Poly1305 AEAD (basis of XChaCha20-Poly1305)
- RFC 9106 - Argon2 memory-hard password hashing (Argon2id master-key KDF)
- RFC 7914 - scrypt (Argon2 predecessor; age backup passphrase KDF)

## Signatures & key encodings

- RFC 8032 - EdDSA / Ed25519 signatures (audit chain + cluster/PKI ed25519 CA)
- RFC 8410 - Ed25519 / X25519 algorithm identifiers in X.509

## PKI / X.509

- RFC 5280 - X.509 certificate & CRL profile (extensions, SKI/AKI)
- RFC 9881 - ML-DSA (FIPS 204) algorithm identifiers & keys in X.509 (PQ certs)

## Two-factor / one-time passwords

- RFC 4226 - HOTP (HMAC-based one-time password)
- RFC 6238 - TOTP (time-based one-time password)

## LDAP

- RFC 3062 - LDAP Password Modify extended operation
- RFC 4515 - LDAP search filter string representation (escaping)

## Naming & networking

- RFC 1035 - DNS domain names (cert SAN / label validation)
- RFC 5890 - IDNA internationalized domain names (label validation surface)
- RFC 1918 - Private IPv4 address allocation (per-token IP allowlists)
- RFC 5737 - IPv4 blocks reserved for documentation (TEST-NET, examples/tests)

## Non-RFC standards (load-bearing, for completeness)

- FIPS 203 - ML-KEM (Kyber); the `X25519MLKEM768` hybrid TLS key exchange
- FIPS 204 - ML-DSA (Dilithium); the post-quantum PKI CA signatures
- NIST SP 800-38D - AES-GCM (DEK double-envelope; NIST CAVP gate)
- NIST ACVP - ML-DSA known-answer vectors (the fips204 conformance gate)
- PHC - Argon2 reference (the password-hashing competition winner)
- libsodium - XChaCha20-Poly1305, Argon2id, Ed25519 (primary crypto impl via PyNaCl)

## Implementation provenance

Not standards the code implements, and not dependencies: upstream work a
cryptographic implementation here was built *from*. For a vault, recording
where a primitive's implementation came from is a property worth having in
its own right - it lets an auditor trace a design back to its source instead
of inferring it.

- geky/gf256 - <https://github.com/geky/gf256>, Copyright C. Haster and
  contributors, BSD-3-Clause. Origin of the GF(2^8) design and algorithms in
  `api/rust/custody-core/src/gf256.rs` (the field arithmetic under Shamir
  custody). Independently rewritten and adapted for constant-time operation,
  then validated against reference arithmetic by exhaustive testing of all
  65 536 operand pairs, property tests, fuzzing, and inspection of the
  compiled output. No code copied; BSD-3-Clause is compatible with
  AGPL-3.0-or-later. See [NOTICE](NOTICE).

## Security assessment & compliance frameworks

A different category from everything above: these are not standards the code
implements, they are frameworks the project's security posture is assessed
*against*. See [SECURITY.md](SECURITY.md) for the full cross-reference table.

- ANSSI-PA-074 - "Regles de programmation pour le developpement d'applications
  securisees en Rust" (ANSSI secure-Rust coding guide); the 51-rule checklist
  `api/rust` and `agent/rust` are audited against
- MITRE ATT&CK (Enterprise) - adversary tactics/techniques mapping, see
  [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md)
- OWASP ASVS - Application Security Verification Standard checklist, see
  [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md)
- NIS2 (EU 2022/2555) - Art. 21 control matrix, see
  [docs/NIS2-COMPLIANCE.md](docs/NIS2-COMPLIANCE.md)
- CRA (EU 2024/2847) - Cyber Resilience Act readiness assessment, see
  [docs/CRA-COMPLIANCE.md](docs/CRA-COMPLIANCE.md)
