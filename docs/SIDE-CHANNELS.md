# Side-channel resistance

Which timing channels are closed, how each is assured, and the one residual not
closed by code. Every claim maps to a primitive, a CI gate, or a deployment
assumption.

## Constant-time crypto

| Primitive | CT mechanism | Assurance |
|---|---|---|
| AES-256-GCM (DEK wrap) | `AES-NI` + `PCLMULQDQ`: data-independent latency, no table, no branch | the instruction is CT; without AES-NI, libsodium/aws-lc use bitsliced software AES, not T-tables |
| XChaCha20-Poly1305 (secrets) | ARX design: no tables, no secret-dependent branches | libsodium, ~decade-audited |
| GF(2^8) for Shamir | bespoke branch-free impl (`api/rust/src/gf256_ct.rs`): mask-based selection, no secret-indexed memory, Itoh-Tsujii inverse | own machinery (below) |

The classic GF(2^8) cache-timing attack (Bernstein, 2005) needs secret-indexed
`exp`/`log` tables; this code has none, so that class is removed by construction.

## How the bespoke GF(2^8) is assured

- **Functional equivalence, exhaustively tested over the byte domain.**
  `cargo test` checks the implementation against a golden table reference over
  all 65 536 `(a,b)` pairs on amd64 and aarch64.
- **Native x86_64 and aarch64 assembly gates.** `tools/check-gf-ct.sh`
  inspects the release assembly of the GF functions and fails on conditional
  branches. `validate.yml` runs it on x86_64; `crypto-arm64.yml` runs the same
  gate on a native GitHub-hosted aarch64 runner. Branchless selection
  instructions (`cmov` on x86_64, `csel`/`cset` and aliases on aarch64) are
  allowed and reported.
- **Undefined-behavior checks.** `cargo miri` covers the unsafe paths exercised
  by its test run.
- **Cross-architecture fuzzing.** `fuzz.yml` runs four cargo-fuzz targets
  (`shamir_split`/`combine`, `aes_gcm_roundtrip`/`decrypt`) for 30 min each on
  x86_64. `crypto-arm64.yml` runs the same targets natively on aarch64 for 30 s
  on relevant pushes/pull requests and 5 min in its weekly job.

Precise wording: **constant-time by design, functionally tested exhaustively
over the byte domain on amd64 and aarch64, with native release assembly checked
for conditional branches on both architectures.** The assembly checks are
machine checks, not a formal proof or a `dudect` timing measurement.

Production Shamir uses the Rust `shamir_split_bytes` / `shamir_combine_bytes`;
Python `crypto.shamir_*` is a test-only parity reference.

## The residual not closed by code

Microarchitectural channels (SMT siblings, port contention, cache-set probing).
No test or asm-grep can prove their absence, only a formal microarch model or
`dudect` measurement on the target silicon could. They are live only when an
untrusted process shares the physical CPU. A single-tenant, sealed-by-default,
VPN-only deployment reduces that exposure but does not prove its absence.
This applies equally to
AES-NI and ChaCha, not specific to the GF code.

## ML-DSA (PKI engine, optional)

The post-quantum PKI option signs with the `fips204` crate (ML-DSA-65). fips204
is constant-time **by design** (constant-time keygen + sign, no secret-dependent
branches or table indices, no heap), but it carries no independent audit and the
asm zero-conditional-jump gate that backs the bespoke GF(2^8) code does **not**
scale to a lattice signature: the implementation is far too large to assert
branch-freedom by disassembly. So the assurance here is different in kind:

- **Conformance** is gated in CI against NIST ACVP ML-DSA-65 sigver
  known-answer vectors and Project Wycheproof vectors
  (`api/rust/tests/vectors/`, consumed by `cargo test` -
  `ml_dsa_65_nist_acvp_sigver_kat` / `ml_dsa_65_wycheproof_external_verify`)
  A supply-chain swap or a non-conformant build trips the test.
  Separately, and not CI-automated: certs signed with `ml-dsa-65` are
  documented to interoperate with OpenSSL 3.5+/`cryptography` 49+ standard
  tooling (`docs/PKI.md`), an operator-runnable interop claim, verified by
  running `openssl verify`/`cryptography` against a generated cert, not a
  build-time gate. (The automated OpenSSL cross-check that *does* run in CI,
  `hybrid_kdf_openssl_kat`, covers the unrelated X25519+ML-KEM hybrid KDF
  combiner, not ML-DSA signatures.)
- **Constant-time** rests on fips204's documented design, not on a rhorizon gate.
- The CA key is a 32-byte seed held mlock'd in Rust; the expanded key is rebuilt
  per sign and zeroized, so the residue profile matches the other sub-keys.

Residual: "unaudited PQ implementation." It is opt-in (`ed25519` is the default
CA algorithm) and confined to the PKI engine; the core vault crypto is unaffected.

## Memory protection

Key material lives in Rust (`api/rust/src/lib.rs`), not the Python heap: `mlock`
(no swap), `zeroize`-on-`Drop` (wipe at seal, not optimizer-elidable), wrap key
and sub-keys on the Rust heap outside the GC. Sub-keys are stored wrapped; each
op decrypts-uses-`zeroize`s inside Rust, plaintext never crosses into Python.

Boundaries: host root can read `/proc/PID/mem` (mlock defeats swap, not root);
rootless with a low `RLIMIT_MEMLOCK` makes mlock best-effort (fails to
`locked=false`, page swap-eligible while unsealed), raise the per-unit
`LimitMEMLOCK` systemd directive (`tools/install-native.sh`/
`tools/drivers/linux.sh` set it automatically to `workers*160 + 256 + 192` MB
- 608 MB for the default single-worker preset, not a fixed value; see
`docs/INSTALL-NATIVE.md`).

## Architecture coverage

aarch64 is a supported crypto target. The Rust crypto suite passes under
aarch64, the full stack has been validated on arm64, and the Linux stack has
been validated on Raspberry Pi 4 hardware. In addition to the
emulated functional matrix, `.github/workflows/crypto-arm64.yml` runs the
release suite, the GF(256) assembly gate, and all four fuzz targets on native
aarch64. `tools/check-arm64-native.sh` reproduces the same checks on a 64-bit
Raspberry Pi 4. See [`tools/TESTING.md`](../tools/TESTING.md) for the
cross-architecture test matrix.
