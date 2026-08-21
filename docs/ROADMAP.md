# Resurgamus Horizon - Roadmap

**Status: Beta, feature-complete core.** Everything under "Shipped" is
implemented and exercised by the Python + Rust test suites (`make test` is the
canonical gate). The API surface is stable; breaking changes are announced in
the CHANGELOG. This document tracks what exists, the near-release hardening
still in flight, and where the project is headed.

Release rule (applies to every item below): do not force existing users through
a destructive schema migration or a secret re-import. Stored ciphertext columns,
and nonce sizes stay byte-compatible. Versioned metadata changes must retain a
read path for existing rows and backups.

---

## Shipped

### Core vault
| Area | What |
|---|---|
| Crypto | 5-layer stack (Argon2id -> HKDF-SHA512 -> XChaCha20-Poly1305 -> AES-256-GCM -> HMAC-SHA512), double-envelope per-secret DEKs, seal/unseal, operator-authorized hierarchical `dek_key` rotation with age monitoring |
| Secrets | CRUD, versioning + rollback, per-secret rotation with grace window, namespaces |
| Tokens | Scopes, per-token IP allowlist (CIDR), ephemeral (short-TTL), rotate/renew, `whoami` |
| Oneshot | Sealed-by-default: unseal -> read one secret -> re-seal in a single call |

### Authentication and access
| Area | What |
|---|---|
| 2FA | WebAuthn/FIDO2 (browser), YubiKey HMAC-SHA1 (CLI), TOTP; modes none/yubikey/totp/any with automatic fallback |
| External auth | LDAP/AD bind + group mapping; SSO proxy headers (Authelia/Authentik/Keycloak) |
| RBAC | Groups (local + LDAP-mapped), namespace sub-admin via scope composition |

### Interfaces and operations
| Area | What |
|---|---|
| Web UI | Full vanilla-JS frontend: dashboard, secrets, tokens, audit, groups, backup, notifications, settings, observability, PKI |
| CLI | `rhorizon` (typer): unseal/seal, secrets, tokens, audit, PKI |
| Notifications | Matrix, generic webhook, email (SMTP) |
| Backup/restore | age-encrypted logical export/restore + `pg_dump | age` full-fidelity DR |

### Automation and delivery
| Area | What |
|---|---|
| Agents | `rh-fetch` (init container), `rh-inject` (env wrapper), `rh-watch` (sidecar + ephemeral token rotation), static musl binaries |
| MCP | Zero-dep stdio server; optional **hub gateway** with per-agent identity, server-side chained MCP audit (`vault_audit_mcp`), and a PQ-TLS sidecar |
| Dynamic secrets | Modular PostgreSQL, MySQL/MariaDB, LDAP, Redis ACL, and Cassandra credentials with leases and auto-revoke; separate Ansible collection |

### Cryptography and PKI
| Area | What |
|---|---|
| PKI engine | Dedicated CA issuing short X.509 leaves; selectable signature algorithm: Ed25519, ML-DSA-65 (FIPS 204), or **composite Ed25519 + ML-DSA-65** |
| PQ KEM certs | **Hybrid X25519 + ML-KEM-768** KEM certificates |
| PQ transport | Post-quantum TLS 1.3 (X25519MLKEM768) on the agent <-> vault path |

### High availability
| Area | What |
|---|---|
| Database HA | Provider-neutral clustering (Patroni-based), streaming-replica health gating, bounded WAL retention |
| Coordination | Cross-container layer: cluster/node identity, HMAC bootstrap join, quarantine state machine, drain/evict/promote |
| Key sharing | Shamir-distributed master key shares, role-based master/follower workers, automatic failover reconstruction |
| Authority model | Two independent deadlines, not one: **DB-authority freshness** (every node -- a secondary that cannot read canonical state cannot prove it is still a secondary) and the **primary lease** (the singleton write claim, primary only). Both evaluated against PostgreSQL's `clock_timestamp()`, never a host wall clock |
| FROZEN state | Losing database authority suspends serving without dropping keys. Expressed as a deadline recomputed on read, so a dead refresher loop fails closed instead of leaving a node serving. A hard fence seals at `lease_ttl + frozen_max`, bounding how long a possibly-stale node sits on key material. That fence runs in its own loop, reading only a monotonic clock: evaluated at the end of a database tick it was never *reached* when the query hung, and a hung loop is not a dead one, so supervision did not catch it. Peers may buy a frozen node time, never the right to serve |
| Transport | Cluster CA with per-node mTLS; `/internal/ha/status` answers with PostgreSQL unreachable (no I/O, no auth -- an endpoint that needs the authority cannot report on losing it) |
| Planned | Peer-aware classification: today a node cannot distinguish a **shared** database outage from its **own** isolation, which warrant opposite reactions (hold vs seal). Peers contribute observations, never authority |

### Memory and audit hardening
| Area | What |
|---|---|
| Key hygiene | Rust crypto core (PyO3): master / `dek_key` / `hmac_key` / `audit_key` held mlock'd and zeroize-on-drop; the wrap key never exists in Python |
| Bulk crypto | Chained Rust secret CRUD, version reads, rollback, rotation, and backup/restore; plaintext DEKs stay inside Rust |
| Audit | Versioned full-row signatures; high-throughput read log with signed Merkle checkpoints; prune-aware roots; durable full verification and signed incremental preflight anchors |

### Supply chain
Multi-arch images (amd64 + arm64), cosign signatures + SLSA provenance + SBOM,
Trivy / bandit / pip-audit / detect-secrets, `cargo audit` / `deny` / `clippy` /
`miri`, cargo-fuzz targets. 2227 Python + 154 Rust tests.

---

## Near-release hardening

Tracked in detail in [`SECURITY-HARDENING-ROADMAP.md`](SECURITY-HARDENING-ROADMAP.md).
Memory and audit hardening is complete. Near-release work is limited to
platform and release validation:

| Item | Scope | Priority |
|---|---|---|
| macOS-native install | Validate `quickstart-laptop-native.sh` on Apple hardware (or a CI macOS runner). Currently container path only on macOS. | Medium |
| Multi-arch agent release binaries | The arm64 build blocker is lifted; publish `rh-*` musl binaries for aarch64 in `release.yml`. | Medium |

---

## Next

### Flagship: hardware-backed unseal (seal-wrap / hardware root of trust)

The one dimension where commercial vaults genuinely lead is a **hardware root of
trust for the master key**. Today rhorizon derives the master key from the
password via Argon2id and holds it mlock'd in the Rust heap. This feature lets
the master (or a key-encryption key that wraps it) live in hardware, so it is
unwrapped *by the device* and is not derivable from a leaked password alone.

**Honest bound (stated up front):** this protects the **root**. It does *not*
make the process memory-immune -- the derived working keys (`dek_key`, etc.) must
still enter RAM to encrypt/decrypt secrets at throughput; routing every per-secret
operation through an HSM is too slow for a general vault. This is the same
limitation seal-wrap has in commercial vaults. The win is hardware binding and
removing the "master key sits in RAM as the sole root" exposure -- not "no key
material ever in RAM."

**Open-source, self-hosted backends only** (no cloud KMS -- SaaS dependency is
off-doctrine). Implemented as a pluggable seal provider, like the 2FA modes, and
**composable with Shamir** (hardware presence *and* M-of-N shares):

| Backend | Hardware | Tooling |
|---|---|---|
| TPM 2.0 | present on most modern hosts | `tpm2-tss` / `tpm2-tools`; seal a KEK to PCRs -> unseal needs this machine + password |
| PKCS#11 HSM | Nitrokey HSM 2 / YubiHSM 2 | `cryptoki` (Rust), OpenSC; KEK held in-device, master unwrapped in the HSM |
| YubiKey PIV | reuses existing YubiKeys | OpenSC/PIV; a slot key wraps the master |

**Proposed seal-provider interface** (sketch -- lives in the Rust crypto boundary
so unwrapped key bytes never surface to Python):

```python
class SealProvider(Protocol):
    name: str                                  # "password" | "tpm2" | "pkcs11" | "yubikey-piv"

    def present(self) -> bool: ...             # device available + authenticated
    def wrap(self, kek: bytes) -> bytes: ...   # protect the vault KEK using the device
    def unwrap(self, wrapped: bytes) -> bytes: ...  # release it via the device (in-HW for HSM)
    def rotate(self) -> None: ...              # re-key the hardware-held secret
```

Default stays `seal_mode = password`; hardware is opt-in and byte-compatible
(only how the master/KEK is protected changes -- stored secret ciphertext is
untouched).

**The two hard parts (design work, not plumbing):**
- **Recovery.** A dead or lost device must not lose the vault. Hardware is *one*
  factor, tied into the existing Shamir + recovery-handle path -- never a single
  point of failure.
- **CI without hardware.** `swtpm` (software TPM) + `SoftHSM2` give TPM/PKCS#11
  coverage in the pipeline; validate against a real Nitrokey/YubiKey before ship.

**Phasing:** (1) seal-provider abstraction + TPM 2.0 (free, universal); (2) PKCS#11
(Nitrokey/YubiHSM, the true removable HSM); (3) YubiKey PIV (reuse existing hardware).

### Candidate directions (not yet committed)

Placeholder for post-launch priorities -- to be filled from early-adopter feedback.

---

## Platform validation

| Target | Status | Next step |
|---|---|---|
| x86-64 Linux | Primary, CI-gated | - |
| aarch64 Linux | Validated on Raspberry Pi 4 hardware | Keep the hardware lane in release validation |
| FreeBSD / OpenBSD | Test suite validated in VM | Keep in the BSD VM matrix |
| macOS native (Apple Silicon) | CI-gated on `macos-latest` | Keep `macos-native.yml` in the release lane |
| macOS native (Intel) | Unmeasured | Needs a self-hosted x86_64 runner or a real Mac: no free `macos-13` image remains |
