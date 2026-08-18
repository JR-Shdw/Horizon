# Security model

How rhorizon is designed to be attacked, and what stops the attack.

## Threat model

The vault assumes :

- **Trusted operator** at the host level. If you have root on the
  host, you can read `/proc/PID/mem` and bypass `mlock`. No vault
  protects against a compromised root.
- **Untrusted clients on the network.** Bearer tokens may leak ; the
  vault must rate-limit, allow IP restriction, and audit every use.
- **Persistent attacker, not script-kiddie.** Attacks include cold
  backups stolen from a tape drive, lateral movement after a
  separate-host compromise, and 2FA token theft via phishing.
- **No HSM.** The master key lives in mlock'd RAM, not in a hardware
  module. If you need FIPS 140-2 / Common Criteria, rhorizon doesn't
  qualify.

## Out of scope (deliberately)

- Defense against a kernel exploit on the host.
- Defense against a malicious Postgres admin.
- Cold-boot or DMA attacks on physical RAM.
- Side-channel timing attacks below the network round-trip threshold
  (token hashes use HMAC-SHA512 with B-tree comparison, no
  constant-time bytes-match - the network jitter dominates).

## Key controls

### Sealed by default

At every restart, the master key does not exist. The operator
unseals manually. A reboot doesn't expose secrets ; an unauthorised
unseal is a high-signal audit event. See
[Seal / Unseal lifecycle](concepts/seal-unseal.md).

### Five-layer cipher

Argon2id -> HKDF -> XChaCha20-Poly1305 -> AES-256-GCM -> HMAC-SHA512.
Each layer addresses a distinct concern :

- Argon2id resists GPU attacks on weak passwords.
- HKDF prevents compromise of one sub-key from leaking the master.
- XChaCha20 uses random 24-byte nonces, making accidental collisions
  negligible at the expected write volume; nonce reuse remains forbidden.
- AES-256-GCM envelope makes DEK rotation cheap (re-wrap, not
  re-cipher).
- HMAC-SHA512 token hashes give O(1) lookup with no per-token scan.

See [Cryptography](concepts/crypto.md).

### Rust memory protection

Long-lived wrap, DEK-cipher, and audit-signing keys use Rust-side `mlock`'d
buffers with `zeroize` on drop. Wrapped sub-key operations and audit-seed
generation/load/rewrap stay in Rust. Linux workers also enforce
`PR_SET_DUMPABLE=0` against same-UID memory inspection. Requested secret values
and unseal/recovery material can still exist briefly in the serving process;
host root, kernel compromise, and code execution inside an unsealed worker are
outside this memory boundary. The agent applies the same custody principle to
bearer tokens (`SecureToken`).

See [Memory protection](concepts/memory-protection.md).

### Tamper-evident audit

Every state-changing operation appends a row signed against the
previous row. Modifying or deleting any row breaks every signature
that follows. Verifiable in O(N) via `/audit/verify`. Dual-written
to PG + JSONL files.

High-volume reads avoid the serialized per-row signing path. Their complete
records are Merkle-hashed into signed checkpoints, then exported into sealed
archives before database pruning.

The audit writer wraps every write in a Postgres advisory transaction lock so
concurrent workers can't fork the chain.

See [Audit chain](concepts/audit.md).

### RBAC + delete protection

UUID-keyed namespaces owned by groups. Two flags, both one-way
ratchets at the DB level :

- `enforce_membership` : strict mode requires live group membership
  on every read/write. A compromised root token cannot relax it.
- `delete_protection` : `free` / `soft` / `protected`. Soft-deletes
  with retention window + restore. Protected mode requires admin +
  2FA + extended retention (no auto-purge if 0).

See [RBAC & namespaces](concepts/rbac.md).

### Per-token IP allowlist

CSV mixing CIDRs and bare IPs (v4 + v6). Limits where a leaked token
can be replayed from. The narrow-is-safer principle is documented
inline in the create-token form ; no preset buttons for wide ranges.

### 2FA (TOTP / YubiKey HMAC / WebAuthn)

Per-unseal and per-protected-action. WebAuthn includes anti-clone
sign counter check ; YubiKey HMAC is challenge-stored-in-DB (single-use,
TTL 60s) to prevent replay. Accepted TOTP counters are consumed atomically in
PostgreSQL, so a code cannot be replayed through another worker or HA node.

See [2FA setup](howto/2fa.md).

### Honeytokens

Tokens or secrets marked `is_honey: true` fire a CRITICAL log + Matrix
alert on any access. Pick attractive names (`prod-pgsql-master`,
`aws-iam`, `cmdb-collect-token`) so attackers want to use them.

### Rate limiting

- **Per-IP** on auth failures : 20 fails -> 30s lockout, 50 -> 5min,
  200 -> 1h (escalating, fail2ban-style). fail2ban-compatible log
  format at `RH_AUTHFAIL_LOG`.
- **Per-actor** on namespace mutations : default 10/hour, triggers a
  Matrix `#SECURITY` alert above the cap.

### Network policies

- **API** binds only to internal interfaces in production ;
  VPN required.
- **Frontend** terminates TLS via nginx or upstream traefik.
- **Postgres** is never exposed outside the docker network in the
  reference compose ; always SSL-on (self-signed certs auto-generated
  in the production compose).
- **Helm chart** ships NetworkPolicy egress lockdown : API can only
  reach PG + DNS.

## Hardening checklist

For a real production deployment :

- [ ] Memorable master passphrase (rotate yearly via
      `/rotate-password emergency=false`).
- [ ] 2FA mode = `any`, >= 2 factors registered.
- [ ] Shamir M-of-N for the master key, with shares stored in
      independent locations.
- [ ] Per-service tokens with narrow scope + tight `allowed_ips`.
      No `admin:rw` for automation.
- [ ] `enforce_membership=true` on prod-grade namespaces.
- [ ] `delete_protection=protected` on irreplaceable secrets.
- [ ] Honeytoken seeded under a name attractive to attackers.
- [ ] Daily age-encrypted backup pushed off-site, master passphrase
      stored separately.
- [ ] Audit log streamed to a SIEM / ingested by `wazuh` /
      forwarded to Matrix.
- [ ] Quarterly disaster-recovery drill on staging.

## Incident response

If you suspect a token leaked :

1. Identify the token via the audit log (`/audit/?actor=...`).
2. Revoke it : `POST /tokens/{id}/revoke`.
3. Search for any access patterns : `/audit/?action=read_secret&actor=ldap:bob`.
4. Rotate any secrets the leaked token could read.
5. Tighten `allowed_ips` on similar tokens going forward.

If you suspect master password leaked :

1. Trigger emergency password rotation :
   `POST /rotate-password {"current_password": "...", "new_password": "...", "emergency": true}`.
   This invalidates **every** existing token immediately, including
   the caller's.
2. Re-issue tokens via the new root token from the post-rotation
   `/unseal`.
3. Review audit log for unexpected `unseal` entries.

If the audit chain breaks :

1. `/audit/verify` returns `intact: false, broken_at: <id>`.
2. Cross-reference the JSONL file mirror at the same date - if it
   matches the DB, your DB was tampered with after the fact (the
   file is append-only with O_APPEND).
3. Investigate ; the row at `broken_at` is the first one after a
   tamper event, so the tamper happened immediately before its
   timestamp.

## Reporting a vulnerability

Do not file a public issue. PGP if available.

- **Paying sponsors / commercial members:** `horizon@resurgamus.com`. First
  response within **48 hours** (or the shorter time in your agreement).
- **Everyone else (OSS / AGPL):** `security@example.com`. First response within
  **96 hours**.

Remediation runs on a separate clock driven by **severity, not reporter**:
critical within 7 days, high within 30. Sponsorship buys attention latency,
never privileged access to a fix.

Full policy, scope, and disclosure terms: [SECURITY.md](https://github.com/JR-Shdw/Horizon/src/branch/main/SECURITY.md).
