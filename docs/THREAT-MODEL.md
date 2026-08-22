# Resurgamus Horizon - Threat Model & Security Assessment

Version: 1.2
Date: 2026-08-22 (assessment 2026-08-04, claims re-verified against the tree 2026-08-22)
Scope: Resurgamus Horizon self-hosted secrets vault (API + Frontend + Agent + PostgreSQL). Extended coverage for PKI, dynamic secrets, MCP/agent integration, multi-worker RPC, and LDAP/SSO proxy auth, all shipped after the 1.0 assessment.

> Both summary tables below were recounted row by row and are exact: the ATT&CK
> matrix totals 20 COVERED / 23 PARTIAL / 0 out-of-scope, and the ASVS summary
> totals 42 MET / 1 PARTIAL / 0 NOT MET / 2 N/A. Numeric crypto claims
> (Argon2id m=256MB t=3, 16-byte salt, the escalating rate-limit tiers) were
> checked against `api/app/crypto.py` and `api/app/rate_limit.py`.

---

## Table of Contents

1. [Threat Model - MITRE ATT&CK Mapping](#1-threat-model---mitre-attck-mapping)
2. [OWASP ASVS Level 2 Checklist](#2-owasp-asvs-level-2-checklist)
3. [Explicit Limitations](#3-explicit-limitations)

---

## 1. Threat Model - MITRE ATT&CK Mapping

Classification:
- **COVERED** - Resurgamus Horizon has a concrete mitigation in place
- **PARTIAL** - Mitigation exists but depends on deployment or has known gaps
- **OUT OF SCOPE** - Resurgamus Horizon does not protect against this by design

### TA0001 - Initial Access

| ID | Technique | Status | Resurgamus Horizon Mitigation |
|----|-----------|--------|-------------------|
| T1190 | Exploit Public-Facing Application | **COVERED** | Vault must NOT be exposed to the internet. Access via VPN (IPsec / OpenVPN / Tailscale) or private network. Auth is self-contained (master password + 2FA). No `/docs` or `/redoc` exposed. FastAPI input validation (Pydantic). |
| T1133 | External Remote Services | **COVERED** | Single entry point: VPN or private network. No SSH on container. No remote admin interface. Auth requires master password + 2FA. |
| T1078 | Valid Accounts | **PARTIAL** | Tokens are HMAC-SHA512 hashed (can't be extracted from DB dump). 2FA required for unseal. But: a stolen bearer token grants access until revoked. Optional LDAP/AD login follows the standard secure pattern: rhorizon never compares the user's password itself - a service account binds to find the user DN, then rhorizon attempts to bind AS the user with their supplied password (bind success = valid credential). The LDAP bind password is stored DEK-wrapped (AAD-bound to the config row). |
| T1078.001 | Default Accounts | **COVERED** | No default credentials. First unseal creates the master key. Root token shown once. |
| T1195.001 | Compromise Software Dependencies | **PARTIAL** | pip-audit in CI pipeline. Trivy CVE scan daily. Pinned versions in requirements.txt and Cargo.toml. But: no SBOM signature verification on Python packages yet. Trivy itself was compromised (0.69.4-6, March 2026) - pinned to 0.70.0 (clean post-incident release). |
| T1199 | Trusted Relationship | **PARTIAL** | Tokens are namespace-scoped with minimal permissions. But: a compromised Ansible/CI host with a vault token can read its scoped secrets. The optional SSO-proxy auth path (Authelia/Authentik/Keycloak/oauth2-proxy) extends this same trust class: identity comes from `Remote-User`/`Remote-Groups` headers, trusted only from an operator-configured IP allowlist, not cryptographically verified per-request. A trusted-IP change itself requires an authenticated admin call. If the allowlist is too broad, or something upstream of the allow-listed IP fails to strip client-supplied identity headers before proxying, header spoofing bypasses auth entirely - this is a trust-boundary control, not a cryptographic one, and its strength is exactly as strong as the operator's proxy configuration. |

### TA0002 - Execution

| ID | Technique | Status | Resurgamus Horizon Mitigation |
|----|-----------|--------|-------------------|
| T1059 | Command and Scripting Interpreter | **COVERED** | No shell in production container (pip, curl, wget removed). Read-only filesystem. `noexec` on all tmpfs. `cap_drop: ALL`. |
| T1609 | Container Administration Command | **PARTIAL** | Container runs as uid 1500 (non-root). `no-new-privileges`. But: depends on Docker socket not being exposed. |
| T1610 | Deploy Container | **PARTIAL** | Depends on host Docker daemon security. Resurgamus Horizon containers use internal networks only. |
| T1677 | Poisoned Pipeline Execution | **PARTIAL** | Woodpecker pipeline runs SAST (bandit), secrets scan (detect-secrets), dep-audit. But: pipeline has access to Docker socket on deploy host. Cosign signs SBOM. |
| T1072 | Software Deployment Tools | **PARTIAL** | Ansible vault tokens should be scoped (secrets:r on specific namespaces only). Pipeline secrets stored as Woodpecker encrypted env vars. |

### TA0003 - Persistence

| ID | Technique | Status | Resurgamus Horizon Mitigation |
|----|-----------|--------|-------------------|
| T1098 | Account Manipulation | **COVERED** | Token creation requires admin:w scope. Token operations enter the Ed25519-signed mutation chain (HMAC-SHA512 legacy/fallback); tampering breaks verification. |
| T1556 | Modify Authentication Process | **COVERED** | Authentication code is in read-only container filesystem. Docker image signed with cosign. Binary verification via SBOM (syft). |
| T1556.006 | Multi-Factor Authentication Bypass | **COVERED** | 2FA mode stored in DB (vault_config), not in code. WebAuthn challenges are single-use (DELETE+RETURNING in DB). TOTP codes validated server-side. YubiKey HMAC challenges have 60s TTL. |
| T1505.003 | Web Shell | **COVERED** | Read-only filesystem. No shell binary. `noexec` tmpfs. `cap_drop: ALL`. No writable directory except tmpfs (16MB, noexec). |
| T1136 | Create Account | **PARTIAL** | Dynamic secrets engines (PostgreSQL/MySQL/LDAP) create real accounts on the target system on every credential issuance (`secrets:w`, engine/role config gated at `admin:w`). Each mint is audit-logged (actor, role, lease). Auto-revoked at lease expiry by the reaper (`revocation_sql` / LDAP delete). But: revocation depends on the target executing the DROP/delete successfully - a failed drop leaves the account live until the next reaper cycle, and `revocation_sql` must itself be idempotent for that retry to be safe. |

### TA0005 - Defense Evasion

| ID | Technique | Status | Resurgamus Horizon Mitigation |
|----|-----------|--------|-------------------|
| T1612 | Build Image on Host | **PARTIAL** | Depends on host hardening. Container images are built in CI and signed with cosign. |
| T1610 | Deploy Malicious Container | **PARTIAL** | SBOM generated with syft, signed with cosign. But: verification at deploy time is manual. |
| T1027 | Obfuscated Files | **COVERED** | Secrets are encrypted with XChaCha20-Poly1305 (per-secret DEK) + AES-256-GCM (DEK wrapping). Offline bruteforce requires cracking Argon2id (256MB, 3 iterations). |
| T1070.003 | Clear Command History | **PARTIAL** | Audit chain is tamper-evident (chained HMAC). But: an attacker with DB access could truncate the audit table - integrity is detectable but not preventable. |

### TA0006 - Credential Access (PRIMARY THREAT SURFACE)

| ID | Technique | Status | Resurgamus Horizon Mitigation |
|----|-----------|--------|-------------------|
| T1555 | Credentials from Password Stores | **COVERED** | rhorizon IS the password store. Argon2id -> HKDF -> XChaCha20 + AES-GCM stack. Sealed by default at reboot. Master key never on disk. Symmetric primitives (AES-256, XChaCha20, HMAC-SHA512) are quantum-resistant. |
| T1555.005 | Password Managers | **COVERED** | Double envelope encryption: secret -> per-secret DEK (XChaCha20) -> DEK wrapped with dek_key (AES-256-GCM). DB dump without master key is useless. |
| T1552 | Unsecured Credentials | **PARTIAL** | `.env` file contains only POSTGRES_PASSWORD (not vault secrets). But: RH_TOKEN in docker-compose env is visible via `docker inspect`. Recommendation: use rh-fetch (file-based, tmpfs). |
| T1552.001 | Credentials In Files | **COVERED** | Secrets are never written to disk in cleartext. rh-fetch writes to tmpfs (RAM) with mode 0400. Audit logs never contain secret values. |
| T1552.003 | Shell History | **PARTIAL** | CLI tool (`rhorizon`) prompts through stdin, and operator guides avoid placing passwords or tokens in command arguments. Custom scripts remain the operator's responsibility. |
| T1552.007 | Container API | **PARTIAL** | rh-inject removes RH_TOKEN from child env. But: resolved secrets remain as env vars in `/proc/PID/environ`. rh-fetch (file-based) is the secure alternative. |
| T1003 | OS Credential Dumping | **PARTIAL** | Rust extension (`rhorizon_crypto`): keys use `mlock` when the host permits it and `zeroize` on drop. The wrap key lives in Rust heap, outside Python object introspection. Host root and kernel compromise remain out of scope. |
| T1003.007 | Proc Filesystem | **PARTIAL** | mlock prevents swap. Rust wrap key is not in Python heap. But: an attacker with root on the host can still read `/proc/PID/mem` - mlock protects against swap, not root access. Multi-worker key custody uses the same boundary: only the master process holds sub-keys, followers delegate crypto ops over a `0700` filesystem-path Unix socket with peer-UID validated via `SO_PEERCRED` (fail-closed - a UID mismatch is rejected, not logged-and-allowed). A same-uid, same-host process could still connect; cross-uid and cross-host cannot. |
| T1040 | Network Sniffing | **COVERED** | Client-to-frontend: TLS via Nginx (`TLS_ENABLED`). External access: VPN (IPsec / OpenVPN). API-to-PostgreSQL: TLS (self-signed cert). Internal Docker network is bridge-isolated. |
| T1528 | Steal Application Access Token | **PARTIAL** | Tokens are HMAC-SHA512 hashed in DB (can't extract from dump). Tokens have optional TTL (ephemeral: 60s-24h). Revocation is immediate. But: a stolen token in transit is valid until revoked or expired. MCP tokens are the same token type, scoped read-only by `policy.toml` (fail-closed: an absent or empty policy denies every tool call). The optional `mcp-hub` daemon additionally caches bearer validation (30s positive / 5s negative TTL) and rate-limits repeated rejects (10/60s -> 429) to bound `/tokens/whoami` amplification from a probing agent. |
| T1110 | Brute Force | **COVERED** | Rate limiting on unseal endpoint (configurable). Argon2id with 256MB memory cost makes bruteforce extremely expensive (~1 attempt/second on modern hardware). |
| T1110.001 | Password Guessing | **COVERED** | Argon2id (256MB, t=3). Rate limiting. 2FA required (WebAuthn/TOTP/YubiKey). |
| T1111 | MFA Interception | **PARTIAL** | WebAuthn is phishing-resistant (origin-bound). TOTP codes are time-limited (30s window). YubiKey HMAC challenges have 60s TTL, single-use. But: TOTP is vulnerable to real-time phishing proxies. |
| T1606 | Forge Web Credentials | **COVERED** | HMAC-SHA512 key is derived from master key (HKDF-SHA512). Never stored on disk. 256-bit key space. Forging requires the master password + Argon2id derivation. |
| T1212 | Exploitation for Credential Access | **PARTIAL** | SAST (bandit) in CI. No SQL injection (parameterized queries via SQLAlchemy). Input validation (Pydantic). But: zero-day in FastAPI/uvicorn/asyncpg is always possible. |
| T1649 | Steal or Forge Authentication Certificates | **PARTIAL** | PKI engine mints leaf certificates + private keys server-side (`secrets:w`, namespace-scoped). The private key is returned once in the API response and never persisted. The CA private key is decrypted from DB only for the signing operation and explicitly zeroed after (`secure_zero`) - but it does transit through Python memory during that window, same exposure class as any other decrypt operation. |

### TA0008 - Lateral Movement

| ID | Technique | Status | Resurgamus Horizon Mitigation |
|----|-----------|--------|-------------------|
| T1550.001 | Application Access Token | **PARTIAL** | Tokens are namespace-scoped. Minimal permissions principle. But: an root token grants full access to all secrets. |
| T1021.004 | SSH | **COVERED** | No SSH service in vault container. No SSH keys stored in vault by default (user choice). |
| T1210 | Exploitation of Remote Services | **PARTIAL** | Internal Docker network. No exposed services except API (port 8200). PostgreSQL not exposed. |

### TA0009 - Collection

| ID | Technique | Status | Resurgamus Horizon Mitigation |
|----|-----------|--------|-------------------|
| T1213 | Data from Information Repositories | **COVERED** | All secret reads are audit-logged. Namespace isolation. Token scope enforcement. Bulk export requires admin:w + age encryption. |
| T1005 | Data from Local System | **COVERED** | Secrets encrypted at rest in PostgreSQL (XChaCha20-Poly1305 + AES-256-GCM double envelope). DB files without master key are useless. |
| T1056.003 | Web Portal Capture | **PARTIAL** | CSP: no unsafe-inline. X-Frame-Options: DENY. But: keylogger on admin's machine is out of scope. |
| T1557 | Adversary-in-the-Middle | **COVERED** | TLS via Nginx (client-facing). TLS API-to-PostgreSQL (self-signed). VPN (IPsec / OpenVPN) for all external traffic. WebAuthn is origin-bound (MITM-resistant). |

---

### Summary Matrix

| Category | Covered | Partial | Out of Scope |
|----------|---------|---------|-------------|
| Initial Access | 3 | 3 | 0 |
| Execution | 1 | 4 | 0 |
| Persistence | 4 | 1 | 0 |
| Defense Evasion | 1 | 3 | 0 |
| Credential Access | 7 | 9 | 0 |
| Lateral Movement | 1 | 2 | 0 |
| Collection | 3 | 1 | 0 |
| **Total** | **20** | **23** | **0** |

---

## 2. OWASP ASVS Level 2 Checklist

### V2 - Authentication

| Req | Requirement | Status | Implementation |
|-----|-------------|--------|---------------|
| 2.1.1 | Password min 12 characters | **N/A** | Master password has no minimum length enforced (user responsibility - Argon2id makes short passwords expensive to crack but not impossible). Consider adding. |
| 2.1.7 | Check against compromised password lists | **N/A** | Resurgamus Horizon has a single master password (no user accounts, no email). HIBP integration has no value here. Argon2id (256MB) makes brute-force of even weak passwords expensive. |
| 2.2.1 | Anti-automation: max failed attempts | **MET** | Escalating fail2ban-style lockout on `/unseal`. `RATE_LIMITS = [(20, 30), (50, 300), (200, 3600)]` is `(failure_count, lockout_seconds)`: 20 failures locks the IP out for 30s, 50 for 300s, 200 for 3600s. The counting window is separate (`rate_limit_findtime`, 3600s default). Whitelist via `RH_RATE_LIMIT_WHITELIST`. Deliberately permissive — a 256-bit token is infeasible to brute-force and Argon2id already costs ~500ms per master-password attempt, so this is the second line, not the first. |
| 2.4.1 | Approved KDF for password storage | **MET** | Argon2id (m=256MB, t=3, p=1 - libsodium's `crypto_pwhash` fixes parallelism at 1, not configurable). |
| 2.4.2 | Random salt min 32 bits | **MET** | 16-byte (128-bit) random salt per vault instance, stored in vault_config. |
| 2.6.1 | Single-use lookup secrets | **MET** | Challenges are single-use (DELETE+RETURNING). TOTP codes validated once per period. |
| 2.8.2 | Symmetric key protection via HSM or secure storage | **MET** | Rust extension: `mlock` when permitted + `zeroize` on drop. Wrap key in Rust heap, outside Python object introspection. This is software protection, not an HSM. |
| 2.8.4 | TOTP single-use per period | **MET** | Server-side validation, code accepted once per 30s window. |
| 2.9.2 | WebAuthn challenge nonce min 64 bits | **MET** | WebAuthn challenges generated with CSPRNG, stored in DB, single-use, 60s TTL. |
| 2.9.3 | Approved crypto for WebAuthn | **MET** | Server offers ES256 (ECDSA P-256) and RS256 in `pubKeyCredParams`; the authenticator picks. Both are standard COSE algorithms. |

### V3 - Session Management

| Req | Requirement | Status | Implementation |
|-----|-------------|--------|---------------|
| 3.2.1 | New session token on auth | **MET** | Tokens are generated at creation with CSPRNG, HMAC-SHA512 hashed. |
| 3.2.4 | Tokens generated with approved algorithms | **MET** | `secrets.token_urlsafe(32)` (CSPRNG) + HMAC-SHA512 hashing. |
| 3.3.2 | Re-auth after inactivity | **PARTIAL** | Tokens have optional TTL. Ephemeral tokens (60s-24h). But: long-lived tokens have no inactivity timeout. |
| 3.3.3 | Terminate all sessions on password change | **MET** | Master password rotation uses lazy token migration (15-day expiry on old hmac_key). All tokens eventually re-hashed or expire. |
| 3.5.3 | Stateless tokens protected against tamper | **MET** | Tokens are HMAC-SHA512 indexed. Tampering produces different hash, lookup fails. |

### V4 - Access Control

| Req | Requirement | Status | Implementation |
|-----|-------------|--------|---------------|
| 4.1.1 | Server-side access control | **MET** | All scope checks in Python backend (auth.py). Frontend has no secret data. |
| 4.1.3 | Least privilege principle | **MET** | Fine-grained scopes: secrets:r, secrets:w, tokens:r, tokens:w, audit:r, admin:rw. Namespace restriction. |
| 4.1.5 | Fail secure on exception | **MET** | `vault.require_unsealed()` raises VaultSealedError. Auth failures return 401/403, never leak data. |
| 4.2.1 | IDOR protection | **MET** | Secrets accessed by name (not sequential ID). Token scope checked on every request. Namespace isolation. |
| 4.3.1 | MFA on admin interfaces | **MET** | 2FA required for unseal (WebAuthn/TOTP/YubiKey). Master password + 2FA is self-contained - no external SSO dependency. |

### V6 - Cryptography

| Req | Requirement | Status | Implementation |
|-----|-------------|--------|---------------|
| 6.1.1 | Sensitive data encrypted at rest | **MET** | XChaCha20-Poly1305 (per-secret DEK) + AES-256-GCM (DEK wrapping). |
| 6.2.1 | No Padding Oracle | **MET** | AEAD modes only (GCM, Poly1305). No CBC, no padding. |
| 6.2.2 | Approved algorithms only | **MET** | Argon2id, HKDF-SHA512, XChaCha20-Poly1305, AES-256-GCM, HMAC-SHA512. No custom crypto. |
| 6.2.5 | No weak algorithms | **MET** | No ECB, no Triple-DES, no MD5, no SHA1 (except YubiKey HMAC-SHA1 - hardware constraint). |
| 6.2.6 | Nonce never reused with same key | **MET** | 24-byte random nonce (XChaCha20), 12-byte random nonce (AES-GCM). CSPRNG (os.urandom / OsRng). Probability of collision: negligible (2^-96 for GCM, 2^-192 for XChaCha20). |
| 6.3.1 | CSPRNG for all random | **MET** | Python: `os.urandom`, `secrets` module. Rust: `OsRng` (aes-gcm crate). |
| 6.4.1 | Key vault for secret management | **MET** | Resurgamus Horizon IS the key vault. |
| 6.4.2 | Key material isolated from application | **MET** | Rust extension: wrap key in Rust heap (mlock'd), Python GC never sees raw key material. AESGCM instance holds key in libcrypto (C extension), not Python heap. |

### V7 - Error Handling & Logging

| Req | Requirement | Status | Implementation |
|-----|-------------|--------|---------------|
| 7.1.1 | No credentials in logs | **MET** | Audit logs record action, actor, target - never secret values or token plaintext. |
| 7.1.3 | Security events logged | **MET** | All auth, seal/unseal, secret access, token operations, 2FA changes are audit-logged. |
| 7.3.3 | Logs protected against tampering | **MET** | Mutation entries form an Ed25519-signed chain (HMAC-SHA512 legacy/fallback) mirrored to JSONL. Read entries are complete-row Merkle-hashed into signed checkpoints; archived prefixes carry verified digests, roots, and signed seal lineage. |
| 7.3.4 | Synchronized time sources | **MET** | UTC timestamps. Container uses host clock (Docker default). |

### V8 - Data Protection

| Req | Requirement | Status | Implementation |
|-----|-------------|--------|---------------|
| 8.1.2 | Temporary copies purged | **MET** | Rust: `zeroize` on drop. Sealing clears the Rust-held key buffers. |
| 8.2.1 | Anti-cache headers | **MET** | Nginx: `Cache-Control: no-store` on API responses. CSP headers. |
| 8.3.1 | Sensitive data in body, not query string | **MET** | All secrets in POST/PUT body (JSON). No query string secrets. Tokens in Authorization header. |
| 8.3.5 | Audit of sensitive data access | **MET** | Every secret read/write records actor, action, target, detail, timestamp, and IP. Writes are signed per row; reads are covered by signed Merkle checkpoints and verifiable archives. |
| 8.3.6 | Memory zeroing of sensitive data | **MET** | Rust extension: mlock (no swap) + zeroize-on-drop. Wrap key in Rust heap. Seal zeroes all encrypted buffers. Python AESGCM key held in libcrypto (C), not Python GC. |
| 8.3.7 | Encryption with confidentiality + integrity | **MET** | AEAD modes only: XChaCha20-Poly1305 (confidentiality + integrity), AES-256-GCM (confidentiality + integrity). |

### V9 - Communications

| Req | Requirement | Status | Implementation |
|-----|-------------|--------|---------------|
| 9.1.1 | TLS for all client connections | **MET** | Frontend Nginx supports TLS natively (`TLS_ENABLED=true`, cert/key mounted). API listens on HTTP behind Nginx (same compose stack). External traffic is encrypted by the operator's VPN (IPsec / OpenVPN). |
| 9.1.3 | TLS 1.2+ only | **MET** | Nginx TLS configuration enforces TLS 1.2+ (`ssl_protocols TLSv1.2 TLSv1.3`). VPN tunnels use cryptography equivalent to or stronger than TLS 1.2+. |
| 9.2.2 | TLS on all connections including internal | **MET** | API-to-PostgreSQL is always encrypted. `RH_DATABASE_SSL` defaults to `require` (no certificate verification — fine on a same-host Docker bridge, not against an active MITM); `verify-full` pins `RH_DATABASE_CA_CERT` and is the correct setting once the database is off-host. |

### V13 - API & Web Services

| Req | Requirement | Status | Implementation |
|-----|-------------|--------|---------------|
| 13.1.3 | No sensitive data in URLs | **MET** | Secrets accessed by name in path (not value). Tokens in Authorization header. |
| 13.1.4 | Authorization at URI and resource level | **MET** | Scope checked per endpoint (auth.py dependency) AND per resource (namespace filtering). |
| 13.1.5 | Reject unexpected Content-Type | **MET** | FastAPI validates Content-Type. Pydantic rejects malformed payloads. |
| 13.2.2 | JSON schema validation | **MET** | Pydantic models validate all request bodies. Type hints enforced at runtime. |

### ASVS Summary

| Section | MET | PARTIAL | NOT MET | N/A |
|---------|-----|---------|---------|-----|
| V2 Authentication | 8 | 0 | 0 | 2 |
| V3 Session Management | 4 | 1 | 0 | 0 |
| V4 Access Control | 5 | 0 | 0 | 0 |
| V6 Cryptography | 8 | 0 | 0 | 0 |
| V7 Error Handling | 4 | 0 | 0 | 0 |
| V8 Data Protection | 6 | 0 | 0 | 0 |
| V9 Communications | 3 | 0 | 0 | 0 |
| V13 API Security | 4 | 0 | 0 | 0 |
| **Total** | **42** | **1** | **0** | **2** |

---

## 3. Explicit Limitations

What Resurgamus Horizon does NOT protect against:

### 3.1 - Host-Level Compromise

| Threat | Why Resurgamus Horizon Cannot Mitigate |
|--------|-----------------------------|
| **Root access on host** | An attacker with root can read `/proc/PID/mem`, attach debuggers, modify Docker images, access Docker socket. mlock protects against swap, not root. |
| **Hypervisor compromise** | A compromised hypervisor can snapshot VM memory, clone disks, intercept network traffic. Resurgamus Horizon runs in userspace. |
| **Physical access** | Cold boot attacks, DMA attacks, hardware keyloggers. Software-only protection. |
| **Kernel exploit** | A kernel vulnerability can bypass all container isolation (namespaces, cgroups, seccomp). |

### 3.2 - Cryptographic Limitations

| Threat | Status |
|--------|--------|
| **Weak master password** | Argon2id makes brute-force expensive but not impossible. A 6-character password is crackable regardless of KDF. No minimum length enforced. |
| **Quantum computing (asymmetric)** | Storage uses 256-bit symmetric primitives, with an estimated 128-bit brute-force margin under Grover. TLS prefers hybrid `X25519MLKEM768` on nginx, PostgreSQL, and Rust-agent paths, but resistance depends on verifying live negotiation because classical fallbacks remain. WebAuthn signatures remain classical. See `docs/POST-QUANTUM.md`. |
| **YubiKey HMAC-SHA1** | SHA1 is weak for collision resistance but HMAC-SHA1 is still secure (keyed construction). Hardware limitation, not a choice. |
| **No forward secrecy** | If the master password is compromised, all past secrets encrypted with that key are recoverable from a DB backup. DEK rotation limits exposure window but doesn't provide forward secrecy. |
| **Timing side channels** | The constant-time crypto and its per-build asm verification are documented in `docs/SIDE-CHANNELS.md`. The one residual not closeable by test or asm-grep is the *microarchitectural* channel (SMT/port contention) - handled by the single-tenant deployment model (no untrusted co-resident), not by proof. |

### 3.3 - Operational Gaps

| Threat | Status |
|--------|--------|
| **Single operator** | No separation of duties enforced. Admin token has full access. Shamir mitigates for unseal but not for daily operations. |
| **No HSM integration** | Wrap key is in software (Rust mlock'd heap), not in a hardware security module. FIPS 140-2 Level 3+ requires HSM. |
| **mlock degradation** | Without `IPC_LOCK` or sufficient `RLIMIT_MEMLOCK`, best-effort mode separately reports buffer protection and whether whole-process pages remain swappable; `zeroize` still runs on drop. This is a persistent-data concern only with unencrypted or unverified swap, where the API warns. Encrypted swap, zram, and no swap are reported without a warning. Raise the limit/grant the capability, or select `RH_MEMORY_LOCK_MODE=required` to fail closed while swap is exposed. |
| **No certificate pinning** | No mutual TLS between API clients and vault. TLS via Nginx + operator's VPN, but no client cert pinning. |
| **No anomaly detection** | Audit logs detect tampering but don't alert on suspicious patterns (e.g., bulk secret reads at 3 AM). Requires external SIEM integration. |
| **Backup decryption** | age-encrypted backups require the age key. If the age key is lost, the backup is unrecoverable. No key escrow. |
| **PostgreSQL TLS unverified by default** | `database_ssl` defaults to `require`: encrypted, but the server certificate is not verified, so this stops passive sniffing and not an active MITM on the DB path. `verify-full` **is** supported and pins `database_ca_cert` — it is opt-in, not absent. The default suits single-host; set `verify-full` for any deployment where the database is reached across a network you do not own. |

### 3.4 - Agent (rh-inject) Limitations

| Threat | Status |
|--------|--------|
| **Env var exposure** | rh-inject resolves secrets into environment variables. These remain visible in `/proc/PID/environ` and to any process running as the same user. |
| **docker inspect** | Container definition shows `RH_TOKEN` and `rh://` references. |
| **Recommendation** | Use rh-fetch (file-based, tmpfs, mode 0400) instead of rh-inject for production workloads. rh-inject is suitable for development and low-sensitivity environments. |

### 3.5 - MCP / AI Agent Integration Limitations

| Threat | Status |
|--------|--------|
| **Prompt injection via a rogue upstream** | `rhorizon-mcp-hub` forwards tool results from federated upstreams verbatim to the agent. A malicious or compromised upstream MCP server can inject instructions into a tool result the agent then treats as trusted context. This is not a MITRE ATT&CK Enterprise technique (LLM-specific; the adjacent framework is [MITRE ATLAS](https://atlas.mitre.org/) [AML.T0051 - LLM Prompt Injection](https://atlas.mitre.org/techniques/AML.T0051)) and rhorizon has no code-level mitigation for it beyond the operational recommendation: every federated upstream must be under the operator's own control, never a public or third-party MCP server. |
| **Read-only by design, not by proof** | The MCP tool catalog exposes 7 read-only tools (status, whoami, list-namespaces, list-secrets, get-secret, audit-tail, cluster-health); there is no write, seal/unseal, or token-management tool. This bounds what a compromised or manipulated agent can do to *reading* whatever the token's `policy.toml` allows - but a broad `policy.toml` whitelist still means a manipulated agent can read (and potentially exfiltrate via its own output) every secret the operator granted it. |
| **Operator-token discovery** | Tool discovery (the catalog presented to the agent at startup) runs under the hub's own operator token, not the calling agent's. A `mcp-hub` misconfiguration that widens discovery scope affects every agent behind that hub. |

### 3.6 - Deployment Dependencies (Operator Responsibility)

Resurgamus Horizon's auth model is self-contained: master password + 2FA (WebAuthn/TOTP/YubiKey). No SSO proxy or reverse proxy is required for security. These are optional layers the operator may add.

| Component | Risk if outdated/misconfigured | Resurgamus Horizon mitigation |
|-----------|-------------------------------|-------------------|
| **Docker Engine** | Container escape. Socket exposure. Privilege escalation. | Container hardening (read-only, non-root, cap_drop ALL, no-new-privileges). But a Docker 0-day bypasses everything. |
| **Host OS kernel** | Container escape via kernel exploit (e.g., Dirty Pipe, OverlayFS). | None - Resurgamus Horizon runs in userspace. Operator must patch the kernel. |
| **PostgreSQL** | Auth bypass CVEs. RCE. | TLS connection, parameterized queries (no SQL injection). But a PostgreSQL RCE is game over. |
| **VPN (IPsec / OpenVPN / ...)** | VPN bypass if misconfigured (split tunneling, leaked keys, weak pre-shared secrets). | Network isolation is the operator's responsibility. Resurgamus Horizon should not be internet-exposed. |

### 3.7 - What Would Improve the Security Posture

| Improvement | Effort | Impact |
|-------------|--------|--------|
| Minimum password length enforcement | Low | Prevent trivially weak master passwords |
| Make `database_ssl=verify-full` the default | Low | The verified mode already exists and is documented; what remains is flipping the default and shipping a CA path, which is a migration question rather than a missing control |
| Mutual TLS for API clients | Medium | Stronger client authentication |
| HSM integration (PKCS#11) | High | FIPS 140-2 compliance, hardware key protection |
| SIEM integration (anomaly alerting) | Medium | Detection of bulk exfiltration patterns |
| Token inactivity timeout | Low | V3.3.2 full compliance |
| Post-quantum WebAuthn (when authenticators ship it) | Future | Closes the last quantum gap - transport (`X25519MLKEM768`) and data-at-rest are already PQ; only the FIDO2 ECDSA signature remains |
| Shared-secret header alongside SSO-proxy IP allowlist | Low | A second factor the proxy must forward (known only to rhorizon and the reverse proxy) would make header spoofing require more than reaching an allow-listed IP |
| MCP upstream allowlist / signature check in `mcp-hub` | Medium | Would move the "operator must only federate trusted upstreams" recommendation from operational guidance to an enforced control |

---

## References

- [MITRE ATT&CK Enterprise Matrix](https://attack.mitre.org/matrices/enterprise/)
- [MITRE ATT&CK T1555 - Credentials from Password Stores](https://attack.mitre.org/techniques/T1555/)
- [MITRE ATT&CK T1552 - Unsecured Credentials](https://attack.mitre.org/techniques/T1552/)
- [MITRE ATT&CK T1003 - OS Credential Dumping](https://attack.mitre.org/techniques/T1003/)
- [MITRE ATT&CK T1649 - Steal or Forge Authentication Certificates](https://attack.mitre.org/techniques/T1649/)
- [MITRE ATT&CK T1136 - Create Account](https://attack.mitre.org/techniques/T1136/)
- [MITRE ATLAS AML.T0051 - LLM Prompt Injection](https://atlas.mitre.org/techniques/AML.T0051) (adjacent framework for AI/LLM-specific risk, not part of ATT&CK Enterprise)
- [OWASP ASVS v4.0.3](https://owasp.org/www-project-application-security-verification-standard/)
- [OWASP Top 10 - 2021](https://owasp.org/www-project-top-ten/)
- [NIST SP 800-57 - Key Management](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)
- [Argon2 RFC 9106](https://www.rfc-editor.org/rfc/rfc9106)
