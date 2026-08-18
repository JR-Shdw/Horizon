# Resurgamus Horizon - NIS2 compliance (Directive (EU) 2022/2555)

Version: 1.1
Date: 2026-08-04
Scope: Resurgamus Horizon as a secrets-management component in an
infrastructure subject to NIS2

---

## Context

The NIS2 directive (Network and Information Security 2) has, since October
2024, imposed reinforced cybersecurity measures on essential and important EU
entities. SMEs/mid-caps in critical sectors (energy, transport, health,
digital, etc.) must demonstrate the compliance of their cyber risk management.

Resurgamus Horizon directly addresses several requirements of **Article 21**
(risk-management measures) as a **central secrets-management and encryption
component**.

This document maps the NIS2 requirements to the features implemented in
Resurgamus Horizon.

> **Product-side counterpart.** NIS2 obliges the *operator*; the **Cyber
> Resilience Act (CRA)** obliges the *manufacturer* of the software and governs
> **CE marking**. See [CRA-COMPLIANCE.md](CRA-COMPLIANCE.md) for the product-side
> gap analysis, Horizon's important class I FOSS classification, the Article
> 32(5) Module A self-assessment, and the roadmap to CE marking.

### Statuses

- **COMPLIANT** - Resurgamus Horizon meets the requirement directly
- **CONTRIBUTES** - Resurgamus Horizon covers it partially; complementary
  measures are needed
- **OUT OF SCOPE** - The requirement is on the organization, not a technical
  tool

---

## Article 21 - Cyber risk-management measures

### (a) Risk-analysis and information-system security policies

| Requirement | Status | Resurgamus Horizon implementation |
|----------|--------|----------------------|
| Documented risk analysis | **CONTRIBUTES** | Published MITRE ATT&CK threat model (docs/THREAT-MODEL.md). 43 techniques evaluated, 20 covered, 23 partial. Threat model specific to a secrets vault. |
| Formalized security checklist | **CONTRIBUTES** | OWASP ASVS Level 2: 42 MET, 1 PARTIAL out of 45 requirements. Covers authentication, crypto, access control, communications, logging. |
| Documented encryption policy | **COMPLIANT** | 5 documented crypto layers: Argon2id, HKDF-SHA512, XChaCha20-Poly1305, AES-256-GCM, HMAC-SHA512. No custom algorithm. |

**Complementary measures required**: organization-wide security policy, asset
register (a CAASM/CMDB can cover this need).

---

### (b) Incident handling

| Requirement | Status | Resurgamus Horizon implementation |
|----------|--------|----------------------|
| Incident detection | **COMPLIANT** | Signed mutation chain plus signed Merkle checkpoints for reads. An integrity failure is a compromise signal. |
| Event logging | **COMPLIANT** | Every event records actor, action, target, detail, timestamp, and IP address in PostgreSQL. Mutations are individually signed and mirrored to daily JSONL; high-volume reads are Merkle-checkpointed into that signed chain and archived before database pruning. |
| Log integrity | **COMPLIANT** | Mutation rows form an Ed25519-signed chain (HMAC-SHA512 for legacy/fallback rows). Complete read records are covered by signed Merkle checkpoints; sealed archives retain checksums, Merkle roots, and signed seal lineage. Tampering is detected by `/audit/verify`. |
| Evidence retention | **COMPLIANT** | Configurable retention (default 365 days, min 365, max 3650). Automatic compression after 7 days. Deletion only beyond the retention window, by an admin. |
| Incident notification within 24h | **CONTRIBUTES** | Built-in notification channels (Matrix, webhook, email). Automatic alerts on critical events (seal/unseal, auth failures, chain break). |

**Complementary measures required**: CSIRT notification procedure, incident
response plan, SIEM integration for correlation.

---

### (c) Business continuity and crisis management

| Requirement | Status | Resurgamus Horizon implementation |
|----------|--------|----------------------|
| Data backup | **COMPLIANT** | Full DR uses `pg_dump \| age`; API logical backups use age/pyrage for migration artifacts. Both are integrable with Restic (configurable RPO). PostgreSQL volume remains separable for independent backup. |
| Restore | **COMPLIANT** | Full restore uses PostgreSQL restore; API age backup restore is partial logical migration. Idempotent SQL schema (IF NOT EXISTS). Documented restore procedure. |
| Service availability | **CONTRIBUTES** | Multi-worker uvicorn (local crypto RPC compartmentalization + Shamir failover; single-worker home preset available) plus provider-neutral Database HA health. Patroni is the tested reference topology; BSD `pgha` is supported but not yet in this repository's automated release lane. Sealed by default at reboot (security > availability). |
| Recovery plan | **CONTRIBUTES** | Restore procedure: deploy a new container, restore PostgreSQL or API logical backup depending on the incident, then unseal. Estimated recovery time: < 15 minutes (single operator) for the logical path. |

**Complementary measures required**: organization-wide business continuity
plan (BCP), documented periodic restore tests, and a supported Database HA
provider with regular failover/rejoin drills.

---

### (d) Supply-chain security

| Requirement | Status | Resurgamus Horizon implementation |
|----------|--------|----------------------|
| Dependency auditing | **COMPLIANT** | CI/CD pipeline: pip-audit (Python vulnerabilities), cargo test (Rust), Trivy (CVE on Docker images). Daily run. |
| Tracked dependencies | **COMPLIANT** | requirements.txt (Python, hash-pinned) and Cargo.lock (Rust, checksummed - Cargo.toml itself only carries loose version ranges). SBOM generated by syft, cosign attestation (`--type cyclonedx`). |
| Verified container images | **COMPLIANT** | Trivy scans 3 images (API, frontend, agent). Config + secret scan. Trivy version pinned at 0.71.2 (0.69.4-6 compromised - supply-chain attack March 2026; >= 0.70.0 = clean post-incident releases). |
| Secret detection in code | **COMPLIANT** | detect-secrets in the CI pipeline. Automatic scan on every push. |
| Static analysis (SAST) | **COMPLIANT** | Bandit (Python SAST) in the CI pipeline. No critical finding tolerated. |
| Auditable open-source code | **COMPLIANT** | Full source code accessible. No SaaS or proprietary dependency. |

**Complementary measures required**: supplier-management policy (for indirect
dependencies), package-signature verification.

---

### (e) Security in acquisition, development and maintenance

| Requirement | Status | Resurgamus Horizon implementation |
|----------|--------|----------------------|
| Secure development | **COMPLIANT** | Mandatory CI pipeline: lint (ruff) + SAST (bandit) + dep audit (pip-audit) + secret scan (detect-secrets) + tests (1815 Python + 136 Rust) + CVE scan (Trivy). |
| Vulnerability management | **COMPLIANT** | Daily Trivy scan (cron 4h UTC). pip-audit on every push. Dependency versions pinned and documented with a bump procedure. |
| Security testing | **COMPLIANT** | Dedicated security test suite (test_security.py): auth bypass (6 vectors), privilege escalation, sealed state, input validation, challenge replay, token revocation. |
| Vulnerability remediation | **CONTRIBUTES** | CI pipeline blocks the merge if SAST or audit fails. Notification on failure. But: no formal remediation SLA. |

**Complementary measures required**: vulnerability-remediation SLA (critical <
24h, high < 7d), responsible-disclosure process.

---

### (f) Assessing the effectiveness of the measures

| Requirement | Status | Resurgamus Horizon implementation |
|----------|--------|----------------------|
| Security metrics | **CONTRIBUTES** | OWASP ASVS 42/45 MET, MITRE ATT&CK 20/43 COVERED. Test coverage 94%. Daily CVE scan with history. |
| Compliance auditing | **CONTRIBUTES** | Built-in audit-chain verification (API endpoint). Threat model and ASVS checklist kept up to date in the repo. |
| Periodic testing | **COMPLIANT** | CI pipeline on every push (security tests + SAST + deps). Daily Trivy. But: no external pentest scheduled. |

**Complementary measures required**: annual external audit, periodic pentest,
quarterly NIS2 compliance review.

---

### (g) Basic cyber-hygiene practices

| Requirement | Status | Resurgamus Horizon implementation |
|----------|--------|----------------------|
| Least privilege | **COMPLIANT** | Granular scopes: secrets:r, secrets:w, tokens:r, tokens:w, audit:r, admin:rw. Namespace isolation. Ephemeral tokens for one-off operations. |
| Non-root containers | **COMPLIANT** | API: uid 1500, frontend: nginx (NET_BIND_SERVICE cap only), PostgreSQL: non-root recommended. `cap_drop: ALL` + `no-new-privileges` on all containers. |
| Read-only filesystem | **COMPLIANT** | API and frontend containers read-only. tmpfs for /tmp and /dev/shm (noexec, nosuid). Per-container memory limits. |
| No default credentials | **COMPLIANT** | No default account. First unseal creates the master key. Root token displayed only once. |
| Component updates | **CONTRIBUTES** | Documented bump procedure (Python, Rust, Docker images). But: no automatic update. |

**Complementary measures required**: operator cybersecurity training, password
policy (recommended minimum master-password length).

---

### (h) Cryptography and encryption policies and procedures

| Requirement | Status | Resurgamus Horizon implementation |
|----------|--------|----------------------|
| Encryption at rest | **COMPLIANT** | Double envelope: XChaCha20-Poly1305 (secret -> DEK) + AES-256-GCM (DEK -> master key). Database useless without the master key. |
| Encryption in transit | **COMPLIANT** | TLS 1.2+1.3 via Nginx. VPN (IPsec / OpenVPN) for external access. TLS API-to-PostgreSQL. |
| Approved algorithms | **COMPLIANT** | Argon2id (RFC 9106), AES-256-GCM (NIST), HMAC-SHA512 (FIPS 198-1), HKDF (RFC 5869), XChaCha20-Poly1305 (IETF). No proprietary or custom algorithm. |
| Key management | **COMPLIANT** | Master key never on disk (derived in RAM, Argon2id 256MB). DEK-key age is monitored; an authenticated operator starts hierarchical rotation, which rewraps DEKs without rewriting secret ciphertext. |
| In-memory key protection | **COMPLIANT** | Rust extension (PyO3): `mlock` when permitted and `zeroize` on drop. Wrap key in the Rust heap, outside Python object introspection. Rootless `mlock` limits are documented as a deployment caveat. |
| Unique nonces | **COMPLIANT** | CSPRNG (os.urandom / OsRng). 24-byte nonce (XChaCha20) or 12-byte (AES-GCM). Negligible collision probability. |
| Post-quantum resilience | **CONTRIBUTES** | Symmetric crypto (AES-256, XChaCha20, HMAC-SHA512): resistant (Grover halves to 128-bit, still infeasible). WebAuthn ECDSA P-256: vulnerable to Shor. Migration needed when available. |

**This point is the core of Resurgamus Horizon's compliance.** The cryptography
is fully documented, uses public standards exclusively, and the implementation
is auditable (< 3000 LOC).

---

### (i) Human-resources security, access control and asset management

| Requirement | Status | Resurgamus Horizon implementation |
|----------|--------|----------------------|
| Access control | **COMPLIANT** | Authentication via HMAC-SHA512 tokens with scopes. Mandatory 2FA for unseal (WebAuthn/TOTP/YubiKey). Immediate token revocation. |
| Privilege segregation | **COMPLIANT** | Granular scopes (secrets:r/w, tokens:r/w, audit:r, admin). Namespaces for secret isolation. Ephemeral tokens for one-off operations (TTL 60s-24h). |
| Secret-asset management | **CONTRIBUTES** | Resurgamus Horizon manages the secrets. CAASM/CMDB integration for secret-to-asset mapping. |
| Access traceability | **COMPLIANT** | Every access to a secret is logged with actor, action, target, detail, IP, and timestamp. Signed Merkle checkpoints make read evidence tamper-evident without serializing every read through a per-row signature. |
| Access revocation | **COMPLIANT** | Immediate token revocation. Master-password rotation invalidates all tokens. Seal cuts all access to secrets. |

**Complementary measures required**: HR policy (operator departure = access
revocation), active-token inventory, periodic rights review.

---

### (j) Multi-factor authentication

| Requirement | Status | Resurgamus Horizon implementation |
|----------|--------|----------------------|
| MFA on administration interfaces | **COMPLIANT** | 4 2FA modes: WebAuthn/FIDO2 (phishing-resistant), TOTP (RFC 6238), YubiKey HMAC-SHA1, `any` mode (user's choice). |
| Phishing-resistant MFA | **COMPLIANT** | WebAuthn/FIDO2: origin-bound challenge, private key in hardware. Resistant to real-time phishing proxies. |
| Single-use challenges | **COMPLIANT** | Challenges stored in the database (not in memory), deleted after use (DELETE+RETURNING), TTL 60 seconds. Cross-worker safe. |
| Fallback on loss | **COMPLIANT** | Automatic fallback: if the last security key is removed -> switch to TOTP or none. Shamir shares for emergency unseal (M-of-N). |

**This point is a major strength of Resurgamus Horizon.** Authentication is
fully self-contained - no dependency on an external identity provider (IdP), no
OIDC, no SAML. This simplifies compliance and removes a failure vector.

---

## Article 21 summary

| Measure | Status | Resurgamus Horizon strengths | To complete |
|--------|--------|---------------------|-------------|
| **(a)** Risk analysis | CONTRIBUTES | ATT&CK threat model + ASVS documented | Organization-wide security policy |
| **(b)** Incident handling | COMPLIANT | Chained audit, 1-10y retention, notification | Notification procedure, SIEM |
| **(c)** Business continuity | CONTRIBUTES | age backup, restore < 15min, provider-neutral Database HA health | Org-wide BCP, Database HA failover drills |
| **(d)** Supply chain | COMPLIANT | Full CI/CD, SBOM, Trivy, pip-audit | Supplier policy |
| **(e)** Secure dev and maintenance | COMPLIANT | Mandatory CI pipeline, security tests | Vuln-remediation SLA |
| **(f)** Measure assessment | CONTRIBUTES | ASVS 42/45, coverage 94% | External audit, pentest |
| **(g)** Cyber-hygiene | COMPLIANT | Least privilege, non-root, read-only | Operator training |
| **(h)** Cryptography | **COMPLIANT** | 5 layers, public standards, Rust mlock | Post-quantum migration |
| **(i)** Access control | COMPLIANT | Scopes, namespaces, revocation, audit | HR policy, rights review |
| **(j)** MFA | **COMPLIANT** | WebAuthn + TOTP + YubiKey, self-contained | - |

**Result: 6 COMPLIANT, 4 CONTRIBUTES, 0 NON-COMPLIANT**

---

## Mapping NIS2 x OWASP ASVS x MITRE ATT&CK

Resurgamus Horizon maintains three cross-referenced security frameworks:

| Framework | Coverage | Document |
|-------------|-----------|----------|
| **NIS2 Article 21** | 6/10 compliant, 4/10 contributes | This document |
| **OWASP ASVS Level 2** | 42 MET, 1 PARTIAL out of 45 | docs/THREAT-MODEL.md |
| **MITRE ATT&CK** | 20 COVERED, 23 PARTIAL out of 43 | docs/THREAT-MODEL.md |

This triple mapping lets you demonstrate compliance to auditors from different
angles:
- **NIS2**: regulatory compliance (mandatory)
- **OWASP ASVS**: application-level technical compliance
- **MITRE ATT&CK**: coverage of real-world threats

---

## Recommendations for full compliance

### High priority (NIS2 required)

| Action | Effort | NIS2 measure |
|--------|--------|-------------|
| Write an organization-wide security policy | Medium | (a) |
| Establish an incident-notification procedure (24h/72h) | Low | (b) |
| Write a BCP including vault restore | Medium | (c) |
| Define a vulnerability-remediation SLA | Low | (e) |
| Schedule an annual external audit | Medium | (f) |

### Medium priority (reinforcement)

| Action | Effort | NIS2 measure |
|--------|--------|-------------|
| Deploy and exercise a supported Database HA provider (Patroni reference, or `pgha` on BSD) | Medium | (c) |
| Integrate a SIEM (Wazuh) for correlation | Medium | (b) |
| Minimum master-password length (16 characters) | Low | (g) |
| Token inactivity timeout (ASVS V3.3.2) | Low | (i) |
| CAASM/CMDB integration for secret-asset mapping | Medium | (i) |

### Low priority (evolution)

| Action | Effort | Impact |
|--------|--------|--------|
| Mutual TLS for API clients | Medium | Reinforces (d) |
| HSM/PKCS#11 for the wrap key | High | FIPS 140-2 if needed |
| Post-quantum WebAuthn migration | Future | Anticipates (h) |

---

## References

- [Directive (EU) 2022/2555 (NIS2)](https://eur-lex.europa.eu/eli/dir/2022/2555)
- [ANSSI - NIS2 transposition into French law](https://www.ssi.gouv.fr/directive-nis-2/)
- [ENISA - NIS2 Implementation Guidance](https://www.enisa.europa.eu/topics/nis-directive)
- [OWASP ASVS v4.0.3](https://owasp.org/www-project-application-security-verification-standard/)
- [MITRE ATT&CK Enterprise](https://attack.mitre.org/matrices/enterprise/)
- [NIST SP 800-57 - Key Management](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)
- [RFC 9106 - Argon2](https://www.rfc-editor.org/rfc/rfc9106)
