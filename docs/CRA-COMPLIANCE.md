# Resurgamus Horizon - CRA readiness (Regulation (EU) 2024/2847)

Version: 1.1
Date: 2026-08-04
Scope: Resurgamus Horizon as a **product with digital elements** placed on the
EU market by a commercial manufacturer (Resurgamus)

---

## Context

The **Cyber Resilience Act** (CRA, Regulation (EU) 2024/2847) is a *product*
regulation: it makes cybersecurity a condition for affixing the **CE marking**
on any "product with digital elements" made available on the EU market. It is
the complement of NIS2 - NIS2 obliges the *operator* (Article 21 risk
management); the CRA obliges the *manufacturer* of the software itself.

Key dates:

| Milestone | Date |
|---|---|
| Entry into force | 10 December 2024 |
| Conformity-assessment bodies notified (Chapter IV) | 11 June 2026 |
| **Vulnerability & severe-incident reporting to ENISA (Article 14)** | **11 September 2026** |
| **Full obligations + CE marking required (Article 71)** | **11 December 2027** |

### CRA position for Horizon

Horizon is one product and one public codebase. The commercial licence grants
alternative terms for the same software and adds commercial support; it is not
a separate proprietary edition.

| Question | Horizon position | Basis |
|---|---|---|
| Is the product in CRA market scope? | **Yes.** Resurgamus offers commercial licences and paid support/SLA. | Articles 3(13), 3(22) and recital 15 |
| Who is the economic operator? | **Resurgamus is the manufacturer**, not an open-source software steward. | Article 3(13); a steward must be a legal person other than the manufacturer under Article 3(14) |
| Does Horizon qualify as FOSS? | **Yes.** Its source is openly shared and the product is made available under AGPL-3.0. Offering alternative commercial terms does not withdraw the AGPL distribution. | Article 3(48) |
| Product category | **Important product, class I.** Self-assessed as Annex III category 3, "password managers" (stores/shares credentials and secrets). Not settled: the Implementing Regulation's technical description of that category centers on client-side store/generate/auto-fill; Horizon is an API-token-gated infra vault with no auto-fill. "Identity and access management / privileged access management software" is also class I and arguably a closer functional fit. Either way the CE-marking route is unchanged (both categories sit in class I, same Module A eligibility), so this is a citation-precision question, not a compliance gap - flag for legal review before the Annex VII technical documentation is finalised. | Annex III and Implementing Regulation (EU) 2025/2392 |
| Conformity procedure | **Internal control, Module A.** Resurgamus uses the FOSS route in Article 32(5) and publishes the Article 31 technical documentation when placing the product on the market. | Articles 32(1)(a), 32(5), 31 and Annex VIII |
| External conformity assessor | **Not required for the adopted route.** | Article 32(5) permits the procedures in Article 32(1), including Module A |
| Remaining manufacturer work | Risk assessment, public technical documentation, EU Declaration of Conformity, CE marking, vulnerability process and Article 14 reporting. | Articles 13-14, 28-32 and Annexes I, V, VII and VIII |

This position depends on maintaining a public AGPL distribution of the same
Horizon product and publishing the complete Article 31 technical documentation.
It must be reviewed if Resurgamus later ships a distinct proprietary-only
edition or stops meeting the Article 3(48) FOSS definition.

### Statuses

- **COMPLIANT** - the product already meets the requirement (code / config)
- **CONTRIBUTES** - partially met; a complementary measure is needed
- **TO PRODUCE** - a manufacturer artefact or process still to be created
  (technical file, declaration, policy) - this is "where we are" for CE marking

---

## Annex I, Part I - Cybersecurity requirements (product properties)

| # | Requirement | Status | Resurgamus Horizon implementation |
|---|---|---|---|
| (1) | Appropriate level of cybersecurity based on risk | **CONTRIBUTES** | MITRE ATT&CK + STRIDE threat model (docs/THREAT-MODEL.md), OWASP ASVS L2 42/45. Needs the formal Article 13(2) risk assessment in the technical file. |
| (2) | Made available without known exploitable vulnerabilities | **COMPLIANT** | CI: pip-audit, cargo audit/deny, Bandit SAST, detect-secrets, Trivy CVE (daily cron). Hash-pinned deps. Merge blocked on failure. |
| (3a) | Secure-by-default configuration + reset to original | **COMPLIANT** | Sealed by default at boot; binds 127.0.0.1 by default; no default account (first unseal mints the master key); root token shown once. Reset = redeploy + fresh unseal. |
| (3b) | Protection from unauthorised access + report it | **COMPLIANT** | HMAC-SHA512 tokens, granular scopes, per-token IP allowlist, mandatory 2FA (WebAuthn/TOTP/YubiKey). fail2ban-ready authfail log + `rhorizon_auth_failures_total`. |
| (3c) | Confidentiality (encryption at rest / in transit) | **COMPLIANT** | Double envelope XChaCha20-Poly1305 -> AES-256-GCM; master key derived in RAM (Argon2id 256MB), never on disk; TLS 1.2/1.3 with post-quantum hybrid KEM X25519MLKEM768; verify-full to PostgreSQL. |
| (3d) | Integrity of data / commands / config + report corruption | **COMPLIANT** | Ed25519-signed mutation chain plus signed Merkle checkpoints and sealed read archives (`GET /audit/verify`); AEAD tags detect ciphertext tampering; pinned PG server cert; cosign-signed images. |
| (3e) | Data minimisation | **COMPLIANT** | Stores only secrets + minimal metadata; audit records only security-necessary fields (actor, action, target, IP, timestamp). No superfluous PII. |
| (3f) | Availability of essential functions; DoS resilience | **CONTRIBUTES** | Admission control (in-flight cap -> 429 load-shed), per-IP rate limiting, local Shamir failover, and provider-neutral Database HA (Patroni tested; BSD `pgha` supported), plus pids/memory limits. Sealed-by-default trades availability for security (documented). |
| (3g) | Minimise negative impact on other services | **COMPLIANT** | Per-container memory/pids caps; internal-only DB network; `/metrics` IP-allow-listed (no amplification); no outbound side effects. |
| (3h) | Limit attack surface incl. external interfaces | **COMPLIANT** | Minimal runtime image; Swagger/ReDoc disabled; single authenticated API; `cap_drop: ALL`, read-only fs, `/dev/shm` 1M; MCP fail-closed (deny_all without policy). |
| (3i) | Reduce incident impact (exploitation mitigation) | **COMPLIANT** | Rust `mlock` where permitted + `zeroize` on drop; `no-new-privileges`; non-root (uid 1500); read-only rootfs; CSP `style-src/script-src 'self'`; worker key compartmentalisation (RPC, no follower holds sub-keys). |
| (3j) | Security logging / monitoring with opt-out | **COMPLIANT** | Signed mutation chain (DB + daily JSONL) plus a read-access log protected by signed Merkle checkpoints and sealed archives; Prometheus `/metrics` (25+ series) + in-app Nova; notification channels (Matrix/webhook/email). Audit directory and retention are configurable. |
| (3k) | Secure permanent deletion + secure transfer of data | **CONTRIBUTES** | `secure_zero` (Rust) + seal zeroes keys; secret/namespace delete; `pg_dump \| age` for full DR and API age logical backup for migration. "Remove all data" = `compose down -v`; a documented decommissioning procedure is the complement. |

**Result Part I: 10 COMPLIANT, 3 CONTRIBUTES, 0 non-compliant (of 13
properties).** The product-side of CRA is essentially satisfied - Horizon is a
hardened cryptographic product by design.

---

## Annex I, Part II - Vulnerability-handling requirements (manufacturer process)

| # | Requirement | Status | Where we are |
|---|---|---|---|
| (1) | Identify + document components; SBOM (machine-readable, >= top-level deps) | **COMPLIANT** | CycloneDX SBOM per image (syft) with a cosign attestation (`--type cyclonedx`) over it, `.woodpecker/build.yml`; hash-pinned `requirements.txt` (pip-compile) and `Cargo.lock` (checksummed, not `Cargo.toml` - that file only carries loose version ranges). Per-module SBOMs also ship as signed release assets (`release.yml`). |
| (2) | Remediate vulnerabilities without delay; updates separate from features | **COMPLIANT** | CI blocks on SAST/audit; daily Trivy; `fix:` commits ship independently of features. `SECURITY.md` now documents both clocks: first response 48h (paying sponsor) / 96h (everyone else), and remediation by **severity, not reporter** - critical 7d, high 30d, medium next release. Fixes are free to all AGPL users with an advisory per issue; sponsorship buys attention latency, never privileged access to a fix. |
| (3) | Effective, regular security tests + reviews | **COMPLIANT** | 1815 Python + 136 Rust tests, dedicated `test_security.py`, cargo-fuzz (4 targets), miri, clippy `-D warnings`; CI on every push, coverage 94%. Functional and KAT crypto coverage runs on both shipped architectures: amd64 (`validate.yml`) and aarch64 (`arch-matrix.yml` / `tools/test-arm64.sh`, 136/136). The GF(256) assembly branch gate is x86_64-specific. |
| (4) | Publicly disclose fixed vulnerabilities (description, affected, impact, severity, remediation) | **TO PRODUCE** | No formal advisory channel yet. Adopt GitHub Security Advisories / CVE IDs + a `CHANGELOG` security section per fixed issue. |
| (5) | Coordinated vulnerability-disclosure (CVD) policy | **COMPLIANT** | `SECURITY.md`: coordinated disclosure, 90-day window, first response 48h/96h by reporter class, severity-driven remediation targets, defined scope, split OSS and commercial contacts. |
| (6) | Facilitate reporting; contact address | **CONTRIBUTES** | `SECURITY.md` gives a reporting email. Gaps: publish `/.well-known/security.txt` (RFC 9116) and use a Resurgamus (commercial-manufacturer) contact rather than an internal one. |
| (7) | Securely distribute updates, automatic where applicable | **COMPLIANT** | cosign-signed multi-arch images + SLSA provenance + verification docs; agent updates ride signed images. |
| (8) | Patches disseminated without delay, free of charge, with advisories | **CONTRIBUTES** | AGPL - updates are free and public. Gap: a formal advisory dissemination channel tied to (4) + the notification list. |

**Result Part II: 5 COMPLIANT, 2 CONTRIBUTES, 1 TO PRODUCE.** The gaps are
paperwork and publication, not engineering.

---

## Annex II - Information and instructions to the user

| Requirement | Status | Note |
|---|---|---|
| Manufacturer identity + contact | **TO PRODUCE** | Add the Resurgamus legal entity + postal/email + point of contact to the docs. |
| Single point of contact for vuln reporting + CVD location | **COMPLIANT** | `SECURITY.md` (align to commercial contact + `security.txt`). |
| Product name / type / version identification | **COMPLIANT** | `version` in `/status`, image tags, release artefacts. |
| Intended purpose, essential + security-relevant functions | **COMPLIANT** | README + CLAUDE.md + docs (network security model, crypto layers). |
| Foreseeable misuse leading to cyber risk | **COMPLIANT** | Documented: "never expose on the internet", VPN-only, threat model assumptions. |
| Where the SBOM is available | **COMPLIANT** | Ships already: per-module CycloneDX SBOMs are published as signed release assets (`<module>.sbom.cdx.json`, `release.yml`) and attached to each image as a cosign `cyclonedx` attestation (`build.yml`). Verification recipes in `docs/verifying-releases.md` and `docs/verifying-images.md`. Remaining: surface the link on the release page itself, not just in the docs. |
| How to install updates | **COMPLIANT** | `docker compose pull` / `install.sh` re-run / native git pull; documented per path. |
| Where the EU Declaration of Conformity is available | **TO PRODUCE** | Produce the DoC (Annex V) and link it. |
| Support period / end-of-support (EOL) date | **COMPLIANT** | `SECURITY.md` "Support period": placed on market September 2026, five years, ends **September 2031** (month+year as Article 13(8) requires). Scoped to the canonical artifact with a graded platform matrix, and the two in-window migrations (Python 3.12 EOL 31 Oct 2028, OpenBSD's 6-month cadence) are named as commitments rather than escape hatches. |
| Secure commissioning / operation / decommissioning | **COMPLIANT** | Quickstart, deployment, TLS, disaster-recovery, secure-deletion notes. |

---

## Manufacturer obligations (Articles 13-14, conformity)

| Obligation | Article | Status | Note |
|---|---|---|---|
| Cybersecurity risk assessment | 13(2) | **TO PRODUCE** | Formalise from the existing threat model into the Article 13(2) format. |
| Technical documentation | 31 + Annex VII | **TO PRODUCE** | Assemble: risk assessment, Annex I evidence, SBOM, test reports, DoC. Most inputs already exist in-repo. |
| Conformity assessment | 32 + Annex VIII | **TO PRODUCE** | Complete and publish the Article 31 technical documentation, then record the Module A internal-control assessment under Article 32(5). |
| EU Declaration of Conformity | 28 + Annex V | **TO PRODUCE** | Draft after completing the Module A assessment. |
| CE marking | 29-30 | **TO PRODUCE** | Affix after DoC. |
| Report actively-exploited vulns + severe incidents to ENISA/CSIRT | 14 | **TO PRODUCE** | **Deadline 11 Sept 2026.** Stand up the 24h early-warning / 72h notification procedure (notification channels already exist as the technical base). |
| Due-diligence on integrated third-party components | 13(5) | **CONTRIBUTES** | pip-audit / cargo audit / Trivy + upstream-trust doc; formalise supplier due-diligence. |

---

## Summary

| CRA area | Result |
|---|---|
| **Annex I Part I** (product properties, 13) | 10 COMPLIANT, 3 CONTRIBUTES, 0 gap |
| **Annex I Part II** (vuln handling) | 5 COMPLIANT, 2 CONTRIBUTES, 1 to produce |
| **Annex II** (user information) | 8 COMPLIANT, 2 to produce (manufacturer legal identity, DoC location) |
| **Manufacturer obligations** | 1 CONTRIBUTES, 6 to produce |

**Read-out for CE marking:** the *technical* substance of the CRA is largely
done - Horizon is secure-by-design, encrypted, audited, hardened, tested, with a
CVD policy and signed supply chain. What remains is the **manufacturer's
compliance file and process**: the risk-assessment write-up, the technical
documentation dossier, the Module A conformity assessment, the EU DoC,
and the Article 14 reporting procedure (due first, 11 Sept 2026).

---

## Correspondence table - Horizon function x NIS2 Art. 21 x CRA Annex I

Argumentaire: one control, two regulations. Each Horizon capability answers a
NIS2 Article 21 measure (operator obligation) **and** a CRA Annex I requirement
(product obligation).

| Horizon function | NIS2 Art. 21 | CRA Annex I |
|---|---|---|
| Double-envelope encryption at rest (XChaCha20 -> AES-256-GCM) | (h) | Part I (3)(c) |
| TLS 1.2/1.3 + post-quantum hybrid KEM in transit | (h) | Part I (3)(c) |
| Master key in mlock'd RAM, never on disk (Argon2id) | (h) | Part I (3)(c), (3)(i) |
| Signed mutation chain + Merkle-protected read evidence | (b) | Part I (3)(d), (3)(j) |
| 2FA WebAuthn / TOTP / YubiKey (phishing-resistant) | (j) | Part I (3)(b) |
| Scoped HMAC tokens + per-token IP allowlist | (i) | Part I (3)(b) |
| Sealed-by-default + no default credentials | (g) | Part I (3)(a) |
| Non-root, read-only fs, cap_drop ALL, no-new-privileges | (g) | Part I (3)(h), (3)(i) |
| Admission control + per-IP rate limiting | (c) | Part I (3)(f) |
| Local Shamir M-of-N failover + provider-neutral Database HA | (c) | Part I (3)(f) |
| Prometheus /metrics + Nova + notification channels | (b), (f) | Part I (3)(j) |
| age-encrypted backup / restore | (c) | Part I (3)(k) |
| Rust secure_zero + seal zeroes keys | (h) | Part I (3)(k) |
| SBOM (syft) + cosign signatures + SLSA provenance | (d) | Part II (1), (7) |
| pip-audit / cargo audit / Trivy / Bandit CI | (d), (e) | Part I (2), Part II (2), (3) |
| SECURITY.md coordinated-disclosure policy | (e) | Part II (5), (6) |

---

## Roadmap to CE marking

### Due first - Article 14 reporting (by 11 September 2026)

| Action | Effort |
|---|---|
| Document the 24h early-warning / 72h notification procedure to ENISA/CSIRT | Low |
| Wire the existing notification channels into that procedure | Low |

### For the declaration of conformity (by 11 December 2027)

| Action | Effort | CRA reference |
|---|---|---|
| Write the Article 13(2) risk assessment (from the threat model) | Medium | 13(2) |
| Assemble the technical documentation dossier | Medium | 31 + Annex VII |
| Link the (already published, already signed) SBOM from the release page | Low | Part II (1), Annex II |
| Adopt GitHub Security Advisories / CVE + advisory channel | Low | Part II (4), (8) |
| Add `/.well-known/security.txt` + commercial contact | Low | Part II (6), Annex II |
| ~~Define + publish support period / EOL policy~~ - **done**: five years, ends September 2031 (`SECURITY.md`) | - | Annex II, Art. 13(8) |
| ~~Define vulnerability-remediation SLA~~ - **done**: response 48h/96h, remediation critical 7d / high 30d (`SECURITY.md`) | - | Part II (2) |
| Publish the technical documentation and complete the Article 32(5) Module A assessment | Medium | 31, 32(1)(a), 32(5) + Annex VIII |
| Draft the EU Declaration of Conformity + affix CE | Medium | 28-30 + Annex V |

### Reinforcement (already CONTRIBUTES)

| Action | Effort | Requirement |
|---|---|---|
| Document decommissioning / secure-wipe procedure | Low | Part I (3)(k) |
| Harden DoS posture beyond rate limiting | Medium | Part I (3)(f) |
| Formalise supplier due-diligence | Low | Art. 13(5) |

---

## References

- [Regulation (EU) 2024/2847 (Cyber Resilience Act)](https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng)
- [Implementing Regulation (EU) 2025/2392 - technical descriptions of CRA product categories](https://eur-lex.europa.eu/eli/reg_impl/2025/2392/oj/eng)
- [European Commission - CRA summary](https://digital-strategy.ec.europa.eu/en/policies/cra-summary)
- [European Commission - Cyber Resilience Act](https://digital-strategy.ec.europa.eu/en/policies/cyber-resilience-act)
- [ENISA - vulnerability disclosure](https://www.enisa.europa.eu/topics/vulnerability-disclosure)
- [RFC 9116 - security.txt](https://www.rfc-editor.org/rfc/rfc9116)
- [NIS2 compliance mapping](NIS2-COMPLIANCE.md) - the operator-side counterpart
- [Threat model (MITRE ATT&CK + OWASP ASVS)](THREAT-MODEL.md)
