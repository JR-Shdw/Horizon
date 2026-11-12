# Requirements and repository evidence

Baseline and status definitions: [index](index.md). This is a readiness mapping,
not a conformity verdict. All requirements below are taken from
[CRA Annex I](https://eur-lex.europa.eu/eli/reg/2024/2847/oj/fra), with its final
numbering: Part I **1 and 2(a)–(m)**, and Part II **1–8**. Applicability of
Part I(2) must be justified by the Article 13 risk assessment; no requirement is
marked inapplicable merely because implementing it would be inconvenient.

## Part I — product properties

| ID | Requirement in practical terms | Evidence located | Status and closure evidence |
|---|---|---|---|
| I-1 | Security appropriate to risk | [Threat model](../docs/THREAT-MODEL.md), [initial risk assessment](risk-assessment.md) | Partial: approve the product boundary, risk methodology, residual risk and lifecycle review |
| I-2a | No known exploitable vulnerabilities at market supply | `.woodpecker/scan.yml`, [image tests](../tests/test_api_image_security.py), [frontend remediation](evidence/2026-10-20-frontend.md) | Partial: attach current reports for exact shipped digests and all architectures; assess exploitability beyond scanner severity and prove the release gate |
| I-2b | Secure defaults and reset to original state | [Configuration](../api/app/config.py), [deployment](../docker-compose.yml), [security tests](../tests/test_security.py) | Partial: demonstrate default install, reset and recovery for each supported mode; network TLS assumptions need explicit treatment |
| I-2c | Security updates, automatic updates where applicable, user notification, opt-out and postponement | [Image verification](../docs/verifying-images.md), [install/update tooling](../tools/install-container.sh) | Partial: document and justify applicability of automatic updates; test notice, deferral, opt-out, update authenticity and migration safety |
| I-2d | Prevent and report unauthorised access | [Authentication](../api/app/auth.py), [auth-failure logging](../api/app/authfail.py), [RBAC regression tests](../tests/test_security_rbac_fixes.py) | Evidence present: collect current auth, scope, revocation, MFA and unauthorised-access reporting test results |
| I-2e | Confidentiality of stored, transmitted and processed data | [Crypto](../api/app/crypto.py), [Rust implementation](../api/rust/src), [TLS guide](../docs/TLS.md) | Partial: validate each channel and deployment; `database_ssl=require` encrypts but does not authenticate the server certificate |
| I-2f | Integrity of data, commands, software and configuration; detect corruption | [Audit implementation](../api/app/audit.py), [audit verification tests](../tests/test_audit_verify_ed25519.py), [release verification](../docs/verifying-releases.md) | Evidence present: retain tamper, rollback, signature and trust-anchor test results against the shipped artifacts |
| I-2g | Data minimisation | [Audit records](../api/app/audit.py), [retention configuration](../api/app/config.py) | Partial: inventory identifiers, IP addresses, logs, exports and retention; test redaction and necessity rather than infer minimisation from encryption |
| I-2h | Availability, recovery and denial-of-service resilience | [HA design](../docs/HA-CLUSTER.md), [security tests](../tests/test_security.py), [chaos harness tests](../tests/test_chaos_k7_harness.py) | Partial: define essential functions, measurable recovery targets and load/failure limits; retain representative load, partition and restore results |
| I-2i | Limit harm to other devices and networks | [Resource/network limits](../docker-compose.yml), [agent code](../agent/rust/src) | Partial: assess retry storms, outbound integrations, SSRF/egress and impact on databases/identity providers; retain tests |
| I-2j | Minimise attack surface, including external interfaces | [API image](../api/Dockerfile), [frontend configuration](../frontend/nginx.conf), [MCP implementation](../mcp) | Evidence present: inventory all enabled endpoints, debug surfaces and optional integrations for the assessed configuration |
| I-2k | Limit incident impact and exploitation | [Rust implementation](../api/rust/src), [container confinement](../docker-compose.yml), [memory hardening tests](../tests/test_mem_hardening.py) | Evidence present: validate privileges, core dumps, key zeroisation, isolation and supported-platform limitations |
| I-2l | Security monitoring/logging with user ability to disable the mechanism | [Audit implementation](../api/app/audit.py), [audit configuration](../api/app/config.py), [audit coverage tests](../tests/test_audit_coverage.py) | Partial: audit/checkpoint/retention controls do not prove a full user-disable mechanism. Resolve applicability, secure behaviour and user instructions explicitly |
| I-2m | Easy, secure and permanent deletion of all data/settings; secure transfers | [Backup routes](../api/app/routes/backup.py), [legacy backup tests](../tests/test_legacy_backup.py), [deployment storage](../docker-compose.yml) | Partial: demonstrate export/import and decommissioning across DB, WAL, replicas, logs, snapshots and backups. Deleting a volume alone does not prove permanent erasure |

## Part II — vulnerability handling

| ID | Requirement in practical terms | Evidence located | Status and closure evidence |
|---|---|---|---|
| II-1 | Document components/vulnerabilities; machine-readable SBOM covering at least top-level dependencies | `.woodpecker/build.yml`, `.woodpecker/release.yml`, dependency lockfiles | Partial: match each SBOM to artifact digest/platform and bundled components, and retain a vulnerability/exploitability register |
| II-2 | Remediate without delay; separate security and feature updates where feasible | [Security policy](../SECURITY.md), [frontend fix record](evidence/2026-10-20-frontend.md) | Partial: preserve dated intake-to-release records, upstream coordination and escalation; severity targets are not permission to delay an urgent fix |
| II-3 | Effective regular security testing and reviews | `.woodpecker/validate.yml`, `.woodpecker/fuzz.yml`, `.woodpecker/arch-matrix.yml` | Evidence present: archive successful runs, failures, exclusions, reviewer decisions and platform coverage for the release |
| II-4 | Disclose fixed vulnerabilities with affected product, impact, severity and remediation | [Changelog](../CHANGELOG.md), [advisory template](vulnerability-handling.md) | Open: establish an advisory channel and attach published advisory records; document any justified delay in public detail |
| II-5 | Adopt and apply a coordinated vulnerability disclosure policy | [Security policy](../SECURITY.md) | Partial: exercise the process and retain case records; the 90-day disclosure policy cannot delay Article 14 notifications |
| II-6 | Facilitate reporting about the product and integrated third-party components; provide contact | [Security policy](../SECURITY.md) | Partial: verify monitored contact and backup coverage; reconcile the dependency exclusion. `security.txt` is a useful implementation choice, not an express CRA requirement |
| II-7 | Secure and timely update distribution; automation where applicable | `.woodpecker/build.yml`, [verification guide](../docs/verifying-images.md) | Partial: prove signatures and attestations survive public distribution and that documented installation verifies them; assess automation applicability |
| II-8 | Disseminate available security fixes without delay and free of charge, with advisories | [Security policy](../SECURITY.md), baseline commercial terms (`LICENSE-COMMERCIAL.md`, since withdrawn; see [current policy](../SUPPORT.md)) | Open: reconcile “priority security updates” with free timely fixes for all affected users; demonstrate advisory distribution and patch access |

## Manufacturer/process obligations

Source: [CRA Articles 13–14, 28–32 and Annexes II, V, VII,
VIII](https://eur-lex.europa.eu/eli/reg/2024/2847/oj/fra).

| Reference | Evidence or working document | Remaining decision/proof |
|---|---|---|
| 13(2)–(4), 13(7) | [Risk assessment](risk-assessment.md) | Approval, actual operating conditions, change history and evidence for exceptions |
| 13(5)–(6) | Lockfiles, base-image pins, [upstream verification tooling](../tools/verify-upstream.sh) | Supplier due diligence, upstream reports and sharing of fixes where required |
| 13(8), 13(19) | [Security support commitment](../SECURITY.md) | Actual release/version scope, expected lifetime, end date at supply and means of notifying expiry where feasible |
| 13(9), 13(13), 13(18) | [Retention plan](technical-file.md) | Durable patch, document and instruction archives; test retrieval and protect retained evidence from pruning |
| 13(12), 28–32, Annexes V/VIII | [Applicability](applicability.md), [technical file](technical-file.md) | Complete assessment, approved route, signed declaration and CE placement only after demonstrated conformity |
| 13(15)–(18), 13(20), Annex II | [User-information checklist](technical-file.md) | Manufacturer identity, single contact, exact product ID, instructions, support and declaration links |
| 13(21)–(23) | [Vulnerability procedure](vulnerability-handling.md) | Corrective action/withdrawal/recall procedure when necessary, authority cooperation and cessation plan |
| 14, 16 | [Reporting runbook](vulnerability-handling.md) | Named primary/backup, SRP access, CSIRT selection, monitoring and a timed exercise |

## Gaps in earlier statements

The [existing CRA assessment](../docs/CRA-COMPLIANCE.md) uses Part I references
`(3a)`–`(3k)` and counts 13 properties. The adopted Annex I has a risk-based
requirement plus 13 subrequirements; updateability in I-2c needs its own entry.
Its “COMPLIANT” labels should not substitute for release evidence.

The [security policy](../SECURITY.md) also has a different Part II count from
the existing assessment. Both describe work due in September 2026 as a roadmap
item. Reconcile them through [A-10](action-plan.md), together with the reported
TLS default, commercial patch wording and version/support discrepancies.
