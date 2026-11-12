# Horizon — Cyber Resilience Act dossier

Assessment date: **20 October 2026**. Repository baseline:
`12e0bf96b11a25763a5a6bf2738f68728fd7064b`.

This is a historical assessment of that baseline. The commercial licence was
withdrawn on 25 October 2026; the current distribution and funding policy is in
[SUPPORT.md](../SUPPORT.md). The commercial-model findings below need
reassessment before they can be used for a current release.

This folder is a working readiness dossier for Regulation (EU) 2024/2847.
It records applicable requirements, repository evidence, unresolved decisions
and work needed before a manufacturer can declare conformity. It is **not a
declaration of conformity, certification, or authorisation to affix CE marking**.
Named owners and release-specific evidence still need to be attached.

At that baseline, Horizon had an AGPL distribution and an advertised commercial
licence/support offering. The working scope was a commercially supplied, dual-licensed
software product, rather than an assumption that all open-source software is
exempt. The manufacturer must confirm the actual supply model and legal entity.
See [applicability](applicability.md).

## Read the dossier

| Document | Purpose |
|---|---|
| [Applicability and classification](applicability.md) | Product boundaries, economic role, dates, class I analysis and conditional Module A route |
| [Requirements and evidence](requirements.md) | Every Annex I requirement, exact numbering, implementation evidence and remaining validation |
| [Cybersecurity risk assessment](risk-assessment.md) | Initial product-specific risks, controls, residual uncertainty and acceptance criteria |
| [Vulnerability handling and Article 14](vulnerability-handling.md) | Intake, triage, 24h/72h reporting, distinct final-report deadlines and advisory template |
| [Technical file and release record](technical-file.md) | Annex VII, user information, support/retention records and unsigned declaration checklist |
| [Action plan](action-plan.md) | Priorities, responsible roles, target milestones and objective completion evidence |
| [Public artifact verification](evidence/2026-10-21-publication.md) | API/agent digests, verified signatures, provenance and SBOM attestations |
| [Frontend CVE evidence](evidence/2026-10-20-frontend.md) | A bounded example of remediation and testing, not whole-product assurance |

## Dates that affect the work now

| Date | Meaning |
|---|---|
| 10 December 2024 | Regulation entered into force |
| 11 June 2026 | Chapter IV, concerning conformity assessment bodies, started applying |
| **11 September 2026** | **Article 14 manufacturer reporting obligations started applying** |
| **11 December 2027** | General application, subject to the transition rules for existing products |

As of this assessment, incident reporting is a current operational issue for
in-scope manufacturers, not a future 2027 project. A scanner finding alone does
not establish active exploitation or a reportable incident. Existing products
need the Article 69 transition analysis; a pre-2027 release is not a blanket
exemption from Article 14. Sources: [CRA, Articles 69 and 71](https://eur-lex.europa.eu/eli/reg/2024/2847/oj/fra)
and [Commission reporting guidance](https://digital-strategy.ec.europa.eu/en/policies/cra-reporting).

## Assessment discipline

- **Evidence present:** code, configuration or documentation was located. This
  says nothing by itself about a released binary or effective operation.
- **Partial:** relevant measures exist, but scope, testing or operational proof
  is incomplete.
- **Open:** a required decision, process or evidence package was not established
  by this review. This is not proof that it does not exist elsewhere.
- **Verified, bounded:** a stated check passed for a named artifact, date and
  scope. It does not imply that all CRA requirements are met.

No aggregate compliance percentage is used. A green CVE scan cannot establish
absence of all exploitable vulnerabilities, a complete risk assessment, an
effective reporting organisation, or conformity of every supported platform.
Tests linked here were located, not rerun as part of this documentation review,
unless a dated evidence record explicitly says otherwise.

The existing [CRA assessment](../docs/CRA-COMPLIANCE.md) and
[security policy](../SECURITY.md) remain useful inputs, but their compliance
counts and release/support assumptions require reconciliation. The action plan
records the differences; this dossier does not silently amend those policies.

## Official sources

Sources consulted on 20 October 2026:

1. [Regulation (EU) 2024/2847, official French text](https://eur-lex.europa.eu/eli/reg/2024/2847/oj/fra)
   — [the CELEX link supplied for this work](https://eur-lex.europa.eu/legal-content/FR/TXT/?uri=CELEX:32024R2847).
2. [Implementing Regulation (EU) 2025/2392](https://eur-lex.europa.eu/eli/reg_impl/2025/2392/oj/fra)
   — technical descriptions used for product classification.
3. [Commission CRA summary](https://digital-strategy.ec.europa.eu/en/policies/cra-summary)
   — explanatory material; the legal text controls.
4. [Commission reporting guidance](https://digital-strategy.ec.europa.eu/en/policies/cra-reporting).
5. [ENISA Single Reporting Platform and current user guidance](https://www.enisa.europa.eu/topics/product-security/vulnerability-services/eu-incident-response-and-cyber-crisis-management/single-reporting-platform-srp).

Recheck amendments, applicable delegated/implementing acts, harmonised-standard
references in the Official Journal and reporting guidance before signing a
release assessment. This review does not assert that any particular standard
currently confers a presumption of conformity on Horizon.
