# Technical file and release record

Status: **assembly checklist and draft records**, not a completed declaration.
Baseline: [index](index.md). Sources: [CRA Articles 13, 28–32 and Annexes II,
V–VIII](https://eur-lex.europa.eu/eli/reg/2024/2847/oj/fra).

## Identity, scope and decision record

| Field | Current record |
|---|---|
| Product/trade name | Resurgamus Horizon |
| Assessed source revision | `12e0bf96b11a25763a5a6bf2738f68728fd7064b` |
| Software version found in API config | `0.9.5-beta`; reconcile component/package versions before selecting a release |
| Legal manufacturer name and postal address | **Open**; the trade name alone is insufficient |
| Main EU establishment and reporting CSIRT | **Open**; apply Article 14(7) |
| Authorised signatory / incident primary / backup | **Open** |
| Product/components/architectures supplied | Complete the [boundary inventory](applicability.md) with exact release identifiers |
| Actual placement on the EU market | **Open**, per supplied version/distribution; distinguish a plan from actual supply |
| Classification and conformity route | Class I and Article 32(5)/Module A are candidates; signed rationale and eligibility evidence outstanding |
| Published support commitment | [SECURITY.md](../SECURITY.md): 1.0.x beta; planned September 2026 supply and September 2031 end date |
| Support reconciliation needed | Confirm which actual releases this commitment covers and expected lifetime; do not reduce a commitment already made |
| Technical-file version / reviewer / approval date | **Open** |

## Annex VII contents

| Annex VII item | Evidence to assemble | Present input / missing evidence |
|---|---|---|
| 1(a)–(b): product description, intended use, relevant versions | Component inventory, versions, diagrams, deployment modes, included remote processing | [Applicability](applicability.md), [deployment guide](../docs/DEPLOYMENT.md); freeze the release-specific boundary |
| 1(c): hardware appearance/marking/layout where applicable | Determine applicability | Software-only working scope; revisit for a supplied hardware appliance |
| 1(d): Annex II user information | Complete the user-information checklist below in the actual distribution | Several identity, support and declaration fields remain open |
| 2(a): design/development and component relationships | System/data-flow/trust-boundary diagrams and security design | [Threat model](../docs/THREAT-MODEL.md), [HA design](../docs/HA-CLUSTER.md), [risk assessment](risk-assessment.md) |
| 2(b): vulnerability handling, SBOM, CVD/contact and secure updates | Adopted process, test of intake, per-artifact SBOM, delivery-verification records | [Vulnerability procedure](vulnerability-handling.md), [security policy](../SECURITY.md), [release verification](../docs/verifying-releases.md); operation still to evidence |
| 2(c): production/monitoring processes and validation | Reviewed build/release procedures, access separation, key custody, reproducibility and promotion records | CI definitions and verification guides are inputs; retain exact run results and independently accessible evidence |
| 3: cybersecurity risk assessment | Approved risks and Annex I applicability/implementation decisions | [Initial assessment](risk-assessment.md), [requirements](requirements.md); acceptance remains open |
| 4: support-period basis | Expected lifetime, user expectations, dependency lifecycles, resources, end date by release | Existing September 2031 promise; detailed justification and release binding required |
| 5: standards/specifications/certifications or other solutions | Exact editions, relevant OJ citations, full/partial coverage and alternate solutions | No harmonised-standard presumption or certification established here; crypto/ASVS/SLSA references alone do not establish it |
| 6: test reports for product and vulnerability processes | Dated results, artifact/platform identity, tool versions, failures and remediation | Test source is not a test report; attach executed results including incident exercises |
| 7: EU declaration of conformity | Approved, signed Annex V declaration after successful assessment | Not produced; checklist below is deliberately unsigned |
| 8: SBOM on reasoned authority request where necessary | Searchable, retained machine-readable inventory | Match SBOM to artifact/version and prove retrieval; public disclosure of every SBOM is not imposed by this item alone |

For the candidate Article 32(5) FOSS route, publish the required technical file
at market placement. Internal CI paths, a list of missing items, or a repository
link inaccessible to the public do not meet that condition. Export reviewed
test summaries and required evidence without credentials, customer data or
private operational endpoints. Resolve any conflict between required public
documentation and sensitive material before choosing the route; do not claim
the condition is met merely by redacting required substance.

## Annex II — information actually supplied to users

| Item | Required content / Horizon input | Open work |
|---|---|---|
| 1 | Manufacturer name/trade name and postal/digital contact | Confirm and include legal contact details |
| 2 | Single vulnerability contact and CVD policy location | Confirm monitored contact, backup and consistent routing of both published mailboxes |
| 3 | Product name/type and unique identification | Bind software version, commit and artifacts/digests |
| 4 | Intended use, security environment and security-relevant functions | Supply deployment assumptions with the product, including external TLS/DB requirements |
| 5 | Known/foreseeable circumstances of significant cyber risk | Include relevant misuse and residual risks from the assessment |
| 6 | Declaration URL where applicable | Publish only after a valid declaration exists |
| 7 | Security support type and end date | Resolve actual supported versions; show month/year clearly at supply |
| 8(a) | Secure commissioning and lifecycle operation | [Deployment](../docs/DEPLOYMENT.md), [TLS](../docs/TLS.md), [compatibility](../docs/COMPATIBILITY.md); test the shipped instructions |
| 8(b) | Security consequences of product modifications | Document effects of disabled controls, third-party modules and configuration changes |
| 8(c) | Installation of security updates | [Image](../docs/verifying-images.md) and [release verification](../docs/verifying-releases.md); include migration/recovery and exact downloads |
| 8(d) | Secure decommissioning and data deletion | Complete storage, backup, replica, WAL, audit and exported-data procedures |
| 8(e) | How to disable default automatic security updates, when applicable | Decide applicability; document actual controls and deferral rather than claim automation exists |
| 8(f) | Information enabling integrators to meet security/documentation duties | Define API/agent/SDK/MCP trust assumptions and supported configurations |
| 9 | SBOM location when supplied to users | Give discoverable per-release links and verification instructions |

Choose languages understandable to the users and market-surveillance
authorities for the countries of supply; a French legal source does not by
itself establish that an English-only instruction set is adequate everywhere.

## Support and retention are different clocks

| Record | Required basis under the cited CRA articles | Implementation decision |
|---|---|---|
| Vulnerability handling during support | 13(8): expected use/lifetime, normally at least five years; shorter expected use has its own condition | A long-lived vault may need more than five years. Explain the chosen period, dependencies and staffing; retain existing promises |
| Security updates already issued | 13(9): availability for at least ten years after issue or the remaining support period, whichever is longer | Preserve immutable downloads and dependencies needed to obtain/install them; a mutable `latest` tag is insufficient |
| Technical documentation and declaration | 13(13): at least ten years after market placement or the support period, whichever is longer | Versioned archive with accountable owner, access control and tested retrieval |
| User information/instructions | 13(18): availability to users/authorities for at least ten years after market placement or support period, whichever is longer | Stable public URLs and archive copies, including documentation for old supported releases |

For illustration only, a security update issued on 20 October 2026 would need
availability to at least 20 October 2036 if Article 13(9) applies and no longer
support period governs. This is not a new promise that every release in this
repository was supplied on that date. Document backup/restore, retention
exemptions from registry pruning, successor/cessation arrangements and periodic
retrieval checks. No retention infrastructure was created by this dossier.

## Release evidence manifest

Complete one record per supplied release. Keep an immutable copy with its
evidence, not just a link to a moving branch or `latest` tag.

```text
Product/component and actual software version:
Source commit/tag and signature verification:
Market-placement date and transition/substantial-modification decision:
Distribution channels and supported architectures/configurations:
Artifact filename/image reference and digest (manifest + platform digests):
SBOM format, digest and verified signature/attestation:
Provenance subject, source revision, builder/run and verification result:
Scan tool/version, database timestamp, options, report hash and triage:
Security/functional/recovery tests, platform coverage and report hashes:
Open vulnerabilities, exploitability decisions and residual-risk approvals:
Advisory IDs, fixed versions and user-update instructions:
Support start/end, basis and retention deadlines:
User-information version and languages:
Classification, conformity route and completed assessment reference:
Declaration/CE record if applicable and complete:
Evidence archive location, public technical-file URL where required:
Release approver and approval timestamp:
```

## Annex V declaration preparation — unsigned checklist

This section is a list of required fields, **not an EU declaration**. Do not
insert a signed conformity assertion until the procedure has demonstrated that
the product and manufacturer processes meet the applicable requirements.

1. Product name/type and unique identification.
2. Manufacturer or authorised representative's name and address.
3. Statement that the declaration is issued under the responsible party's sole
   responsibility, using the applicable legal wording.
4. Traceable identification of the declaration's subject.
5. Applicable Union harmonisation legislation and the conformity statement.
6. Applied harmonised standards/common specifications/certifications and their
   precise references and coverage.
7. Notified body, procedure and certificate reference where applicable.
8. Additional information, place/date, signatory name/function and signature.

Article 30 permits software CE marking on the declaration or accompanying
website, with accessible user instructions as applicable. Record the chosen
placement only after the Article 28 declaration and assessment are complete.
Do not generate a CE badge or populate this checklist with invented identities,
certificates or assessment results.
