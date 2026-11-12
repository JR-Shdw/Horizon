# CRA action plan

Baseline: 20 October 2026, [assessed revision and scope](index.md).
**All actions below are open** unless a dated evidence record states a bounded
result. Roles are proposed; a named accountable owner and completion date must
be assigned. A document draft does not close the operational action it describes.

P0 means current operational readiness or a prerequisite to relying on a claim;
P1 means completion before a release that needs full CRA conformity; P2 means
ongoing evidence and lifecycle maintenance. These priorities are project choices.

## Work register

| ID | Priority / target | Action | Responsible role | Completion evidence |
|---|---|---|---|---|
| A-01 | P0 — now | Confirm manufacturer identity, commercial scope, EU establishment, supplied product/version inventory and actual market dates | Manufacturer/legal | Approved [applicability](applicability.md) and identity/release record |
| A-02 | P0 — now; Article 14 already applies to in-scope manufacturers | Adopt [reporting procedure](vulnerability-handling.md); appoint primary/backup, verify SRP access and CSIRT, exercise both notification tracks | Manufacturer/PSIRT | Access confirmation, timed tabletop record, absence coverage, tested receipts/evidence storage; review known cases since applicability without assuming every CVE was reportable |
| A-03 | P0 — next security release | Establish consistent reporting/advisory access and free timely fix dissemination; reconcile commercial “priority security updates” and dependency exclusion | Manufacturer/PSIRT | Approved policy wording, monitored single contact, published advisory examples and access test for unpaid users |
| A-04 | P0 — before next artifact promotion | Bind scans, SBOMs, signatures and provenance to exact shipped digests/platforms; prove promotion cannot use stale reports | Release engineering | Immutable release manifest, current report hashes, negative gate test and verified public artifacts |
| A-05 | P1 — before final conformity-route decision | Decide class I categories/core functionality and FOSS eligibility; validate Article 32(5) publication condition or alternative route | Manufacturer/legal/security | Signed rationale against current technical descriptions, complete public-file plan or notified-body engagement where required |
| A-06 | P1 — before conformity assessment | Complete [risk assessment](risk-assessment.md) for all supplied configurations and map applicable Annex I controls | Security/component owners | Scored risks with evidence, documented applicability exceptions, residual-risk decisions and change-review procedure |
| A-07 | P1 — before conformity assessment | Resolve technical gaps: TLS defaults, update automation/notice/deferral, logging-disable requirement, secure deletion, availability and impact on other systems | Engineering/security | Implemented or justified measures, test reports and matching user instructions for I-2b/c/e/h/i/l/m |
| A-08 | P1 — before next support claim and conformity assessment | Reconcile 0.9.5-beta code with 1.0.x support text; determine expected lifetime and release-specific support end dates; design long-term archives | Manufacturer/release | Approved version-support table, dependency migration plan, retained patch/document inventory and successful restore/retrieval test; no reduction of promises already made |
| A-09 | P1 — before applicable market placement / general application on 11 December 2027 | Complete Annex II/VII, execute the selected conformity procedure, then sign the declaration and affix CE where applicable | Manufacturer/signatory | Complete technical file, successful assessment, signed declaration and verifiable user-facing marking/location |
| A-10 | P0 — before reusing existing compliance statements | Reconcile [old CRA assessment](../docs/CRA-COMPLIANCE.md), [SECURITY.md](../SECURITY.md) and baseline commercial terms (`LICENSE-COMMERCIAL.md`, since withdrawn; see [current policy](../SUPPORT.md)) | Documentation/manufacturer | Correct requirement numbering, consistent status labels/counts, present-tense reporting dates, factual classification and policy consistency |
| A-11 | P2 — each release and material change | Maintain evidence, risk/classification decisions, advisories, upstream coordination and support inventory | Release/PSIRT | Reviewed release record plus dated lifecycle/risk updates |
| A-12 | P2 — periodic and before conformity sign-off | Recheck CRA amendments, delegated/implementing acts, OJ standards, authority guidance and SRP procedure | Manufacturer/legal | Dated source register showing relevance, changes and affected actions |

## Specific inconsistencies to resolve

- The old assessment uses Part I `(3a)`–`(3k)` and omits a distinct mapping for
  security updateability. The adopted structure is I-1 plus I-2(a)–(m).
- Its broad “COMPLIANT” conclusions and security-policy totals are inconsistent
  with one another and with open evidence needs. Replace them with traceable
  findings for the assessed product/release.
- The September 2026 reporting milestone has passed. Verify the operating
  process now; a roadmap date is not evidence of activation or a missed report.
- The technical description for password managers includes remote storage;
  lack of browser autofill is not by itself a reason to exclude category 3.
- `database_ssl=require` is the actual default; `verify-full` is supported but
  opt-in. Do not describe default server authentication as already proven.
- The commercial licence mentions priority patches while the security policy
  says fixes are free and available to everyone. Clarify support response versus
  access to security fixes and ensure the operational process matches.
- The security policy excludes third-party dependency issues from scope while
  requesting upstream reports. The manufacturer's own handling obligations
  still cover integrated components; distinguish upstream ownership from
  responsibility for the shipped product.
- A planned 1.0 launch and September 2031 support end date do not establish the
  support treatment of the current 0.9.5-beta artifacts or later market supply.

This work adds the dossier under `cra/`; it does not amend the listed policies,
change repository/registry publication policy, sign a declaration, or contact an
authority.

## Release decision checklist

- [ ] Scope, dates, legal role and conformity route decided for the release.
- [ ] Applicable product requirements and vulnerability processes demonstrated.
- [ ] Current vulnerability/exploitability review attached to exact artifacts.
- [ ] SBOM, provenance, signatures and retained public distribution verified.
- [ ] Support, patch retention and Annex II information attached to the release.
- [ ] Article 14 operations staffed and exercised, and outstanding cases handled.
- [ ] Required technical documentation complete and publicly available where
      the chosen FOSS route requires it.
- [ ] Conformity assessment complete; declaration signed and CE applied only
      where applicable and supported by that assessment.

The manufacturer records the decision and evidence; this checklist cannot
automatically establish conformity from a green pipeline.
