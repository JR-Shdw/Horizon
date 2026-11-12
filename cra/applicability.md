# Applicability and classification

Status: working assessment, 20 October 2026. Legal entity, actual market dates
and final classification require manufacturer confirmation. See the
[dossier index](index.md) for the assessed revision and sources.

## Does all EU software need CRA conformity?

No. The analysis concerns a product with digital elements made available on the
Union market whose intended or reasonably foreseeable use includes a direct or
indirect connection to a device or network. Market supply in the course of a
commercial activity can be paid or free. Under Article 2(1), the market-supply
definition in Article 3(22), and recital 18, non-commercial FOSS development or
supply does not itself trigger the manufacturer regime; the separate steward
role must still be considered where relevant. Sector-specific exclusions also
need consideration. AGPL licensing alone does
not decide the commercial-activity question. Sources: [CRA, Articles 2 and 3,
recitals 15–19](https://eur-lex.europa.eu/eli/reg/2024/2847/oj/fra).

Horizon provides a networked secrets vault, authentication/access controls,
cryptographic services, agents and integrations. The baseline's `LICENSE-COMMERCIAL.md`
offers commercial licensing and paid support. The existing
[CRA position](../docs/CRA-COMPLIANCE.md) describes Resurgamus as manufacturer.
These are evidence for the working commercial-product scope, not proof of a
particular sale, establishment, legal identity or market-placement date.

| Question | Working answer | Decision/evidence still needed |
|---|---|---|
| Product with digital elements? | Yes, connected software with separately supplied components | Inventory the actual distributions and versions |
| Supplied in a commercial activity? | Assess on that basis because commercial terms/support are advertised | Confirm actual supply arrangements and intended EU users |
| Manufacturer? | The person/entity marketing the product under the Resurgamus name is the candidate | Legal name, postal address, establishment, accountable representative |
| Open-source software steward instead? | Not the working role: Article 3(14) concerns a legal person other than the manufacturer | Reassess only if the actual legal/organisational facts differ; Article 24 is not a general FOSS exemption |
| Separate proprietary edition? | Existing documentation says alternative terms for the same public codebase | Confirm the source and feature equivalence of each supplied edition |
| Excluded sector or defence-only product? | No evidence established in this review | Record any actual exclusion and its legal basis, rather than infer it from a customer sector |

## Product boundary

The inventory must cover what is actually supplied, not merely which packages
are public in a registry. Build or hosting policy does not determine CRA scope.

| Surface | Repository evidence | Boundary decision |
|---|---|---|
| Vault API and Rust cryptographic components | [API image](../api/Dockerfile), [Rust crate](../api/rust/Cargo.toml) | Identify versions, wheel, architecture and dependent services |
| Browser UI and Nginx recipe/image | [Frontend image](../frontend/Dockerfile), [TLS configuration](../frontend/nginx-tls.conf) | Include the recipe and any supplied image; lack of a public GHCR frontend image does not remove this surface |
| Agents | [Agent image](../agent/Dockerfile), [Rust agent](../agent/rust/Cargo.toml) | Record supported architectures and standalone binary releases |
| CLI, SDK, Terraform provider, MCP and hub | [CLI](../cli/pyproject.toml), [SDK](../sdk/node/package.json), [provider](../terraform-provider-rhorizon/go.mod), [MCP](../mcp/pyproject.toml), [hub](../mcp-hub/pyproject.toml) | Decide which are separate products/components and maintain their own evidence and support records |
| Packaging and integrated dependencies | [Compose](../docker-compose.yml), [Helm](../helm/rhorizon/Chart.yaml), [PostgreSQL image](../postgres/Dockerfile) | Record who supplies each dependency and the security configuration assumed by the vault |
| Hosted/remote services | No hosted offering assessed here | Distinguish standalone services from remote processing necessary for product functions under Article 3(2); do not assume that every SaaS offering is either included or excluded |

## Important-product classification

**Provisional conclusion: class I is a credible working classification.**
Compare the product's core functionality, including each separately marketed
component, to Article 7, Annex III and the technical descriptions in
[Implementing Regulation (EU) 2025/2392, Annex I](https://eur-lex.europa.eu/eli/reg_impl/2025/2392/oj/fra):

- Category 3 covers password storage locally or on a remote server, including
  generation, sharing and integration with applications. Browser autofill is
  not a prerequisite in that description. Horizon's secret storage and
  distribution make this a plausible match.
- Category 1 covers identity and privileged-access management. Compare
  Horizon's token scopes, identity integration and control of sensitive
  resources against this definition; ordinary authentication in any application
  is not enough by itself to establish that it is the product's core function.
- Category 9 covers PKI and certificate issuance software. Horizon's
  [PKI routes](../api/app/routes/pki.py) warrant an explicit assessment when that
  functionality is marketed or supplied as a core function.

The older CRA document's suggestion that category 3 centres on client-side
autofill should not be carried into the final classification decision. Record
actual marketed functions and an approved rationale; do not treat two possible
class I categories as interchangeable evidence. No class II or Annex IV
classification has been established by this review.

## Conformity route

Article 32(5) permits manufacturers of qualifying FOSS products in Annex III
to use an Article 32(1) procedure, including internal control (Module A), **if
the Article 31 technical documentation is publicly available at market
placement**. A public repository or this incomplete folder is not sufficient
evidence that this condition is met. The route does not waive essential
requirements, vulnerability handling, the assessment itself or the declaration.
Source: [CRA, Articles 31–32 and Annex VIII](https://eur-lex.europa.eu/eli/reg/2024/2847/oj/fra).

For Horizon, Module A is a **conditional candidate**, not a completed assessment.
Before adopting it, record the FOSS qualification of the supplied product,
approved classification, complete public technical file and internal-control
results. If a product does not qualify for this route, evaluate Article 32(2)
for class I, including the coverage of applicable harmonised standards/common
specifications/certification and any required notified-body procedure. Do not
assume an external assessor is unnecessary for every future edition.

## Dates and existing versions

Article 14 has applied since 11 September 2026. General application is
11 December 2027. Article 69(2) addresses products already placed on the market
before that date and subsequent substantial modifications; Article 69(3)
preserves the reporting obligations for existing in-scope products. The
[Commission summary](https://digital-strategy.ec.europa.eu/en/policies/cra-summary)
explicitly explains that Article 14 also covers products placed on the market
before 11 December 2027.

For each supplied version record the actual first market placement, applicable
transition analysis and whether a later change meets the Article 3(30)
substantial-modification definition. A release tag, a planned September 2026
launch, or a beta label alone does not settle those questions. Retain existing
published support commitments while resolving the version/date mismatch in
the [technical file](technical-file.md).
