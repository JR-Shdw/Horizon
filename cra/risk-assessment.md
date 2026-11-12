# Initial cybersecurity risk assessment

Status: **draft for manufacturer review**, 20 October 2026; not a signed
acceptance of residual risk. Product baseline: [index](index.md).
This develops the existing [threat model](../docs/THREAT-MODEL.md) into an
Article 13(2)–(4) working record. It must be completed for actual supplied
versions and deployments. Legal basis: [CRA Article 13 and Annex VII(3)](https://eur-lex.europa.eu/eli/reg/2024/2847/oj/fra).

## Context, assets and trust boundaries

Intended use: organisations storing and distributing credentials/secrets,
controlling access to them, using cryptographic/PKI functions and integrating
applications through the API, agents and tooling. The expected operating
environment includes an administratively controlled host or cluster,
PostgreSQL, protected network channels, managed authentication and backup
storage. A required VPN or reverse proxy is part of the assessed deployment
assumptions, not a substitute for assessing foreseeable exposure.

Assets: secret plaintext, encryption and signing keys, Shamir shares, bearer
tokens, identities and authorisation policies, certificates, audit evidence,
availability of credential retrieval, encrypted backups, release artifacts and
their trust roots. A vault compromise can enable compromise of systems whose
credentials it stores; the impact is not confined to this application.

Trust boundaries: browser to frontend/API; API to database; API to crypto/key
custody processes; cluster peers; agents/MCP clients to API; external identity
and notification providers; build/signing infrastructure to registries; backup
and audit archives to operators. Record which party controls each boundary.

Reasonably foreseeable misuse includes direct internet exposure, unverified
database TLS, overly broad tokens, disabled verification, stale base images,
loss of recovery shares, restored stale snapshots, and public exposure of
backups. These remain in the analysis even where deployment instructions advise
against them. No healthcare, industrial-safety or other safety-critical use was
established; identify potential health/safety consequences if such use is
marketed or reasonably foreseeable.

## Method and acceptance rule

For each release, rate impact (1 limited, 2 material, 3 serious organisational,
4 cross-system compromise/major outage) and likelihood (1 requires multiple
unlikely preconditions, 2 plausible with privileged/local access, 3 realistic
remote or routine misuse, 4 observed exploitation or readily reproducible
exposure). Record evidence and deployment assumptions for each rating.

Proposed prioritisation is impact × likelihood: 1–3 low, 4–7 medium, 8–11 high,
12–16 critical. These are project triage bands, not statutory thresholds or a
replacement for CVSS or Article 14 incident classification. Ratings below remain
unscored until an owner supplies the actual deployment/exploitability evidence.

Acceptance requires a named accountable person, rationale, remaining controls,
test evidence, review date and conditions invalidating the decision. Do not
accept a known exploitable vulnerability at market supply simply because its
score is below a scanner gate. Missing evidence remains open.

## Risk register

| ID | Scenario and impact | Existing controls/evidence | Residual uncertainty and closure criteria | Owner role |
|---|---|---|---|---|
| R-01 | A vulnerable integrated package allows code execution or data disclosure | Pinned images, dependency scans, [frontend CVE remediation](evidence/2026-10-20-frontend.md) | Inventory exact artifacts/platforms; check reachable attack paths, all severities and upstream advisories; prove current release gate and patch distribution | Release/security |
| R-02 | Credentials or DB traffic intercepted because deployment uses HTTP or unauthenticated TLS | [TLS guidance](../docs/TLS.md), Nginx TLS templates, `database_ssl=verify-full` option | Default is `require`, not certificate verification. Test certificate rejection and every hop for each supported topology; document safe default/required setup | Platform/security |
| R-03 | Stolen token, scope bypass or identity-provider mistake exposes other namespaces | [Authentication](../api/app/auth.py), [RBAC tests](../tests/test_security_rbac_fixes.py), [token IP tests](../tests/test_token_ip_acl.py) | Retain cross-namespace denial, revocation, MFA and recovery tests; assess residual privilege of root tokens and proxy trust | API/security |
| R-04 | Memory, process or host compromise exposes keys and downstream credentials | Rust custody, zeroisation, [memory tests](../tests/test_mem_hardening.py), container limits | Demonstrate dump/swap/key-lifetime behaviour per platform; explicitly state host-admin trust and recovery-share controls | Crypto/platform |
| R-05 | Partition, overload, DB failure or loss of shares prevents essential service or causes unsafe failover | [HA design](../docs/HA-CLUSTER.md), fencing tests, backup routes | Approve RTO/RPO, quorum and overload assumptions; retain representative restore/load/partition tests, including sealed state | HA/operations |
| R-06 | Malicious package, compromised build or substituted registry tag is installed | Signed artifacts, provenance, SBOMs, [verification guides](../docs/verifying-images.md) | Verify exact distributed digests, architectures and referrers; ensure installation instructions enforce verification; document trust-root rotation/revocation | Release/security |
| R-07 | Logs leak sensitive data or fail to provide reliable incident evidence | Signed audit records, retention controls, [audit coverage tests](../tests/test_audit_coverage.py) | Review log fields/redaction, tamper coverage, clock assumptions, export access and I-2l user-disable behaviour | Audit/privacy |
| R-08 | Deleted secrets remain recoverable in snapshots, WAL, replicas or exports | Encrypted storage/backup and application deletion | Demonstrate lifecycle-wide deletion, key destruction where suitable, operator instructions and limits of shared storage/snapshots | Storage/operations |
| R-09 | Outbound integrations amplify an outage or reach unintended services | Network/resource limits and scoped integrations | Test retry budgets, egress/SSRF controls, timeouts and failure isolation for enabled modules | Integrations |
| R-10 | An exploited flaw is not reported, or supported users cannot obtain a fix | [Security policy](../SECURITY.md), proposed [reporting procedure](vulnerability-handling.md) | Assign primary/backup, exercise 24h/72h clocks, resolve patch-priority wording and fund support/retention obligations | Manufacturer/PSIRT |

Every row currently has **residual risk acceptance open**. Add inherent and
residual ratings, affected versions/configurations, test report IDs and review
signatures before relying on this as the completed technical-file assessment.

## Review triggers

Review on each release affecting security, new deployment/architecture or
integration, new exploit intelligence, dependency end-of-support, incident,
material change of intended use, or change to a required external service.
Record whether the change is a substantial modification under Article 3(30).
As a proposed operating cadence, review open risks monthly and the whole
assessment at least annually; these intervals are project choices, not periods
specified by the CRA.

Attach the [requirements matrix](requirements.md), explain any inapplicable
Part I(2) requirements, and identify which mitigations must be provided by an
integrator or operator in the shipped user instructions.
