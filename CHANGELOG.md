# Changelog

Format loosely follows [Keep a Changelog](https://keepachangelog.com/).
Dates are calendar dates, not release dates - there's no fixed release
cadence; things ship when they're ready.

## Unreleased

## 0.9.5-beta - 2026-09-15

### Added

- Identity-separated AI onboarding on Linux with
  `tools/quickstart-ai-system.sh`. Horizon runs as the non-login `rhorizon`
  account; the AI account receives a scoped MCP token, a trusted local CA
  certificate and an initially empty MCP secret whitelist.

### Security

- AI onboarding and the personal quickstart create a governed `mcp` namespace,
  a read-only agent group and a namespace-scoped token with an explicit
  membership grant. The vault enforces the grant even when an agent bypasses
  MCP or edits its local policy.
- Identity-separated onboarding retains the master password and administrator
  token under `/etc/rhorizon/secrets`, readable only by root. It rejects root
  and service accounts as AI identities, agent-writable source paths, source
  symlinks, Docker group/socket access and detected passwordless sudo/doas
  authority.
- Updated the pinned frontend base image and vulnerable system packages, and
  the Terraform provider's gRPC dependency, to address dependency scan findings.

### Fixed

- The AI installation guides now target `v0.9.5-beta`, which includes the
  dedicated onboarding script missing from `v0.9.4-beta`.
- Kubernetes HA audit checks can be retried, and unseal checks reuse the
  existing helper Pod instead of creating a Pod for every request.
- Public source exports sanitize private network prefixes as well as complete
  addresses.

### Documentation

- AI prompts distinguish the root-only persistent administrator token in the
  identity-separated install from the personal quickstart's one-time display
  and file removal. Privileged operations stay with the operator; the assistant
  receives only its scoped credential.
- MCP documentation identifies vault-side token permissions and grants as the
  authoritative boundary. Local policy is additional filtering for MCP calls,
  not an OS boundary against an agent running under the same UID.
- Hub audit metadata is described as caller-reported attribution, not verified
  client or model provenance.
- Client-secret examples use namespace `mcp` and names such as
  `clients/<name>`; `mcp/clients` is a different namespace and is outside an
  exact `mcp` grant.
- English and French guides clarify the service identity, recovery-material
  ownership and limitations of a personal local installation.

## 0.9.4-beta - 2026-08-30

### Added

- Native installers run the API under a dedicated `rhorizon` account while
  keeping vault secrets root-readable only. Linux, BSD and macOS install paths
  now assert the effective service identity, code readability and memory-lock
  limit after privilege drop.
- Helm application HA can use a stock nginx TLS proxy and a stable chart-made
  self-signed certificate, so the internal JOIN/mTLS path does not depend on a
  separately published web-UI image or a hand-created certificate Secret.
- Added a dedicated Kubernetes HA test lane for the complete one-Pod bootstrap,
  three-Pod JOIN, live mTLS preflight, bootstrap-Secret removal, secondary
  restart and primary failover sequence. The lane now passes on k3d/k3s and
  gates Kubernetes application HA releases.
- The maintainer release transaction now creates a real GitHub Release and
  copies the signed Gitea artifact set after the public tag is available.
  Signed API and agent images are promoted under both the release version and
  `latest`, with their OCI signatures, SBOMs and provenance referrers.

### Security

- HA nodes now default to a 30-second non-serving FROZEN grace before sealing,
  down from 300 seconds. The strict same-LAN profile accepts 20-30 seconds;
  same-region and multi-region deployments should set 45-60 seconds and
  90-120 seconds respectively. With the default 20-second authority lease, an
  isolated node now drops its keys after about 50 seconds. Peer-confirmed
  shared outages may retain keys for a bounded three times the configured
  grace, but can never restore serving authority.
- Credential proxy bindings cannot target the vault itself, closing the path
  where an agent could use a stored credential to call back into Horizon.
- BSD native services receive their memory-lock allowance before privilege
  drop. The install tests check both the effective process limit and Horizon's
  own memory-protection verdict.

### Fixed

- A Unix-socket reset after connecting to the local crypto master now enters
  the normal master-recovery path instead of escaping as an HTTP 500.
- K7 marks a node fault before stopping the remote service and rolls the marker
  back when the stop fails. An unavailable `/cluster/health` request during the
  declared fault window is recorded as availability evidence, while a returned
  non-green database state remains a hard failure.
- Native quickstart reads the token path actually written by the installer.
- Kubernetes HA keeps certificate permissions stable across PVC remounts,
  permits the configured Patroni REST probes through NetworkPolicy, and states
  that the one-time HA bootstrap password must be stored as decoded raw bytes.
- Kubernetes defers liveness checks until slow multi-worker startup completes,
  preventing kubelet from turning a valid first start or upgrade into a restart
  loop.
- Helm can disable the web UI without removing the API service, ingress and
  network-policy path needed by API-only deployments.

### Testing

- Kubernetes bootstrap no longer waits for readiness before unseal. The smoke
  test reaches sealed Pods directly, then requires readiness, and preserves
  failures from its in-cluster HTTP helper.

### Documentation

- Added FROZEN timing profiles and the exact distinction between loss of
  serving authority, key retention and hard sealing. The public roadmap now
  reflects the shipped peer-aware classifier.
- The compatibility matrix separates single-application-node Helm deployment,
  tested Kubernetes application HA, and database HA. The in-chart PostgreSQL
  remains a single database instance; production database HA uses Patroni.

## 0.9.3-beta - 2026-08-28

### Added

- `vault_call_api`: an agent can use a stored credential without being allowed
  to read it. It names the credential and a request path, the call is made
  server-side, and only the API's answer comes back. The host, the injection
  point and the credential format come from the operator's `[proxy]` binding.
  `allow_read = false` makes the same credential unreadable through
  `vault_get_secret`, on the stdio path and the hub path alike.

### Security

- The credential plaintext never enters the hub process: the `rh-mcp-gateway`
  sidecar reads it, attaches it and drops it. It checks the destination against
  `RH_MCP_EGRESS_ALLOW` independently of the hub's own policy, so a bug in the
  policy layer cannot reach a host the operator never listed.
- Proxied calls refuse redirects, withhold a reply that echoes the credential,
  cap the response size and rate-limit per credential.
- `RH_MCP_EGRESS_CAFILE` anchors an internal API served by a private CA for the
  proxy's upstream leg. It is added to the public roots, not substituted for
  them, and stays separate from `RH_VAULT_CAFILE` so the vault's CA cannot
  certify the API being called.

### Fixed

- A malformed `[proxy]` binding is caught before the credential is read. The
  inject format and type were validated at injection time, so a typo spent a
  vault read -- decrypting and auditing a credential for a call that was never
  going to happen -- and then reported itself as whatever the read returned,
  usually "secret not found". Both paths had the same ordering.
- Proxy refusals name the fix rather than the symptom: a binding that exists
  but sets `allow_proxy = false` says so instead of asking for a table that is
  already there, a method refusal lists the methods that are allowed, an
  unknown credential lists the ones that are bound, and a non-https `base_url`
  is distinguished from a missing one. A vault error now keeps the same
  `{error, message}` shape as every other refusal from the tool.

### Testing

- `make mcp-proxy-e2e` drives the credential proxy end to end against a running
  vault -- agent, hub daemon, sidecar, vault, third-party API -- and asserts the
  credential reaches the API and nothing of it reaches the caller. Point it at a
  standalone instance or a cluster; `RH_E2E_NODE_URLS` adds a per-node pass that
  proves a follower can serve the call over cluster RPC.

## 0.9.2-beta - 2026-08-25

### Security

- GF(256) multiplication now has native, architecture-specific assembly gates
  on x86_64 and AArch64. The AArch64 lane also runs the complete Rust test
  suite and all four libFuzzer targets on GitHub's native ARM runner.
- Shamir validation covers all 65,536 GF(256) products, Rust/Python parity,
  fuzzing, and compiler-output inspection. A Raspberry Pi 4 can reproduce the
  same native ARM checks with `make arm64-native-check`.

### Changed

- The GF(256) and Shamir implementation provenance now explicitly credits the
  adapted `geky/gf256` work and carries its BSD-3-Clause attribution.
- All distributed package metadata is aligned with this release: Python and
  Rust wheels, CLI, MCP server and hub, Rust agents, npm SDK, and Helm chart.

### Documentation

- The HA peer-status endpoint and the cross-architecture side-channel evidence
  are documented in the public reference and security material.

## 0.9.1-beta - 2026-08-24

### Fixed

- Home installers now explain the expected first-browser certificate warning
  before printing the URL and show the exact SHA-256 fingerprint to verify.
- Release publication uses the correct vault token for each namespace and
  checks the Cosign bundle that the pipeline actually publishes.

### Added

- TLS trust instructions for macOS, Linux, BSD, WSL, Docker and Podman, with a
  separate path for replacing the local certificate with a public ACME
  certificate.
- Maintainer release targets gate public tags on an existing signed private
  release with provenance.

### Documentation

- Public repository links, API references and image-verification claims now
  match the artifacts that are actually published.

## 0.9.0-beta - 2026-08-22

First tagged release.

### Security

- The hard fence now fires on every worker. Under a PostgreSQL blackout one
  worker in five dropped its key material and the other four sat past a
  terminal deadline with keys resident for the life of the process: the fence
  was evaluated at the end of a heartbeat tick that began with an unbounded
  database await, so a hung query meant it was never *reached*, and nothing
  raised. It now runs in its own loop reading only a monotonic clock -- no
  database, no peers -- so nothing can starve it. Measured 5 of 5 after, 1 of 5
  before.
- The heartbeat's database block is bounded by the authority TTL. A worker
  parked in that await never re-renews either, and the kernel retransmits for
  roughly fifteen minutes before erroring -- far past the fence -- so a blackout
  that had already ended still walked workers to a permanent seal.
- Agent request URLs percent-encode the secret name. A name arriving from the
  environment containing `/`, `?`, `#` or `..` silently changed which URL was
  requested. Bearer auth still enforced RBAC, so this was defence in depth
  rather than an authentication bypass. Six call sites.

### Fixes

- A sealed vault no longer keeps an authority deadline it cannot renew. The
  heartbeat returns early while sealed, so the deadline stayed frozen at its
  lapsed value; any re-attach inherited it and the fence loop re-sealed the
  worker before the heartbeat could refresh it. A node flapped between wholly
  sealed and wholly active for minutes after a fence. FROZEN is a property of
  the node, not of a worker -- all workers on a host now march together.
- `primary_since` is readable. It was written on every promote and read
  nowhere. Stamped with the PostgreSQL clock under the election lock, so it
  moves at every failover, which makes it the referent a node needs to tell a
  shared database outage from its own isolation. Published on
  `/internal/ha/status`; nothing acts on it yet.

### Documentation

- `INSTALL.md` is a complete install reference -- every path in, verification,
  upgrade, and the uninstall procedure, which was documented in no language. It
  was also unreachable from anywhere in the docs.
- Corrected claims a reader would have acted on: a quickstart that started the
  operator/VPN stack (which cannot bind on a laptop) and continued over
  plaintext HTTP; a PKI page documenting a superseded default algorithm while
  omitting the verification recipe for the new one; compose resource limits
  that disagreed with `docker-compose.yml`; a security tracker listing four
  fixed issues as open, two of them high.
- French documentation is at parity for the maintained set, plus new
  translations of the compatibility matrix, disaster recovery, the two
  supply-chain verification guides, and the BSD-native PostgreSQL HA design.

### Known limitations

- Peer-aware classification is not implemented. A node still cannot distinguish
  a shared database outage from its own isolation, and the two want opposite
  reactions. `primary_since` is the published input; the classifier is not
  written.
- `SECURITY-AUDIT`, `THREAT-MODEL` and `slsa-compliance` are English-only by
  choice: a compliance document that drifts in translation is worse than one
  that is not translated.
- macOS Intel is unmeasured -- no free x86_64 darwin runner exists to replace
  the retired image.

### Security (earlier in this cycle)

- TOTP counters are consumed atomically in PostgreSQL. A code accepted by one
  worker cannot be reused through another worker or HA node.
- New secret writes use length-prefixed AAD for the secret name and namespace.
  Existing ciphertext remains readable under the v1 encoding; logical backups
  record the AAD version and restore v1 rows as v2.
- HA rekey X25519 key generation, private-key wrapping, and sealed-box opening
  run in Rust. Plaintext rekey private keys no longer enter Python memory.
- Normal secret CRUD, version reads, rollback, and rotation now chain DEK
  unwrap/wrap with XChaCha20-Poly1305 inside Rust. Plaintext DEKs no longer
  enter Python.
- Token scope and namespace parsing now fail closed on malformed permission
  data. Expiry is enforced at the expiry instant.
- Key epochs and Shamir shares reject invalid ranges and malformed inputs
  before use.

### Operations

- `RH_WORKERS` is the canonical worker setting. `1` selects single-worker mode,
  `2` through `4` are promoted to `5`, and values above `254` are rejected.
- Cancelling an unseal request no longer releases its Argon2 memory slot while
  the derivation thread is still running.

## 2026-04-07 - first usable version (never tagged)

Recorded at the time as "1.0.0-beta". No git tag was ever cut and no artifact
was ever published under that number, so nothing shipped as 1.0.0. The version
string lived only in `settings.version` and in this file.

Renumbered rather than left standing: the first real tagged release is
0.9.0-beta above, and leaving a higher number here would have put the
changelog in contradiction with every signed artifact and with semver ordering
for anyone consuming them.

Deployed on my own stack since this date. API considered stable under
`/api/v1/vault/`.

### Vault core

- Seal/unseal with Argon2id-derived master key
- Per-secret DEK (XChaCha20-Poly1305), DEK wrap with AES-256-GCM
- Version history per secret (default 10, auto-pruned) + rollback
- Namespace isolation with per-token scope restriction
- 2FA on unseal: TOTP, YubiKey HMAC-SHA1, WebAuthn - or any combination
- Shamir split (M-of-N) of the master password
- Chained-HMAC audit log, dual-written to DB and daily JSONL files
- DB-backed rate limiting with multi-tier lockout
- Multi-worker key sync via AES-GCM-encrypted file in `/dev/shm`

### CLI

- `rhorizon` (typer): login, status, unseal, seal
- Secrets: get / set (`--file`, `--stdin`) / delete / list / rotate
- Tokens: create / list / revoke
- Namespaces, versions, import/export (dotenv + JSON)
- Installable with `pip install -e cli/`

### External auth

- LDAP / AD bind via `bonsai` (async), group -> permission mapping
- Bind password stored encrypted (DEK envelope)
- RFC 4515 escaping on all LDAP filters
- SSO proxy auth (Authelia / Authentik / Keycloak) from trusted IPs only

### Container / agent integration

- `uvicorn[standard]` replaced with `uvicorn` plus explicit `httptools` and
  `uvloop`. The extra pulled `watchfiles` (auto-reload, which must never run in
  production), `websockets` (rhorizon serves no WebSocket endpoints -- the audit
  stream is SSE) and `pyyaml` (unused, and carrying a deserialisation-CVE
  history no vault image should hold for nothing). 35 -> 32 packages.
  `httptools` and `uvloop` were load-bearing all along -- both launchers pass
  `--http httptools --loop uvloop` -- but arrived implicitly through the extra,
  so a uvicorn release reshuffling it could have broken startup with nothing in
  the manifest to explain why.
- The Rust agents no longer depend on `reqwest`. A minimal blocking HTTP/1.1
  client over the existing rustls config replaces it, cutting the shipped
  dependency closure from 138 crates to 35. The whole `hyper`/`h2`/`tokio`
  stack is gone, along with 25 crates of `icu_*`/`idna` that existed only to
  normalise internationalised domain names -- more attack surface for parsing
  hostnames the agent will never see than for its cryptography.
- TLS is unchanged: the same `rustls` `ClientConfig`, aws-lc-rs provider and
  webpki roots the agents already built by hand, now used directly instead of
  handed to reqwest. `tools/pq-verify.sh` confirms OpenSSL 3.6.3 and aws-lc-rs
  still independently negotiate X25519MLKEM768.
- HTTP/2 is dropped, including in `rh-mcp-gateway`. It had been enabled so a
  documentation claim would be true rather than because anything needed it;
  measured on a live endpoint, the agents' sequential one-shot JSON calls gain
  nothing from multiplexing, and connection count per client is identical
  under HTTP/1.1 keep-alive.
- The agent client keeps connections alive between requests (7.7 ms vs 10.0 ms
  per request measured against a live vault). Non-ASCII hostnames, userinfo in
  URLs, CRLF in header values and unbounded response bodies are refused rather
  than handled, since dropping `idna` means not pretending to punycode.
- `rustls` now declares its `std` feature explicitly. reqwest had been
  supplying it silently, so removing reqwest broke the build in a way no
  manifest showed.
- `agent/inject.py`: resolve `rh://` env vars, then `exec` (PID 1)
- `agent/fetch.py`: pull secrets to files as an init container
- Runtime image is non-root, no pip/curl/wget, tmpfs-only writes
- Agent token cleared from child env after resolution

### RBAC, notifications, backup/restore

- Group CRUD with JSONB permissions, LDAP-source groups
- Notification channels: Matrix, webhook, email - filter by event
- Webhook SSRF guard (localhost + cloud metadata blocked)
- Age-encrypted backup/restore (Argon2id + AES-256-GCM), SHA-256 verified

### Dynamic secrets

- PostgreSQL + MySQL engines with SQL role templates
- Ephemeral credentials with configurable TTL
- Lease tracking: list, revoke
- Connection URLs stored encrypted

### Frontend

- Vanilla JS SPA, no build step
- Black hole canvas animation (ported from `harlok_keygen`)
- 8 views: Horizon, Singularity, Orbits, Jets, Gravity, Accretion, Pulsar, Core

### CI/CD

- Woodpecker pipeline: ruff, bandit, pip-audit, detect-secrets, compose + file checks
- 219 tests, ~92% coverage
- Deploy pipeline with real healthcheck (`docker exec` against `/health`)

### Security notes

- Tokens are HMAC-SHA512 hashed, per-instance key - DB dump alone is useless
- `/docs` and `/redoc` are not exposed
- pip/wget/curl removed from the production image
- Read-only filesystem, uid 1500, all caps dropped
- Internal DB errors never leak to HTTP responses
- Auth errors are generic - no username enumeration
