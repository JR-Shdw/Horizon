# Changelog

Format loosely follows [Keep a Changelog](https://keepachangelog.com/).
Dates are calendar dates, not release dates - there's no fixed release
cadence; things ship when they're ready.

## Unreleased

### Security

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

## 1.0.0-beta - 2026-04-07

First usable version. Deployed on my own stack since then. API is
considered stable under `/api/v1/vault/`.

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
