# REST API reference

All endpoints sit under `/api/v1/vault/`. Authentication is via
`Authorization: Bearer rh_...` for token-protected routes, except
where noted (`/health`, `/status`, `/challenge`, `/unseal`, login
flows).

The interactive Swagger / ReDoc UIs and the OpenAPI schema are
**disabled by default**: `docs_url`, `redoc_url`, and `openapi_url`
are all gated by the `enable_docs` setting (`RH_ENABLE_DOCS`,
default `false`). When enabled, the schema is served unauthenticated
at `/openapi.json` (root path) - put it behind SSO or a reverse proxy
in production, and leave it off otherwise.

## Vault lifecycle

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| GET | `/health` | none | Liveness probe (returns `{"status":"ok"}` always) |
| GET | `/status` | none | Sealed state + 2FA mode + version |
| POST | `/challenge?purpose=...` | none | YubiKey/WebAuthn challenge (purposes: `unseal`, `namespace_mutation`, `delete_protected_secret`) |
| POST | `/unseal` | password + 2FA, or Shamir quorum | Unseal; use atomic `{"shares":[...]}` behind multi-worker listeners (`share` is the five-minute compatibility accumulator) |
| POST | `/seal` | admin:w | Seal - zero keys in RAM |
| POST | `/rotate-password` | admin:w | Rotate master password (lazy or emergency) |
| POST | `/admin/rotate-dek-key` | admin:w | Operator-initiated, scriptable DEK-key rotation; master-password re-authentication required |
| POST | `/shamir/init` | admin:w | Initialise Shamir M-of-N |
| DELETE | `/shamir` | admin:w | Tear down Shamir, revert to password-only |
| GET | `/cluster` | admin:r | topology |

## Secrets

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| POST | `/secrets/` | secrets:w | Create |
| GET | `/secrets/` | secrets:r | List |
| GET | `/secrets/{name}` | secrets:r | Read decrypted |
| PUT | `/secrets/{name}` | secrets:w | Update value (new DEK) |
| DELETE | `/secrets/{name}` | secrets:w | Delete (mode depends on namespace `delete_protection`) |
| POST | `/secrets/{name}/restore` | secrets:w | Un-delete (soft / protected modes only) |
| GET | `/secrets/{name}/versions` | secrets:r | List version history |
| GET | `/secrets/{name}/versions/{n}` | secrets:r | Read a specific version |
| POST | `/secrets/{name}/rollback/{n}` | secrets:w | Restore an old version |
| POST | `/secrets/{name}/rotate` | secrets:w | Operator-initiated, scriptable per-secret DEK rotation |
| GET | `/secrets/namespaces` | secrets:r | List distinct namespaces with counts |

## Tokens

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| POST | `/tokens/` | tokens:w | Create long-lived |
| GET | `/tokens/` | tokens:r | List (with `is_ephemeral` flag) |
| GET | `/tokens/whoami` | token | Introspection |
| POST | `/tokens/{id}/revoke` | tokens:w | Revoke |
| POST | `/tokens/{id}/rotate` | tokens:w (+ POLA on target perms) | Re-mint the secret in place (same id/name/scopes), shown once |
| POST | `/tokens/{id}/renew` | tokens:w | Extend expiry |
| DELETE | `/tokens/{id}` | tokens:w | Delete |
| POST | `/tokens/ephemeral` | tokens:w | Mint short-TTL token (with optional `inherit_group_membership`) |

## Namespaces (RBAC)

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| POST | `/namespaces/` | admin:w + 2FA | Create with chosen flags |
| GET | `/namespaces/` | token | List visible |
| GET | `/namespaces/{name}` | token (claim or membership) | One + secret count |
| PUT | `/namespaces/{name}` | admin:w + 2FA | Change owner / upgrade `enforce_membership` / upgrade `delete_protection` |
| DELETE | `/namespaces/{name}` | admin:w + 2FA | Soft archive (refused if non-empty) |

## Audit

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| GET | `/audit/` | audit:r | List entries from the chained log (mutations) |
| GET | `/audit/lite` | audit:r | List entries from the checkpointed read log (`vault_audit_lite`) - bulk read traffic |
| GET | `/audit/stream` | audit:r | SSE live tail of the chained log |
| GET | `/audit/verify` | audit:r | Verify the full chain synchronously (compatibility path) |
| GET | `/audit/verify/incremental` | audit:r | Verify evidence added after the newest signed full-verification anchor |
| POST | `/audit/verify/preflight` | audit:r | Check the incremental state; queue a full job when its anchor is missing or stale |
| POST | `/audit/verify/jobs` | audit:r | Queue or join the cluster-wide full-verification job |
| GET | `/audit/verify/jobs/{job_id}` | audit:r | Poll durable job status and result |
| POST | `/audit/verify/legacy-adopt` | admin:w | Explicitly adopt the exact unsigned legacy checkpoint rows committed by a signed full-job candidate |
| POST | `/audit/export` | audit:r | Download one signed `.tar.gz` evidence bundle for an optional `since`/`until` range |
| GET | `/audit/files` | audit:r | List daily JSONL files |
| GET | `/audit/files/{date}` | audit:r | Read one day |
| DELETE | `/audit/files/{date}` | admin:w | Delete (only beyond retention) |
| POST | `/audit/rotate-all` | admin:w | Bulk gzip files older than threshold |

The chained log (`/audit/`) is Ed25519-signed by default, with an HMAC fallback,
and every row signs the previous row. It records mutations (write, delete,
seal, unseal, token mint, ...). High-volume reads go to the unchained
`vault_audit_lite` table so the request path stays cheap. Signed Merkle
checkpoints protect completed read windows; `/audit/verify` reports the newest
uncheckpointed tail separately. Both logs share the same listing fields. Use
the durable job endpoints for retained production evidence:
only one pending/running verifier is allowed cluster-wide, and a different
unsealed worker reclaims the job if its owner stops heartbeating.

Checkpointed audit-lite prefixes older than `RH_AUDIT_DB_RETENTION_DAYS` are
exported as canonical gzip JSONL beside the main audit archives, sealed through
the signed main chain, and then removed from PostgreSQL. Full verification
checks their content digest, Merkle root, seal lineage, and linked prune anchor.

A clean full run writes an independently Ed25519-signed anchor containing the
main, read-log and archive high-water marks. Incremental verification checks
that signature, the mutation suffix, new Merkle windows, the current tail and
archive seals. It reports `verification_scope: incremental` because historical
rows are trusted from the anchor rather than read again. Preflight first closes
the current read-log tail; if a fresh anchor is unavailable it returns the
durable full-job id instead of holding the HTTP request open for an O(N) scan.

`POST /audit/export` accepts optional ISO-8601 `since` (inclusive) and `until`
(exclusive) fields. Its only output format is a portable `.tar.gz`. The bundle
contains live mutation and read rows, overlapping sealed archives, signer
public keys, verification anchors, both archive-seal lineages, and an
Ed25519-signed manifest committing every member's byte length and SHA-256
digest. Export generation uses a repeatable database snapshot and the retention
lock, so pruning cannot move a row between the database and an archive midway
through the export. Ordinary writes remain concurrent. The completed export is
itself recorded as `audit_evidence_export` in the mutation chain.

The endpoint first runs the bounded preflight. It refuses to sign an export if
the evidence is not intact. When the full anchor is missing or stale, the `409`
message includes the durable full-verification job that was queued; retry after
that job succeeds. Only one export runs cluster-wide at a time.

## 2FA

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| PUT | `/2fa?mode=...` | admin | Set mode (`none`, `totp`, `yubikey`, `any`) |
| POST | `/yubikey` | admin | Register a YubiKey HMAC secret |
| GET | `/yubikey` | admin | List |
| DELETE | `/yubikey/{serial}` | admin | Remove (auto-fallback if last) |
| POST | `/totp/setup` | admin | Generate secret + URI |
| POST | `/totp/enable` | admin | Activate (after code verification) |
| DELETE | `/totp` | admin | Disable (auto-fallback) |

## WebAuthn / FIDO2

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| POST | `/webauthn/register/begin` | admin | Get credential creation options |
| POST | `/webauthn/register/complete` | admin | Save the credential |
| POST | `/webauthn/auth/begin` | none | Get authentication options |
| GET | `/webauthn/` | admin | List registered credentials |
| DELETE | `/webauthn/{id}` | admin | Remove |

## External auth (LDAP + SSO proxy)

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| POST | `/auth/ldap` | LDAP bind | Login -> session token |
| POST | `/auth/ldap/config` | admin | Configure LDAP (encrypted bind password) |
| GET | `/auth/ldap/config` | admin | Read config (password masked) |
| PUT | `/auth/ldap/mappings` | admin | Map groups -> permissions |
| GET | `/auth/ldap/mappings` | admin | Read mappings |
| POST | `/auth/proxy` | trusted IP | SSO proxy login |
| GET | `/auth/proxy/config` | admin | Read config |

## Groups RBAC

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| POST | `/groups/` | admin:w | Create local or LDAP-mapped |
| GET | `/groups/` | admin:r | List |
| PUT | `/groups/{id}` | admin:w | Update name / permissions / mapping |
| DELETE | `/groups/{id}` | admin:w | Delete (refused if owns namespaces) |
| GET | `/groups/{id}/members` | admin:r | List members |
| POST | `/groups/{id}/members` | admin:w | Add typed principal: `external` + `ldap:subject`/`proxy:subject`, or `token` + token UUID |
| DELETE | `/groups/{id}/members/{member_id}` | admin:w | Remove the typed membership by UUID returned by list/add |

## Notification channels

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| POST | `/channels/` | admin:w | Create (Matrix, webhook, email) |
| GET | `/channels/` | admin:r | List |
| PUT | `/channels/{id}` | admin:w | Update |
| DELETE | `/channels/{id}` | admin:w | Remove |
| POST | `/channels/{id}/test` | admin:w | Emit a test message |

## Backup / restore

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| POST | `/backup/create` | admin:w | Create age-encrypted logical backup |
| POST | `/backup/restore` | admin:w | Restore from age archive |

## Oneshot

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| POST | `/oneshot` | password + 2FA + secret name | Unseal -> read 1 -> re-seal |

## Dynamic secrets

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| POST | `/dynamic/engines` | admin:w | Create an enabled PostgreSQL, MySQL/MariaDB, LDAP, Redis, or Cassandra engine |
| GET | `/dynamic/engines` | admin:r | List engines |
| GET | `/dynamic/engines/compatibility` | admin:r | List drivers and validated engine targets |
| POST | `/dynamic/engines/test-connection` | admin:w | Read-only bind/version probe; unknown versions are reported, not blocked |
| PUT | `/dynamic/modules/{engine_type}` | admin:w | Schedule fine-grained cluster module enable/disable; all API nodes must restart |
| DELETE | `/dynamic/engines/{id}` | admin:w | Delete engine |
| POST | `/dynamic/engines/{id}/roles` | admin:w | Define backend creation/revocation templates and TTL |
| GET | `/dynamic/engines/{id}/roles` | admin:r | List roles |
| POST | `/dynamic/engines/{id}/creds/{role_name}` | secrets:w | Issue credentials |
| GET | `/dynamic/leases` | admin:r | Active leases |
| POST | `/dynamic/leases/{id}/revoke` | admin:w | Manual revoke |

## Observability - Prometheus metrics

`GET /metrics` (Prometheus exposition format, on the API port).
Access is **IP-allow-listed** - the endpoint reads the direct peer IP
(NOT `X-Forwarded-For`) and matches it against
`metrics_allowed_cidrs`. An empty allow-list refuses everyone.
Disabled entirely if `metrics_enabled = false`. Routinely
disabled in schema (`include_in_schema=False`) so it does not appear
in the OpenAPI export.

### Live snapshot for the UI - `GET /api/v1/vault/observability`

Token-authed (scope `audit:r`) JSON view over the same registry, for the in-app
**Nova** dashboard (the browser cannot use the IP-allow-listed `/metrics`).
Returns `reads_total`, `writes_total`, `http_total`, `http_https`,
`auth_failures_total`, `active_tokens`, `active_connections`, `decrypt_p95_ms`,
`sealed`. Route-layer only: reads already-computed metric values, never touches
keys or crypto. Counters are monotonic totals; the client diffs successive polls
into per-second rates.

Series by category:

### Lifecycle

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `rhorizon_unseal_attempts_total` | counter | `result` (success/failure) | Unseal attempts |
| `rhorizon_seal_events_total` | counter | - | Seal calls |
| `rhorizon_unseal_duration_seconds` | histogram | - | Wall-clock time of an unseal |
| `rhorizon_vault_sealed` | gauge | - | 1 = sealed, 0 = unsealed |

### Secrets and tokens

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `rhorizon_secrets_read_total` | counter | - | Successful secret reads |
| `rhorizon_secrets_write_total` | counter | `op` (create/update/delete/rotate) | Mutations |
| `rhorizon_secret_decrypt_duration_seconds` | histogram | - | Per-secret AES-GCM unwrap |
| `rhorizon_tokens_created_total` | counter | `kind` (long_lived/ephemeral) | Token mints |
| `rhorizon_tokens_revoked_total` | counter | - | Revocations |
| `rhorizon_active_tokens` | gauge | - | Currently active token count |
| `rhorizon_locked_ips` | gauge | - | IPs currently rate-limit-locked |

### Auth and security observability

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `rhorizon_auth_failures_total` | counter | `reason` (invalid_token/missing/scope/namespace/ip_not_allowed/revoked) | Auth rejections - drives the `AuthFailureSpike` alert |
| `rhorizon_audit_events_total` | counter | `category`, `result` | Audit log entries written, bucketed by category |
| `rhorizon_audit_verify_duration_seconds` | histogram | - | `/audit/verify` chain walk time - feeds `AuditVerifySlow` |
| `rhorizon_audit_chain_breaks_total` | counter | - | Chain integrity violations detected (page immediately) |
| `rhorizon_audit_chain_length` | gauge | - | Rows in `vault_audit` (mutations log) |
| `rhorizon_audit_lite_length` | gauge | - | Rows in `vault_audit_lite` (read log) |
| `rhorizon_honey_access_total` | counter | `kind` (secret/token) | Honeytoken trips - **any non-zero rate is an alert** |
| `rhorizon_sealed_op_attempts_total` | counter | `op` (read/write/other) | Requests rejected because the vault is sealed |
| `rhorizon_http_requests_total` | counter | `transport` (http/https from `X-Forwarded-Proto`) | Admitted request volume - direct API vs via the nginx TLS frontend |
| `rhorizon_requests_inflight` | gauge | - | Requests currently admitted |
| `rhorizon_requests_shed_total` | counter | `reason` (`request_concurrency_limit`/`unseal_concurrency_limit`) | Requests rejected with 429, by admission path |
| `rhorizon_master_password_rotated_total` | counter | `mode` (admin_ops/sec_ops) | Master password rotations |
| `rhorizon_reaper_failures_total` | counter | - | Failed background cleanup cycles; each failure is retried after five minutes |

### DEK lifecycle

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `rhorizon_dek_key_stale` | gauge | - | 1 = the dek_key exceeds its SLO or its rotation timestamp cannot be trusted |
| `rhorizon_dek_key_age_seconds` | gauge | - | Age of the current dek_key; `-1` means its rotation timestamp is missing or invalid |

### Cluster

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `rhorizon_master_rpc_inflight` | gauge | - | RPC calls currently in flight on the master |
| `rhorizon_master_rpc_duration_seconds` | histogram | `op` | RPC dispatch time (master-side) |
| `rhorizon_master_rpc_errors_total` | counter | `op` | RPC errors (non-vault failures) |
| `rhorizon_cluster_failover_total` | counter | `result` (success/quorum_missing/failure) | Master failover events |

> See [`howto/observability-alerts.md`](../howto/observability-alerts.md)
> for the recommended Prometheus alerting rules ranked by severity
> (critical / serious / capacity) and Matrix routing per channel.

## Rate limiting

The vault enforces a global rate limit per source IP on auth-failures
(via `vault_rate_limits` table). Limits:

- 10 failures / 60s -> 60s lockout
- 50 failures / 5min -> 1h lockout
- 100 failures / 1h -> 24h lockout

Plus per-actor rate-limit on namespace mutations
(`namespace_mutation_rate_per_hour`, default 10).

## Error format

FastAPI's standard:

```json
{"detail": "Missing scope: secrets"}
```

Status codes follow REST conventions:

- **401** - invalid / missing token
- **403** - token valid but lacks the required scope or namespace
- **404** - resource not found (or hidden via deletion)
- **409** - duplicate name / archived target
- **423** - set-once flag rejected (one-way ratchet violated)
- **429** - rate limited
- **503** - vault is sealed
