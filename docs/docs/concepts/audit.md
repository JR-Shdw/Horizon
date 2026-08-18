# Audit chain

Every state-changing operation emits a **chained** audit entry, written to
**both** PostgreSQL (`vault_audit`) and a daily JSONL file
(`/var/log/rhorizon/audit-YYYY-MM-DD.jsonl`).

Reads are different, and deliberately so. `read_secret` and friends go to
`vault_audit_lite` - same columns, queryable through the same `/audit`
endpoints, but **not** part of the signed chain:

| | `vault_audit` (chained) | `vault_audit_lite` |
|---|---|---|
| What lands here | state mutations: create/update/delete, seal/unseal, token and namespace ops | reads: `read_secret`, `read_secret_version`, MCP tool calls |
| Per-row signature | yes, chained | no |
| Tamper-evident | yes, per row | **yes, per checkpoint** (see below) |
| Cluster advisory lock | yes, serialised | no, inserts run in parallel |
| `prev_signature` round-trip + master RPC sign | yes | no |
| Daily JSONL mirror | yes | no, PostgreSQL only |
| Endpoint | `GET /audit/` | `GET /audit/lite` |

The reasoning: reads are the hot path, and threading every one of them through
a cluster-wide lock plus a master RPC signing call would serialise the vault.

### Merkle checkpoints - reads are tamper-evident too

Skipping per-row signatures does **not** mean reads are unverifiable.
`api/app/audit_mtree.py` periodically hashes an ordered window of lite rows
into a Merkle root and writes **one signed `vault_audit` entry** for it
(`action=audit_lite_checkpoint`). Tampering with any read row changes the
recomputed root and no longer matches the signed checkpoint.

Each Merkle leaf covers the complete canonical read record: `id`, `timestamp`,
`actor`, `action`, `target`, `detail`, and `ip_address`. Changing any one of
those stored values, deleting a checkpointed row, or inserting a row into an
already checkpointed range is detected. Integrity proves that recorded
evidence has not changed; it does not independently prove that an asserted
identity or client address was truthful at ingestion. Client IP attribution
therefore depends on a correct
[trusted-proxy configuration](../reference/env-vars.md).

| Setting | Default | Meaning |
|---|---|---|
| `RH_AUDIT_LITE_CHECKPOINT_ENABLED` | `true` | Checkpoint loop on |
| `RH_AUDIT_LITE_CHECKPOINT_INTERVAL_SECS` | `60` | How often a window is sealed |
| `RH_AUDIT_LITE_CHECKPOINT_MAX_ROWS` | `10000` | Max rows folded into one checkpoint |

`GET /audit/verify` verifies the checkpoints alongside the chain and returns
`audit_lite_intact` plus `audit_lite_uncheckpointed_rows`. A broken checkpoint
increments a metric and dispatches a `[critical]` event naming the offending
checkpoint id and reason.

So the residual is **latency, not absence**: rows written since the last
checkpoint (under a minute by default) are not yet anchored, and
`audit_lite_uncheckpointed_rows` is exactly that backlog. Everything already
checkpointed is as tamper-evident as the mutation chain, because its evidence
*is* an entry in that chain.

Each entry signs the previous - modifying or deleting any single row breaks
the chain for everything that follows. Entries are signed with **Ed25519 by
default**; HMAC-SHA512 is the fallback and is what pre-Ed25519 rows carry.
Each row records which was used, so verification dispatches per entry.

## Schema

```sql
CREATE TABLE vault_audit (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    timestamp   TIMESTAMPTZ DEFAULT NOW(),
    actor       TEXT NOT NULL,           -- token name, username, or service identity
    action      TEXT NOT NULL,           -- e.g. create_secret, unseal
    target      TEXT,                    -- secret/token name, etc.
    detail      JSONB,                   -- per-action context
    ip_address  INET,
    signature   BYTEA,                   -- signature over the chain
    prev_signature BYTEA,                -- previous entry's signature
    sig_alg     TEXT NOT NULL DEFAULT 'hmac',  -- 'ed25519' | 'hmac'
    signer_fpr  TEXT                     -- which signing identity produced it
);
```

## Chain construction

Both algorithms cover the same versioned payload and previous signature, so
the linkage property is identical; only the signing primitive differs. Current
v2 rows cover `id`, `timestamp`, `actor`, `action`, `target`, `detail`,
`ip_address`, `key_epoch`, `sig_alg`, and `signer_fpr`. Historical v1 rows keep
their original actor/action/target/detail payload for backward verification.

```
payload_n  = canonical_json(all signed v2 row fields)
preimage_n = sig_{n-1} || payload_n

sig_n = Ed25519(audit_seed, preimage_n)        # default
sig_n = HMAC-SHA512(audit_key, preimage_n)     # fallback / legacy rows
```

`sig_0` (first entry ever) hashes an empty `prev_signature`.

**Which one is my chain actually using?** Don't infer it - every row records
its own `sig_alg`, and a vault that predates the Ed25519 migration keeps HMAC
rows until it re-unseals (`ensure_audit_identity()` mints an identity when
absent). A mixed chain is normal and verifies fine, because `/audit/verify`
dispatches per entry. To see the real distribution, including for the
read-log checkpoints:

```sql
-- overall mix
SELECT sig_alg, count(*) FROM vault_audit GROUP BY sig_alg;

-- just the read-log checkpoints
SELECT sig_alg, count(*) FROM vault_audit
WHERE action = 'audit_lite_checkpoint' GROUP BY sig_alg;
```

A steady trickle of `hmac` rows on a vault that *has* an identity is worth
investigating - the fallback fires when signing fails mid-failover, and the
`hmac_fallback` metric exists to make that visible rather than silent.

**Why Ed25519 is the default.** A public-key signature makes the chain
externally verifiable - an auditor can check it without ever holding a key
that could forge it. It also removes a cluster failure mode: the whole cluster
writes `ed25519` once an audit identity exists, because a follower falling
back to `hmac` would reintroduce per-epoch cross-host fragility.

The 32-byte Ed25519 seed lives in `vault_config`, wrapped under `dek_key`, and
is held only in a Rust `AuditSigner` (mlock'd, zeroize-on-drop); followers
delegate signing to the master over RPC. The `audit_key` used by the HMAC
fallback is one of the five HKDF-derived sub-keys and lives in the master
process's mlock'd RAM. See [cryptography](crypto.md).

## Tamper evidence

For small chains, the synchronous compatibility endpoint returns the full
result directly:

```bash
curl -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:8200/api/v1/vault/audit/verify

# {
#   "chain_intact": true,
#   "evidence_intact": true,
#   "total_entries": 12847
# }
```

For retained production evidence, queue the same authoritative verification
as a durable background job and poll it. This avoids coupling the O(N) scan to
an HTTP or reverse-proxy timeout; it does not sample or skip signatures.

```bash
JOB_ID=$(curl -fsS -X POST -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:8200/api/v1/vault/audit/verify/jobs | jq -r .job_id)

curl -fsS -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:8200/api/v1/vault/audit/verify/jobs/$JOB_ID" | jq .
```

The persisted status is `pending`, `running`, `succeeded`, or `failed`; a
successful response carries the unchanged full verifier output in `result`.
There is at most one active job across the API cluster. The owner heartbeats
while verifying, and another unsealed worker can reclaim a stale job after a
process or node failure.

A successful stable full run also creates a signed verification anchor. Routine
checks can then verify only what was appended after that point:

```bash
curl -fsS -X POST -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:8200/api/v1/vault/audit/verify/preflight | jq .
```

`preflight_ready: true` means the anchor is valid and fresh, the mutation
suffix and new read-log checkpoints verify, the read-log tail is empty, and
archive seals are intact. If a deep scan is required, the response contains
`full_verification_job.job_id`; the request itself does not wait for that scan.
The result is labelled `incremental`: it authenticates the historical prefix
through the signed anchor but does not claim to have read those old rows again.

### Audit-lite retention

When the main-chain retention job reaches a fully checkpointed audit-lite
prefix, it exports those read rows as canonical gzip JSONL in the audit
directory. Before deleting anything, Rhorizon reopens the file and verifies
its row count, SHA-256 content digest, and Merkle root. A seal containing the
exact bounds and the previous archive digest is written through the signed
main audit chain and retained in a compact seal table. The new signed prune
anchor then links the archived prefix to the next live checkpoint, and the
database rows are deleted in the same transaction.

A failed write, cross-check, signature, chain check, or archive verification
leaves the database rows in place. Full verification re-hashes the archived
files and verifies the live checkpoint suffix. Incremental verification trusts
the archived prefix only through a fresh signed full-verification anchor; a
new prune forces another full verification.

Old installations can contain an `audit_lite_checkpoint` written while the
vault was sealed. Such a row is marked `unsigned`; verification reports
`unsigned_main_chain_entries` and does not create a trusted anchor. After a
stable full job, the server emits a signed `legacy_adoption_candidate` that
commits every stored field of the exact unsigned rows. An administrator may
adopt that one historical baseline explicitly:

```bash
curl -fsS -X POST -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{\"job_id\":\"$JOB_ID\",\"unsigned_row_ids\":[\"$ROW_ID\"],\
       \"confirmation\":\"ADOPT LEGACY AUDIT BASELINE\"}" \
  http://127.0.0.1:8200/api/v1/vault/audit/verify/legacy-adopt | jq .
```

The job requester must perform the adoption with `admin:w`. The signed
candidate, row IDs, evidence high-water marks, and current row commitments
must all match. New unsigned rows are never covered automatically. Incremental
verification rechecks the adopted historical rows and fails if one is edited,
deleted, or added.

### Portable evidence export

Jets and the CLI expose one evidence format: a signed `.tar.gz` bundle.

```bash
rhorizon audit export evidence.tar.gz \
  --since 2026-08-01T00:00:00Z \
  --until 2026-08-18T00:00:00Z

rhorizon audit verify-export evidence.tar.gz \
  --trusted-signer "$PINNED_AUDIT_SIGNER_FINGERPRINT"
```

The bundle contains canonical live mutation and read JSONL, any sealed archive
that overlaps the requested range, public signer metadata, verification
anchors, and both archive-seal lineages. Its Ed25519-signed manifest commits
the exact path, size, and SHA-256 digest of every member. `verify-export` reads
the archive without extracting it, rejects unsafe or unlisted members, checks
all member digests, checks the public-key fingerprint, and verifies the
manifest signature.

The public key shipped inside a bundle proves self-consistency, not who owns
that key. For external evidence, record the audit signer fingerprint through a
separate trusted channel and pass it with `--trusted-signer`. Without that pin,
the verifier succeeds but prints a trust-on-first-use warning.

If any row was modified or deleted, `chain_intact: false` and `broken_at`
points to the first row whose signature doesn't match. The Jets view
in the UI runs this every refresh and shows a red banner if the
chain is broken.

## Multi-worker safety

Multiple workers writing concurrently could fork the chain (two
workers read the same `prev_signature`, both insert with that prev,
chain branches). Every write is wrapped in a Postgres advisory
xact lock :

```python
await db.execute(
    text("SELECT pg_advisory_xact_lock(hashtext('rhorizon:cluster:audit_chain'))")
)
# Now serialised cluster-wide for this transaction.
```

The lock is xact-scoped - released on commit/rollback/crash. Audit
writes are rare (token / secret / unseal), so contention is
negligible.

## File mirror

In addition to PG, every **chained** entry is appended to
`/var/log/rhorizon/audit-YYYY-MM-DD.jsonl`. One file per day. Lite (read)
entries are not mirrored - that file IO would reintroduce the serialisation
point the lite path exists to avoid.

- **Compression** : files older than `RH_AUDIT_COMPRESS_DAYS`
  (default 1, clamped to `[1, retention_days]`) are gzip'd by the
  reaper. The API decompresses
  transparently when reading.
- **Retention** : files older than `RH_AUDIT_RETENTION_DAYS`
  (default 365 ; range 365-3650) can be deleted by an admin via
  `DELETE /audit/files/{date}`. Files within the retention window
  are immutable from the API's perspective.

Database pruning is stricter than file retention. Before deleting a timestamp
prefix, the reaper requires contiguous verified archive seals, requires their
entry counts to cover exactly every database row selected for deletion, and
streams that complete prefix through the mutation-chain signature verifier.
An unsigned row, a signature mismatch, a missing/unsealed day, or a boundary
signature mismatch refuses the prune and leaves the database rows in place.
This O(N) work runs only in the background retention path; routine preflight
uses the signed incremental verification anchor.

The dual-write protects against either side being compromised
independently. If PG is wiped, the file mirror lets you reconstruct
recent activity. If the file mirror is tampered with, the PG chain
detects it.

## What gets audited

Categories :

| Category | Example actions |
|----------|-----------------|
| Vault lifecycle | `unseal`, `seal`, `unseal_failed`, `password_rotated` |
| Secrets (chained) | `create_secret`, `update_secret`, `delete_secret`, `soft_delete_secret`, `restore_secret` |
| Secrets (lite, unchained) | `read_secret`, `read_secret_previous`, `read_secret_version` |
| Tokens | `create_token`, `revoke_token`, `create_ephemeral_token` |
| RBAC | `create_namespace`, `update_namespace`, `archive_namespace`, `admin_bypass_namespace_rbac` |
| 2FA | `enable_totp`, `register_yubikey`, `register_webauthn` |
| Auth | `proxy_login`, `ldap_login`, `auth_failure` (with `reason`) |
| Honey | `honey_access` (decoy token / secret access) |
| Backup | `backup_export`, `backup_restore` |

Honey access fires a CRITICAL log + Matrix `#SECURITY` alert in
addition to the audit row.

## Live tail

The Jets view subscribes to `/audit/stream` (Server-Sent Events) for
real-time tail. Auto-refresh tickrate is configurable (default 1 s,
toggle via the "Live" button).
