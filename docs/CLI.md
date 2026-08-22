# CLI

The `rhorizon` command is the canonical way to drive the vault from an
operator terminal or a script. It wraps the same HTTP API that powers the
web UI, with output forms tuned for both interactive use and shell
pipelines.

For the underlying API and the auth model, see
[`SECRETS-AND-TOKENS.md`](SECRETS-AND-TOKENS.md). For deployment
context, see [`DEPLOYMENT.md`](DEPLOYMENT.md).

---

## 1. Install

The CLI lives in `cli/` of the rhorizon repo and is a regular Python
package.

```bash
cd ~/dev/tools/rhorizon/cli
python -m venv .venv
source .venv/bin/activate
pip install -e .

rhorizon --help     # ensure it's on PATH
```

Dependencies are minimal: `typer` (commands), `httpx` (HTTP client),
`tomlkit` (config reader). Python 3.12+.

---

## 2. Configure

```bash
rhorizon login http://10.0.0.20:8200
# Connected to rhorizon 0.9.0-beta (sealed=False)
# Token (rh_...): ********
# Token saved.
```

This writes:

| File | Mode | Contents |
|---|---|---|
| `~/.config/rhorizon/config.toml` | 0600 | Active profile, vault URL |
| `~/.config/rhorizon/token.<profile>` | 0600 | The token, plain text (default profile -> `token.default`) |

Subsequent `rhorizon` calls read both. To switch vaults, re-run
`rhorizon login <other-url>`. To clear, remove the files.

Environment overrides (useful for CI / scripts):

| Var | Effect |
|---|---|
| `RH_ADDR` (or `RH_URL`) | Vault URL (overrides the config file) |
| `RH_TOKEN` | Token (overrides the token file) |
| `RH_TOKEN_STDIN=1` | Read the token from one line of stdin (never touches disk) |
| `RH_CONFIG_DIR` | Config dir (default `~/.config/rhorizon`) |
| `RH_CA_FILE` | PEM to verify the vault's TLS certificate against. Needed when the vault uses a self-signed or private-CA cert, which is not in the system trust store. `RH_VAULT_CAFILE` (the agent sidecar's name) is accepted too, so one export covers both. There is deliberately no flag to skip verification. |

---

## 3. Vault commands

### `rhorizon status` - vault state

```bash
rhorizon status
# Status:   UNSEALED
# Version:  0.9.0-beta
# Uptime:   10h27m
# 2FA:      none

rhorizon status --json    # machine-readable
```

No authentication required.

### `rhorizon whoami` - token introspection

```bash
rhorizon whoami
# Token:        ansible-prod
# ID:           a1b2c3d4-...
# Scopes:       secrets:r
# Namespaces:   prod, staging
# Active:       true
# Ephemeral:    false
# Created at:   2026-04-15T10:23:00Z
# Last used:    2026-04-29T07:45:00Z
# Expires at:   (no expiry)

rhorizon whoami --json
```

Useful for an agent or script that wants to check what it can do
before attempting an operation. Any valid token can call this.

### `rhorizon unseal` - bring the vault online

```bash
rhorizon unseal
# Master password: ********
# (TOTP code if 2FA is enabled)
# Status: unsealed
```

Prompts interactively. For non-interactive use, hit the API directly
or use `oneshot` (see section 10).

### `rhorizon seal` - take the vault offline

```bash
rhorizon seal
# Status: sealed
```

Requires a token with `admin:rw`. Forces zeroing of all sub-keys in
RAM. The vault must be re-unsealed manually (or via Shamir quorum)
afterward.

---

## 4. Secrets

### `rhorizon set` - create or update

```bash
# Interactive value without shell history or process arguments
read -rsp 'Secret value: ' RH_SECRET; echo
printf '%s' "$RH_SECRET" | rhorizon set prod/db-password --stdin
unset RH_SECRET

# From a file
rhorizon set prod/tls-cert --file ./fullchain.pem

# From stdin (pipeline-friendly)
openssl rand -hex 32 | rhorizon set ci/build-token --stdin

# Update an existing secret (creates a new version)
read -rsp 'New secret value: ' RH_SECRET; echo
printf '%s' "$RH_SECRET" | rhorizon set prod/db-password --stdin --update
unset RH_SECRET

# Custom namespace, reading from a protected file
rhorizon set my-key --file ./value.txt --namespace mcp/demo
# rhorizon set -n mcp/demo my-key --file ./value.txt  (short form)
```

Avoid the positional `VALUE` form for real secrets: command arguments may be
captured by shell history, process inspection, or job logs. Prefer `--stdin`
or `--file`.

### `rhorizon get` - read a secret

```bash
rhorizon get prod/db-password
# s3cure-p4ssw0rd

rhorizon get prod/db-password --json
# {"name": "prod/db-password", "value": "...", "version": 3, ...}
```

The plain output is **just the value** - designed for `$(rhorizon get
foo)` and `--password "$(rhorizon get foo)"` patterns. Use `--json`
when you want metadata.

### `rhorizon list` - names only

```bash
rhorizon list
#   prod/db-password         v3  [prod]
#   prod/redis-password      v1  [prod]
#   default/test             v1
# 3 secret(s)

rhorizon list --namespace mcp/demo
```

Values are never returned by `list` - only names, versions, and
namespaces.

### `rhorizon delete` - drop a secret

```bash
rhorizon delete prod/old-key
# Deleted: prod/old-key
```

Drops every version of the secret. The audit chain still references
it; the value is unrecoverable.

### `rhorizon rotate` - re-encrypt with a new DEK

```bash
# Single secret
rhorizon rotate prod/db-password

# All secrets
rhorizon rotate --all
# Rotated 47 secret(s)
```

Internal rotation: the secret value is unchanged, only the DEK that
encrypts it is replaced. Transparent to consumers.

This is an explicit operator action; no background task rewrites secrets on a
timer. Rhorizon separately monitors the age of the hierarchical `dek_key` and
alerts when an authorized `/admin/rotate-dek-key` operation is due.
Explicit operations remain scriptable. Put readiness checks, a verified
encrypted backup, the rotation call, and post-rotation checks in the same
operator-controlled maintenance workflow; do not place the master password in
arguments or logs.

### `rhorizon versions` - list past versions

```bash
rhorizon versions prod/db-password
#   v3  2026-04-29T07:45:00Z  by alice
#   v2  2026-03-12T12:01:00Z  by bob
#   v1  2026-02-01T09:30:00Z  by alice
```

History is retained up to `RH_SECRET_MAX_VERSIONS` (default 10).

### `rhorizon rollback` - restore a past version

```bash
rhorizon rollback prod/db-password 2
# Restored v2 -> v4
```

Creates a new version with the value from the chosen past version.
Doesn't delete the intervening versions - you can roll forward again
with another `rollback` if needed.

### `rhorizon generate` - random key generator

```bash
# 32-character key, all charsets (default)
rhorizon generate 32

# 64 chars, alphanumeric only (no special chars)
rhorizon generate 64 --no-special

# 10 keys of 16 chars each
rhorizon generate 16 -c 10

# Generate and store directly
rhorizon generate 48 --store prod/api-key --namespace prod
```

Charsets:

| Flag | What |
|---|---|
| `-a / --no-alpha` | A-Z a-z |
| `-n / --no-numeric` | 0-9 |
| `-s / --no-special` | ASCII punctuation (33-47, 58-64, 91-96, 123-126) |
| `-c / --count` | Number of keys to generate |
| `--store NAME` | Generate, then store the last one as `NAME` |
| `--namespace NS` | Namespace for `--store` |

Uses `secrets.choice` (CSPRNG) - safe for production credentials.

---

## 5. Tokens

### `rhorizon token create` - long-lived token

```bash
# Recommended: --scope and --namespace flags
rhorizon token create my-bot --scope secrets:r --namespace mcp/mail

# Multiple scopes, multiple namespaces (repeatable)
rhorizon token create deploy \
    --scope secrets:rw \
    --scope tokens:r \
    --namespace prod \
    --namespace staging

# Token: rh_xxxxxxxxxxxx
# Name:  deploy
# Perms: {"secrets":"rw","tokens":"r","namespaces":["prod","staging"]}
# (shown once - save it now)

# JSON fallback for unusual permissions
rhorizon token create admin '{"admin":"rw"}'
```

The token string is shown **once**. The DB stores only the
HMAC-SHA512 hash. Save it immediately or re-create.

### `rhorizon token list` - see existing tokens

```bash
rhorizon token list
#   a1b2c3d4  ansible-prod   [active]    {"secrets":"r","namespaces":["prod"]}
#   e5f6g7h8  ci-frontend    [active]    {"secrets":"r","namespaces":["ci/frontend"]}
#   i9j0k1l2  old-deploy     [REVOKED]   {"secrets":"rw"}
```

### `rhorizon token show` - full details

```bash
rhorizon token show a1b2c3d4    # by ID prefix
rhorizon token show ansible-prod  # by name

# ID:           a1b2c3d4-...
# Name:         ansible-prod
# Active:       true
# Permissions:  {"secrets":"r","namespaces":["prod"]}
# Created by:   alice
# Created at:   2026-04-15T10:23:00Z
# Last used:    2026-04-29T07:45:00Z
# Expires at:   (no expiry)
# Revoked at:   (not revoked)
```

### `rhorizon token revoke` - kill switch

```bash
rhorizon token revoke a1b2c3d4
# Revoked: ansible-prod
```

Effective on the next API request - no propagation delay.

### `rhorizon token rotate` - re-mint a leaked token in place

```bash
rhorizon token rotate a1b2c3d4
# New value shown ONCE, same id/name/permissions/allowed_ips/expiry
```

**This is the response to a leaked token, not `revoke` + `create`.** Rotating
keeps the token id, so the audit lineage stays attached to one identity and
every group membership, namespace claim and IP allowlist survives. The old
value stops authenticating immediately; `last_used_at` resets to NULL so the
new value reads as unused. Delete-and-recreate loses all of that and mints an
id your RBAC and audit queries do not know.

Rotating is re-issuing, so it takes the same least-privilege gate as creation:
a namespace-restricted caller can only rotate a token whose namespaces are a
subset of its own.

### `rhorizon token set-ip` - change the IP allowlist

```bash
rhorizon token set-ip a1b2c3d4 "10.0.0.1,10.0.0.1"
```

Updates `allowed_ips` on a live token without re-minting it. Narrow is safer:
the allowlist is what bounds the blast radius if the value leaks.

### `rhorizon token renew` - extend an ephemeral

```bash
rhorizon token renew a1b2c3d4 --ttl 7200
# Renewed:  ci-build-eph
# Expires:  2026-04-29T11:00:00Z
# TTL:      7200s
```

Refuses long-lived tokens (no expiry to extend). Use only for
ephemerals when you need to push the deadline out.

### `rhorizon token ephemeral` - short-lived token

```bash
# Mint a 5-minute read-only token for the `mcp/mail` namespace
rhorizon token ephemeral \
    --ttl 300 \
    --scope secrets:r \
    --namespace mcp/mail \
    --label claude-mail-session

# Token:    rh_eph_xxxxxx
# Name:     eph-xxxxxx
# Expires:  2026-04-29T08:30:00Z (300s)
# Perms:    {"secrets":"r","namespaces":["mcp/mail"]}
# Label:    claude-mail-session

# Pipeline-friendly: print only the token
TOK=$(rhorizon token ephemeral -q --ttl 300 -s secrets:r -n demo)
```

Constraints (server-enforced):

| Limit | Default |
|---|---|
| Min TTL | 60s |
| Max TTL | `RH_EPHEMERAL_MAX_TTL` (default 24h) |
| `admin` scope | **forbidden** |

The reaper purges expired rows every 5 minutes. See [`SECRETS-AND-TOKENS.md`](SECRETS-AND-TOKENS.md#ephemeral-tokens) for the full rationale.

---

## 6. Namespaces

Lightweight grouping helpers (the namespace itself is implicit - it's
just whatever string you set in a secret's `namespace` field).

```bash
rhorizon ns list
#   default       12 secrets
#   prod          47 secrets
#   ci/frontend   8 secrets
#   mcp/mail      3 secrets

rhorizon ns delete old-namespace
# Refuses if non-empty - drop the secrets first.
```

---

## 7. Import / export

### Import from `.env`

```bash
rhorizon import dotenv ./prod.env --namespace prod
#   db-password
#   redis-password
#   api-key
# 3 secret(s) imported into namespace 'prod'
```

Comment lines (`#`) and blank lines are ignored. `export FOO=...` is
accepted. Quoted values are unquoted.

### Import from JSON

```bash
rhorizon import json ./backup.json
# Reads {"secrets": [...]} or a top-level [...]
```

### Migrate from Vault

```bash
export VAULT_ADDR=https://vault.example
export VAULT_TOKEN=...

# Dry-run by default. Conflicts are renamed, never overwritten.
rhorizon migrate vault

# Apply after reviewing the plan.
rhorizon migrate vault --apply
```

### Migrate from Infisical (experimental)

```bash
export INFISICAL_ADDR=https://us.infisical.com
export INFISICAL_TOKEN=...
export INFISICAL_PROJECT_ID=...
export INFISICAL_ENVIRONMENT=prod

# Dry-run by default. This adapter is experimental until live-tested.
rhorizon migrate infisical --dry-run
```

Universal Auth is also supported with `INFISICAL_CLIENT_ID` and
`INFISICAL_CLIENT_SECRET`. Conflicts are renamed by default.

Plaintext bulk export has been removed. Use `rhorizon backup export`
for age-encrypted vault backups.

---

## 8. Audit

### `rhorizon audit tail` - last N entries

```bash
# Default: last 20 entries
rhorizon audit tail

# Filtered
rhorizon audit tail -n 100 --actor mcp-agent
rhorizon audit tail --action read_secret --since 2026-04-29T00:00:00Z
rhorizon audit tail --until 2026-04-28T23:59:59Z

# Output format:
#   [OK]  2026-04-29T07:45:00Z   ansible-prod              read_secret             prod/db-password
#   [OK]  2026-04-29T07:44:55Z   ci-frontend               create_secret           ci/frontend/build-id
#   [OK]  2026-04-29T07:44:30Z   alice                     unseal
#   [FAIL]  2026-04-29T07:43:00Z   bob                       login_failed
```

The leading marker is the chain integrity status:

| Marker | Meaning |
|---|---|
| `[OK]` | Verified |
| `[BROKEN]` | Chain broke between this entry and the previous one - investigate |
| `[UNSIGNED]` | Entry has no signature (very old data, before audit-chain feature) |

### `rhorizon audit follow` - live tail

```bash
rhorizon audit follow
# Polls every 2 seconds, prints new entries as they arrive
# Ctrl-C to stop

rhorizon audit follow --interval 1     # faster polling
```

### `rhorizon audit verify` - audit evidence integrity check

```bash
rhorizon audit verify
# [OK] Chain intact: 12,453 entries verified
# [OK] Read-audit mtree intact (8,901 rows checkpointed, 12 pending)
```

Or, on failure:

```bash
rhorizon audit verify
# [FAIL] CHAIN BROKEN - 12,453 entries, see /audit/verify
# or:
# [FAIL] READ AUDIT MTREE BROKEN - id=... reason=merkle_root_mismatch
# Exit code: 2
```

This checks the signed mutation audit chain and the Merkle checkpoints covering
`vault_audit_lite` read events. Schedule it daily via cron / CI job and alert
on non-zero exit.

### `rhorizon audit export` - portable signed evidence

```bash
rhorizon audit export evidence.tar.gz \
  --since 2026-08-01T00:00:00Z \
  --until 2026-08-18T00:00:00Z
```

The single supported format is `.tar.gz`. It contains mutation rows, read rows,
overlapping sealed archives, signer public keys, Merkle and archive proofs, and
an Ed25519-signed manifest covering every member's size and SHA-256 digest. The
download is written to a private temporary file and atomically renamed when
complete; an existing destination requires `--force`.

Verify it without contacting the vault:

```bash
rhorizon audit verify-export evidence.tar.gz \
  --trusted-signer "$PINNED_AUDIT_SIGNER_FINGERPRINT"
```

Keep the trusted fingerprint outside the bundle. Omitting it checks internal
signature consistency but prints a warning because the included public key is
then trust-on-first-use.

### `rhorizon audit files` - list JSONL archives

```bash
rhorizon audit files
#   audit-2026-04-29.jsonl    (current, 1.2 MB)
#   audit-2026-04-28.jsonl    (yesterday, 4.8 MB)
#   audit-2026-04-22.jsonl.gz (compressed, 880 KB)
```

The reaper compresses files older than `RH_AUDIT_COMPRESS_DAYS`
(default 1).

### `rhorizon audit read` - read one day

```bash
rhorizon audit read 2026-04-29
# JSONL output, one entry per line, gzip-decompressed transparently
```

---

## 9. Master password

### `rhorizon master rotate` - change the master password

```bash
# Routine rotation (lazy migration of existing tokens)
rhorizon master rotate
# Current master password: ********
# New master password: ********
# Confirm new master password: ********
# [OK] Rotated (lazy mode)
#   DEKs re-encrypted: 47
#   Active tokens at rotation time: 12
#   prev_hmac_key stored - existing tokens keep working for ~15 days

# Emergency rotation (immediate token invalidation)
rhorizon master rotate --emergency
# Type 'rotate-emergency' to confirm: rotate-emergency
# [OK] Rotated (emergency mode)
#   All tokens are now invalid - re-authenticate via rhorizon login + create new tokens.
```

Two modes - pick the right one:

| Mode | When | Tokens after rotation |
|---|---|---|
| Default (lazy) | Routine hygiene, no compromise suspected | Existing tokens keep working for ~15 days; the reaper drops the fallback after that window |
| `--emergency` | Token / password leaked, incident response | All tokens invalidated immediately, including yours - re-mint everything |

See [`SECRETS-AND-TOKENS.md`](SECRETS-AND-TOKENS.md#27-token-rotation)
for the full discussion.

---

## 10. `rhorizon oneshot` - decrypt-and-die

```bash
# Vault must be SEALED at call time
rhorizon oneshot prod/api-key
# Master password: ********
# Output is the secret value on stdout (everything else on stderr).

rhorizon oneshot api-token --namespace mcp/linkedin --totp 123456
```

A single call: unseal -> read one secret -> re-seal. The vault is
sealed again **before the response is returned**, so the unsealed
window is bounded by the Argon2id derivation (~500 ms). Everything
after is sealed.

Use case: a one-shot job (CI runner, a recovery script, a CronJob)
that genuinely needs *one* secret with no further interaction. The
output goes to stdout (script-friendly); diagnostics go to stderr.

After this, the vault is sealed. An operator must re-unseal for
ordinary operation to resume.

---

## 11. Cluster (inspect + lifecycle)

For HA deployments. `rhorizon cluster status` is the read-only state
view - a debug utility, not a control panel - showing membership and
certificate lifecycle (`admin:r`).

```bash
rhorizon cluster status          # compact table (see below)
rhorizon cluster status --json   # full /cluster/ha payload
rhorizon cluster health          # live end-to-end component health
rhorizon cluster health --json   # provider, leader, replicas, lag and evidence
```

```text
cluster_id:        prod-7f3a
primary_uuid:      a1b2c3d4-...
ha_loaded:         true
uuid_ip_conflicts: 0

  UUID           IP                 STATE        HEARTBEAT       CERT
  a1b2c3d4       10.0.0.1         primary           3s ago     88d
  e5f6a7b8       10.0.0.1         secondary         2s ago     88d
```

The columns: short node UUID, source IP, HA state, heartbeat age,
certificate expiry. This is the rhorizon layer - node state, heartbeats,
certs. It identifies the **application primary**, not the PostgreSQL leader.

`cluster health` combines `database`, `database HA`, `node`, and `application
HA` without conflating their roles. The color/dot contract is:

```text
  ● green       verified healthy
  ● orange      forming, recovering, or degraded
  ● red         verified unsafe or unavailable
  ○ black/grey  unknown, disabled, or not configured; never healthy
```

The Database HA layer is observed through the configured Patroni or
`rhorizon-pgha` status provider and appears as `database_ha`. Use `--json` for
the provider-specific evidence: leader count/identity where available,
members, streaming state, replica lag, and timelines. Patroni supplies the
verified leader count but not its member identity; `pgha` also supplies leader
identity, agent freshness, quorum, and write-VIP ownership. The three distinct
terms are **local crypto master**, **application primary**, and **database
leader**.

Lifecycle verbs (operator actions, not inspection):

```bash
rhorizon cluster init            # bootstrap the cluster CA on the primary
rhorizon cluster join <addr>     # join an existing cluster
rhorizon cluster promote <uuid>  # / demote / drain / evict <uuid>
rhorizon cluster rotate-cert --all   # / rotate-ca / ca-bundle
```

The Web UI under **Cluster -> HA** combines that membership view with local
worker topology, held cluster locks, certificate lifecycle, and the normalized
Database HA evidence. Its dots use the same state contract as the CLI.

---

## 12. PKI and dynamic secrets

Two command groups are driven from the same binary but documented with their
feature, because the CLI is a thin wrapper over concepts that need explaining
(CA algorithms, lease lifecycles) rather than flag reference.

**`rhorizon pki`** - issue short-lived X.509 certs from a per-namespace CA:

| Command | Role |
|---|---|
| `pki init` | Mint the namespace CA (once). Defaults to the `ed25519-mldsa65` composite hybrid |
| `pki ca` | Fetch the CA cert PEM |
| `pki issue` | Issue a leaf; cert + private key shown once |
| `pki kem-issue` | Issue a KEM cert (ML-KEM-768 subject key, `--mode x25519-ml-kem` for the hybrid) |
| `pki certs` | List issued certs |
| `pki revoke` | Mark a cert revoked by serial |
| `pki rotate` | Rotate the CA, old cert kept in a grace window |

Full reference, algorithm trade-offs and verification recipes:
[`PKI.md`](PKI.md).

**`rhorizon dynamic`** - generate credentials on demand with a lease:

| Command | Role |
|---|---|
| `dynamic engines` / `engine-add` / `engine-rm` | Manage backends (PostgreSQL, MySQL, LDAP, Redis, Cassandra) |
| `dynamic roles` / `role-add` | Define what a credential may do, and its TTL |
| `dynamic creds` | Mint a credential against a role |
| `dynamic leases` / `renew` / `revoke` | Inspect and control outstanding leases |

Full reference, per-backend templates and the TTL/revocation model:
[`DYNAMIC-SECRETS.md`](DYNAMIC-SECRETS.md).

Other commands not covered above: `rhorizon update` (self-update),
`rhorizon import age` (import an age-encrypted export), `rhorizon backup
restore`, and the remaining cluster lifecycle verbs (`demote`, `drain`,
`evict`, `unrevoke`, `ca-bundle`, `rotate-ca`) documented in
[`HA-RUNBOOK.md`](HA-RUNBOOK.md). `rhorizon --help` and
`rhorizon <group> --help` are authoritative for flags.

## 13. Recipes

### Use a secret in a one-liner

```bash
DB_URL=$(rhorizon get prod/db-url) psql "$DB_URL"
```

### Mint an ephemeral token for a CI job

```bash
TOK=$(rhorizon token ephemeral -q --ttl 900 \
        --scope secrets:r --namespace ci/frontend \
        --label "ci-build-${BUILD_ID}")
RH_TOKEN=$TOK rhorizon get ci/frontend/registry-token
```

### Verify the chain in CI nightly

```bash
#!/bin/bash
# Returns non-zero if the audit chain is broken.
rhorizon audit verify || {
    curl -X POST "$ALERT_WEBHOOK" -d "rhorizon audit chain BROKEN"
    exit 1
}
```

### Generate, store, and immediately read a fresh credential

```bash
rhorizon generate 48 --store prod/new-api-key
rhorizon get prod/new-api-key | ./register-with-third-party.sh
```

### Migrate a `.env` to the vault

```bash
# 1. Move secrets in
rhorizon import dotenv ./.env --namespace prod
# 2. Mint a token for the consuming app
rhorizon token create app-prod --scope secrets:r --namespace prod
# 3. Reconfigure the app to read from rhorizon (cf. USE-CASES.md)
# 4. Delete .env from the host (don't just .gitignore it)
shred -u ./.env
```

---

## 14. Configuration files

### `~/.config/rhorizon/config.toml`

```toml
[default]
url = "http://10.0.0.20:8200"

[other-vault]
url = "http://192.168.50.10:8200"
```

The CLI reads and writes only the `default` profile. You can define
extra profiles in the file by hand, but selecting one from the CLI is
not yet wired.

### `~/.config/rhorizon/token.<profile>`

The token, plain text, mode 0600 (default profile -> `token.default`).
Read at every CLI invocation via the resolution order in section 2:
`RH_TOKEN` env, then `RH_TOKEN_STDIN=1` (one line of stdin, never on
disk), then this file.

There is no per-file path override. To pass a token without this file,
use `RH_TOKEN` or `RH_TOKEN_STDIN`; to relocate the whole config dir
(both `config.toml` and `token.<profile>`), set `RH_CONFIG_DIR`.

---

## 15. Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Operational error (network, vault sealed, token invalid, missing argument, etc.) |
| 2 | Audit chain integrity violation (only emitted by `audit verify`) |

---

## 16. Caveats

- **No retry / backoff in the CLI itself.** A transient network blip => exit 1. Wrap with `until rhorizon ... do sleep 2; done` if you need that.
- **The token file is your weakest link.** Mode 0600 protects against other users; it does not protect against root or against your own shell history if you `cat ~/.config/rhorizon/token.default`.
- **`rhorizon get` prints the value to stdout.** That's the point - but `set -x` in your script will leak it. Be deliberate about what you echo.
- **`oneshot` seals the vault.** Don't use it on a vault that anything else is using; you'll annoy the rest of your operators.
