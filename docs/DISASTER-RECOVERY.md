# Disaster Recovery - rhorizon

Two recovery paths exist. They are not interchangeable.

| Path | Use case | Coverage | Operator workload |
|------|----------|----------|-------------------|
| **`pg_dump` / `pg_restore`** | Full DR: node crash, datacenter loss, schema corruption, point-in-time recovery, vault migration to a new host. | **Everything**: every table, every relationship, the audit chain in its entirety. | Plain SQL - no application logic. The vault container is stopped, the DB is restored, and the container is restarted. |
| **`/backup/restore` (API)** | Selective migration: carry secrets, namespaces, groups, and token metadata across vault installations, e.g. when bootstrapping a new environment from a known-good state. | **Partial logical restore**: current secret rows + DEK + namespaces + groups + group members + restorable config + token metadata stubs. **Not**: 2FA credentials, notifications, dynamic engines and leases, audit chain, version history, live token hashes or plaintexts. | UI button. Manual follow-up afterward: 2FA review or re-enrollment where needed, notification channel recreation, token rotation. |

`pg_dump` is the recommended path for DR. `/backup/restore` is a migration tool with explicit limits.

---

## Path 1 - `pg_dump` (recommended)

Stop the API, dump the database under `age` symmetric encryption, and store the artifact off-site.

### Backup

```bash
# In a host that can reach the rhorizon postgres
docker compose stop api
docker compose exec postgres \
    pg_dump -U rhorizon -d rhorizon --no-owner --no-privileges \
    | age -p > rhorizon-$(date +%Y%m%d-%H%M).sql.age
# enter a strong passphrase (32+ chars, stored in your secondary password manager)
docker compose start api
```

The artifact is a regular age-encrypted file decryptable with the `age` CLI alone; no rhorizon instance is needed for inspection.

### Restore

```bash
# On the target host (fresh vault or existing one to overwrite)
docker compose down -v                          # wipes the PG volume
docker compose up -d postgres
age -d rhorizon-YYYYMMDD-HHMM.sql.age \
    | docker compose exec -T postgres \
        psql -U rhorizon -d rhorizon
docker compose up -d api
```

The vault comes up exactly as it was at dump time: same `argon2_salt`, same `master_check`, same `hmac_key` once unsealed, every client-held token still valid, every 2FA credential enrolled, every notification channel functional, and every audit row chained as before.

### Cadence

- Daily cron via Restic onto a separate datacenter - RPO ~24 h is acceptable per `~/dev/sextant/rhorizon/...` doctrine.
- Verify the dump can be decrypted by piping the first KB through `age -d` weekly.
- Rotate the passphrase every quarter and re-encrypt the latest dump.

---

## Path 2 - `/backup/restore` (partial migration)

Triggered from the UI in **Accretion -> Backup Vault (encrypted)** / **Restore Vault (from encrypted backup)**, or via the API (`POST /api/v1/vault/backup/create` / `POST /api/v1/vault/backup/restore`).

### What `/backup/create` exports

| Table | Fields carried |
|---|---|
| `vault_secrets` | name, namespace, ciphertext, nonce, aad_version, dek_id, metadata, version, created_by, created_at, updated_at, expires_at, is_honey, deleted_at, purge_after. `dek_rotated_at` is intentionally reset by restore because every secret receives a fresh restore-time DEK. |
| `vault_dek` | encrypted_key, nonce (AAD-bound to dek_id) |
| `vault_namespaces` | name, owner_group_id, enforce_membership, delete_protection, archived_at |
| `vault_groups` | name, permissions, source, ldap_dn |
| `vault_group_members` | External principals: group_name, principal_type, source-qualified principal_id, added_at. Native-token memberships travel with token metadata and are attached to the fresh token UUID after restore rotation. |
| `vault_config` | every restorable key/value. The running vault identity and dek-bound integrations are **not** overwritten: `argon2_salt`, `master_check`, `dek_key_version`, `vault_initialized`, `prev_hmac_key`, `pending_restore_*`, TOTP / 2FA keys, LDAP keys, and audit identity keys stay current or are reconfigured after restore. The backup carries its own copy of `argon2_salt` + `master_check` + `dek_key_version`; they describe how to read the backup, not how to replace the current vault's identity. |
| `vault_tokens` | **metadata only** - name, namespace, permissions, allowed_ips, expires_at, is_honey. Hash is **not** carried: every restore wipes `vault_tokens` and inserts the metadata into `vault_pending_token_rotations` so an admin explicitly mints a fresh plaintext per token. |

The payload is serialized as JSON, checksummed (SHA-256), and encrypted with the `age` passphrase the operator types in the UI.

### Restore needs two credentials, not one

The operator types **both** at restore time:

- the **age passphrase** - decrypts the `.age` envelope (scrypt + ChaCha20-Poly1305);
- the **vault master password used at backup time** - derives the BACKUP-side `dek_key` so the DEKs inside the payload can be unwrapped.

The two credentials are independent. The age passphrase alone is not enough to read any secret; the master password alone is not enough to open the envelope. Both must be preserved with the same care.

### What restore *does* - dual-context crypto

1. Decrypts the age envelope, verifies the SHA-256 checksum of the JSON payload, and reads the schema version / coverage manifest.
2. Builds a **BACKUP crypto context** from the payload's `argon2_salt` + `master_check` + `dek_key_version` and the operator-supplied `master_password_backup`. The context derives the backup's `hmac_key` + `dek_key` from Argon2id + HKDF-SHA512 in a Rust `LockedBuf` (mlock'd, zeroized on `Drop`). A wrong master password is detected here as a `master_check` mismatch and the call returns `401` before any DB mutation.
3. Wipes `vault_leases`, `vault_dynamic_roles`, `vault_dynamic_engines`, `vault_secret_versions`, `vault_secrets`, `vault_notification_channels`, `vault_tokens`, `vault_dek`, `vault_pending_token_rotations`, `vault_group_members`, `vault_namespaces`, `vault_groups` - in this FK-safe order.
4. Re-inserts groups + namespaces (`namespace.owner_group_id` is re-resolved by **name** because every restored group gets a fresh UUID) + external group principals. Native-token principals remain on their pending rotation stubs and are attached when each fresh token UUID is minted.
5. For each secret in the payload: `BackupCryptoContext.decrypt_secret()` chains unwrap-DEK-then-decrypt-secret in a single Rust call; backup format v4 supplies `aad_version`, while older payloads default to v1; a fresh DEK is generated and wrapped under the **CURRENT** `dek_key` (AES-256-GCM); the secret is re-encrypted with v2 AAD under the new DEK (XChaCha20-Poly1305); both rows are inserted in the same transaction; the plaintext bytearray is `secure_zero()`ed in the `finally` clause.
6. Inserts each token row as a stub into `vault_pending_token_rotations` (the legacy plaintext is gone, only an admin can mint a fresh one).
7. Sets two flags in `vault_config`:
   - `pending_restore_bootstrap` - consumed by the next `/unseal`, which mints a fresh `root-restore-<ts>` token with TTL = `RH_RECOVERY_TOKEN_TTL_DAYS` (default 7).
   - `pending_restore_review` - drives the UI panel in Settings / Core.
8. Calls `stop_master_services()` + `vault.seal()`. The RPC server is torn down, the Shamir share-back KeyServer is closed, and the in-RAM sub-keys are zeroed. The next `/unseal` restarts the cluster wiring cleanly under the **CURRENT** master password - the operator does not need to re-type the backup's password to make the restored data readable.

```mermaid
flowchart TD
    subgraph BACKUP["BACKUP context (in-memory, in Rust)"]
        bpw["master_password_backup<br/>(operator input)"]
        bmk["backup master_key<br/>(LockedBuf, mlock'd)"]
        bhmac["backup hmac_key<br/>verify master_check -> mismatch? raise 401"]
        bdek["backup dek_key"]
        pdek["plaintext DEK_i<br/>(Rust stack, zeroized before return)"]
        psec["plaintext secret_i<br/>(PyByteArray, secure_zero in finally)"]
        bpw -->|"Argon2id(backup argon2_salt)"| bmk
        bmk -->|"HKDF-SHA512 info=hmac-tokens"| bhmac
        bmk -->|"HKDF-SHA512 info=dek-encrypt[-vN]"| bdek
        bdek -->|"AES-256-GCM unwrap (one DEK per secret)"| pdek
        pdek -->|"XChaCha20-Poly1305 decrypt"| psec
    end
    subgraph CURRENT["CURRENT context (persisted)"]
        cmk["current master_key<br/>(already in RAM)"]
        cdek["current dek_key"]
        cmk --> cdek
    end
    psec -->|"re-encrypt under fresh DEK_i' wrapped by current dek_key"| ins["INSERT vault_dek + vault_secrets"]
    cdek --> ins
    ins -.->|"on exit: del backup_ctx"| z["Rust Drop zeroizes master_key + hmac_key + dek_key, munlocks pages"]
```

Three properties follow from running the restore in two contexts:

- **Free crypto rotation of every secret.** Each restore re-rolls every DEK and every XChaCha20 nonce. A backup-restore cycle is equivalent to a full bulk rotation, at no extra cost.
- **Master-password drift is supported.** Restoring a backup taken six months ago, under a different master password, on a vault that has since rotated its own password, is a normal use case. Neither side overwrites the other.
- **The plaintext never enters Python on the fast path.** `rotate_secret()`
  chains decrypt-under-BACKUP and encrypt-under-CURRENT in a single Rust call,
  so neither the secret plaintext nor either DEK crosses the boundary. The
  `BackupCryptoContext`'s `LockedBuf` still zeroes master_key + hmac_key +
  dek_key on `Drop`, and the transient plaintext is zeroized inside Rust on
  every exit path, including the error paths. See
  [the two restore paths](#the-two-restore-paths) below for the one case that
  still round-trips through Python.

### Recovery flow for the operator

```mermaid
flowchart TD
    a["/backup/restore returns sealed=true"]
    b["/unseal with the CURRENT vault master password<br/>(NOT the backup's - the backup password was only needed during<br/>the restore call itself, to unwrap the BACKUP-side DEKs)"]
    c["response carries a fresh root_token (root-restore-&lt;ts&gt;)<br/>shown once, TTL 7 days, scope admin:rw"]
    d["Quasar -> Pending rotations: Show & Rotate each token<br/>you still need, Revoke the rest"]
    e["Reconfigure: YubiKeys, WebAuthn, TOTP, notification channels,<br/>dynamic engines (see the Settings panel checklist)"]
    f["Create a fresh long-lived root token"]
    g["Settings -> Mark as reviewed -> recovery root token revoked,<br/>pending_restore_review flag cleared"]
    a --> b --> c --> d --> e --> f --> g
```

### Reconfigure these after a restore

These tables and config surfaces are outside the API logical backup. On a fresh
target they are absent; on an in-place restore, target-side rows that are not in
the wipe list may remain, but they are never imported from the backup. Review
each one deliberately:

| Table | Why | What you do |
|---|---|---|
| `vault_yubikeys` | Not imported from the backup. Backup-side HMAC secrets are DEK-bound and would need explicit re-keying; existing target rows may remain on an in-place restore. | Verify current target registrations; re-enroll via Settings -> Two-Factor Authentication when moving to a fresh target. |
| `vault_webauthn` | Not imported from the backup. Public keys could in principle be moved across, but the operator should re-attest from the actual security key to maintain the chain of custody. Existing target rows may remain on an in-place restore. | Verify current target registrations; re-register from each FIDO2 device when moving to a fresh target. |
| `vault_config` keys for TOTP secret | Not imported from the backup. Backup-side TOTP material is DEK-bound; the target vault's current 2FA mode is left untouched so a restore can never lock you out of unseal. | Verify current target 2FA; set up TOTP again when moving to a fresh target. |
| `vault_config` keys for LDAP (`ldap_config`, `ldap_group_mappings`) | Not imported from the backup. Backup-side LDAP bind material is DEK-bound and its standalone DEK is not carried. | Reconfigure LDAP in Settings. |
| `vault_config` audit-chain identity (`audit_identity_seed_enc`, `audit_identity_pub`, `key_epoch`) | Belongs to the current vault's audit chain, which is not imported from the backup (see `vault_audit` below). | Kept on an in-place target; bootstrapped automatically on next unseal if absent. |
| `vault_notification_channels` | Cleared by logical restore. Channel config can contain external delivery URLs or tokens and is not carried in the API backup. | Recreate Matrix / webhook / email channels in Pulsar, then send a test alert. |
| `vault_dynamic_engines` / `vault_dynamic_roles` / `vault_leases` | `connection_url` and credentials are encrypted under `dek_key`. Active leases would point at users that no longer exist on the target DBs. | Redeclare engines and roles; let the new credentials flow through your apps naturally. |
| `vault_secret_versions` | History of past versions of each secret, encrypted under their original DEKs. Carrying these would inflate the backup substantially with little operational benefit; the current version suffices for rollover. | If you need a specific historical version, restore from a `pg_dump` of that date instead. |
| `vault_audit` | The API backup does not carry audit rows. A fresh target starts its own chain; an in-place target keeps its existing chain and records the restore event under the current audit identity. | Keep archived JSONL logs for pre-migration evidence and run `/audit/verify` after unseal. |
| Honey campaign review | Secret `is_honey` and token `is_honey` metadata are preserved, but the decoy catalogue is still environment-specific. | Review and re-seed any missing decoys via `tools/seed_honey.py`. |

### Pending token rotations - lifecycle

- A stub stays in `vault_pending_token_rotations` until an admin either rotates or revokes it via the UI.
- The reaper purges any stub older than `RH_RESTORE_ROTATION_GRACE_DAYS` (default 30, clamp 7-90). Past this, the legacy identifier is lost - equivalent to a late revocation. Admin must re-create a token under that name if they still need it.
- Rotation supersedes any pre-existing active token in `vault_tokens` sharing the stub's name: the old row is revoked (`active=false`, `revoked_at=NOW()`) and the new plaintext takes its place.
- The freshly minted token wears a green `NEW` badge in the Tokens tab for 7 days, until its first use (`last_used_at` set).

### Permissions matrix on the new endpoints

| Endpoint | Required scope | Namespace check |
|---|---|---|
| `GET /tokens/pending/` | `tokens:r` | filtered to caller's `namespaces` claim, if any |
| `POST /tokens/pending/{id}/rotate` | `tokens:w` | `check_namespace` on the stub's namespace |
| `DELETE /tokens/pending/{id}` | `tokens:w` | `check_namespace` on the stub's namespace |
| `POST /vault/post-restore-review/dismiss` | `admin:w` | none (global op) |

A namespace sub-admin can be represented with existing scopes:

```json
{"secrets": "rw", "tokens": "rw", "namespaces": ["prod"]}
```

This token can rotate or revoke pending stubs scoped to `prod` and CRUD secrets in `prod`, but cannot seal, unseal, or dismiss the post-restore review panel.

### If the backup master password is lost

There is no recovery path. The BACKUP-side `dek_key` is derived from the master password via Argon2id; without the password, the DEKs inside the payload cannot be unwrapped, and the secrets cannot be read. The age passphrase decrypts the *envelope*, not the secrets themselves - both credentials are required, independently.

This is by design and matches the threat model of `pg_dump | age -p` without the passphrase. A backup whose master password is irretrievable is equivalent to encrypted garbage. Store the master password in the same offline vault as the age passphrase.

If only the **age passphrase** is lost, the same conclusion applies in reverse: the envelope cannot be opened, and the rest of the chain never runs.

### The two restore paths

`BackupCryptoContext.rotate_secret()` is **shipped**. Restore takes one of two
paths per secret, decided by whether the worker handling the request holds the
sub-keys:

| | Fast path | Fallback |
|---|---|---|
| When | The worker is the local crypto master (or single-worker mode) | The worker is a follower - `rotate_secret_from_backup()` returns `None` |
| How | `rotate_secret()` chains decrypt-under-BACKUP + encrypt-under-CURRENT in **one Rust call** | `decrypt_secret()` returns a `PyByteArray`, Python re-wraps under the CURRENT context |
| Plaintext in the CPython heap | **Never** | For one loop iteration, then `secure_zero()`ed in a `finally` |

The fast path removes the residual this section used to describe: a Python
heap dump during the restore window leaks nothing, because the plaintext and
both DEKs stay on the Rust side.

The fallback exists because only the master holds the sub-keys. Dispatching it
over RPC would have meant paying the Argon2id derivation per secret rather than
per restore, so the follower case keeps the Python round-trip with explicit
zeroization instead. Restores driven against the master - the normal case, and
always true in single-worker mode - take the fast path throughout.

---

## Break-glass - `tools/emergency_root_token.py`

If the restore flow itself fails halfway (interrupted network, container crash mid-restore, manually changed `argon2_salt`, ...), the operator may be locked out without a usable root token.

`tools/emergency_root_token.py` re-derives the current `hmac_key` from the master password and the in-DB `argon2_salt`, generates a fresh root token plaintext, computes its hash, and INSERTs it directly into `vault_tokens`. The script needs:

- the master password (typed on stdin),
- direct PostgreSQL access (typically by `docker cp`'ing the file into the API container).

Refuse to run if an active root token already exists unless `--force` is passed, so it does not silently double the attack surface. The operation is audit-logged as `recovery-token-mint`.

```bash
docker cp tools/emergency_root_token.py rhorizon_api:/tmp/recovery.py
docker exec -it rhorizon_api env \
    RH_DB_URL="postgresql://rhorizon:${POSTGRES_PASSWORD}@postgres:5432/rhorizon" \
    python3 /tmp/recovery.py
```

This path is a last resort. The normal route is `/backup/restore` -> `/unseal` (which mints the recovery root token automatically).

### Break-glass second factor (optional)

By default the tool needs only the master password + DB access. That is the vault's root secret, so it is not a privilege bypass -- but it does collapse "master password + 2FA device" down to "master password + DB write": anyone holding both mints an admin token with no second factor. If your threat model needs more, arm a break-glass second factor.

Arm it by setting `vault_config.break_glass_2fa` to one of `totp | yubikey | fido2 | shamir`. Once armed there is **no bypass** -- a valid factor is mandatory. That is the point, and the risk: keep a backup of the factor (a spare seed, a backup FIDO2 key, M reachable shareholders) or you lock yourself out of recovery too. If the value is set but the factor is not yet implemented in the tool, the tool **refuses to mint** rather than skipping it -- fail-closed, never fall-open.

A factor only adds protection against a master-password-plus-database attacker
if its verifier is stored **outside that attacker's reach**:

| Factor | Protects against master password + DB? | Automatable (unattended HA)? | Notes |
|---|---|---|---|
| **totp** | Only if the seed is stored independently of the master key (see below); the enrolled-vault seed is master-decryptable | **Yes** -- a code is computable from the seed | Simplest; the only automatable factor -> lets an HA controller drive break-glass unattended |
| **yubikey** (HMAC-SHA1) | Only if the verifier secret is stored independently | No -- needs the physical token | Offline/CLI; *(planned)* |
| **fido2 / webauthn** | **Yes**, if the authenticator and enrollment process remain trusted -- public key in DB, private key on hardware | No -- needs user presence | Resistant to a DB-plus-password compromise; needs the key present where the tool runs; *(planned)* |
| **shamir** (M-of-N) | **Yes**, if shares are independent and the threshold remains uncompromised | Partially (only if shares are held by agents) | Reuses the vault Shamir and removes a single-holder recovery decision; *(planned)* |

`totp` is wired today. Its seed is read in this order:

1. **`RH_BREAK_GLASS_TOTP_SECRET`** (env) -- an out-of-band seed **not** in the DB. This is the only source that resists a master-password+DB attacker, and the one an HA controller injects to recover unattended. Use it for the hardened / automated case.
2. **`vault_config.totp_secret`** -- the enrolled unseal TOTP, decrypted with the password-derived `dek_key`. Convenience/reuse: it gates a password-only misuse and enables the HA-automation path, but a master-password+DB attacker can also decrypt it, so it is **not** proof against that stronger attacker. For that, use `fido2` or `shamir`.

`totp` is the only listed factor a machine can supply. An HA controller can
therefore use a separately held TOTP seed for unattended recovery;
`fido2`/`yubikey` require user presence and block that automation. Choose the
factor from the threat model: `totp` for automatable recovery, `fido2` for
hardware-backed user presence, or `shamir` when recovery must require a quorum.

The verified factor is recorded in the break-glass audit row (`second_factor`).
