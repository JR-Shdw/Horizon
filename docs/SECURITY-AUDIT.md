# Security audit tracker

Internal security-audit tracker. Two review passes are recorded, each a
**point-in-time snapshot**, plus a verification of every finding's current
status.

> **Read the scope before the findings.** The 2026-04-29 pass reviewed 28 Python
> files (~9.7k LOC) and 10 `unsafe` blocks. The tree now holds **81 Python files
> (~46k LOC) and 32 `unsafe` blocks**, so that pass covered roughly a fifth of
> today's Python surface. Its clean verdicts do not extend to code written
> since. Neither pass is a substitute for the automated gates in
> `.woodpecker/validate.yml`, which run on every push.

## Current status of every recorded finding

Re-verified against the working tree on 2026-08-22. This table is the answer to
"is anything still open" — the historical sections below are kept for
traceability, not for triage.

| Severity | Finding | Status | Evidence |
|---|---|---|---|
| high | Token namespace escalation (`_check_grant_permissions` skipped the namespace check) | **fixed** | `api/app/routes/tokens.py` — enforces a namespaces subset, explicitly "applies even to admin" |
| high | `export_secrets` namespace bypass | **fixed** | Endpoint removed; age backup is the export path |
| medium | `/oneshot` non-constant-time `master_check` comparison | **fixed** | `api/app/routes/oneshot.py:183` — `_hmac.compare_digest` |
| medium | `/oneshot` YubiKey path referenced a non-existent column | **fixed** | `api/app/routes/oneshot.py:129` — reads `hmac_secret`, with a comment recording the original bug |
| low | Shamir reconstruction left sub-keys in the Python heap | **fixed** | `api/app/cluster_setup.py` — `secure_zero` on every key and on `secret_bytes` in a `finally` |
| low | Agent URLs concatenate `secret_name` without percent-encoding | **fixed** | `e607483` — six sites, not the one cited (inject, watch and three in podman shared the shape). Reuses the existing `http::encode_component` |
| low | Python heap residual: plaintext secret on create/update | **accepted** | Immutable `str`/`bytes` from the request body cannot be zeroed in CPython. A boundary limitation of any JSON-over-HTTP secrets API, symmetric on reads |
| info | 6 architectural notes (audit-chain race, audit file/DB divergence, `creation_sql` templates, `require_permission` coupling, wire-format ceilings) | **accepted** | See the 2026-04-29 sections |

**No finding is open.** The last one, a low-severity defence-in-depth item, was closed in `e607483`.

## Follow-up — 2026-07-07

Scope: Python vault paths, Rust crypto module, Rust master RPC key custody, MCP
server auth boundary, CI/CD dependency gates.

### Resolved this pass

| Area | What changed | Evidence |
|---|---|---|
| Rust RPC key custody | `MasterRpcState.key` locked, fail-closed on `mlock` failure | `api/rust/src/master_rpc.rs` |
| Shamir | Malformed-share length checks moved before indexing | `api/app/vault_state.py`, `api/rust/src/key_share.rs` |
| DEK-key rotation | `/admin/rotate-dek-key` rolls back on unwrap failure before the version/epoch bump | `api/app/routes/vault.py` |
| Key epoch | A `None` in-RAM epoch against an existing DB epoch now probes DEK decryptability or fails closed | `api/app/key_epoch.py` |
| Rust buffers | `SecureBuffer::try_new_locked()` zeroizes the incoming plaintext on `mlock` failure — in `apply_memory_lock_result`, one level below the originally cited site | `api/rust/src/lib.rs` |
| Backup context | `decrypt_config()` was missing the transient-`Vec` zeroize that `decrypt_secret()` already had | `api/rust/src/backup_context.rs` |
| Backup restore | `BackupCryptoContext::rotate_secret()` chains decrypt-under-BACKUP + encrypt-under-CURRENT entirely in Rust, removing two un-zeroable Python copies. **Master-only**: a follower would re-run Argon2id per secret over RPC, so it falls back to the Python path there — the residual is now scoped to followers instead of every restore | `api/rust/src/backup_context.rs`, `api/app/routes/backup.py` |
| MCP hub | Bearer auth caches were unbounded — distinct bogus bearers or source IPs grew them without limit. Added TTL pruning on cache-miss plus a 10k hard cap | `mcp-hub/rhorizon_mcp_hub/gateway.py` |
| MCP hub | Per-agent token IP binding: the vault only ever saw the sidecar's IP, so `allowed_ips` could not distinguish one agent from another. The hub now forwards the real agent address as `X-Forwarded-For`. **No vault-side code changed** — `client_ip.py` already resolved it correctly; nothing upstream sent the header. Unconfigured, the vault still ignores it | `mcp-hub/rhorizon_mcp_hub/`, `agent/rust/src/mcp_gateway.rs` |

### Not reproducible

"Rust subkey error paths." Every `*_subkey_*` call site unwraps into a
`SecureBuffer`, whose `Drop` zeroizes on any scope exit — success, an early `?`,
or a panic unwind. None extracts the key into an unprotected `Vec<u8>`. The
HKDF intermediate uses the same unconditional pattern. Either it was fixed
between the citation and this pass, or the citation pointed at replaced code.

### Dependency floors

`cryptography==50.0.0` and `fido2==2.2.1` (`api/requirements.in`). The bump
chain mattered: `fido2==2.2.0` pinned `cryptography<49`, making every CVE-clean
version uninstallable until fido2 widened it. `msgpack>=1.2.1` floored in
`tools/ci-requirements.in` for GHSA-6v7p-g79w-8964.

> An earlier row in this file recorded `cryptography==48.0.1` as the fix for
> GHSA-537c-gmf6-5ccf. That was superseded by the 50.0.0 bump above; the pin in
> the tree is 50.0.0. `api/requirements.in` is the source of truth, not this
> page.

### Tooling caveats from that pass

`pip-audit`, `cargo-audit` and `cargo-deny` were not installed in that shell, so
CI remains the source of truth for advisory gates. `cargo clippy --all-targets`
failed only on deprecated `fips204` test-helper use — not a runtime issue, but
it will block if CI moves the API crate to all-targets clippy.

## Security audit — 2026-04-29

Review for SQL injection, XSS, buffer overflow, chronology/precedence flaws,
auth bypass, and crypto misuse.

> Scope as reviewed **at that date**: 28 Python files (~9.7k LOC), 5 Rust files
> (~1.6k LOC), 8 frontend JS files, `index.html`, `nginx.conf`. Every `text()`
> SQL call (419 then) and every `innerHTML` site was inspected; all `unsafe`
> blocks (10 then) were read for soundness; the unseal, rotate-password, seal,
> oneshot, `attach_to_master` and `reconstruct_and_become_master` flows were
> stepped through line by line. The tree has since roughly quintupled — see the
> scope note at the top.

### 1. SQL injection

| Severity | Site | Verdict |
|---|---|---|
| info | `api/app/routes/secrets.py` | Safe — interpolated placeholders are server-generated (`:ns0, :ns1, …`), values bound via `params` |
| info | `api/app/routes/dynamic.py` | Safe — `.format()` substitutes a branch-chosen literal; the user-controlled `:ns` is bound |
| low | `api/app/routes/dynamic.py` (creation templates) | User/password are server-generated and the charset excludes quotes, but an admin-authored malformed `creation_sql` could still let a password break out. Admin-only. **Recommendation:** require parameter placeholders in templates |

All other call sites used `:name` parameters with a dict. **No vulnerable SQL
injection found.**

### 2. XSS / output encoding

CSP: `default-src 'self'; script-src 'self' 'sha256-…'; style-src 'self';
connect-src 'self'` — no `unsafe-inline`, no `unsafe-eval`; the one inline
script is hash-whitelisted. `X-Frame-Options: DENY`, `Referrer-Policy:
no-referrer`, `Permissions-Policy` disabling camera/mic/geo,
`X-Content-Type-Options: nosniff`, and HSTS all present.

`esc()` sets `textContent`, re-reads `innerHTML`, then escapes quotes. Every
`innerHTML` interpolation site across the eight views was audited and every
server-returned string passes through it. **No XSS finding.**

### 3. Buffer overflow / unsafe Rust

All 10 `unsafe` blocks then present were reviewed; soundness contracts held:
`mlock`/`munlock` pointer+len match the `Vec`; `secure_zero` holds the GIL with
no allocation or GIL release between borrow and drop; `getsockopt(SO_PEERCRED)`
fully initialises `cred` and `len` with no aliasing; `libc_getuid` cannot fail.

Length-prefixed wire formats are bounded by `MAX_PAYLOAD` (4096 Rust, 1 MB
Python RPC), zero-length is rejected, and `with_capacity` + `read_exact` cannot
overflow. Agent binaries contain no `unsafe`. **No BOF finding.**

### 4. Chronology / precedence

| Severity | Site | Description |
|---|---|---|
| medium | `oneshot.py` YubiKey branch | Referenced column `secret`; schema field is `hmac_secret`, and decoding was wrong. Functional break, not a state leak — raised before `vault.unseal`. **Fixed** |
| medium | `oneshot.py` master_check | Non-constant-time comparison gave a per-byte timing oracle. **Fixed** |
| info | `vault.py` unseal | rate-limit -> derive -> master_check -> 2FA -> unseal -> broadcast -> audit -> commit. Safe |
| info | `vault.py` rotate_password | re-encrypt DEKs -> re-encrypt 2FA -> master_check -> audit -> commit -> then flip state. Safe |
| info | `oneshot.py` | `try/finally` re-seals regardless of exception. Safe |
| info | `audit.py` | The chain's prev-sig read shares the insert's transaction but takes no `SELECT … FOR UPDATE`, so concurrent calls can fork the chain. Documented limitation |
| info | `audit.py` | `_write_file()` precedes `db.commit()`; a failed commit leaves the file. Accepted as fail-secure |
| low | `cluster_setup.py` | Shamir sub-keys lingered in the Python heap after reconstruction. **Fixed** — `secure_zero` in a `finally` |

### 5. Auth / scope bypass

| Severity | Site | Description |
|---|---|---|
| high | `routes/tokens.py` | `_check_grant_permissions` skipped the namespace check, so a token with `{"secrets":"rw","namespaces":["dev"],"tokens":"w"}` could mint one scoped to `prod` — and a namespace-restricted admin could mint an unrestricted root token. **Fixed**, subset enforced including for admin |
| high | `routes/secrets.py` | `export_secrets` required admin but never called `check_namespace`. **Fixed** by removing the plaintext bulk-export endpoint |
| info | `auth.py` | The `require_permission` admin bypass does not call `check_namespace`; each endpoint calls it explicitly. Works, but brittle by construction |
| info | `auth.py` | `prev_hmac_key` lazy migration is last-writer-wins on an idempotent UPDATE. Safe |

### 6. Crypto misuse / constant-time / traversal / logging

| Severity | Site | Description |
|---|---|---|
| info | `routes/audit.py` | `_DATE_RE` matches `^\d{4}-\d{2}-\d{2}$` strictly; traversal-safe |
| info | AES-GCM nonces | Generated by `os.urandom(12)` or Rust `OsRng`; never reused. Mutation-audit v2 canonicalises every immutable row field; legacy HMAC-SHA512 rows stay verifiable |
| info | Comparisons | All security-sensitive comparisons use `hmac.compare_digest` — including `oneshot.py`, since that finding was fixed |
| low | `agent/rust/src/{inject,fetch,watch}.rs` | `secret_name` is concatenated into the URL without percent-encoding. Bearer auth still enforces RBAC. **Still open** |
| info | Logging | No log line carries a secret value, plaintext password, or token. Password fields use Pydantic `SecretStr` |

### Score-card as recorded then

12 findings: 0 critical, 2 high, 2 medium, 2 low, 6 info. **As of 2026-08-22, 5
of the 6 non-info findings are fixed and 1 low remains open** — see the status
table at the top of this file.
