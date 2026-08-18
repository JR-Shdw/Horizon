# Security audit tracker

This document is the living internal security-audit tracker. Older
point-in-time review notes are kept below for traceability; the latest
follow-up is the current release posture.

## Follow-up - 2026-07-07

Scope: deep reassessment of the Python vault paths, Rust crypto module,
Rust master RPC key custody, MCP server auth boundary, and CI/CD
dependency gates.

### CI/CD dependency gate

| Severity | Status | Evidence | Notes |
|---|---|---|---|
| high | resolved | `api/requirements.in` and `api/requirements.txt` pin `cryptography==48.0.1`; committed in `1cbfb32 fix: bump cryptography cve floor`. | This addresses the CI failure where `pip-audit` reported `cryptography 46.0.7` vulnerable to `GHSA-537c-gmf6-5ccf` and fixed in `48.0.1`. Re-run Woodpecker `validate.yml` on the pushed commit. |

Local tool availability during the reassessment:

- `ruff check api/app mcp/rhorizon_mcp cli/rhorizon`: passed.
- `python3 -m compileall -q api/app mcp/rhorizon_mcp cli/rhorizon`: passed.
- `cargo clippy --locked --no-default-features --lib -- -D warnings`
  in `api/rust`: passed.
- Full local dependency advisory scans were not reproduced because
  `pip-audit`, `cargo-audit`, and `cargo-deny` were not installed in
  this shell. The CI runner remains the source of truth for those gates.
- `cargo clippy --locked --no-default-features --all-targets -- -D warnings`
  currently fails only on deprecated `fips204` internal test helper use
  in `api/rust/src/lib.rs:945` and `api/rust/src/lib.rs:951`. This is
  not a runtime vulnerability, but it will block if CI switches the API
  crate to all-targets clippy.
- `cargo test --locked --no-default-features` ran 139 tests successfully
  and hit an environment-specific Unix socket permission failure in
  `key_share::tests::ipc_socket_roundtrip`. Re-run outside the sandbox or
  in the Proxmox/CI lab before release sign-off.

### Open findings

| Severity | Area | Evidence | Assessment / fix direction |
|---|---|---|---|
| low | Python heap residual: secret value, live CRUD paths only | `api/app/routes/secrets.py:421-422` (create), `:741-742` (update) - `body.value.encode()` | **Narrower than previously stated for live CRUD - re-verified this pass.** The DEK never enters Python as plaintext on create/update/rollback/rotation: `vault.secret_encrypt` and `secret_reencrypt` call the Rust `chained_secret_encrypt`/`chained_secret_reencrypt`, which generate, wrap, and use the DEK entirely inside Rust and return only the wrapped (encrypted) DEK or ciphertext - rollback/rotation are ciphertext-in, ciphertext-out, no plaintext in Python at all. The read path returns a mutable `bytearray` that `_decode_and_wipe()` explicitly `secure_zero()`s in a `finally` block. The one real, unavoidable residual on these paths: on create/update, the plaintext secret value arrives from the HTTP request body as an immutable Python `str`/`bytes` (`body.value.encode()`) before Rust ever sees it. CPython cannot safely zero an immutable object (it may be interned/shared; a forced `ctypes` overwrite risks corrupting unrelated objects) - an accepted boundary limitation of any JSON-over-HTTP secrets API, not a fixable bug. Same boundary exists symmetrically on every read response. |

### Rechecked prior findings

| Status | Finding | Evidence |
|---|---|---|
| fixed | Rust `MasterRpcState.key` is now locked and fail-closed on `mlock` failure. | `api/rust/src/master_rpc.rs:79-126`, `api/rust/src/master_rpc.rs:161-168`, `api/rust/src/master_rpc.rs:286-317` |
| fixed | Python/Rust Shamir malformed-share length checks now happen before indexing. | `api/app/vault_state.py:854`, `api/rust/src/key_share.rs:102-124` |
| fixed | `/admin/rotate-dek-key` aborts and rolls back on DEK unwrap failure before version/epoch bump. | `api/app/routes/vault.py:2123-2134` |
| fixed | `vault.key_epoch is None` with an existing DB epoch now probes current DEK decryptability or fails closed. | `api/app/key_epoch.py:202-211` |
| fixed | Python `cryptography` CVE floor, re-bumped `48.0.1` -> `50.0.0` (GHSA-m2h6-j472-rp4c, GHSA-g6cj-pr64-35w5, GHSA-jwv3-5hgf-82ww). Required bumping `fido2` `2.2.0` -> `2.2.1` too (`fido2==2.2.0` pinned `cryptography<49`, making every CVE-clean version uninstallable until fido2 widened it). Separately, `msgpack` (transitive via `cachecontrol` in `tools/ci-requirements.in`) floored at `>=1.2.1` for GHSA-6v7p-g79w-8964. All 8 `*requirements*.in` -> `.txt` rehashed and pip-audited clean; full pytest suite (2399 tests) re-run against the new `cryptography`/`fido2` and passed. | `api/requirements.in:7,12`, `tools/ci-requirements.in:11` |
| fixed | `SecureBuffer::try_new_locked()` zeroizes the incoming plaintext on `mlock` failure. Not at the site originally cited - the zeroize happens one level down, inside `lock_secret_memory` -> `apply_memory_lock_result`, which wipes the buffer in place under the `Required` memory-lock policy before propagating the error back up through `?`. | `api/rust/src/lib.rs` (`try_new_locked`, `lock_secret_memory`, `apply_memory_lock_result`) |
| fixed | `BackupCryptoContext::decrypt_secret()` and `decrypt_config()` both zeroize their transient Rust-side plaintext `Vec` after copying into the returned `PyByteArray`. `decrypt_secret()` already had this; `decrypt_config()` was missing it (same AEAD-output-lingering gap) and has been given the identical one-line fix this pass. `cargo clippy -D warnings` clean; `cargo test` 179/179 (including `decrypt_config_roundtrip`). | `api/rust/src/backup_context.rs:300-305` (`decrypt_secret`), `:321-327` (`decrypt_config`) |
| fixed | Backup restore's plaintext-DEK gap (previously an Open finding: `generate_dek()` in Python + `encrypt_secret(bytes(secret_clear), ...)` forced two un-zeroable copies). Implemented the planned `BackupCryptoContext::rotate_secret()`: chains decrypt(BACKUP) + encrypt(CURRENT) entirely in Rust via a new `WrapKey::unwrap_dek_key` (Rust-only sibling of the `decrypt` pymethod) and the existing `chained_secret_encrypt`. `api/app/vault_state.py` gained `VaultState.rotate_secret_from_backup()`; `api/app/routes/backup.py`'s restore loop tries it first. **Master-only** - a follower can't cheaply reconstruct the ephemeral, password-derived `BackupCryptoContext` (would re-run Argon2id, ~0.5-1.5s, per secret via RPC instead of once per restore), so `rotate_secret_from_backup` returns `None` there and the pre-existing Python-orchestrated sequence runs unchanged as a fallback - same residual as before, but now scoped to followers only instead of every restore. Verified: `cargo clippy --all-targets -D warnings` clean, `cargo test` 180/180 (new `rotate_secret_roundtrip` unit test confirms the output re-encrypts under the CURRENT dek_key, not a passthrough of the backup ciphertext), full pytest suite (2400 passed, 3 skipped) green, and two rewritten integration tests in `tests/test_legacy_backup.py` directly assert the security property: the fast path calls `secure_zero` zero times (proving no Python-side plaintext existed), the forced-fallback path still calls it >= once per secret. | `api/rust/src/backup_context.rs` (`rotate_secret`, `decrypt_secret_raw`), `api/rust/src/lib.rs` (`WrapKey::unwrap_dek_key`), `api/app/vault_state.py` (`rotate_secret_from_backup`), `api/app/routes/backup.py` |
| fixed | MCP auth cache DoS (`mcp-hub/rhorizon_mcp_hub/gateway.py`). `BearerAuth._pos`/`_neg`/`_rl` were plain dicts with only lazy, same-key expiry - many distinct bogus bearers or source IPs grew them without bound. Added `_prune_locked()`: drops expired entries (by each cache's own TTL) on every cache-miss `resolve()` call - i.e. exactly the traffic that causes growth, since cache hits return early and don't need it - plus a `_MAX_ENTRIES = 10_000` hard-cap backstop that evicts the oldest entries if pruning alone can't keep up. New test file (`mcp-hub/tests/test_gateway_bearer_auth.py`, this package had zero test coverage before): confirms expired entries are pruned, the hard cap evicts oldest-first while keeping the newest, and the actual positive/negative caching behavior still works correctly after pruning (3/3 pass). | `mcp-hub/rhorizon_mcp_hub/gateway.py` (`BearerAuth._prune_locked`) |
| not reproducible | "Rust subkey error paths" (previously Open, previously flagged as unverified/stale-citation last pass). Traced properly this time: every `*_subkey_*` call site in `lib.rs` (`aesgcm_subkey_encrypt`, `aesgcm_subkey_encrypt_bytearray`, `aesgcm_subkey_decrypt`, `derive_and_aesgcm_encrypt`) unwraps via `self.decrypt(encrypted_subkey)?` into a `SecureBuffer`, whose `Drop` impl unconditionally zeroizes on ANY scope exit - success, an early `?` return, or a panic unwind - since Rust always runs destructors on scope exit. None of the four extract the decrypted key into a plain, unprotected `Vec<u8>`. The HKDF-derive intermediate in `hkdf_derive_and_aes_gcm_encrypt_aad` uses the sibling pattern (`let result = (|| {...})(); derived.zeroize(); result`), which also zeroizes unconditionally regardless of the closure's outcome. Either this was fixed between the 2026-07-07 citation and now, or the citation pointed at code since replaced - either way, the concern does not reproduce against the current codebase. | `api/rust/src/lib.rs` (`WrapKey::aesgcm_subkey_encrypt`, `aesgcm_subkey_encrypt_bytearray`, `aesgcm_subkey_decrypt`, `derive_and_aesgcm_encrypt`, `hkdf_derive_and_aes_gcm_encrypt_aad`) |
| fixed | MCP HTTP token IP binding. The vault only ever saw the `rh-mcp-gateway` sidecar's own connecting IP for every agent behind the hub - a per-token `allowed_ips` restriction could distinguish the sidecar's host from the outside world, but not one agent from another. Implemented the design already used for SSO-proxy auth (`api/app/client_ip.py`'s `X-Forwarded-For` + `xff_trusted_ips`/`proxy_trusted_ips`, unchanged): the hub's HTTP handler already captures the real agent socket address (`self.client_address[0]`); it now flows through `ctx["client_ip"]` -> `VaultBackend.call`/`emit_mcp_audit` -> `SidecarClient.request(..., client_ip=...)` -> the Rust sidecar, which sets `X-Forwarded-For` on the actual vault call. **No vault-side (`api/app`) code changed at all** - `client_ip.py`/`auth.py` already resolve and enforce this correctly; the gap was purely that nothing upstream ever sent the header. Unconfigured (`xff_trusted_ips`/`proxy_trusted_ips` empty, the default), the vault ignores the header exactly as before - this cannot itself grant trust an operator hasn't opted into. Verified: `cargo clippy --all-targets -D warnings` clean on `agent/rust` and `cargo fmt --check` clean on both Rust crates; new `mcp-hub/tests/test_gateway_client_ip_forwarding.py` (5 tests) confirms the ctx -> VaultBackend/emit_mcp_audit -> SidecarClient wire payload chain, including the no-client_ip case staying a no-op rather than synthesizing a fake IP. The Rust sidecar's own header-setting (`mcp_gateway.rs`) is covered by compilation + code inspection only - that binary has no existing test harness to extend, and a full E2E check needs a live vault + hub + sidecar stack. | `mcp-hub/rhorizon_mcp_hub/{gateway,sidecar,hub}.py`, `agent/rust/src/mcp_gateway.rs` |

## Security audit - 2026-04-29

Review of `rhorizon` source code for SQL injection,
XSS, buffer overflow, chronology/precedence flaws, auth bypass, and
crypto misuse.

## Methodology

- Reviewed all 28 Python files under `api/app/` (~9760 LOC), 5 Rust
  files (~1600 LOC), 8 frontend JS files plus `index.html` and
  `nginx.conf`.
- Each `text()`/SQL call was inspected (419 occurrences). Each
  `innerHTML` site (40+ occurrences) was checked against the `esc()`
  helper.
- All `unsafe` Rust blocks were read for soundness contracts and
  length-prefixed wire formats verified against `MAX_PAYLOAD` ceilings.
- Critical flows (unseal, rotate-password, seal, oneshot,
  attach_to_master, reconstruct_and_become_master) were stepped through
  line-by-line.

## Findings

### 1. SQL Injection

| Severity | File:line | Verdict |
|----------|-----------|---------|
| info | `api/app/routes/secrets.py:455-466` | Safe - placeholders interpolated are server-generated `:ns0, :ns1, ...` (no user input), values bound via `params` dict. |
| info | `api/app/routes/dynamic.py:130, 133, 525, 528` | Safe - `.format()` substitutes a fixed string literal chosen by branch; the user-controlled `:ns` parameter is properly bound. |
| low | `api/app/routes/dynamic.py:413-426` | The user/password are server-generated; password charset excludes `'` and `"`, but a defensively malformed `creation_sql` template (admin-controlled) could still make the password break out. Admin-only endpoint. **Recommendation:** require parameter placeholders in templates. |

All other 415 SQL call sites use `:name` parameters with a `{...}` dict
and are safe. **No vulnerable SQL injection found.**

### 2. XSS / Output Encoding

CSP review (`frontend/nginx.conf:45`):
`default-src 'self'; script-src 'self' 'sha256-...'; style-src 'self';
connect-src 'self'`. No `unsafe-inline`/`unsafe-eval`. The inline
`<script>` for service worker registration is whitelisted via SHA-256
hash. Strong policy.

`X-Frame-Options DENY`, `Referrer-Policy no-referrer`,
`Permissions-Policy` disable camera/mic/geo, `X-Content-Type-Options
nosniff`, `Strict-Transport-Security` all present.

`esc()` in `frontend/js/api.js:51-56` correctly uses `textContent`
then re-reads `innerHTML` and escapes single/double quotes. Audited
every `innerHTML` interpolation site (eclipse, quasar, jets, cluster,
accretion, pulsar, core, horizon): every server-returned string passes
through `esc()`. **No XSS finding.**

### 3. Buffer Overflow / Unsafe Rust

10 `unsafe` blocks across `api/rust/src/lib.rs` and
`api/rust/src/key_share.rs`. All reviewed - soundness contracts hold:

- `memsec::mlock`/`munlock` on `Vec<u8>`: pointer + len match the Vec
- `secure_zero`: GIL held via `Bound<'_, _>`, no allocation/Python
  callbacks/GIL release between borrow and drop
- `getsockopt(SO_PEERCRED)`: `cred` fully zero-initialized, `len`
  initialized, no aliasing
- `libc_getuid`: never fails or touches user memory

Length-prefix wire formats (Shamir share serving, RPC) are bounded
against `MAX_PAYLOAD = 4096` (Rust) and `1 MB` (Python RPC); zero is
rejected; `Vec::with_capacity(len)` then `read_exact` cannot overflow.

Agent binaries (`agent/rust/src/{inject,fetch,watch}.rs`) contain no
`unsafe` blocks. **No BOF finding.**

### 4. Chronology / Precedence in critical flows

| Severity | File:line | Description |
|----------|-----------|-------------|
| medium | `api/app/routes/oneshot.py:113-125` | The yubikey 2FA branch references column `secret` but the schema field is `hmac_secret`. Format decoding also wrong. **The yubikey path of /oneshot is broken.** Functional bug; not a state-leakage vuln (raises before `vault.unseal`). |
| medium | `api/app/routes/oneshot.py:167` | `if hmac_token(...) != check_row.value:` - non-constant-time string comparison. Per-byte timing leak gives an oracle for password verification. |
| info | `api/app/routes/vault.py` unseal | Order is rate-limit -> derive -> master_check -> 2FA -> unseal -> broadcast -> audit -> commit. **Safe.** |
| info | `api/app/routes/vault.py` rotate_password | Documented order: re-encrypt DEKs -> re-encrypt 2FA -> master_check -> audit -> commit -> THEN flip vault state. **Safe.** |
| info | `api/app/routes/oneshot.py:190-245` | `try/finally` re-seals regardless of exception. **Safe.** |
| info | `api/app/audit.py:74-91` | Chain prev-sig read happens in same DB transaction as insert, but **without `SELECT ... FOR UPDATE`**. Concurrent calls can fork the chain. Documented limitation. |
| info | `api/app/audit.py:51-59` | `_write_file()` runs before `db.commit()`. If commit fails, file persists - DB and file diverge. Acceptable for fail-secure audit. |
| low | `api/app/cluster_setup.py:489` | After Shamir reconstruction, `secret_bytes` and `keys` slices live in Python heap until GC. The Rust SecureBuffer is dropped/zeroized but the Python copies are not. |

### 5. Auth / Scope Bypass

| Severity | File:line | Description |
|----------|-----------|-------------|
| **high** | `api/app/routes/tokens.py:33-56` | `_check_grant_permissions` skips namespace check. **A non-root token with `{"secrets":"rw","namespaces":["dev"], "tokens":"w"}` can mint a new token in `["prod"]` namespace** and read/write secrets there. Also bypassed for admin (a namespace-restricted admin can mint an unrestricted root token). |
| **high** | `api/app/routes/secrets.py:287-365` | Historical: `export_secrets` required admin but did not call `check_namespace`. Current remediation is removal of the plaintext bulk export endpoint; age backup remains the export path. |
| info | `api/app/auth.py:139-148` | `require_permission` admin-bypass does not call `check_namespace`. Each endpoint calls it explicitly - pattern works but is brittle. |
| info | `api/app/auth.py:50-83` | `prev_hmac_key` lazy-migration has no race issue: last-writer-wins on idempotent UPDATE. **Safe.** |

### 6. Crypto Misuse / Constant-Time / Path Traversal / Logging

| Severity | File:line | Description |
|----------|-----------|-------------|
| medium | `api/app/routes/oneshot.py:167` | (Same as section 4) - non-constant-time master_check comparison. Use `_hmac.compare_digest`. |
| info | `api/app/routes/audit.py:23` | `_DATE_RE = r"^\d{4}-\d{2}-\d{2}$"` strictly matches; traversal-safe. |
| info | All AES-GCM nonces are generated via `os.urandom(12)` or Rust `OsRng.fill_bytes`; never reused. Current mutation-audit v2 payloads canonicalise every immutable row field; HMAC-SHA512 legacy/fallback rows remain backward-verifiable. |
| info | All HMAC and signature comparisons (`audit.py:79-87`, `routes/audit.py:95, 101, 263, 266`) use `hmac.compare_digest`. `routes/backup.py:207-209` uses `compare_digest`. `crypto.py:196, 222` use `compare_digest`. **All security-sensitive comparisons are constant-time except oneshot.py:167.** |
| low | `agent/rust/src/{inject,fetch,watch}.rs` | `format!("{addr}/api/v1/vault/secrets/{secret_name}")` - `secret_name` from env is concatenated without URL-encoding. Token-bearer-auth still enforces RBAC, but defence-in-depth says percent-encode. |
| info | Log review: zero hits for log lines containing secret values, plaintext passwords, or token content. Pydantic `SecretStr` is used for all password fields. **No secret leakage in logs.** |

## Score-card

- **Total findings: 12**
- **Critical: 0**
- **High: 2** (token namespace escalation, export_secrets namespace bypass)
- **Medium: 2** (oneshot non-constant-time master_check, oneshot YubiKey path broken)
- **Low: 2** (agent URL not percent-encoded, master-key Python heap residue after Shamir reconstruct)
- **Info: 6** (creation_sql template, audit chain race, audit file/db divergence, require_permission/check_namespace coupling pattern, dynamic.py admin SQL on target DB, length-prefix wire format ceilings - all safe-but-worth-noting)

## Remediation plan

| Phase | Findings | Status |
|-------|----------|--------|
| Immediate | 2 high (tokens namespace, export bypass) + 2 medium (oneshot constant-time, oneshot yubikey decoding) | Fixed in `fix(security): ...` commit |
| Short term | 2 low (agent URL encoding, Shamir Python heap residue) | Tracked, fix on next iteration |
| Long term | 6 info (architecture-level recommendations) | Roadmap, accept as documented limitations |
