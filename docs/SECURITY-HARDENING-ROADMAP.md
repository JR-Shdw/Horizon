# Security hardening roadmap

All items in this roadmap are shipped. Backup restore's re-encryption is
plaintext-free on the master; a follower falls back to a Python-orchestrated
path with a documented, narrower exception (see below). Existing secrets
remain readable and do not require re-import.

## Constraints

- Existing ciphertext must remain readable.
- AAD and backup metadata changes require an explicit version and upgrade path.
- Stored ciphertext and nonce formats remain compatible.
- Cryptographic operations use maintained implementations of
  XChaCha20-Poly1305, AES-256-GCM, HKDF-SHA512, Ed25519, and SHA-256.
- Normal secret reads necessarily return plaintext to the API process. The
  memory-hardening claim applies to keys and avoidable intermediate plaintext,
  not to an authorized response.

## Completed items

| Item | Status | Result |
|---|---|---|
| Rust-chained normal secret CRUD | **Shipped** | Create and update generate the DEK, wrap it, and encrypt the secret inside Rust. Read and version-read unwrap the DEK and decrypt inside Rust. The plaintext DEK does not enter Python. |
| Rust-chained rollback and rotation | **Shipped** | Rollback, per-secret rotation, and bulk rotation decrypt and re-encrypt under a fresh DEK inside Rust. Neither DEK nor the intermediate plaintext enters Python. |
| Multi-worker chained crypto | **Shipped** | For decrypt/reencrypt (only the master holds keys), followers send ciphertext and AAD to the native master RPC server and get back ciphertext outputs or the authorized plaintext result. For encrypt (`secret_encrypt`, e.g. `create_secret` on a follower), there is no ciphertext yet - the follower necessarily sends the plaintext value (hex-encoded) to the master, which is where a fresh DEK gets generated. This RPC channel is a `0700` filesystem-path Unix domain socket, `SO_PEERCRED` peer-UID validated, fail-closed - same-host and same-UID only, never network-exposed. |
| Backup/restore re-encryption | **Shipped** | `BackupCryptoContext::rotate_secret()` now chains decrypt(BACKUP) + encrypt(CURRENT) entirely in Rust (`WrapKey::unwrap_dek_key` unwraps the CURRENT dek_key without it entering Python, `chained_secret_encrypt` mints and wraps the fresh DEK) - matching live create/update. `VaultState.rotate_secret_from_backup()` uses this on the master. On a follower it returns `None` and the restore falls back to the old Python-orchestrated sequence, because reconstructing the ephemeral, password-derived `BackupCryptoContext` on the master via RPC would re-run Argon2id (~0.5-1.5s) per secret instead of once per restore. |
| Mutable plaintext cleanup | **Shipped, with a follower exception** | Rust returns wipeable `bytearray` values where Python must handle plaintext, and callers wipe the mutable source immediately after decoding or use (`_decode_and_wipe`, `secure_zero`). Backup restore's master/single-worker path now has no Python-side plaintext to wipe at all (proven by `test_restore_fast_path_needs_no_python_plaintext`: `secure_zero` is called zero times). The one remaining exception is the follower fallback above, where PyNaCl's binding still forces an immutable copy of the plaintext and the new DEK - unchanged from before, just now scoped to followers only. |
| `vault_audit_lite` Merkle checkpoints | **Shipped** | Read-log windows are covered by signed `sha256-merkle-v1` checkpoints in the chained audit log. |
| Plaintext bulk export removal | **Shipped** | The supported bulk movement path is the age-encrypted logical backup. |

## Secret CRUD boundary

The persisted model is unchanged:

```text
vault_dek.encrypted_key =
    AES-256-GCM(DEK, dek_key, AAD=dek:{dek_id})

vault_secrets.ciphertext =
    XChaCha20-Poly1305(secret, DEK,
                      AAD=secret_aad(aad_version, name, namespace))
```

Normal reads follow this path:

```text
encrypted DEK + encrypted secret
                |
                v
Rust: unwrap DEK -> decrypt secret -> wipe DEK
                |
                v
wipeable plaintext buffer -> API response
```

Create and update receive plaintext from the request, so that plaintext already
exists in Python. Rust generates the fresh DEK and returns only:

```text
encrypted_dek, dek_nonce, ciphertext, secret_nonce
```

Rollback and rotation start from ciphertext and return ciphertext. Their
intermediate plaintext remains inside Rust and is wiped before return.

## Compatibility

- AAD v1 rows remain readable.
- New writes use length-prefixed AAD v2.
- Rewriting or restoring a v1 secret upgrades it to v2.
- Backup format v4 records `aad_version`; older backups default to v1.
- Python/Rust and PyNaCl/Rust parity tests cover both AAD versions, tampering,
  local execution, Python RPC, and the production native Rust RPC listener.

## Out of scope

Hardware-backed root protection is tracked separately in
[ROADMAP.md](ROADMAP.md): TPM 2.0 first, then PKCS#11 HSM and YubiKey PIV, with
Shamir-compatible recovery.
