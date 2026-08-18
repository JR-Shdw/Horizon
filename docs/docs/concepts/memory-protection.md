# Memory protection

Python `bytes` and `bytearray` objects are garbage-collected and may be
copied, retained in freed pages, swapped under memory pressure, or exposed
through `/proc/PID/mem`. Those properties are undesirable for key material.

rhorizon keeps long-lived operational keys in a Rust extension (`api/rust/`,
`rhorizon_crypto`) that uses `zeroize` and attempts `mlock(2)`. Password derivation,
unseal, and returning a requested secret still require short-lived cleartext
in the serving process; those paths are not described as zero-copy.

## `WrapKey` lifecycle

The process wrap key, active DEK cipher, audit signing seed, and operational
sub-key custody live in Rust objects that follow the configured memory-lock
policy. Sub-keys held by Python state
are ciphertexts under `WrapKey`. The audit seed's production
generate/load/rewrap path stays entirely in Rust. The wrap key sits in a
`WrapKey` struct:

```rust
pub struct WrapKey {
    inner: Box<SecureBuffer>,   // Vec<u8> mlock'd + zeroize-on-drop
}

impl WrapKey {
    pub fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<...> {
        // AES-256-GCM with the bytes that NEVER cross to Python.
    }
}

impl Drop for WrapKey {
    // The zeroize crate preserves the drop-time wipe.
}
```

Normal crypto operations call Rust with wrapped key material and return only
their result. Secret CRUD chains DEK unwrap/wrap with secret encryption inside
Rust. Reads return a mutable plaintext buffer that is wiped after decoding;
rollback and rotation return only new ciphertext. Python still handles
authorized request and response plaintext, so this is key protection rather
than a zero-plaintext claim.

The HA rekey X25519 private key does not cross that boundary. `WrapKey`
generates the keypair, wraps the private key, and opens incoming sealed boxes
inside Rust. Python stores the public key and wrapped private-key ciphertext.
Envelope keys returned to Python are mutable buffers and are wiped by the
consumer.

## What this defends against

| Threat | Mitigation |
|--------|------------|
| Swap-out of the master key page to disk | `mlock(2)` pins the page in RAM |
| GC retention of Rust-managed key bytes | `zeroize` performs a preserved wipe on drop |
| Same-UID `/proc/PID/mem` or `ptrace` | Linux workers fail startup unless `PR_SET_DUMPABLE=0` succeeds |
| Root or kernel memory read | Out of scope; `mlock` and non-dumpable state do not constrain host root |
| Heap fragmentation copies | Rust ownership limits copies for Rust-managed keys; Python plaintext values are a documented transient |
| Whole-process pages reaching swap | `mlockall(MCL_CURRENT\|MCL_FUTURE)` (`memlock_all`, default on) pins the *entire* address space, not just the key buffers ; `RLIMIT_CORE=0` forbids core dumps. See [Docker hardening](https://github.com/JR-Shdw/Horizon/blob/main/docs/DOCKER.md) for the memory sizing this requires. |
| Cold-boot / DMA attack | Out of scope - TPM-attested boot would be needed (keys live in RAM while unsealed) |

`mlock` requires sufficient `RLIMIT_MEMLOCK` or `IPC_LOCK` on Linux. Compose
and Helm use a portable best-effort default and leave the capability to the
operator; this avoids rootless runtime and Pod Security admission failures.
`PR_SET_DUMPABLE=0` needs no extra capability and is enforced independently.

## Tokens follow the same path

The agent (`agent/rust/src/lib.rs`) defines the same primitives for
bearer tokens :

```rust
pub struct SecureToken {
    ptr: NonNull<u8>,
    len: usize,
    cap: usize,
}

impl SecureToken {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        // alloc -> mlock -> copy -> return
    }

    pub fn as_bearer(&self) -> &str {
        // Borrowed slice - never escapes the wrapper
    }
}

impl Drop for SecureToken {
    // Wipe + munlock + dealloc
}
```

The `rh-watch` sidecar holds its bootstrap token in `SecureToken` for
the lifetime of the process. Ephemerals minted via `/tokens/ephemeral`
are the same - see [Agents](../howto/agents.md).

## Limits

The default `RH_MEMORY_LOCK_MODE=best-effort` keeps the service available when
locking is unavailable. It reports `zeroize-only`; secret buffers remain wiped
on release. A security warning is emitted when persistent swap is unencrypted
or cannot be classified. With encrypted swap, zram, or no swap, the same state
is informational. Set the mode to `required` to fail closed on a buffer lock
failure, or a whole-process `mlockall` failure while swap is unencrypted or
unknown. An invalid value also fails closed.

`mlock` is defense in depth. It does **not** :

- Defend against an attacker who already has root on the host (they
  can read `/proc/PID/mem` regardless).
- Defend against a kernel exploit that bypasses memory permissions.
- Replace a hardware HSM. If you need FIPS 140-2 / Common Criteria,
  rhorizon doesn't qualify.

It reduces exposure through accidental heap copies, same-UID process
inspection, core dumps, and swap. It cannot protect cleartext from code already
executing inside the unsealed worker, nor from a privileged host or kernel
compromise. `seal()` zeroizes managed Rust buffers; restarting a worker also
discards its Python address space and is the stronger response after a process
compromise.

## Verifying it's on

The `/api/v1/vault/status` endpoint, Horizon dashboard, and `rhorizon status`
show `mlock` when every attempted Rust secret allocation was locked. They show
`zeroize-only` after any lock failure in that API worker. The accompanying
`process_memory_protection` value reports `mlock`, `swappable`, `disabled`, or
`unsupported` for the worker address space. `swap_protection` is `protected`,
`unencrypted`, or `unknown`; only the latter two make a degraded memory state a
warning.

```bash
curl http://127.0.0.1:8200/api/v1/vault/status \
  | jq '{memory_protection, process_memory_protection, swap_protection}'
```
