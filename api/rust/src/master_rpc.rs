// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
//! Master crypto-ops RPC server.
//!
//! Replaces `cluster_rpc.MasterRpcServer` (Python asyncio) with a native
//! Rust thread that listens on the same Unix socket. Followers connect
//! exactly the same way, only the master end of the wire changes.
//!
//! Why : the Python implementation was the cluster's read_secret throughput
//! ceiling, every follower crypto op went through the master's asyncio
//! event loop under the GIL, so all the dispatch (JSON parse, route lookup,
//! response encoding) was serialised on a single Python thread. Native
//! Rust threads bypass the GIL, so the master can dispatch in parallel
//! across all CPU cores it has.
//!
//! Wire format (unchanged from Python implementation) :
//!   request  : 4-byte big-endian length || JSON {op, args}
//!   response : 4-byte big-endian length || JSON {result|error}
//!
//! Ops served, all bytes hex-encoded in JSON :
//!   hmac_sha512        : HMAC-SHA512(hmac_subkey, message)
//!   hmac_sha512_prev   : same with prev_hmac_subkey (lazy migration)
//!   aesgcm_encrypt     : AES-256-GCM-encrypt(dek_subkey, plaintext, aad)
//!   aesgcm_decrypt     : AES-256-GCM-decrypt(dek_subkey, ciphertext, aad)
//!   secret_encrypt     : fresh DEK + chained DEK-wrap/secret-encrypt
//!   secret_decrypt     : chained DEK-unwrap/secret-decrypt
//!   secret_reencrypt   : decrypt then re-encrypt under a fresh DEK
//!   audit_sign         : HMAC-SHA512(audit_subkey, prev_signature || payload)
//!   audit_sign_identity: Ed25519-sign(prev_signature || payload)
//!   ha_password_hmac   : HMAC-SHA512 with the in-memory HA password
//!   ha_wrap_encrypt    : encrypt with the HA wrapping subkey
//!   ha_wrap_decrypt    : decrypt with the HA wrapping subkey
//!   pki_wrap_encrypt   : encrypt with the PKI wrapping subkey
//!   pki_wrap_decrypt   : decrypt with the PKI wrapping subkey
//!   wrap_node_key_for_joiner   : wrap a node key for an HA joiner
//!   wrap_server_key_for_joiner : wrap a server key for an HA joiner
//!   set_ha_password_from_plain : load the HA password into protected state
//!   clear_ha_password  : clear the protected HA password
//!   has_ha_password    : report whether the HA password is loaded
//!
//! Concurrency model : one OS thread per accepted connection. Master
//! serves at most N-1 followers (~4 in the standard 5-worker setup),
//! plus the occasional cluster-setup probe, a thread-per-conn pattern
//! is cheaper than an async runtime here and keeps the code linear.
//!
//! Thread safety : the server state is wrapped in `Arc<MasterRpcState>` and
//! shared by connection threads. The master AES key is immutable; encrypted
//! subkeys and optional HA/PKI material are updated through mutex-protected,
//! atomic swaps.

use std::net::Shutdown;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

#[cfg(test)]
use hmac::Mac;
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use rhorizon_custody_core::control::{dispatch_compatibility_control, WrappedSecretSlot};
use rhorizon_custody_core::operations::{audit_ed25519_sign, audit_hmac_sha512, hmac_sha512};
#[cfg(test)]
use rhorizon_custody_core::rpc::zeroize_json_strings;
use rhorizon_custody_core::rpc::{dispatch_request, error_response};
use rhorizon_custody_core::MAX_RPC_FRAME_BYTES;
use serde_json::Value;
use zeroize::{Zeroize, Zeroizing};

#[cfg(test)]
use crate::HmacSha512;
use crate::{
    aes_gcm_decrypt_aad, aes_gcm_decrypt_aad_locked, aes_gcm_encrypt_aad, chained_secret_decrypt,
    chained_secret_encrypt, chained_secret_reencrypt, hkdf_derive_and_aes_gcm_encrypt_aad,
    lock_secret_memory, ChainedSecretCiphertext, ChainedSecretReencryptInput, DEK_WRAPPED_BYTES,
};
use rhorizon_custody_core::peer_cred::read_peer_cred;

/// 4-byte big-endian length prefix + JSON payload. The API permits request
/// bodies up to 1 MiB; hex encoding plus JSON overhead requires a 3 MiB frame.
const MAX_PAYLOAD: usize = MAX_RPC_FRAME_BYTES;
const HKDF_SUBKEY_BYTES: usize = 32;
const AES_GCM_NONCE_BYTES: usize = 12;

#[derive(Clone, Copy)]
enum WrappedLength {
    Exact(usize),
    AtLeast(usize),
}

/// Per-connection IO timeout. A misbehaving client never holds a
/// dispatch thread for more than this long.
const IO_TIMEOUT: Duration = Duration::from_secs(5);

/// Bound native worker threads even if a same-UID local process floods the
/// Unix socket. Excess connections are closed immediately.
const MAX_ACTIVE_CONNECTIONS: usize = 64;

/// Accept-loop poll interval when there are no pending connections.
/// This is the latency floor on a fresh request when traffic is
/// bursty: every gap in the accept stream forces the loop into a
/// sleep of this length. 1ms is the right balance : negligible CPU
/// cost when idle (~1000 wakeups/s = 0.5% of one core) and a sub-ms
/// floor that does not show up in p99 measurements. Earlier 20ms was
/// fine for one-off accepts (Shamir share serving) but capped this
/// hot-loop's throughput at ~200 conn/s.
const ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(1);

/// RAII helper: Vec<u8> that follows the memory-lock policy and is zeroized
/// at drop. Locked pages stay locked for the process lifetime (see
/// custody-core `secure_memory`).
struct LockedBuf {
    data: Vec<u8>,
    // Read by the cfg(test) accessor only.
    #[cfg_attr(not(test), allow(dead_code))]
    locked: bool,
}

impl LockedBuf {
    fn new(mut data: Vec<u8>) -> PyResult<Self> {
        if data.is_empty() {
            return Ok(LockedBuf {
                data,
                locked: false,
            });
        }
        let locked =
            lock_secret_memory(&mut data, "MasterRpcState key").map_err(PyValueError::new_err)?;
        Ok(LockedBuf { data, locked })
    }

    /// Allocate and lock non-secret zeroes before copying secret input.
    fn from_slice(data: &[u8]) -> PyResult<Self> {
        let mut locked = Self::new(vec![0u8; data.len()])?;
        locked.data.copy_from_slice(data);
        Ok(locked)
    }

    fn as_slice(&self) -> &[u8] {
        &self.data
    }

    fn zeroize(&mut self) {
        self.data.zeroize();
    }

    #[cfg(test)]
    fn is_locked(&self) -> bool {
        self.locked
    }
}

impl Drop for LockedBuf {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

fn validate_wrapped_value(
    master_key: &[u8],
    wrapped: &[u8],
    name: &str,
    expected: WrappedLength,
) -> PyResult<()> {
    let plaintext = aes_gcm_decrypt_aad_locked(master_key, wrapped, &[])
        .map_err(|e| PyValueError::new_err(format!("invalid {name}: {e}")))?;
    let actual = plaintext.data.len();
    match expected {
        WrappedLength::Exact(length) if actual != length => Err(PyValueError::new_err(format!(
            "invalid {name}: expected {length} plaintext bytes, got {actual}"
        ))),
        WrappedLength::AtLeast(length) if actual < length => Err(PyValueError::new_err(format!(
            "invalid {name}: expected at least {length} plaintext bytes, got {actual}"
        ))),
        _ => Ok(()),
    }
}

fn validate_wrapped_subkey(master_key: &[u8], wrapped: &[u8], name: &str) -> PyResult<()> {
    validate_wrapped_value(
        master_key,
        wrapped,
        name,
        WrappedLength::Exact(HKDF_SUBKEY_BYTES),
    )
}

/// The three HKDF sub-keys (hmac / dek / audit), each AES-GCM-encrypted
/// under the master `key`. Grouped behind one Mutex so a master-password
/// rotation swaps all three atomically via `set_subkeys` -- a follower
/// RPC call never observes a half-applied generation (e.g. the new
/// hmac_key paired with the still-old dek_key). The ciphertext is public
/// (the secret is `key`), but the buffers are zeroized on swap + drop so
/// no stale generation lingers in the heap.
struct SubKeys {
    hmac_enc: Vec<u8>,
    dek_enc: Vec<u8>,
    audit_enc: Vec<u8>,
}

impl SubKeys {
    fn zeroize(&mut self) {
        self.hmac_enc.zeroize();
        self.dek_enc.zeroize();
        self.audit_enc.zeroize();
    }
}

/// Shared state for the master RPC server.
///
/// `Arc` shares this state across the accept loop and connection threads
/// without copying the master key. The master AES key follows the configured
/// lock policy, then is zeroized and conditionally unlocked on drop. Encrypted
/// subkeys are ciphertext; mutexes allow atomic rotation while requests run.
struct MasterRpcState {
    /// Master AES-256 wrap key, policy-locked while the RPC state lives. Used to
    /// AES-GCM-decrypt the encrypted subkeys on each call. The plaintext
    /// subkey lives in locked Rust heap memory and is zeroized before
    /// being unlocked on drop.
    ///
    /// Unchanged by a master-password rotation : `vault.unseal` reuses
    /// the same process WrapKey, only re-deriving the sub-keys below.
    /// So `set_subkeys` swaps `subkeys` but never `key`.
    key: LockedBuf,
    /// Live HKDF sub-keys. Interior-mutable so a master that rotates its
    /// own password refreshes the generation the listener serves to its
    /// followers (see `set_subkeys`). Without this the accept loop keeps
    /// the construction-time snapshot for its whole life -- the loop
    /// captures one `Arc<MasterRpcState>` at `start()` and never re-reads
    /// `MasterRpcServer.state`, so only intra-Arc Mutex mutation is visible.
    subkeys: Mutex<SubKeys>,
    /// ha_wrap_key subkey, encrypted
    /// under `key`. Backs the `ha_wrap_encrypt` / `ha_wrap_decrypt`
    /// ops (cluster CA private key + ha_password at-rest wrapping).
    /// Loaded before the listener starts when available. Operations fail
    /// closed while this slot is `None`.
    ha_wrap_enc: Mutex<Option<Vec<u8>>>,
    /// pki_wrap_key subkey, encrypted under `key`. Backs the
    /// `pki_wrap_encrypt` / `pki_wrap_decrypt` ops (PKI-engine CA private key
    /// at-rest wrapping). Loaded before the listener starts when available;
    /// operations fail closed while this slot is `None`.
    pki_wrap_enc: Mutex<Option<Vec<u8>>>,
    /// ha_password buffer, AES-GCM-
    /// encrypted under `key`. Backs the `ha_password_hmac`,
    /// `wrap_node_key_for_joiner`, and `wrap_server_key_for_joiner`
    /// ops. `None` before /cluster/init or when load_ha_password_into_ram
    /// has not yet been called ; the corresponding ops fail with
    /// "ha_password not loaded" when None.
    ha_password_enc: WrappedSecretSlot,
    /// Previous HMAC subkey, encrypted under `key`. Set during a
    /// non-emergency master-password rotation while old tokens are
    /// being lazy-migrated.
    prev_hmac_enc: Mutex<Option<Vec<u8>>>,
    /// Audit chain Ed25519 signing seed (32 bytes), AES-GCM-encrypted under
    /// `key`. Backs the `audit_sign_identity` op so a follower delegates audit
    /// signing to the master without ever holding the seed. `None` until the
    /// master loads its identity (vault_state.install_audit_signer pushes it
    /// via `set_audit_seed_enc`) ; the op fails "audit_seed not loaded" when None.
    audit_seed_enc: Mutex<Option<Vec<u8>>>,
    /// Owner UID used for SO_PEERCRED validation, only connections
    /// from this UID are accepted, fail-closed otherwise.
    owner_uid: libc::uid_t,
    /// Fail-closed seal latch. `vault.seal()` flips this synchronously so a
    /// master sealed without the async `stop()` teardown stops serving crypto
    /// at once -- `dispatch` returns "vault sealed" before touching a subkey.
    /// `set_subkeys` clears it (a re-unseal refresh re-arms). Mutated through
    /// the shared `Arc`, so the running accept loop observes it.
    sealed: AtomicBool,
}

impl Drop for MasterRpcState {
    fn drop(&mut self) {
        self.key.zeroize();
        if let Ok(mut g) = self.subkeys.lock() {
            g.zeroize();
        }
        for slot in [
            &self.prev_hmac_enc,
            &self.ha_wrap_enc,
            &self.pki_wrap_enc,
            &self.audit_seed_enc,
        ] {
            if let Ok(mut g) = slot.lock() {
                if let Some(ref mut v) = *g {
                    v.zeroize();
                }
            }
        }
    }
}

impl MasterRpcState {
    /// Snapshot the live `hmac_enc` ciphertext (cloned under the lock so
    /// the lock is released before the HMAC op runs ; the clone is public
    /// ciphertext). A concurrent `set_subkeys` either lands fully before
    /// or fully after this read -- never mid-swap.
    fn hmac_enc(&self) -> Result<Vec<u8>, String> {
        Ok(self
            .subkeys
            .lock()
            .map_err(|e| format!("subkeys lock poisoned: {e}"))?
            .hmac_enc
            .clone())
    }

    /// Snapshot the live `dek_enc` ciphertext (see `hmac_enc`).
    fn dek_enc(&self) -> Result<Vec<u8>, String> {
        Ok(self
            .subkeys
            .lock()
            .map_err(|e| format!("subkeys lock poisoned: {e}"))?
            .dek_enc
            .clone())
    }

    /// Snapshot the live `audit_enc` ciphertext (see `hmac_enc`).
    fn audit_enc(&self) -> Result<Vec<u8>, String> {
        Ok(self
            .subkeys
            .lock()
            .map_err(|e| format!("subkeys lock poisoned: {e}"))?
            .audit_enc
            .clone())
    }
}

/// Python-facing handle. Owns the listener thread + a stop flag.
///
/// `#[pyclass]` makes this constructable / callable from Python via PyO3.
/// The methods are `#[pymethods]`-decorated, that's how `start()` and
/// `stop()` become callable from cluster_setup.py.
#[pyclass]
pub struct MasterRpcServer {
    /// Filesystem path the listener is bound to.
    socket_path: PathBuf,
    /// `Arc` so the accept thread + every per-conn thread can share
    /// the immutable key state. Present from construction until `stop()`.
    state: Mutex<Option<Arc<MasterRpcState>>>,
    /// Cooperative stop flag. The accept loop polls this between
    /// connections; setting it makes the loop exit and drop the listener.
    stop: Arc<AtomicBool>,
    /// Handle to the accept-loop thread. Joined on `stop()`.
    accept_thread: Mutex<Option<JoinHandle<()>>>,
}

// Plain Rust constructor, callable from anywhere in the crate
// (notably from `WrapKey::create_master_rpc_server` in lib.rs which
// builds an instance using its internal key without exposing those
// bytes to Python). The `#[new]` PyO3 wrapper below also forwards
// here so unit tests + the WrapKey factory share one code path.
impl MasterRpcServer {
    pub(crate) fn new_from_key_bytes(
        socket_path: &str,
        key: &[u8],
        hmac_enc: &[u8],
        dek_enc: &[u8],
        audit_enc: &[u8],
        owner_uid: u32,
    ) -> PyResult<Self> {
        if key.len() != 32 {
            return Err(PyValueError::new_err("master key must be 32 bytes"));
        }
        validate_wrapped_subkey(key, hmac_enc, "hmac_enc")?;
        validate_wrapped_subkey(key, dek_enc, "dek_enc")?;
        validate_wrapped_subkey(key, audit_enc, "audit_enc")?;
        let state = MasterRpcState {
            key: LockedBuf::from_slice(key)?,
            subkeys: Mutex::new(SubKeys {
                hmac_enc: hmac_enc.to_vec(),
                dek_enc: dek_enc.to_vec(),
                audit_enc: audit_enc.to_vec(),
            }),
            ha_wrap_enc: Mutex::new(None),
            pki_wrap_enc: Mutex::new(None),
            ha_password_enc: WrappedSecretSlot::empty("ha_password_enc"),
            prev_hmac_enc: Mutex::new(None),
            audit_seed_enc: Mutex::new(None),
            owner_uid: owner_uid as libc::uid_t,
            sealed: AtomicBool::new(false),
        };
        Ok(MasterRpcServer {
            socket_path: PathBuf::from(socket_path),
            state: Mutex::new(Some(Arc::new(state))),
            stop: Arc::new(AtomicBool::new(false)),
            accept_thread: Mutex::new(None),
        })
    }
}

#[pymethods]
impl MasterRpcServer {
    /// Bind the listener + spawn the accept thread. No-op if already started.
    fn start(&self) -> PyResult<()> {
        let mut at = self
            .accept_thread
            .lock()
            .map_err(|e| PyValueError::new_err(format!("accept_thread mutex poisoned: {e}")))?;
        if at.is_some() {
            return Ok(()); // already running
        }

        // Clean up any stale socket file from a crashed previous master
        // (matches `socket_paths.acquire_socket_path` semantics, the
        // Python side has already verified no live process holds it).
        if self.socket_path.exists() {
            std::fs::remove_file(&self.socket_path).map_err(|e| {
                PyValueError::new_err(format!("remove stale socket {:?}: {e}", self.socket_path))
            })?;
        }

        let listener = UnixListener::bind(&self.socket_path)
            .map_err(|e| PyValueError::new_err(format!("bind {:?}: {e}", self.socket_path)))?;
        listener.set_nonblocking(true).map_err(|e| {
            PyValueError::new_err(format!(
                "configure {:?} as nonblocking: {e}",
                self.socket_path
            ))
        })?;

        // chmod 0600, only the owner UID can connect. SO_PEERCRED on
        // the accepted stream is the second layer of defence.
        let mut perms = std::fs::metadata(&self.socket_path)
            .map_err(|e| PyValueError::new_err(format!("stat socket: {e}")))?
            .permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&self.socket_path, perms)
            .map_err(|e| PyValueError::new_err(format!("chmod socket: {e}")))?;

        // Snapshot Arc handles to move into the accept thread. Cloning an
        // Arc just bumps an atomic refcount, no key-material copy.
        let state = self
            .state
            .lock()
            .map_err(|e| PyValueError::new_err(format!("state mutex poisoned: {e}")))?;
        let state_clone = Arc::clone(
            state
                .as_ref()
                .ok_or_else(|| PyValueError::new_err("server has been stopped, recreate it"))?,
        );
        drop(state);
        let stop_clone = Arc::clone(&self.stop);
        self.stop.store(false, Ordering::SeqCst);

        // The accept loop runs on a native thread. No Python interpreter,
        // no GIL, every request gets dispatched in parallel without
        // serialising on a Python event loop.
        *at = Some(std::thread::spawn(move || {
            accept_loop(listener, state_clone, stop_clone);
        }));
        Ok(())
    }

    /// Stop the accept thread, drop the key state, remove the socket.
    /// Idempotent : safe to call when not running.
    fn stop(&self, py: Python<'_>) -> PyResult<()> {
        self.stop.store(true, Ordering::SeqCst);

        // Take the JoinHandle out under the lock so the join itself
        // doesn't hold the Mutex.
        let handle = {
            let mut at = self
                .accept_thread
                .lock()
                .map_err(|e| PyValueError::new_err(format!("accept_thread mutex poisoned: {e}")))?;
            at.take()
        };

        let accept_panicked = if let Some(h) = handle {
            // The accept thread polls the stop flag every
            // ACCEPT_POLL_INTERVAL; release the GIL so any
            // Python coroutine waiting on the master worker isn't
            // frozen during the join.
            py.detach(|| h.join()).is_err()
        } else {
            false
        };

        // Clear the state, Arc refcount drops, the inner Drop zeroises
        // the master key and subkeys. Per-connection threads still
        // holding their own Arc finish their request first ; their
        // Drop runs when those threads exit.
        let state_poisoned = match self.state.lock() {
            Ok(mut state) => {
                *state = None;
                false
            }
            Err(poisoned) => {
                *poisoned.into_inner() = None;
                true
            }
        };

        // Best-effort socket cleanup. If removal fails (already gone,
        // permissions), the next start() will retry.
        let _ = std::fs::remove_file(&self.socket_path);
        if accept_panicked {
            return Err(PyRuntimeError::new_err("master RPC accept thread panicked"));
        }
        if state_poisoned {
            return Err(PyRuntimeError::new_err(
                "master RPC state mutex was poisoned during shutdown",
            ));
        }
        Ok(())
    }

    /// Update the previous-HMAC subkey (lazy migration during rotation).
    /// `None` clears it. Called from rotate-password handler.
    fn set_prev_hmac(&self, enc: Option<&[u8]>) -> PyResult<()> {
        self.set_optional_slot(|state| &state.prev_hmac_enc, "prev_hmac_enc", enc, None)
    }

    /// Replace the three live sub-key ciphertexts after a master-password
    /// rotation. Called from `vault.unseal` whenever it re-derives keys on
    /// a worker that is already serving as master. Without it the listener
    /// keeps the construction-time generation : followers delegating via
    /// RPC then 401 every token minted under the new hmac_key and tag-fail
    /// every DEK re-wrapped under the new dek_key, while the rotating
    /// master (which reads its own Python state directly) looks healthy.
    ///
    /// Atomic : all three swap under one lock, so a concurrent dispatch
    /// never pairs a new hmac with an old dek. The retiring ciphertexts
    /// are zeroized before the swap. `key` is intentionally untouched --
    /// a master-password rotation reuses the same process WrapKey.
    fn set_subkeys(&self, hmac_enc: &[u8], dek_enc: &[u8], audit_enc: &[u8]) -> PyResult<()> {
        let guard = self
            .state
            .lock()
            .map_err(|e| PyValueError::new_err(format!("MasterRpcServer state poisoned: {e}")))?;
        if let Some(state) = guard.as_ref() {
            validate_wrapped_subkey(state.key.as_slice(), hmac_enc, "hmac_enc")?;
            validate_wrapped_subkey(state.key.as_slice(), dek_enc, "dek_enc")?;
            validate_wrapped_subkey(state.key.as_slice(), audit_enc, "audit_enc")?;
            let replacement = SubKeys {
                hmac_enc: hmac_enc.to_vec(),
                dek_enc: dek_enc.to_vec(),
                audit_enc: audit_enc.to_vec(),
            };
            let mut g = state
                .subkeys
                .lock()
                .map_err(|e| PyValueError::new_err(format!("subkeys lock poisoned: {e}")))?;
            g.zeroize();
            *g = replacement;
            // Fresh generation installed -> a re-unseal re-arms a sealed server.
            state.sealed.store(false, Ordering::Release);
        }
        Ok(())
    }

    /// Fail-closed seal latch (sync). `vault.seal()` calls this so a master
    /// whose RPC listener is still up -- the safety window before the async
    /// `stop()` teardown, or if teardown is skipped -- refuses every crypto op
    /// immediately. The `key` + ciphertexts are still freed by `stop()`/Drop;
    /// this only stops them being served. No-op once torn down (state None).
    fn seal(&self) -> PyResult<()> {
        let guard = self
            .state
            .lock()
            .map_err(|e| PyValueError::new_err(format!("MasterRpcServer state poisoned: {e}")))?;
        if let Some(state) = guard.as_ref() {
            state.sealed.store(true, Ordering::Release);
        }
        Ok(())
    }

    /// update the ha_wrap_key subkey buffer. Called
    /// at master start after `vault.unseal` populates ``_ha_wrap_enc``,
    /// and during master-password rotation when the subkey changes.
    fn set_ha_wrap_enc(&self, enc: Option<&[u8]>) -> PyResult<()> {
        self.set_optional_slot(
            |state| &state.ha_wrap_enc,
            "ha_wrap_enc",
            enc,
            Some(WrappedLength::Exact(HKDF_SUBKEY_BYTES)),
        )
    }

    /// update the pki_wrap_key subkey buffer. Called at master start after
    /// `vault.unseal` populates ``_pki_wrap_enc``, and during master-password
    /// rotation when the subkey changes.
    fn set_pki_wrap_enc(&self, enc: Option<&[u8]>) -> PyResult<()> {
        self.set_optional_slot(
            |state| &state.pki_wrap_enc,
            "pki_wrap_enc",
            enc,
            Some(WrappedLength::Exact(HKDF_SUBKEY_BYTES)),
        )
    }

    /// Push (or clear) the audit Ed25519 seed, AES-GCM-encrypted under `key`.
    /// Called by the master when it loads/rotates its audit identity, so the
    /// live RPC listener can serve `audit_sign_identity` to followers.
    fn set_audit_seed_enc(&self, enc: Option<&[u8]>) -> PyResult<()> {
        self.set_optional_slot(
            |state| &state.audit_seed_enc,
            "audit_seed_enc",
            enc,
            Some(WrappedLength::Exact(32)),
        )
    }

    /// update the ha_password buffer. Called by
    /// ``ha_password.set_ha_password`` (post /cluster/init) and by
    /// ``ha_password.load_ha_password_into_ram`` (post-restart load).
    /// `None` clears the slot ; subsequent ha_password_* / wrap_*_key_
    /// for_joiner ops then return ``ha_password not loaded``.
    fn set_ha_password_enc(&self, enc: Option<&[u8]>) -> PyResult<()> {
        let guard = self
            .state
            .lock()
            .map_err(|e| PyValueError::new_err(format!("MasterRpcServer state poisoned: {e}")))?;
        if let Some(state) = guard.as_ref() {
            if let Some(candidate) = enc {
                validate_wrapped_value(
                    state.key.as_slice(),
                    candidate,
                    "ha_password_enc",
                    WrappedLength::AtLeast(32),
                )?;
            }
            state
                .ha_password_enc
                .replace_from_slice(enc)
                .map_err(PyValueError::new_err)?;
        }
        Ok(())
    }

    /// follow-up -- Python-callable accessor on the
    /// ``ha_password_enc`` slot. Used by ``ha_password.is_loaded_anywhere``
    /// on the master worker, where the local Python ``vault._ha_password_enc``
    /// is ``None`` whenever ``/cluster/init`` (or any later
    /// ``set_ha_password``) landed on a different worker : the
    /// follow-up RPC populates the master Rust state but cannot reach back
    /// into the master process's own Python state. Without this accessor,
    /// the master worker has ``vault._rpc_client = None`` (it does not RPC
    /// to itself) and ``is_loaded_anywhere`` returns ``False`` for every
    /// ``/cluster/ha`` hit that round-robins onto the master.
    ///
    /// Returns ``false`` if the server has been stopped (state moved out
    /// of the outer ``Mutex``) -- consistent with the slot being
    /// functionally unreachable.
    fn has_ha_password_enc(&self) -> PyResult<bool> {
        let guard = self
            .state
            .lock()
            .map_err(|e| PyValueError::new_err(format!("MasterRpcServer state poisoned: {e}")))?;
        let Some(state) = guard.as_ref() else {
            return Ok(false);
        };
        state
            .ha_password_enc
            .is_loaded()
            .map_err(PyValueError::new_err)
    }
}

impl MasterRpcServer {
    /// Internal helper backing the optional encrypted-slot setters.
    /// Locks the server state, optionally authenticates and checks the
    /// wrapped plaintext length, then locks the slot and zeroizes the old
    /// buffer before replacement.
    fn set_optional_slot<F>(
        &self,
        slot: F,
        slot_name: &str,
        enc: Option<&[u8]>,
        expected_length: Option<WrappedLength>,
    ) -> PyResult<()>
    where
        F: for<'a> Fn(&'a MasterRpcState) -> &'a Mutex<Option<Vec<u8>>>,
    {
        let guard = self
            .state
            .lock()
            .map_err(|e| PyValueError::new_err(format!("MasterRpcServer state poisoned: {e}")))?;
        if let Some(state) = guard.as_ref() {
            if let (Some(expected), Some(candidate)) = (expected_length, enc) {
                validate_wrapped_value(state.key.as_slice(), candidate, slot_name, expected)?;
            }
            let mut g = slot(state)
                .lock()
                .map_err(|e| PyValueError::new_err(format!("{slot_name} lock poisoned: {e}")))?;
            if let Some(ref mut old) = *g {
                old.zeroize();
            }
            *g = enc.map(|b| b.to_vec());
        }
        Ok(())
    }
}

// =====================================================================
// Accept loop + per-connection handler. Pure stdlib, no PyO3, all of
// this runs on native OS threads completely outside the GIL.
// =====================================================================

struct ConnectionPermit {
    active: Arc<AtomicUsize>,
}

impl ConnectionPermit {
    fn try_acquire(active: &Arc<AtomicUsize>) -> Option<Self> {
        active
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                (current < MAX_ACTIVE_CONNECTIONS).then_some(current + 1)
            })
            .ok()?;
        Some(Self {
            active: Arc::clone(active),
        })
    }
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Long-running accept loop for the master socket.
///
/// The listener is configured as nonblocking before this thread starts,
/// letting it poll the stop flag at every accept attempt. When Python calls
/// `stop()`, the loop notices within
/// `ACCEPT_POLL_INTERVAL` and exits. Up to `MAX_ACTIVE_CONNECTIONS`
/// accepted connections are handed off to worker threads.
fn accept_loop(listener: UnixListener, state: Arc<MasterRpcState>, stop: Arc<AtomicBool>) {
    let active_connections = Arc::new(AtomicUsize::new(0));
    loop {
        if stop.load(Ordering::SeqCst) {
            return;
        }
        match listener.accept() {
            Ok((stream, _addr)) => {
                let Some(permit) = ConnectionPermit::try_acquire(&active_connections) else {
                    let _ = stream.shutdown(Shutdown::Both);
                    continue;
                };
                let state_clone = Arc::clone(&state);
                // The permit is captured by the closure and released on
                // normal return, panic, or thread-creation failure.
                let _ = std::thread::Builder::new()
                    .name("rhorizon-master-rpc".to_string())
                    .spawn(move || {
                        let _permit = permit;
                        handle_connection(stream, state_clone);
                    });
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(ACCEPT_POLL_INTERVAL);
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => {
                // Resource-pressure and other unexpected errors may be
                // transient. Back off before retrying; the loop rechecks
                // the stop flag before the next accept attempt.
                std::thread::sleep(ACCEPT_POLL_INTERVAL);
            }
        }
    }
}

/// Handle one RPC request : peer-uid check, read frame, dispatch,
/// write response, close. Errors are logged via best-effort returns
/// in the response payload ; never panics out of the worker thread.
fn handle_connection(mut stream: UnixStream, state: Arc<MasterRpcState>) {
    // SO_PEERCRED (Linux) / getpeereid (BSD/macOS), fail-closed if
    // the peer's UID does not match the master's owner UID. Same
    // contract as the previous Python MasterRpcServer.
    if let Ok((peer_uid, _)) = read_peer_cred(&stream) {
        if peer_uid != state.owner_uid {
            let _ = stream.shutdown(Shutdown::Both);
            return;
        }
    } else {
        let _ = stream.shutdown(Shutdown::Both);
        return;
    }

    if stream.set_read_timeout(Some(IO_TIMEOUT)).is_err()
        || stream.set_write_timeout(Some(IO_TIMEOUT)).is_err()
    {
        let _ = stream.shutdown(Shutdown::Both);
        return;
    }

    // -- Read length-prefixed JSON request --
    let req_buf = match read_frame(&mut stream) {
        Ok(buf) => buf,
        Err(_) => {
            let _ = stream.shutdown(Shutdown::Both);
            return;
        }
    };

    // Parsing copies JSON strings into the Value tree, so release and wipe
    // the raw frame as soon as parsing finishes.
    let parsed_request = serde_json::from_slice::<Value>(&req_buf);
    drop(req_buf);

    // -- Parse + dispatch --
    let response_value = match parsed_request {
        Ok(request) => dispatch_request(request, |operation, arguments| {
            dispatch(&state, operation, arguments).map(Value::String)
        }),
        Err(_) => error_response("invalid JSON request"),
    };

    // -- Write length-prefixed JSON response --
    let resp_bytes = response_value.to_bytes();
    drop(response_value);
    let _ = write_frame(&mut stream, &resp_bytes);
    let _ = stream.shutdown(Shutdown::Both);
}

fn read_frame(stream: &mut UnixStream) -> std::io::Result<Zeroizing<Vec<u8>>> {
    rhorizon_custody_core::rpc::read_frame(stream, MAX_PAYLOAD)
}

fn write_frame(stream: &mut UnixStream, payload: &[u8]) -> std::io::Result<()> {
    rhorizon_custody_core::rpc::write_frame(stream, payload, MAX_PAYLOAD)
}

/// Dispatch table for the master RPC operations using the shared JSON wire
/// format. Binary values are hex-encoded in transit; sensitive plaintext and
/// wire copies are wiped by their owning buffers and guards.
fn encode_chained_secret(result: ChainedSecretCiphertext) -> String {
    let mut wire = Vec::with_capacity(
        result.wrapped_dek.len() + result.secret_nonce.len() + result.ciphertext.len(),
    );
    wire.extend_from_slice(&result.wrapped_dek);
    wire.extend_from_slice(&result.secret_nonce);
    wire.extend_from_slice(&result.ciphertext);
    hex::encode(wire)
}

fn encode_sensitive_hex(mut plaintext: Vec<u8>) -> String {
    let encoded = hex::encode(&plaintext);
    plaintext.zeroize();
    encoded
}

fn wrapped_dek_from_args(
    args: &Value,
    encrypted_field: &str,
    nonce_field: &str,
) -> Result<Vec<u8>, String> {
    let encrypted = decode_hex(args, encrypted_field)?;
    let nonce = decode_hex(args, nonce_field)?;
    if nonce.len() != AES_GCM_NONCE_BYTES {
        return Err(format!(
            "{nonce_field} must be exactly {AES_GCM_NONCE_BYTES} bytes"
        ));
    }
    let encrypted_bytes = DEK_WRAPPED_BYTES - AES_GCM_NONCE_BYTES;
    if encrypted.len() != encrypted_bytes {
        return Err(format!(
            "{encrypted_field} must be exactly {encrypted_bytes} bytes"
        ));
    }
    let mut wrapped = Vec::with_capacity(nonce.len() + encrypted.len());
    wrapped.extend_from_slice(&nonce);
    wrapped.extend_from_slice(&encrypted);
    Ok(wrapped)
}

fn dispatch(state: &MasterRpcState, op: &str, args: &Value) -> Result<String, String> {
    if matches!(op, "has_ha_password" | "clear_ha_password") {
        return dispatch_compatibility_control(
            state.sealed.load(Ordering::Acquire),
            &state.ha_password_enc,
            op,
        )
        .expect("HA password status and clear are shared compatibility operations")
        .and_then(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| "invalid shared control response".to_string())
        });
    }
    // Fail-closed: a sealed master refuses every op before touching a subkey.
    if state.sealed.load(Ordering::Acquire) {
        return Err("vault sealed".to_string());
    }
    match op {
        "hmac_sha512" => {
            let msg = Zeroizing::new(decode_hex(args, "message")?);
            hmac_op(state.key.as_slice(), &state.hmac_enc()?, &msg)
        }
        "hmac_sha512_prev" => {
            let msg = Zeroizing::new(decode_hex(args, "message")?);
            let guard = state
                .prev_hmac_enc
                .lock()
                .map_err(|e| format!("prev_hmac lock poisoned: {e}"))?;
            match guard.as_ref() {
                Some(prev_enc) => hmac_op(state.key.as_slice(), prev_enc, &msg),
                None => Ok(String::new()),
            }
        }
        "audit_sign" => {
            // Python wire format : payload is a string (already JSON-
            // serialised audit row), prev_signature is hex.
            let payload = args
                .get("payload")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "missing payload".to_string())?;
            let prev = args
                .get("prev_signature")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            audit_hmac_op(state.key.as_slice(), &state.audit_enc()?, payload, prev)
        }
        // Audit chain Ed25519 signing on behalf of a follower. Same message as
        // `audit_sign` (prev_signature || payload) but signed with the per-node
        // Ed25519 identity seed instead of the symmetric audit_key. The seed is
        // AES-GCM-decrypted under `key`, used on the stack, and zeroized -- it
        // never crosses back to the follower (only the 64-byte signature does).
        "audit_sign_identity" => {
            let payload = args
                .get("payload")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "missing payload".to_string())?;
            let prev = args
                .get("prev_signature")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let seed_enc = require_optional_slot(&state.audit_seed_enc, "audit_seed")?;
            ed25519_sign_op(state.key.as_slice(), &seed_enc, prev, payload)
        }
        "aesgcm_encrypt" => {
            let plaintext = Zeroizing::new(decode_hex(args, "plaintext")?);
            let aad = Zeroizing::new(decode_hex(args, "aad")?);
            let subkey = aes_gcm_decrypt_aad_locked(state.key.as_slice(), &state.dek_enc()?, &[])?;
            let result = aes_gcm_encrypt_aad(&subkey.data, &plaintext, &aad);
            let wrapped = result?;
            // Python wire format : nonce_hex (24 chars) || ct_hex
            // wrapped layout from aes_gcm_encrypt_aad : nonce(12) || ct
            Ok(hex::encode(&wrapped))
        }
        "aesgcm_decrypt" => {
            let ct = decode_hex(args, "ciphertext")?;
            let nonce = decode_hex(args, "nonce")?;
            if nonce.len() != AES_GCM_NONCE_BYTES {
                return Err(format!("nonce must be exactly {AES_GCM_NONCE_BYTES} bytes"));
            }
            let aad = Zeroizing::new(decode_hex(args, "aad")?);
            // aes_gcm_decrypt_aad wants nonce(12) || ct concatenated.
            let mut wrapped = Vec::with_capacity(nonce.len() + ct.len());
            wrapped.extend_from_slice(&nonce);
            wrapped.extend_from_slice(&ct);
            let subkey = aes_gcm_decrypt_aad_locked(state.key.as_slice(), &state.dek_enc()?, &[])?;
            let result = aes_gcm_decrypt_aad(&subkey.data, &wrapped, &aad);
            Ok(encode_sensitive_hex(result?))
        }
        "secret_encrypt" => {
            let plaintext = Zeroizing::new(decode_hex(args, "plaintext")?);
            let dek_aad = Zeroizing::new(decode_hex(args, "dek_aad")?);
            let secret_aad = Zeroizing::new(decode_hex(args, "secret_aad")?);
            let dek_key = aes_gcm_decrypt_aad_locked(state.key.as_slice(), &state.dek_enc()?, &[])?;
            let result = chained_secret_encrypt(&dek_key.data, &plaintext, &dek_aad, &secret_aad);
            Ok(encode_chained_secret(result?))
        }
        "secret_decrypt" => {
            let wrapped_dek = wrapped_dek_from_args(args, "encrypted_dek", "dek_nonce")?;
            let dek_aad = Zeroizing::new(decode_hex(args, "dek_aad")?);
            let ciphertext = decode_hex(args, "ciphertext")?;
            let secret_nonce = decode_hex(args, "secret_nonce")?;
            let secret_aad = Zeroizing::new(decode_hex(args, "secret_aad")?);
            let dek_key = aes_gcm_decrypt_aad_locked(state.key.as_slice(), &state.dek_enc()?, &[])?;
            let result = chained_secret_decrypt(
                &dek_key.data,
                &wrapped_dek,
                &dek_aad,
                &ciphertext,
                &secret_nonce,
                &secret_aad,
            );
            let plaintext = result?;
            Ok(hex::encode(plaintext.as_slice()))
        }
        "secret_reencrypt" => {
            let old_wrapped_dek =
                wrapped_dek_from_args(args, "old_encrypted_dek", "old_dek_nonce")?;
            let old_dek_aad = Zeroizing::new(decode_hex(args, "old_dek_aad")?);
            let old_ciphertext = decode_hex(args, "old_ciphertext")?;
            let old_secret_nonce = decode_hex(args, "old_secret_nonce")?;
            let old_secret_aad = Zeroizing::new(decode_hex(args, "old_secret_aad")?);
            let new_dek_aad = Zeroizing::new(decode_hex(args, "new_dek_aad")?);
            let new_secret_aad = Zeroizing::new(decode_hex(args, "new_secret_aad")?);
            let dek_key = aes_gcm_decrypt_aad_locked(state.key.as_slice(), &state.dek_enc()?, &[])?;
            let result = chained_secret_reencrypt(
                &dek_key.data,
                ChainedSecretReencryptInput {
                    old_wrapped_dek: &old_wrapped_dek,
                    old_dek_aad: &old_dek_aad,
                    old_ciphertext: &old_ciphertext,
                    old_secret_nonce: &old_secret_nonce,
                    old_secret_aad: &old_secret_aad,
                    new_dek_aad: &new_dek_aad,
                    new_secret_aad: &new_secret_aad,
                },
            );
            Ok(encode_chained_secret(result?))
        }
        // HMAC-SHA512(ha_password, message). Used by
        // /cluster/join to verify the joiner's HMAC proof of the canonical
        // (cluster_id || node_uuid || source_ip || nonce || issued_at)
        // bytes. ha_password is wrapped under master `key` ; decrypt it,
        // run HMAC, zeroise.
        "ha_password_hmac" => {
            let msg = decode_hex(args, "message")?;
            let buf = state.ha_password_enc.snapshot("ha_password")?;
            hmac_op(state.key.as_slice(), &buf, &msg)
        }
        // AES-256-GCM wrap of `plaintext` under
        // ha_wrap_key with AAD binding. Wire format identical to
        // `aesgcm_encrypt` (subkey is the only difference) : combined
        // nonce || ct, hex-encoded.
        "ha_wrap_encrypt" => {
            let plaintext = Zeroizing::new(decode_hex(args, "plaintext")?);
            let aad = Zeroizing::new(decode_hex(args, "aad")?);
            let buf = require_optional_slot(&state.ha_wrap_enc, "ha_wrap")?;
            let subkey = aes_gcm_decrypt_aad_locked(state.key.as_slice(), &buf, &[])?;
            let result = aes_gcm_encrypt_aad(&subkey.data, &plaintext, &aad);
            Ok(hex::encode(&result?))
        }
        // inverse of `ha_wrap_encrypt`. Wire format
        // is the combined nonce || ct blob from the encrypt side, hex.
        "ha_wrap_decrypt" => {
            let wrapped = decode_hex(args, "wrapped")?;
            let aad = Zeroizing::new(decode_hex(args, "aad")?);
            let buf = require_optional_slot(&state.ha_wrap_enc, "ha_wrap")?;
            let subkey = aes_gcm_decrypt_aad_locked(state.key.as_slice(), &buf, &[])?;
            let plaintext = aes_gcm_decrypt_aad_locked(&subkey.data, &wrapped, &aad)?;
            Ok(hex::encode(&plaintext.data))
        }
        // PKI-engine CA key at-rest wrap under pki_wrap_key. Same shape as
        // `ha_wrap_encrypt` (subkey is the only difference): combined
        // nonce || ct, hex-encoded.
        "pki_wrap_encrypt" => {
            let plaintext = Zeroizing::new(decode_hex(args, "plaintext")?);
            let aad = Zeroizing::new(decode_hex(args, "aad")?);
            let buf = require_optional_slot(&state.pki_wrap_enc, "pki_wrap")?;
            let subkey = aes_gcm_decrypt_aad_locked(state.key.as_slice(), &buf, &[])?;
            let result = aes_gcm_encrypt_aad(&subkey.data, &plaintext, &aad);
            Ok(hex::encode(&result?))
        }
        // inverse of `pki_wrap_encrypt`. Wire format is the combined
        // nonce || ct blob from the encrypt side, hex.
        "pki_wrap_decrypt" => {
            let wrapped = decode_hex(args, "wrapped")?;
            let aad = Zeroizing::new(decode_hex(args, "aad")?);
            let buf = require_optional_slot(&state.pki_wrap_enc, "pki_wrap")?;
            let subkey = aes_gcm_decrypt_aad_locked(state.key.as_slice(), &buf, &[])?;
            let plaintext = aes_gcm_decrypt_aad_locked(&subkey.data, &wrapped, &aad)?;
            Ok(hex::encode(&plaintext.data))
        }
        // HKDF(ha_password, info=b"cluster-node-key-
        // wrap:"+node_uuid)[:32] then AES-256-GCM(derived, node_key_pem,
        // aad=b"vault-cluster:node-key:"+node_uuid). Returns combined
        // nonce || ct, hex. The joiner replays the HKDF derivation
        // locally to unwrap the node-key after /cluster/join.
        "wrap_node_key_for_joiner" => wrap_for_joiner_op(
            state,
            args,
            "node_key_pem",
            b"cluster-node-key-wrap:",
            b"vault-cluster:node-key:",
        ),
        // same recipe as `wrap_node_key_for_joiner`
        // with the server-cert HKDF info / AAD domain. Distinct
        // domain enforces that a server-key wrap cannot be re-cast as a
        // node-key wrap (or vice versa) under the same ha_password +
        // node_uuid.
        "wrap_server_key_for_joiner" => wrap_for_joiner_op(
            state,
            args,
            "server_key_pem",
            b"cluster-server-key-wrap:",
            b"vault-cluster:server-key:",
        ),
        // follower-routed set_ha_password requires
        // master to learn the new ha_password buffer (the Python ha_
        // password.set_ha_password singleton lives on whichever worker
        // received the request and cannot push directly to a different
        // process). The follower sends the plaintext over the trusted
        // Unix socket ; the master encrypts it under its own master key
        // and stores in state.ha_password_enc. Returns "" on success.
        // Idempotent : a re-push of the same plain replaces the existing
        // buffer (zeroising the previous one). Companion RPC for
        // `clear_ha_password` lets ha_password.clear() propagate too.
        "set_ha_password_from_plain" => {
            let plain = Zeroizing::new(decode_hex(args, "plain")?);
            let wrapped = aes_gcm_encrypt_aad(state.key.as_slice(), &plain, &[]);
            let wrapped = wrapped?;
            state.ha_password_enc.replace(Some(wrapped))?;
            Ok(String::new())
        }
        other => Err(format!("unknown op: {other}")),
    }
}

/// helper -- read a `Mutex<Option<Vec<u8>>>` slot and
/// surface a meaningful error when it has not been populated yet.
/// The returned guarded clone lets the caller drop the mutex immediately
/// and wipes the wrapped bytes automatically when the operation completes.
fn require_optional_slot(
    slot: &Mutex<Option<Vec<u8>>>,
    label: &str,
) -> Result<Zeroizing<Vec<u8>>, String> {
    let guard = slot
        .lock()
        .map_err(|e| format!("{label} lock poisoned: {e}"))?;
    guard
        .as_ref()
        .map(|value| Zeroizing::new(value.clone()))
        .ok_or_else(|| format!("{label} not loaded"))
}

/// shared body for `wrap_node_key_for_joiner` and
/// `wrap_server_key_for_joiner`. Reads ``<pem_arg_name>`` and
/// ``node_uuid`` from `args`, constructs the per-call HKDF info + AAD
/// from the hardcoded prefix + node_uuid (matching the Python module-
/// level constants in `ha_password.py`), recovers the ha_password
/// plaintext under master `key`, and delegates to
/// `hkdf_derive_and_aes_gcm_encrypt_aad`. The recovered ha_password
/// plaintext is zeroised before return.
fn wrap_for_joiner_op(
    state: &MasterRpcState,
    args: &Value,
    pem_arg_name: &str,
    info_prefix: &[u8],
    aad_prefix: &[u8],
) -> Result<String, String> {
    let pem = Zeroizing::new(decode_hex(args, pem_arg_name)?);
    let node_uuid = args
        .get("node_uuid")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing node_uuid".to_string())?;
    let mut info = Vec::with_capacity(info_prefix.len() + node_uuid.len());
    info.extend_from_slice(info_prefix);
    info.extend_from_slice(node_uuid.as_bytes());
    let mut aad = Vec::with_capacity(aad_prefix.len() + node_uuid.len());
    aad.extend_from_slice(aad_prefix);
    aad.extend_from_slice(node_uuid.as_bytes());
    let buf = state.ha_password_enc.snapshot("ha_password")?;
    let parent = aes_gcm_decrypt_aad_locked(state.key.as_slice(), &buf, &[])?;
    let result = hkdf_derive_and_aes_gcm_encrypt_aad(&parent.data, &info, &pem, &aad);
    Ok(hex::encode(&result?))
}

/// Ed25519-sign `prev || payload` with a wrapped 32-byte seed. Decrypts the
/// seed under the master key, signs (PureEd25519, message signed directly --
/// identical construction to `crypto.sign_audit_ed25519` and the Rust
/// `AuditSigner`, gated by the parity test), zeroizes the seed + transient
/// SigningKey, and returns the 64-byte signature hex.
fn ed25519_sign_op(
    master_key: &[u8],
    wrapped_seed: &[u8],
    prev_signature: &str,
    payload: &str,
) -> Result<String, String> {
    let seed = aes_gcm_decrypt_aad_locked(master_key, wrapped_seed, &[])?;
    if seed.data.len() != 32 {
        return Err("audit_seed must be 32 bytes".to_string());
    }
    audit_ed25519_sign(&seed.data, payload, prev_signature).map(hex::encode)
}

/// HMAC-SHA512 with a wrapped subkey. Decrypts the subkey using the
/// master key into locked memory, runs HMAC, then wipes and unlocks the
/// plaintext subkey on drop.
fn hmac_op(master_key: &[u8], wrapped_subkey: &[u8], message: &[u8]) -> Result<String, String> {
    let subkey = aes_gcm_decrypt_aad_locked(master_key, wrapped_subkey, &[])?;
    hmac_sha512(&subkey.data, message).map(hex::encode)
}

fn audit_hmac_op(
    master_key: &[u8],
    wrapped_subkey: &[u8],
    payload: &str,
    prev_signature: &str,
) -> Result<String, String> {
    let subkey = aes_gcm_decrypt_aad_locked(master_key, wrapped_subkey, &[])?;
    audit_hmac_sha512(&subkey.data, payload, prev_signature).map(hex::encode)
}

/// Read a hex-encoded byte argument from the request JSON.
fn decode_hex(args: &Value, key: &str) -> Result<Vec<u8>, String> {
    let s = args
        .get(key)
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("missing arg: {key}"))?;
    hex::decode(s).map_err(|e| format!("invalid hex for {key}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aes_gcm_encrypt_aad as enc_aad;
    use crate::{AES_GCM_TAG_BYTES, XCHACHA_NONCE_BYTES};
    use serde_json::json;

    /// Build a state for tests : 32-byte master key, three subkeys
    /// wrapped under it. Returns the state plus the plain hmac/dek/audit
    /// subkeys so tests can reproduce the expected output.
    fn fixture() -> (MasterRpcState, Vec<u8>, Vec<u8>, Vec<u8>) {
        let master = [0x42u8; 32];
        let hmac_subkey = [0x01u8; HKDF_SUBKEY_BYTES];
        let dek_subkey = [0x02u8; 32];
        let audit_subkey = [0x03u8; HKDF_SUBKEY_BYTES];
        let hmac_enc = enc_aad(&master, &hmac_subkey, &[]).unwrap();
        let dek_enc = enc_aad(&master, &dek_subkey, &[]).unwrap();
        let audit_enc = enc_aad(&master, &audit_subkey, &[]).unwrap();
        let state = MasterRpcState {
            key: LockedBuf::from_slice(&master).expect("mlock master rpc key"),
            subkeys: Mutex::new(SubKeys {
                hmac_enc,
                dek_enc,
                audit_enc,
            }),
            ha_wrap_enc: Mutex::new(None),
            pki_wrap_enc: Mutex::new(None),
            ha_password_enc: WrappedSecretSlot::empty("ha_password_enc"),
            prev_hmac_enc: Mutex::new(None),
            audit_seed_enc: Mutex::new(None),
            owner_uid: 0,
            sealed: AtomicBool::new(false),
        };
        (
            state,
            hmac_subkey.to_vec(),
            dek_subkey.to_vec(),
            audit_subkey.to_vec(),
        )
    }

    #[test]
    fn fixture_master_key_is_locked() {
        let (state, _, _, _) = fixture();
        assert!(state.key.is_locked());
        assert_eq!(state.key.as_slice(), &[0x42u8; 32]);
    }

    #[test]
    fn connection_permit_enforces_limit_and_releases_capacity() {
        let active = Arc::new(AtomicUsize::new(0));
        let mut permits: Vec<ConnectionPermit> = (0..MAX_ACTIVE_CONNECTIONS)
            .map(|_| ConnectionPermit::try_acquire(&active).unwrap())
            .collect();

        assert_eq!(active.load(Ordering::Acquire), MAX_ACTIVE_CONNECTIONS);
        assert!(ConnectionPermit::try_acquire(&active).is_none());

        drop(permits.pop());
        let replacement = ConnectionPermit::try_acquire(&active).unwrap();
        assert_eq!(active.load(Ordering::Acquire), MAX_ACTIVE_CONNECTIONS);

        drop(replacement);
        drop(permits);
        assert_eq!(active.load(Ordering::Acquire), 0);
    }

    #[test]
    fn zeroize_json_strings_clears_nested_string_values() {
        let mut value = json!({
            "secret": "top-secret",
            "nested": ["second-secret", {"value": "third-secret"}],
            "number": 7,
        });

        zeroize_json_strings(&mut value);

        assert_eq!(value["secret"], "");
        assert_eq!(value["nested"][0], "");
        assert_eq!(value["nested"][1]["value"], "");
        assert_eq!(value["number"], 7);
    }

    #[test]
    fn dispatch_hmac_matches_direct_computation() {
        let (state, hmac_subkey, _, _) = fixture();
        let msg = b"hello world";
        let args = json!({ "message": hex::encode(msg) });

        let got = dispatch(&state, "hmac_sha512", &args).unwrap();

        // Reproduce the expected HMAC directly with the plain subkey.
        let mut mac = <HmacSha512 as Mac>::new_from_slice(&hmac_subkey).unwrap();
        mac.update(msg);
        let expected = hex::encode(mac.finalize().into_bytes());
        assert_eq!(got, expected);
    }

    #[test]
    fn dispatch_refuses_when_sealed() {
        let (state, _, _, _) = fixture();
        // Arm the fail-closed seal latch (what vault.seal() does sync).
        state.sealed.store(true, Ordering::Release);
        let args = json!({ "message": hex::encode(b"x") });
        let err = dispatch(&state, "hmac_sha512", &args).unwrap_err();
        assert!(err.contains("sealed"), "expected sealed error, got: {err}");
        // set_subkeys re-arms (a re-unseal refresh clears the latch).
        state.sealed.store(false, Ordering::Release);
        assert!(dispatch(&state, "hmac_sha512", &args).is_ok());
    }

    #[test]
    fn dispatch_aesgcm_roundtrip() {
        let (state, _, _, _) = fixture();
        let plaintext = b"top secret value";
        let aad = b"namespace=default,name=hello";

        let enc_args = json!({
            "plaintext": hex::encode(plaintext),
            "aad": hex::encode(aad),
        });
        let wrapped_hex = dispatch(&state, "aesgcm_encrypt", &enc_args).unwrap();
        // Python wire format: nonce_hex || ct_hex.
        let nonce_hex_len = AES_GCM_NONCE_BYTES * 2;
        let nonce_hex = &wrapped_hex[..nonce_hex_len];
        let ct_hex = &wrapped_hex[nonce_hex_len..];

        let dec_args = json!({
            "ciphertext": ct_hex,
            "nonce": nonce_hex,
            "aad": hex::encode(aad),
        });
        let got = dispatch(&state, "aesgcm_decrypt", &dec_args).unwrap();
        assert_eq!(got, hex::encode(plaintext));
    }

    #[test]
    fn dispatch_aesgcm_rejects_malformed_nonce_boundary() {
        let (state, _, _, _) = fixture();
        let aad = b"namespace=default,name=hello";
        let wrapped_hex = dispatch(
            &state,
            "aesgcm_encrypt",
            &json!({
                "plaintext": hex::encode(b"top secret value"),
                "aad": hex::encode(aad),
            }),
        )
        .unwrap();

        let err = dispatch(
            &state,
            "aesgcm_decrypt",
            &json!({
                "ciphertext": wrapped_hex,
                "nonce": "",
                "aad": hex::encode(aad),
            }),
        )
        .unwrap_err();

        assert_eq!(err, "nonce must be exactly 12 bytes");
    }

    #[test]
    fn wrapped_dek_parser_enforces_component_lengths() {
        const ENCRYPTED_DEK_BYTES: usize = DEK_WRAPPED_BYTES - AES_GCM_NONCE_BYTES;
        let valid = json!({
            "encrypted_dek": hex::encode([0u8; ENCRYPTED_DEK_BYTES]),
            "dek_nonce": hex::encode([0u8; AES_GCM_NONCE_BYTES]),
        });
        assert_eq!(
            wrapped_dek_from_args(&valid, "encrypted_dek", "dek_nonce")
                .unwrap()
                .len(),
            DEK_WRAPPED_BYTES
        );

        let short_nonce = json!({
            "encrypted_dek": hex::encode([0u8; ENCRYPTED_DEK_BYTES]),
            "dek_nonce": hex::encode([0u8; AES_GCM_NONCE_BYTES - 1]),
        });
        assert_eq!(
            wrapped_dek_from_args(&short_nonce, "encrypted_dek", "dek_nonce").unwrap_err(),
            format!("dek_nonce must be exactly {AES_GCM_NONCE_BYTES} bytes")
        );

        let short_ciphertext = json!({
            "encrypted_dek": hex::encode([0u8; ENCRYPTED_DEK_BYTES - 1]),
            "dek_nonce": hex::encode([0u8; AES_GCM_NONCE_BYTES]),
        });
        assert_eq!(
            wrapped_dek_from_args(&short_ciphertext, "encrypted_dek", "dek_nonce").unwrap_err(),
            format!("encrypted_dek must be exactly {ENCRYPTED_DEK_BYTES} bytes")
        );
    }

    #[test]
    fn dispatch_chained_secret_roundtrip_and_reencrypt() {
        let (state, _, _, _) = fixture();
        let plaintext = b"secret value";
        let old_dek_aad = b"dek:old";
        let old_secret_aad = b"secret:legacy:binding";
        let encrypted = dispatch(
            &state,
            "secret_encrypt",
            &json!({
                "plaintext": hex::encode(plaintext),
                "dek_aad": hex::encode(old_dek_aad),
                "secret_aad": hex::encode(old_secret_aad),
            }),
        )
        .unwrap();
        let wire = hex::decode(encrypted).unwrap();
        let dek_nonce_end = AES_GCM_NONCE_BYTES;
        let wrapped_dek_end = DEK_WRAPPED_BYTES;
        let secret_nonce_end = DEK_WRAPPED_BYTES + XCHACHA_NONCE_BYTES;
        let decrypted = dispatch(
            &state,
            "secret_decrypt",
            &json!({
                "dek_nonce": hex::encode(&wire[..dek_nonce_end]),
                "encrypted_dek": hex::encode(&wire[dek_nonce_end..wrapped_dek_end]),
                "secret_nonce": hex::encode(&wire[wrapped_dek_end..secret_nonce_end]),
                "ciphertext": hex::encode(&wire[secret_nonce_end..]),
                "dek_aad": hex::encode(old_dek_aad),
                "secret_aad": hex::encode(old_secret_aad),
            }),
        )
        .unwrap();
        assert_eq!(decrypted, hex::encode(plaintext));

        let new_dek_aad = b"dek:new";
        let new_secret_aad = b"secret:v2:new-binding";
        let reencrypted = dispatch(
            &state,
            "secret_reencrypt",
            &json!({
                "old_dek_nonce": hex::encode(&wire[..dek_nonce_end]),
                "old_encrypted_dek": hex::encode(&wire[dek_nonce_end..wrapped_dek_end]),
                "old_secret_nonce": hex::encode(&wire[wrapped_dek_end..secret_nonce_end]),
                "old_ciphertext": hex::encode(&wire[secret_nonce_end..]),
                "old_dek_aad": hex::encode(old_dek_aad),
                "old_secret_aad": hex::encode(old_secret_aad),
                "new_dek_aad": hex::encode(new_dek_aad),
                "new_secret_aad": hex::encode(new_secret_aad),
            }),
        )
        .unwrap();
        let new_wire = hex::decode(reencrypted).unwrap();
        assert_ne!(
            &new_wire[dek_nonce_end..wrapped_dek_end],
            &wire[dek_nonce_end..wrapped_dek_end]
        );
        let reopened = dispatch(
            &state,
            "secret_decrypt",
            &json!({
                "dek_nonce": hex::encode(&new_wire[..dek_nonce_end]),
                "encrypted_dek": hex::encode(&new_wire[dek_nonce_end..wrapped_dek_end]),
                "secret_nonce": hex::encode(&new_wire[wrapped_dek_end..secret_nonce_end]),
                "ciphertext": hex::encode(&new_wire[secret_nonce_end..]),
                "dek_aad": hex::encode(new_dek_aad),
                "secret_aad": hex::encode(new_secret_aad),
            }),
        )
        .unwrap();
        assert_eq!(reopened, hex::encode(plaintext));
    }

    #[test]
    fn dispatch_audit_sign_chains_prev_then_payload() {
        let (state, _, _, audit_subkey) = fixture();
        let payload = "{\"action\":\"unseal\"}";
        let prev = "abcdef0123456789";

        let args = json!({ "payload": payload, "prev_signature": prev });
        let got = dispatch(&state, "audit_sign", &args).unwrap();

        // Direct computation : HMAC(audit_subkey, prev || payload) with
        // prev and payload concatenated as ASCII strings (Python wire
        // contract).
        let mut chained = String::from(prev);
        chained.push_str(payload);
        let mut mac = <HmacSha512 as Mac>::new_from_slice(&audit_subkey).unwrap();
        mac.update(chained.as_bytes());
        let expected = hex::encode(mac.finalize().into_bytes());
        assert_eq!(got, expected);
    }

    #[test]
    fn dispatch_audit_sign_identity_matches_rfc8032() {
        // RFC 8032 TEST 1 seed + signature. The op wraps the seed under the
        // master key, decrypts, and Ed25519-signs prev||payload. With prev=""
        // and payload="" the message is empty -> the RFC TEST 1 signature.
        let (state, _, _, _) = fixture();
        let seed = hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
            .unwrap();
        let seed_enc = enc_aad(state.key.as_slice(), &seed, &[]).unwrap();
        *state.audit_seed_enc.lock().unwrap() = Some(seed_enc);

        let args = json!({ "payload": "", "prev_signature": "" });
        let got = dispatch(&state, "audit_sign_identity", &args).unwrap();
        assert_eq!(
            got,
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555f\
             b8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        );
    }

    #[test]
    fn dispatch_audit_sign_identity_chains_and_errors_when_unset() {
        let (state, _, _, _) = fixture();
        // Unset seed -> op errors (follower falls back / surfaces upstream).
        let args = json!({ "payload": "p", "prev_signature": "a" });
        assert!(dispatch(&state, "audit_sign_identity", &args).is_err());

        // With a seed, prev is bound into the signature (chain tamper-evidence).
        let seed = [0x07u8; 32];
        let seed_enc = enc_aad(state.key.as_slice(), &seed, &[]).unwrap();
        *state.audit_seed_enc.lock().unwrap() = Some(seed_enc);
        let s1 = dispatch(
            &state,
            "audit_sign_identity",
            &json!({ "payload": "p", "prev_signature": "a" }),
        )
        .unwrap();
        let s2 = dispatch(
            &state,
            "audit_sign_identity",
            &json!({ "payload": "p", "prev_signature": "b" }),
        )
        .unwrap();
        assert_ne!(s1, s2);
    }

    #[test]
    fn dispatch_hmac_prev_returns_empty_when_unset() {
        let (state, _, _, _) = fixture();
        let args = json!({ "message": "deadbeef" });
        let got = dispatch(&state, "hmac_sha512_prev", &args).unwrap();
        assert!(
            got.is_empty(),
            "expected empty string when prev_hmac_enc is None"
        );
    }

    #[test]
    fn dispatch_unknown_op_errors() {
        let (state, _, _, _) = fixture();
        let args = json!({});
        let err = dispatch(&state, "rotate_planet", &args);
        assert!(err.is_err());
        assert!(err.unwrap_err().contains("unknown op"));
    }

    #[test]
    fn dispatch_missing_message_errors() {
        let (state, _, _, _) = fixture();
        let args = json!({}); // no "message" key
        let err = dispatch(&state, "hmac_sha512", &args);
        assert!(err.is_err());
    }

    #[test]
    fn skeleton_constructs_and_drops_cleanly() {
        // Valid wrapped subkeys exercise construction and Drop zeroisation.
        let master = [0u8; 32];
        let hmac_enc = enc_aad(&master, &[1u8; HKDF_SUBKEY_BYTES], &[]).unwrap();
        let dek_enc = enc_aad(&master, &[2u8; HKDF_SUBKEY_BYTES], &[]).unwrap();
        let audit_enc = enc_aad(&master, &[3u8; HKDF_SUBKEY_BYTES], &[]).unwrap();
        let s = MasterRpcServer::new_from_key_bytes(
            "/tmp/rhorizon-test-skeleton.sock",
            &master,
            &hmac_enc,
            &dek_enc,
            &audit_enc,
            0,
        )
        .expect("constructor");
        drop(s);
    }

    #[test]
    fn constructor_rejects_invalid_wrapped_subkeys() {
        let master = [0u8; 32];
        let valid = enc_aad(&master, &[1u8; HKDF_SUBKEY_BYTES], &[]).unwrap();
        let wrong_length = enc_aad(&master, &[2u8; HKDF_SUBKEY_BYTES - 1], &[]).unwrap();

        assert!(MasterRpcServer::new_from_key_bytes(
            "/tmp/rhorizon-test-invalid-ciphertext.sock",
            &master,
            b"invalid ciphertext",
            &valid,
            &valid,
            0,
        )
        .is_err());
        assert!(MasterRpcServer::new_from_key_bytes(
            "/tmp/rhorizon-test-invalid-length.sock",
            &master,
            &wrong_length,
            &valid,
            &valid,
            0,
        )
        .is_err());
    }

    #[test]
    fn rejects_wrong_master_key_size() {
        assert!(MasterRpcServer::new_from_key_bytes(
            "/tmp/x.sock",
            &[0u8; 16], // too small
            b"h",
            b"d",
            b"a",
            0,
        )
        .is_err());
    }

    // -- ha_password / ha_wrap / wrap_*_for_joiner ops --

    /// Return a fixture state populated with `ha_wrap_enc` and
    /// `ha_password_enc`.
    fn fixture_with_ha(ha_wrap_subkey: &[u8; 32], ha_password: &[u8]) -> MasterRpcState {
        let (state, _, _, _) = fixture();
        let ha_wrap_enc = enc_aad(state.key.as_slice(), ha_wrap_subkey, &[]).unwrap();
        let ha_password_enc = enc_aad(state.key.as_slice(), ha_password, &[]).unwrap();
        *state.ha_wrap_enc.lock().unwrap() = Some(ha_wrap_enc);
        state
            .ha_password_enc
            .replace(Some(ha_password_enc))
            .unwrap();
        state
    }

    #[test]
    fn dispatch_ha_password_hmac_matches_direct_computation() {
        let ha_password = b"unguessable-cluster-ha-password-32".to_vec();
        let state = fixture_with_ha(&[0xA0u8; 32], &ha_password);
        let msg = b"cluster_id||node_uuid||source_ip||nonce||issued_at";
        let args = json!({ "message": hex::encode(msg) });

        let got = dispatch(&state, "ha_password_hmac", &args).unwrap();

        let mut mac = <HmacSha512 as Mac>::new_from_slice(&ha_password).unwrap();
        mac.update(msg);
        let expected = hex::encode(mac.finalize().into_bytes());
        assert_eq!(got, expected);
    }

    #[test]
    fn dispatch_ha_password_hmac_unloaded_errors() {
        let (state, _, _, _) = fixture();
        let args = json!({ "message": hex::encode(b"deadbeef") });
        let err = dispatch(&state, "ha_password_hmac", &args).unwrap_err();
        assert!(err.contains("ha_password"), "got: {err}");
    }

    #[test]
    fn dispatch_ha_wrap_encrypt_decrypt_roundtrip() {
        let state = fixture_with_ha(&[0xB1u8; 32], b"ha-password");
        let plaintext = b"row-payload";
        let aad = b"vault-cluster:ha_password";

        let enc_args = json!({
            "plaintext": hex::encode(plaintext),
            "aad": hex::encode(aad),
        });
        let wrapped_hex = dispatch(&state, "ha_wrap_encrypt", &enc_args).unwrap();
        // Wire format is the combined nonce || ciphertext hex blob.
        let dec_args = json!({
            "wrapped": wrapped_hex,
            "aad": hex::encode(aad),
        });
        let got = dispatch(&state, "ha_wrap_decrypt", &dec_args).unwrap();
        assert_eq!(got, hex::encode(plaintext));
    }

    #[test]
    fn dispatch_ha_wrap_aad_mismatch_fails() {
        let state = fixture_with_ha(&[0xC2u8; 32], b"hap");
        let wrapped_hex = dispatch(
            &state,
            "ha_wrap_encrypt",
            &json!({
                "plaintext": hex::encode(b"x"),
                "aad": hex::encode(b"aad-A"),
            }),
        )
        .unwrap();
        let err = dispatch(
            &state,
            "ha_wrap_decrypt",
            &json!({
                "wrapped": wrapped_hex,
                "aad": hex::encode(b"aad-B"),
            }),
        );
        assert!(err.is_err(), "expected AAD mismatch to fail");
    }

    #[test]
    fn dispatch_pki_wrap_roundtrip_and_aad_binding() {
        let (state, _, _, _) = fixture();
        let pki_wrap_enc = enc_aad(state.key.as_slice(), &[0xD3u8; 32], &[]).unwrap();
        *state.pki_wrap_enc.lock().unwrap() = Some(pki_wrap_enc);
        let plaintext = b"pki-ca-private-key";
        let aad = b"pki-ca:root";

        let wrapped_hex = dispatch(
            &state,
            "pki_wrap_encrypt",
            &json!({
                "plaintext": hex::encode(plaintext),
                "aad": hex::encode(aad),
            }),
        )
        .unwrap();
        let got = dispatch(
            &state,
            "pki_wrap_decrypt",
            &json!({
                "wrapped": wrapped_hex.clone(),
                "aad": hex::encode(aad),
            }),
        )
        .unwrap();
        assert_eq!(got, hex::encode(plaintext));

        assert!(dispatch(
            &state,
            "pki_wrap_decrypt",
            &json!({
                "wrapped": wrapped_hex,
                "aad": hex::encode(b"pki-ca:other"),
            }),
        )
        .is_err());
    }

    #[test]
    fn dispatch_wrap_node_key_for_joiner_unwraps_with_python_recipe() {
        // The Rust master wraps under HKDF(ha_password, info=
        // b"cluster-node-key-wrap:"+node_uuid)[:32] with aad=
        // b"vault-cluster:node-key:"+node_uuid. The joiner replays the
        // same HKDF derivation locally to unwrap. Reproduce the joiner-
        // side path directly with crypto crates to validate the wire.
        use aes_gcm::aead::{Aead, KeyInit, Payload};
        use aes_gcm::{Aes256Gcm, Nonce};
        use hkdf::Hkdf;
        use sha2::Sha512;

        let ha_password = b"x".repeat(32);
        let state = fixture_with_ha(&[0xD3u8; 32], &ha_password);
        let node_key_pem = b"-----BEGIN PRIVATE KEY-----\nfake\n-----END\n".to_vec();
        let node_uuid = "deadbeef".repeat(4);

        let args = json!({
            "node_key_pem": hex::encode(&node_key_pem),
            "node_uuid": &node_uuid,
        });
        let wrapped_hex = dispatch(&state, "wrap_node_key_for_joiner", &args).unwrap();
        let wrapped = hex::decode(&wrapped_hex).unwrap();
        assert_eq!(
            wrapped.len(),
            AES_GCM_NONCE_BYTES + AES_GCM_TAG_BYTES + node_key_pem.len()
        );

        // Joiner-side recipe.
        let mut info = b"cluster-node-key-wrap:".to_vec();
        info.extend_from_slice(node_uuid.as_bytes());
        let mut aad = b"vault-cluster:node-key:".to_vec();
        aad.extend_from_slice(node_uuid.as_bytes());
        let hk = Hkdf::<Sha512>::new(None, &ha_password);
        let mut derived = [0u8; HKDF_SUBKEY_BYTES];
        hk.expand(&info, &mut derived).unwrap();
        let cipher = Aes256Gcm::new_from_slice(&derived).unwrap();
        let nonce = Nonce::from_slice(&wrapped[..AES_GCM_NONCE_BYTES]);
        let plain = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &wrapped[AES_GCM_NONCE_BYTES..],
                    aad: &aad,
                },
            )
            .expect("joiner recipe must unwrap the master's blob");
        assert_eq!(plain, node_key_pem);
    }

    #[test]
    fn dispatch_wrap_server_key_for_joiner_distinct_domain() {
        // The server-key blob must NOT decrypt as a node-key blob, even
        // with the same ha_password + node_uuid : the HKDF info /
        // AAD domains are deliberately separate.
        use aes_gcm::aead::{Aead, KeyInit, Payload};
        use aes_gcm::{Aes256Gcm, Nonce};
        use hkdf::Hkdf;
        use sha2::Sha512;

        let ha_password = b"y".repeat(32);
        let state = fixture_with_ha(&[0xE4u8; 32], &ha_password);
        let server_key_pem = b"-----BEGIN PRIVATE KEY-----\nserverkey\n-----END\n".to_vec();
        let node_uuid = "cafebabe".repeat(4);

        let args = json!({
            "server_key_pem": hex::encode(&server_key_pem),
            "node_uuid": &node_uuid,
        });
        let wrapped_hex = dispatch(&state, "wrap_server_key_for_joiner", &args).unwrap();
        let wrapped = hex::decode(&wrapped_hex).unwrap();

        // Joiner unwraps with the server-key domain : works.
        let mut info = b"cluster-server-key-wrap:".to_vec();
        info.extend_from_slice(node_uuid.as_bytes());
        let mut aad = b"vault-cluster:server-key:".to_vec();
        aad.extend_from_slice(node_uuid.as_bytes());
        let hk = Hkdf::<Sha512>::new(None, &ha_password);
        let mut derived = [0u8; HKDF_SUBKEY_BYTES];
        hk.expand(&info, &mut derived).unwrap();
        let cipher = Aes256Gcm::new_from_slice(&derived).unwrap();
        let nonce = Nonce::from_slice(&wrapped[..AES_GCM_NONCE_BYTES]);
        let plain = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &wrapped[AES_GCM_NONCE_BYTES..],
                    aad: &aad,
                },
            )
            .expect("server domain must unwrap");
        assert_eq!(plain, server_key_pem);

        // Joiner tries to unwrap with the NODE-key domain : fails (AAD +
        // info mismatch combined).
        let mut wrong_info = b"cluster-node-key-wrap:".to_vec();
        wrong_info.extend_from_slice(node_uuid.as_bytes());
        let mut wrong_aad = b"vault-cluster:node-key:".to_vec();
        wrong_aad.extend_from_slice(node_uuid.as_bytes());
        let mut wrong_derived = [0u8; HKDF_SUBKEY_BYTES];
        Hkdf::<Sha512>::new(None, &ha_password)
            .expand(&wrong_info, &mut wrong_derived)
            .unwrap();
        let wrong_cipher = Aes256Gcm::new_from_slice(&wrong_derived).unwrap();
        let attempt = wrong_cipher.decrypt(
            nonce,
            Payload {
                msg: &wrapped[AES_GCM_NONCE_BYTES..],
                aad: &wrong_aad,
            },
        );
        assert!(attempt.is_err(), "cross-domain unwrap must fail");
    }

    #[test]
    fn dispatch_wrap_node_key_for_joiner_unloaded_ha_password_errors() {
        let (state, _, _, _) = fixture();
        let args = json!({
            "node_key_pem": hex::encode(b"pem"),
            "node_uuid": "abc",
        });
        let err = dispatch(&state, "wrap_node_key_for_joiner", &args).unwrap_err();
        assert!(err.contains("ha_password"), "got: {err}");
    }

    // -- follow-up: set_ha_password_from_plain /
    //    clear_ha_password ops. The propagation hook in ha_password.py
    //    fires these from any worker (master local OR follower via RPC)
    //    so master state.ha_password_enc converges on the right value.

    /// After `set_ha_password_from_plain`, `ha_password_hmac` succeeds
    /// and matches a direct HMAC using the supplied plaintext. This proves
    /// the stored slot can be decrypted under the master key and recovered
    /// by subsequent dispatch operations.
    #[test]
    fn dispatch_set_ha_password_from_plain_populates_slot() {
        let (state, _, _, _) = fixture();
        let plain = b"plain-cluster-ha-password-32-byts".to_vec();

        // Op succeeds and returns empty string ("" = success sentinel).
        let result = dispatch(
            &state,
            "set_ha_password_from_plain",
            &json!({ "plain": hex::encode(&plain) }),
        )
        .unwrap();
        assert_eq!(result, "");

        // Now the HMAC op must produce the canonical HMAC-SHA512(plain, msg).
        let msg = b"deadbeef";
        let got = dispatch(
            &state,
            "ha_password_hmac",
            &json!({ "message": hex::encode(msg) }),
        )
        .unwrap();
        let mut mac = <HmacSha512 as Mac>::new_from_slice(&plain).unwrap();
        mac.update(msg);
        let expected = hex::encode(mac.finalize().into_bytes());
        assert_eq!(got, expected);
    }

    /// A second `set_ha_password_from_plain` replaces the previous
    /// buffer (zeroising the old one) -- subsequent ops use the latest
    /// value. Guards against an accumulator bug.
    #[test]
    fn dispatch_set_ha_password_from_plain_replaces_previous() {
        let (state, _, _, _) = fixture();
        for plain in [
            b"first-cluster-ha-password-32-byt".as_slice(),
            b"second-cluster-ha-password-32-by".as_slice(),
        ] {
            dispatch(
                &state,
                "set_ha_password_from_plain",
                &json!({ "plain": hex::encode(plain) }),
            )
            .unwrap();
            let msg = b"probe";
            let got = dispatch(
                &state,
                "ha_password_hmac",
                &json!({ "message": hex::encode(msg) }),
            )
            .unwrap();
            let mut mac = <HmacSha512 as Mac>::new_from_slice(plain).unwrap();
            mac.update(msg);
            assert_eq!(got, hex::encode(mac.finalize().into_bytes()));
        }
    }

    /// `clear_ha_password` empties the slot; subsequent
    /// `ha_password_hmac` calls fail with the unloaded-slot error.
    /// This mirrors `dispatch_ha_password_hmac_unloaded_errors` while
    /// exercising the explicit clear path used by `ha_password.clear()`
    /// and `clear_async()`.
    #[test]
    fn dispatch_clear_ha_password_drops_slot() {
        let (state, _, _, _) = fixture();
        dispatch(
            &state,
            "set_ha_password_from_plain",
            &json!({ "plain": hex::encode(b"x".repeat(32)) }),
        )
        .unwrap();
        // Confirm the slot is populated.
        dispatch(
            &state,
            "ha_password_hmac",
            &json!({ "message": hex::encode(b"x") }),
        )
        .unwrap();

        let result = dispatch(&state, "clear_ha_password", &json!({})).unwrap();
        assert_eq!(result, "");

        let err = dispatch(
            &state,
            "ha_password_hmac",
            &json!({ "message": hex::encode(b"x") }),
        )
        .unwrap_err();
        assert!(err.contains("ha_password"), "got: {err}");
    }

    /// `clear_ha_password` on an empty slot is a no-op (the propagation
    /// hook for `ha_password.clear_async()` on a sealed vault must not
    /// surface an error -- the follower path always fires unconditionally).
    #[test]
    fn dispatch_clear_ha_password_idempotent_on_empty_slot() {
        let (state, _, _, _) = fixture();
        let result = dispatch(&state, "clear_ha_password", &json!({})).unwrap();
        assert_eq!(result, "");
        // Slot already empty ; the second clear must also succeed.
        let result = dispatch(&state, "clear_ha_password", &json!({})).unwrap();
        assert_eq!(result, "");
    }

    /// The `set_ha_password_from_plain` op rejects a missing `plain`
    /// argument cleanly (the dispatch arm uses `decode_hex` which
    /// returns a meaningful error). Guards against a panic on a
    /// malformed wire payload.
    #[test]
    fn dispatch_set_ha_password_from_plain_missing_arg_errors() {
        let (state, _, _, _) = fixture();
        let err = dispatch(&state, "set_ha_password_from_plain", &json!({})).unwrap_err();
        assert!(err.contains("plain"), "got: {err}");
    }

    /// `has_ha_password` returns "0" on an empty
    /// slot. Backs the follower-side `is_loaded_anywhere()` Python helper
    /// when the cluster is not yet provisioned.
    #[test]
    fn dispatch_has_ha_password_returns_zero_on_empty_slot() {
        let (state, _, _, _) = fixture();
        let result = dispatch(&state, "has_ha_password", &json!({})).unwrap();
        assert_eq!(result, "0");
    }

    /// `has_ha_password` returns "1" after the slot
    /// is populated via `set_ha_password_from_plain` (the follower-side
    /// propagation path). Wire format mirrors the dispatch return
    /// convention (string "1"/"0", not JSON bool).
    #[test]
    fn dispatch_has_ha_password_returns_one_after_set() {
        let (state, _, _, _) = fixture();
        let plain = vec![0xABu8; 32];
        dispatch(
            &state,
            "set_ha_password_from_plain",
            &json!({ "plain": hex::encode(&plain) }),
        )
        .unwrap();
        let result = dispatch(&state, "has_ha_password", &json!({})).unwrap();
        assert_eq!(result, "1");
    }

    /// `has_ha_password` flips back to "0" after
    /// `clear_ha_password`. Pairs with the propagation of
    /// `ha_password.clear_async()` from a follower : the master clears
    /// its slot, and a subsequent `/cluster/ha` answered by any worker
    /// surfaces ``ha_loaded=false`` as the cluster-truth view.
    #[test]
    fn dispatch_has_ha_password_returns_zero_after_clear() {
        let (state, _, _, _) = fixture();
        let plain = vec![0xCDu8; 32];
        dispatch(
            &state,
            "set_ha_password_from_plain",
            &json!({ "plain": hex::encode(&plain) }),
        )
        .unwrap();
        dispatch(&state, "clear_ha_password", &json!({})).unwrap();
        let result = dispatch(&state, "has_ha_password", &json!({})).unwrap();
        assert_eq!(result, "0");
    }

    /// The two `MasterRpcServer` setters (`set_ha_wrap_enc` +
    /// `set_ha_password_enc`) accept `None` to clear the slot ; the
    /// dispatch arms then surface the "<label> not loaded" error.
    /// Exercises the Python-facing surface of the slot accessors
    /// (the dispatch ops cover the read paths).
    #[test]
    fn setters_accept_none_to_clear() {
        let plain = b"plain-cluster-ha-password-32-byt".to_vec();
        let state = fixture_with_ha(&[0xF5u8; 32], &plain);

        // Build a Python-facing server pointing at the same Arc so the
        // setter mutations are visible to dispatch.
        let server = MasterRpcServer {
            socket_path: PathBuf::from("/tmp/rhorizon-slot-setter-test.sock"),
            state: Mutex::new(Some(Arc::new(state))),
            stop: Arc::new(AtomicBool::new(false)),
            accept_thread: Mutex::new(None),
        };

        server.set_ha_wrap_enc(None).unwrap();
        server.set_ha_password_enc(None).unwrap();

        // ha_wrap_encrypt now fails because the ha_wrap slot is empty.
        let guard = server.state.lock().unwrap();
        let inner = guard.as_ref().unwrap();
        let err = dispatch(
            inner,
            "ha_wrap_encrypt",
            &json!({ "plaintext": hex::encode(b"x"), "aad": hex::encode(b"y") }),
        )
        .unwrap_err();
        assert!(err.contains("ha_wrap"), "got: {err}");

        let err = dispatch(
            inner,
            "ha_password_hmac",
            &json!({ "message": hex::encode(b"x") }),
        )
        .unwrap_err();
        assert!(err.contains("ha_password"), "got: {err}");
    }

    /// Populating `ha_wrap_enc` and `ha_password_enc` through the server
    /// setters makes both values available through its shared dispatch state.
    /// The test verifies an HA-wrap round trip and a canonical HA-password
    /// HMAC using the newly installed values.
    #[test]
    fn setters_populate_dispatch_slots() {
        let (state, _, _, _) = fixture();
        let server = MasterRpcServer {
            socket_path: PathBuf::from("/tmp/rhorizon-slot-setter-roundtrip.sock"),
            state: Mutex::new(Some(Arc::new(state))),
            stop: Arc::new(AtomicBool::new(false)),
            accept_thread: Mutex::new(None),
        };

        // Build the wrapped subkey + password buffers under the same
        // master key the fixture used (0x42 * 32 -- pinned in
        // `fixture` above).
        let master = [0x42u8; 32];
        let ha_wrap_subkey = [0x77u8; 32];
        let ha_password = b"\x99".repeat(32);
        let ha_wrap_enc = enc_aad(&master, &ha_wrap_subkey, &[]).unwrap();
        let ha_password_enc = enc_aad(&master, &ha_password, &[]).unwrap();

        server.set_ha_wrap_enc(Some(&ha_wrap_enc)).unwrap();
        server.set_ha_password_enc(Some(&ha_password_enc)).unwrap();

        // ha_wrap roundtrip works.
        let guard = server.state.lock().unwrap();
        let inner = guard.as_ref().unwrap();
        let wrapped_hex = dispatch(
            inner,
            "ha_wrap_encrypt",
            &json!({
                "plaintext": hex::encode(b"payload"),
                "aad": hex::encode(b"vault-cluster:ha_password"),
            }),
        )
        .unwrap();
        let got = dispatch(
            inner,
            "ha_wrap_decrypt",
            &json!({
                "wrapped": wrapped_hex,
                "aad": hex::encode(b"vault-cluster:ha_password"),
            }),
        )
        .unwrap();
        assert_eq!(got, hex::encode(b"payload"));

        // ha_password_hmac yields the canonical HMAC under the new key.
        let msg = b"probe";
        let got = dispatch(
            inner,
            "ha_password_hmac",
            &json!({ "message": hex::encode(msg) }),
        )
        .unwrap();
        let mut mac = <HmacSha512 as Mac>::new_from_slice(&ha_password).unwrap();
        mac.update(msg);
        assert_eq!(got, hex::encode(mac.finalize().into_bytes()));
    }

    // Direct coverage for the Python-facing key-slot setters and getters.
    // Earlier tests exercise HA setters through dispatch; the tests below
    // pin validation, atomic replacement, clearing, round-trip, and
    // post-stop behavior.

    fn server_with_state(state: MasterRpcState, sock: &str) -> MasterRpcServer {
        MasterRpcServer {
            socket_path: PathBuf::from(sock),
            state: Mutex::new(Some(Arc::new(state))),
            stop: Arc::new(AtomicBool::new(false)),
            accept_thread: Mutex::new(None),
        }
    }

    #[test]
    fn wrapped_key_setters_reject_invalid_updates_atomically() {
        let (state, _, _, _) = fixture();
        let master = [0x42u8; 32];
        let old_ha = enc_aad(&master, &[0x61u8; HKDF_SUBKEY_BYTES], &[]).unwrap();
        let old_pki = enc_aad(&master, &[0x62u8; HKDF_SUBKEY_BYTES], &[]).unwrap();
        *state.ha_wrap_enc.lock().unwrap() = Some(old_ha.clone());
        *state.pki_wrap_enc.lock().unwrap() = Some(old_pki.clone());
        let server = server_with_state(state, "/tmp/rhorizon-invalid-wrapped-keys.sock");

        let wrong_length = enc_aad(&master, &[0x63u8; HKDF_SUBKEY_BYTES - 1], &[]).unwrap();
        assert!(server.set_ha_wrap_enc(Some(b"invalid ciphertext")).is_err());
        assert!(server.set_pki_wrap_enc(Some(&wrong_length)).is_err());

        let guard = server.state.lock().unwrap();
        let inner = guard.as_ref().unwrap();
        assert_eq!(*inner.ha_wrap_enc.lock().unwrap(), Some(old_ha));
        assert_eq!(*inner.pki_wrap_enc.lock().unwrap(), Some(old_pki));
    }

    #[test]
    fn identity_and_ha_password_setters_validate_before_replacement() {
        let (state, _, _, _) = fixture();
        let master = [0x42u8; 32];
        let old_seed = enc_aad(&master, &[0x71u8; 32], &[]).unwrap();
        let old_password = enc_aad(&master, &[0x72u8; 32], &[]).unwrap();
        *state.audit_seed_enc.lock().unwrap() = Some(old_seed.clone());
        state
            .ha_password_enc
            .replace(Some(old_password.clone()))
            .unwrap();
        let server = server_with_state(state, "/tmp/rhorizon-invalid-identity-password.sock");

        let short_password = enc_aad(&master, &[0x73u8; 31], &[]).unwrap();
        assert!(server
            .set_audit_seed_enc(Some(b"invalid ciphertext"))
            .is_err());
        assert!(server.set_ha_password_enc(Some(&short_password)).is_err());

        {
            let guard = server.state.lock().unwrap();
            let inner = guard.as_ref().unwrap();
            assert_eq!(*inner.audit_seed_enc.lock().unwrap(), Some(old_seed));
            assert_eq!(
                inner
                    .ha_password_enc
                    .snapshot("ha_password")
                    .unwrap()
                    .as_slice(),
                old_password
            );
        }

        let long_password = enc_aad(&master, &[0x74u8; 48], &[]).unwrap();
        server.set_ha_password_enc(Some(&long_password)).unwrap();
        let guard = server.state.lock().unwrap();
        let inner = guard.as_ref().unwrap();
        assert_eq!(
            inner
                .ha_password_enc
                .snapshot("ha_password")
                .unwrap()
                .as_slice(),
            long_password
        );
    }

    #[test]
    fn set_prev_hmac_populates_dispatch_arm() {
        let (state, hmac_subkey, _, _) = fixture();
        let server = server_with_state(state, "/tmp/rhorizon-set-prev-hmac.sock");

        // No prev_hmac yet -- the dispatch arm returns the empty string.
        let guard = server.state.lock().unwrap();
        let inner = guard.as_ref().unwrap();
        let pre = dispatch(inner, "hmac_sha512_prev", &json!({ "message": "00" })).unwrap();
        assert!(pre.is_empty(), "expected empty, got {pre:?}");
        drop(guard);

        // Setter populates the slot with an encrypted prev subkey.
        // The fixture's hmac_subkey is reused as a stand-in for the
        // pre-rotation subkey -- the arm just HMACs with whatever slot
        // it finds.
        let prev_enc = enc_aad(&[0x42u8; 32], &hmac_subkey, &[]).unwrap();
        server.set_prev_hmac(Some(&prev_enc)).unwrap();

        let guard = server.state.lock().unwrap();
        let inner = guard.as_ref().unwrap();
        let msg = b"after rotation";
        let got = dispatch(
            inner,
            "hmac_sha512_prev",
            &json!({ "message": hex::encode(msg) }),
        )
        .unwrap();
        let mut mac = <HmacSha512 as Mac>::new_from_slice(&hmac_subkey).unwrap();
        mac.update(msg);
        assert_eq!(got, hex::encode(mac.finalize().into_bytes()));
        drop(guard);

        // None clears the slot ; the arm falls back to empty again.
        server.set_prev_hmac(None).unwrap();
        let guard = server.state.lock().unwrap();
        let inner = guard.as_ref().unwrap();
        let post = dispatch(inner, "hmac_sha512_prev", &json!({ "message": "00" })).unwrap();
        assert!(post.is_empty(), "expected empty after clear, got {post:?}");
    }

    #[test]
    fn set_subkeys_refreshes_dispatch_generation() {
        // Regression for the master-password-rotation gap : a master that
        // rotates its own password must refresh the generation its listener
        // serves to followers. Before set_subkeys the dispatch arms kept the
        // construction-time snapshot, so followers 401'd every fresh token.
        let (state, old_hmac, old_dek, old_audit) = fixture();
        let master = [0x42u8; 32]; // pinned in `fixture`
        let server = server_with_state(state, "/tmp/rhorizon-set-subkeys.sock");

        // Sanity : pre-rotation, hmac_sha512 matches the OLD hmac subkey.
        let msg = b"token-to-validate";
        {
            let guard = server.state.lock().unwrap();
            let inner = guard.as_ref().unwrap();
            let got = dispatch(
                inner,
                "hmac_sha512",
                &json!({ "message": hex::encode(msg) }),
            )
            .unwrap();
            let mut mac = <HmacSha512 as Mac>::new_from_slice(&old_hmac).unwrap();
            mac.update(msg);
            assert_eq!(got, hex::encode(mac.finalize().into_bytes()));
        }

        // Rotate : derive a fresh generation, encrypt under the SAME master
        // wrap key (rotation reuses the process WrapKey), push via setter.
        let new_hmac = [0x11u8; HKDF_SUBKEY_BYTES];
        let new_dek = [0x22u8; HKDF_SUBKEY_BYTES];
        let new_audit = [0x33u8; HKDF_SUBKEY_BYTES];
        let new_hmac_enc = enc_aad(&master, &new_hmac, &[]).unwrap();
        let new_dek_enc = enc_aad(&master, &new_dek, &[]).unwrap();
        let new_audit_enc = enc_aad(&master, &new_audit, &[]).unwrap();
        server
            .set_subkeys(&new_hmac_enc, &new_dek_enc, &new_audit_enc)
            .unwrap();

        let guard = server.state.lock().unwrap();
        let inner = guard.as_ref().unwrap();

        // hmac_sha512 now matches the NEW hmac subkey, and differs from the
        // pre-rotation generation.
        let got = dispatch(
            inner,
            "hmac_sha512",
            &json!({ "message": hex::encode(msg) }),
        )
        .unwrap();
        let mut new_mac = <HmacSha512 as Mac>::new_from_slice(&new_hmac).unwrap();
        new_mac.update(msg);
        assert_eq!(got, hex::encode(new_mac.finalize().into_bytes()));
        let mut old_mac = <HmacSha512 as Mac>::new_from_slice(&old_hmac).unwrap();
        old_mac.update(msg);
        assert_ne!(got, hex::encode(old_mac.finalize().into_bytes()));

        // audit_sign now signs under the NEW audit subkey.
        let payload = "audit-row-json";
        let got = dispatch(
            inner,
            "audit_sign",
            &json!({ "payload": payload, "prev_signature": "" }),
        )
        .unwrap();
        let mut amac = <HmacSha512 as Mac>::new_from_slice(&new_audit).unwrap();
        amac.update(payload.as_bytes());
        assert_eq!(got, hex::encode(amac.finalize().into_bytes()));
        let mut old_amac = <HmacSha512 as Mac>::new_from_slice(&old_audit).unwrap();
        old_amac.update(payload.as_bytes());
        assert_ne!(got, hex::encode(old_amac.finalize().into_bytes()));

        // AES-GCM encryption uses the new DEK, not merely a self-consistent
        // key retained by both RPC arms.
        let plaintext = b"secret-payload";
        let aad = b"vault:dek";
        let wrapped_hex = dispatch(
            inner,
            "aesgcm_encrypt",
            &json!({ "plaintext": hex::encode(plaintext), "aad": hex::encode(aad) }),
        )
        .unwrap();
        let wrapped = hex::decode(&wrapped_hex).unwrap();
        let direct = aes_gcm_decrypt_aad(&new_dek, &wrapped, aad).unwrap();
        assert_eq!(direct, plaintext);
        assert!(aes_gcm_decrypt_aad(&old_dek, &wrapped, aad).is_err());

        // Wire layout from aesgcm_encrypt: nonce || ciphertext, hex. Split for
        // the decrypt arm which wants nonce + ciphertext separately.
        let (nonce, ct) = wrapped.split_at(AES_GCM_NONCE_BYTES);
        let got = dispatch(
            inner,
            "aesgcm_decrypt",
            &json!({
                "ciphertext": hex::encode(ct),
                "nonce": hex::encode(nonce),
                "aad": hex::encode(aad),
            }),
        )
        .unwrap();
        assert_eq!(got, hex::encode(plaintext));
    }

    #[test]
    fn set_subkeys_rejects_invalid_generation_atomically() {
        let (state, _, _, _) = fixture();
        let server = server_with_state(state, "/tmp/rhorizon-invalid-subkeys.sock");

        let before = {
            let guard = server.state.lock().unwrap();
            let inner = guard.as_ref().unwrap();
            inner.sealed.store(true, Ordering::Release);
            (
                inner.hmac_enc().unwrap(),
                inner.dek_enc().unwrap(),
                inner.audit_enc().unwrap(),
            )
        };

        let master = [0x42u8; 32];
        let new_hmac = enc_aad(&master, &[0x81u8; HKDF_SUBKEY_BYTES], &[]).unwrap();
        let new_dek = enc_aad(&master, &[0x82u8; HKDF_SUBKEY_BYTES], &[]).unwrap();
        let new_audit = enc_aad(&master, &[0x83u8; HKDF_SUBKEY_BYTES], &[]).unwrap();
        let invalid = b"invalid ciphertext".as_slice();
        let attempts: [(&[u8], &[u8], &[u8]); 3] = [
            (invalid, &new_dek, &new_audit),
            (&new_hmac, invalid, &new_audit),
            (&new_hmac, &new_dek, invalid),
        ];

        for (hmac, dek, audit) in attempts {
            assert!(server.set_subkeys(hmac, dek, audit).is_err());

            let guard = server.state.lock().unwrap();
            let inner = guard.as_ref().unwrap();
            assert!(inner.sealed.load(Ordering::Acquire));
            assert_eq!(inner.hmac_enc().unwrap(), before.0);
            assert_eq!(inner.dek_enc().unwrap(), before.1);
            assert_eq!(inner.audit_enc().unwrap(), before.2);
        }
    }

    #[test]
    fn has_ha_password_enc_reports_slot_state() {
        let (state, _, _, _) = fixture();
        let server = server_with_state(state, "/tmp/rhorizon-has-ha-pw.sock");

        // Empty -> false (this is the follow-up invariant on the
        // master worker : Python `_ha_password_enc` is None when init
        // landed on another worker, so the Rust slot is the only source
        // of truth on the master).
        assert!(!server.has_ha_password_enc().unwrap());

        // Populated -> true. Encrypt under the fixture master key.
        let ha_password = b"0123456789abcdef0123456789abcdef".to_vec();
        let enc = enc_aad(&[0x42u8; 32], &ha_password, &[]).unwrap();
        server.set_ha_password_enc(Some(&enc)).unwrap();
        assert!(server.has_ha_password_enc().unwrap());

        // Clear -> false again.
        server.set_ha_password_enc(None).unwrap();
        assert!(!server.has_ha_password_enc().unwrap());
    }

    #[test]
    fn has_ha_password_enc_false_after_stop() {
        // When the server has been stopped, `state` is None and the
        // accessor must return false (slot is unreachable, no panic).
        let server = MasterRpcServer {
            socket_path: PathBuf::from("/tmp/rhorizon-has-ha-pw-stopped.sock"),
            state: Mutex::new(None),
            stop: Arc::new(AtomicBool::new(true)),
            accept_thread: Mutex::new(None),
        };
        assert!(!server.has_ha_password_enc().unwrap());
    }

    #[test]
    fn setters_are_noops_after_stop() {
        // When state is None (post-stop), setters succeed silently
        // without touching anything. This mirrors the runtime case
        // where Python code may race with /seal -- we must not panic.
        let server = MasterRpcServer {
            socket_path: PathBuf::from("/tmp/rhorizon-set-after-stop.sock"),
            state: Mutex::new(None),
            stop: Arc::new(AtomicBool::new(true)),
            accept_thread: Mutex::new(None),
        };
        server.set_prev_hmac(Some(b"ignored")).unwrap();
        server
            .set_subkeys(b"ignored", b"ignored", b"ignored")
            .unwrap();
        server.set_ha_wrap_enc(Some(b"ignored")).unwrap();
        server.set_pki_wrap_enc(Some(b"ignored")).unwrap();
        server.set_audit_seed_enc(Some(b"ignored")).unwrap();
        server.set_ha_password_enc(Some(b"ignored")).unwrap();
        server.set_prev_hmac(None).unwrap();
        server.set_ha_wrap_enc(None).unwrap();
        server.set_pki_wrap_enc(None).unwrap();
        server.set_audit_seed_enc(None).unwrap();
        server.set_ha_password_enc(None).unwrap();
        // Sanity: the accessor still reports false after the no-op sets.
        assert!(!server.has_ha_password_enc().unwrap());
    }
}

// Wire-framing property tests : length-prefixed frames + hex arg decoding.
// Socket props are #[cfg_attr(miri, ignore)] (miri has no syscalls) and are
// additionally exercised by the ASAN CI job over the FFI/socket paths.
#[cfg(test)]
mod wire_proptests {
    use super::*;
    use proptest::prelude::*;
    use std::io::{ErrorKind, Write};
    use std::net::Shutdown;

    proptest! {
        #![proptest_config(ProptestConfig {
            // Miri runs with isolation on, so proptest's default file
            // failure-persistence (getcwd -> absolutize .proptest-regressions)
            // hits an unsupported syscall. Disable persistence under Miri only;
            // keep it for normal runs so regression seeds are still saved.
            failure_persistence: if cfg!(miri) {
                None
            } else {
                Some(Box::new(proptest::test_runner::FileFailurePersistence::SourceParallel(
                    ".proptest-regressions",
                )))
            },
            ..ProptestConfig::default()
        })]

        // Generated valid, non-empty payloads survive write_frame -> read_frame
        // byte-for-byte.
        #[test]
        #[cfg_attr(miri, ignore)]
        fn prop_frame_roundtrip(payload in proptest::collection::vec(any::<u8>(), 1..=4096)) {
            let (mut w, mut r) = UnixStream::pair().unwrap();
            write_frame(&mut w, &payload).unwrap();
            let got = read_frame(&mut r).unwrap();
            prop_assert_eq!(got.as_slice(), payload.as_slice());
        }

        // A declared length above MAX_PAYLOAD is rejected before allocating the
        // attacker-chosen size -- the DoS guard on read_frame.
        #[test]
        #[cfg_attr(miri, ignore)]
        fn prop_oversized_len_rejected(extra in 1u32..=4_000_000) {
            let (mut w, mut r) = UnixStream::pair().unwrap();
            let bad = (MAX_PAYLOAD as u32).saturating_add(extra);
            w.write_all(&bad.to_be_bytes()).unwrap();
            w.shutdown(Shutdown::Write).ok();
            let err = read_frame(&mut r).unwrap_err();
            prop_assert_eq!(err.kind(), ErrorKind::InvalidData);
            prop_assert_eq!(err.to_string(), "frame length out of bounds");
        }

        // decode_hex never panics on arbitrary input : it returns Ok/Err only.
        #[test]
        fn prop_decode_hex_never_panics(s in ".*", key in "[a-z]{1,8}") {
            let mut m = serde_json::Map::new();
            m.insert(key.clone(), Value::String(s.clone()));
            let v = Value::Object(m);
            let _ = decode_hex(&v, &key);
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn zero_length_frame_is_rejected() {
        let (mut w, mut r) = UnixStream::pair().unwrap();
        w.write_all(&0u32.to_be_bytes()).unwrap();
        w.shutdown(Shutdown::Write).ok();
        let err = read_frame(&mut r).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
        assert_eq!(err.to_string(), "frame length out of bounds");
    }
}
