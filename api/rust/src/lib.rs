// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
//! Native cryptographic and secure-memory operations for Horizon.
//!
//! Provides locked, zeroizing key buffers; AES-256-GCM and XChaCha20-Poly1305;
//! HMAC-SHA-512, HKDF, Ed25519 and post-quantum PKI primitives; Shamir secret
//! sharing; and the Unix-socket crypto dispatcher used by multi-worker nodes.

use aes_gcm::aead::consts::U24;
use aes_gcm::aead::{Aead, AeadInPlace, KeyInit, OsRng, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use blake2::{Blake2b, Digest};
#[cfg(test)]
use crypto_box::SecretKey as BoxSecretKey;
use crypto_secretbox::{Kdf, Key as SecretBoxKey, Tag as SecretBoxTag, XSalsa20Poly1305};
use curve25519_dalek::{
    scalar::{clamp_integer, Scalar},
    MontgomeryPoint,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use fips203::ml_kem_768;
use fips203::traits::{Decaps, Encaps, KeyGen as MlKemKeyGen, SerDes as MlKemSerDes};
use fips204::ml_dsa_65;
use fips204::traits::{SerDes, Signer as MlDsaSign, Verifier as MlDsaVerify};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use pyo3::exceptions::{PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyByteArray, PyBytes};
#[cfg(test)]
use rhorizon_custody_core::operations::XCHACHA_NONCE_BYTES;
use rhorizon_custody_core::operations::{
    aes256_gcm_decrypt as core_aes256_gcm_decrypt, aes256_gcm_encrypt as core_aes256_gcm_encrypt,
    chained_secret_decrypt, chained_secret_encrypt, chained_secret_reencrypt,
    ChainedSecretCiphertext, ChainedSecretReencryptInput, DEK_WRAPPED_BYTES,
};
use sha2::Sha512;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;
use zeroize::{Zeroize, Zeroizing};

mod gf256_ct;

// key_share stays private for normal (Python wheel) builds, its
// pub items (ShamirShare, KeyServer, KeyClient) are surfaced through
// the PyO3 #[pymodule] block below, never via the Rust crate root.
// Under `--features fuzzing`, the module is made public so the
// in-tree cargo-fuzz harness can reach `key_share::fuzz_api`.
mod backup_context;
#[cfg(feature = "fuzzing")]
pub mod key_share;
#[cfg(not(feature = "fuzzing"))]
mod key_share;
mod master_rpc;

pub(crate) type HmacSha512 = Hmac<Sha512>;

const MEMORY_LOCK_MODE_ENV: &str = "RH_MEMORY_LOCK_MODE";
const LEGACY_MEMORY_LOCK_MODE_ENV: &str = "RHORIZON_MEMORY_LOCK_MODE";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MemoryLockPolicy {
    BestEffort,
    Required,
}

static MEMORY_LOCK_POLICY: OnceLock<Result<MemoryLockPolicy, String>> = OnceLock::new();
static MEMORY_LOCK_DEGRADED: AtomicBool = AtomicBool::new(false);

fn parse_memory_lock_policy(value: Option<&str>) -> Result<MemoryLockPolicy, String> {
    match value
        .unwrap_or("best-effort")
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "best-effort" | "best_effort" => Ok(MemoryLockPolicy::BestEffort),
        "required" => Ok(MemoryLockPolicy::Required),
        value => Err(format!(
            "invalid {MEMORY_LOCK_MODE_ENV}={value:?}; expected best-effort or required"
        )),
    }
}

fn memory_lock_policy() -> Result<MemoryLockPolicy, String> {
    MEMORY_LOCK_POLICY
        .get_or_init(|| {
            let configured = std::env::var(MEMORY_LOCK_MODE_ENV)
                .ok()
                .or_else(|| std::env::var(LEGACY_MEMORY_LOCK_MODE_ENV).ok());
            parse_memory_lock_policy(configured.as_deref())
        })
        .clone()
}

/// Attempt to lock a secret allocation. In best-effort mode, a failure keeps
/// zeroize-on-drop protection and records degraded status. The Python startup
/// layer reports it according to the host's swap-encryption state.
/// Required mode preserves fail-closed behavior.
pub(crate) fn lock_secret_memory(buffer: &mut [u8], label: &str) -> Result<bool, String> {
    if buffer.is_empty() {
        return Ok(false);
    }
    let policy = match memory_lock_policy() {
        Ok(policy) => policy,
        Err(error) => {
            buffer.zeroize();
            return Err(error);
        }
    };
    if cfg!(miri) {
        return Ok(true);
    }
    let locked = unsafe { memsec::mlock(buffer.as_mut_ptr(), buffer.len()) };
    apply_memory_lock_result(buffer, label, policy, locked)
}

fn apply_memory_lock_result(
    buffer: &mut [u8],
    label: &str,
    policy: MemoryLockPolicy,
    locked: bool,
) -> Result<bool, String> {
    if locked {
        return Ok(true);
    }
    if policy == MemoryLockPolicy::Required {
        buffer.zeroize();
        return Err(format!(
            "Resurgamus Horizon: mlock failed for {label}; grant CAP_IPC_LOCK, raise \
             RLIMIT_MEMLOCK, or set {MEMORY_LOCK_MODE_ENV}=best-effort"
        ));
    }

    MEMORY_LOCK_DEGRADED.store(true, Ordering::Release);
    Ok(false)
}

#[pyfunction]
fn memory_lock_status() -> &'static str {
    if MEMORY_LOCK_DEGRADED.load(Ordering::Acquire) {
        "zeroize-only"
    } else {
        "mlock"
    }
}

/// A secure memory buffer: zeroized on drop and mlock'd when available or
/// required by the operator's memory-lock policy.
///
/// Data lives in Rust heap, outside Python's GC. On drop, the buffer is
/// wiped with `zeroize`; its pages stay locked for the process lifetime.
/// munlock(2) is page-granular and not reference-counted, so unlocking one
/// dropped buffer could unlock a live neighbor's page -- size RLIMIT_MEMLOCK
/// for the peak secret footprint (same policy as custody-core
/// `secure_memory`).
#[pyclass]
pub struct SecureBuffer {
    pub(crate) data: Vec<u8>,
    pub(crate) locked: bool,
}

impl SecureBuffer {
    fn try_from_slice_locked(data: &[u8]) -> Result<Self, String> {
        if data.is_empty() {
            return Ok(SecureBuffer {
                data: Vec::new(),
                locked: false,
            });
        }
        let mut protected = vec![0u8; data.len()];
        let locked = lock_secret_memory(&mut protected, "SecureBuffer")?;
        protected.copy_from_slice(data);
        Ok(SecureBuffer {
            data: protected,
            locked,
        })
    }

    fn try_new_locked(mut data: Vec<u8>) -> Result<Self, String> {
        if data.is_empty() {
            return Ok(SecureBuffer {
                data,
                locked: false,
            });
        }
        let locked = lock_secret_memory(&mut data, "SecureBuffer")?;
        Ok(SecureBuffer { data, locked })
    }

    pub(crate) fn new_locked(data: Vec<u8>) -> PyResult<Self> {
        Self::try_new_locked(data).map_err(PyValueError::new_err)
    }
}

impl Drop for SecureBuffer {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

#[pymethods]
impl SecureBuffer {
    #[new]
    fn py_new(data: &[u8]) -> PyResult<Self> {
        SecureBuffer::try_from_slice_locked(data).map_err(PyValueError::new_err)
    }

    /// Return a mutable Python copy that the caller can securely wipe.
    fn to_bytearray<'py>(&self, py: Python<'py>) -> Bound<'py, PyByteArray> {
        PyByteArray::new(py, &self.data)
    }

    fn __len__(&self) -> usize {
        self.data.len()
    }

    fn zeroize(&mut self) {
        self.data.zeroize();
    }

    #[getter]
    fn is_locked(&self) -> bool {
        self.locked
    }
}

// -- Pure crypto functions (no PyO3, testable with cargo test) --

const AES_GCM_NONCE_BYTES: usize = 12;
pub(crate) const AES_GCM_TAG_BYTES: usize = 16;
const AES_GCM_MIN_WRAPPED_BYTES: usize = AES_GCM_NONCE_BYTES + AES_GCM_TAG_BYTES;
const SEALED_BOX_PUBLIC_KEY_BYTES: usize = 32;
const SEALED_BOX_TAG_BYTES: usize = 16;
const SEALED_BOX_MIN_BYTES: usize = SEALED_BOX_PUBLIC_KEY_BYTES + SEALED_BOX_TAG_BYTES;

pub(crate) fn try_os_fill(destination: &mut [u8]) -> Result<(), String> {
    use aes_gcm::aead::rand_core::RngCore;

    if OsRng.try_fill_bytes(destination).is_err() {
        destination.zeroize();
        return Err("operating-system random number generation failed".into());
    }
    Ok(())
}

fn x25519_public_from_private(private: &[u8; 32]) -> [u8; 32] {
    let mut clamped = clamp_integer(*private);
    let mut scalar = Scalar::from_bytes_mod_order(clamped);
    clamped.zeroize();
    let public = MontgomeryPoint::mul_base(&scalar).to_bytes();
    scalar.zeroize();
    public
}

fn sealed_box_seal_locked(public_key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let recipient_public_bytes: [u8; SEALED_BOX_PUBLIC_KEY_BYTES] = public_key
        .try_into()
        .map_err(|_| "X25519 public key must be exactly 32 bytes".to_string())?;
    let recipient_public = MontgomeryPoint(recipient_public_bytes);

    let mut ephemeral_private = Zeroizing::new([0u8; SEALED_BOX_PUBLIC_KEY_BYTES]);
    try_os_fill(ephemeral_private.as_mut())?;
    let mut clamped = clamp_integer(*ephemeral_private);
    let mut scalar = Scalar::from_bytes_mod_order(clamped);
    clamped.zeroize();

    let ephemeral_public = MontgomeryPoint::mul_base(&scalar);
    let mut shared_secret = scalar * recipient_public;
    scalar.zeroize();
    let key = Zeroizing::new(<XSalsa20Poly1305 as Kdf>::kdf(
        SecretBoxKey::from_slice(shared_secret.as_bytes()),
        &Default::default(),
    ));
    shared_secret.zeroize();

    let mut nonce_hasher = Blake2b::<U24>::new();
    nonce_hasher.update(ephemeral_public.as_bytes());
    nonce_hasher.update(recipient_public.as_bytes());
    let nonce = nonce_hasher.finalize();
    let cipher = XSalsa20Poly1305::new(&key);
    let mut protected = SecureBuffer::try_from_slice_locked(plaintext)?;
    let tag = cipher
        .encrypt_in_place_detached(&nonce, &[], &mut protected.data)
        .map_err(|_| "sealed box encryption failed".to_string())?;

    let capacity = SEALED_BOX_MIN_BYTES
        .checked_add(protected.data.len())
        .ok_or_else(|| "sealed box plaintext is too large".to_string())?;
    let mut ciphertext = Vec::with_capacity(capacity);
    ciphertext.extend_from_slice(ephemeral_public.as_bytes());
    ciphertext.extend_from_slice(&tag);
    ciphertext.extend_from_slice(&protected.data);
    Ok(ciphertext)
}

fn sealed_box_open_locked(private: &[u8], ciphertext: &[u8]) -> PyResult<SecureBuffer> {
    if private.len() != SEALED_BOX_PUBLIC_KEY_BYTES {
        return Err(PyValueError::new_err("invalid wrapped X25519 private key"));
    }
    if ciphertext.len() < SEALED_BOX_MIN_BYTES {
        return Err(PyValueError::new_err("sealed box open failed"));
    }

    let mut plaintext = SecureBuffer::new_locked(ciphertext[SEALED_BOX_MIN_BYTES..].to_vec())?;
    let ephemeral_public_bytes: [u8; SEALED_BOX_PUBLIC_KEY_BYTES] = ciphertext
        [..SEALED_BOX_PUBLIC_KEY_BYTES]
        .try_into()
        .map_err(|_| PyValueError::new_err("sealed box open failed"))?;
    let ephemeral_public = MontgomeryPoint(ephemeral_public_bytes);

    let mut private_bytes = [0u8; SEALED_BOX_PUBLIC_KEY_BYTES];
    private_bytes.copy_from_slice(private);
    let mut clamped = clamp_integer(private_bytes);
    private_bytes.zeroize();
    let mut scalar = Scalar::from_bytes_mod_order(clamped);
    clamped.zeroize();

    let recipient_public = MontgomeryPoint::mul_base(&scalar);
    let mut shared_secret = scalar * ephemeral_public;
    scalar.zeroize();
    let key = Zeroizing::new(<XSalsa20Poly1305 as Kdf>::kdf(
        SecretBoxKey::from_slice(shared_secret.as_bytes()),
        &Default::default(),
    ));
    shared_secret.zeroize();

    let mut nonce_hasher = Blake2b::<U24>::new();
    nonce_hasher.update(ephemeral_public_bytes);
    nonce_hasher.update(recipient_public.as_bytes());
    let nonce = nonce_hasher.finalize();
    let cipher = XSalsa20Poly1305::new(&key);
    let tag =
        SecretBoxTag::from_slice(&ciphertext[SEALED_BOX_PUBLIC_KEY_BYTES..SEALED_BOX_MIN_BYTES]);
    cipher
        .decrypt_in_place_detached(&nonce, &[], &mut plaintext.data, tag)
        .map_err(|_| PyValueError::new_err("sealed box open failed"))?;
    Ok(plaintext)
}

fn aes_gcm_encrypt(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    aes_gcm_encrypt_aad(key, plaintext, &[])
}

fn aes_gcm_encrypt_aad_locked_input(
    key: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|error| error.to_string())?;
    let mut nonce_bytes = [0u8; AES_GCM_NONCE_BYTES];
    try_os_fill(&mut nonce_bytes)?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let mut protected = SecureBuffer::try_new_locked(plaintext.to_vec())?;
    let tag = cipher
        .encrypt_in_place_detached(nonce, aad, &mut protected.data)
        .map_err(|_| "Encryption failed".to_string())?;

    let mut result =
        Vec::with_capacity(AES_GCM_NONCE_BYTES + protected.data.len() + AES_GCM_TAG_BYTES);
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&protected.data);
    result.extend_from_slice(&tag);
    Ok(result)
}

#[cfg(test)]
pub(crate) fn aes_gcm_decrypt(key: &[u8], wrapped: &[u8]) -> Result<Vec<u8>, String> {
    aes_gcm_decrypt_aad(key, wrapped, &[])
}

pub(crate) fn aes_gcm_encrypt_aad(
    key: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    core_aes256_gcm_encrypt(key, plaintext, aad)
}

pub(crate) fn aes_gcm_decrypt_aad(
    key: &[u8],
    wrapped: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    core_aes256_gcm_decrypt(key, wrapped, aad)
}

pub(crate) fn aes_gcm_decrypt_aad_locked(
    key: &[u8],
    wrapped: &[u8],
    aad: &[u8],
) -> Result<SecureBuffer, String> {
    if wrapped.len() < AES_GCM_MIN_WRAPPED_BYTES {
        return Err("Wrapped data too short".into());
    }
    let tag_offset = wrapped.len() - AES_GCM_TAG_BYTES;
    let mut plaintext =
        SecureBuffer::try_new_locked(wrapped[AES_GCM_NONCE_BYTES..tag_offset].to_vec())?;
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|error| error.to_string())?;
    let nonce = Nonce::from_slice(&wrapped[..AES_GCM_NONCE_BYTES]);
    let tag = aes_gcm::aead::Tag::<Aes256Gcm>::from_slice(&wrapped[tag_offset..]);
    cipher
        .decrypt_in_place_detached(nonce, aad, &mut plaintext.data, tag)
        .map_err(|_| "Decryption failed - wrong key or tampered data".to_string())?;
    Ok(plaintext)
}

pub(crate) type PyChainedSecretCiphertext<'py> = (
    Bound<'py, PyBytes>,
    Bound<'py, PyBytes>,
    Bound<'py, PyBytes>,
    Bound<'py, PyBytes>,
);

fn chained_secret_to_python<'py>(
    py: Python<'py>,
    result: &ChainedSecretCiphertext,
) -> PyChainedSecretCiphertext<'py> {
    (
        PyBytes::new(py, &result.wrapped_dek[12..]),
        PyBytes::new(py, &result.wrapped_dek[..12]),
        PyBytes::new(py, &result.ciphertext),
        PyBytes::new(py, &result.secret_nonce),
    )
}

/// HKDF-SHA512(salt=None, ikm=parent_key, info, L=32) -> 32B subkey,
/// then AES-256-GCM-encrypt `plaintext` under that subkey with `aad`.
/// Returns nonce(12) || ciphertext.
///
/// The derived subkey lives only on the stack and is zeroized before
/// return. Designed for the cluster-join flow : the master
/// wraps a freshly-minted node private key under a derivation of
/// `ha_password` keyed by `node_uuid` ; the joiner replays the same
/// HKDF derivation locally to unwrap, then persists the key on its
/// volume.
///
/// Derivation = RFC 5869 (HKDF) with SHA-512, salt absent (RFC section 2.2
/// "if not provided, set to a string of HashLen zeros") -- the IKM is
/// already high-entropy (cluster ha_password >= 32 bytes), so extraction does
/// not rely on a salt to strengthen low-entropy input. The IKM remains stable;
/// `info` varies by node UUID and purpose so the same parent key produces
/// domain-separated subkeys.
#[cfg(test)]
fn validate_hkdf_wrap_context(parent_key: &[u8], info: &[u8], aad: &[u8]) -> Result<(), String> {
    if parent_key.len() < 32 {
        return Err("HKDF parent key must be at least 32 bytes".into());
    }
    if info.is_empty() {
        return Err("HKDF info must not be empty".into());
    }
    if aad.is_empty() {
        return Err("AES-GCM AAD must not be empty".into());
    }
    Ok(())
}

pub(crate) fn hkdf_derive_and_aes_gcm_encrypt_aad(
    parent_key: &[u8],
    info: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    rhorizon_custody_core::operations::hkdf_sha512_aes256_gcm_encrypt(
        parent_key, info, plaintext, aad,
    )
}

/// Mirror of `hkdf_derive_and_aes_gcm_encrypt_aad` -- re-derive the
/// subkey from (parent_key, info) and decrypt `wrapped` under `aad`.
/// Test-only : the production decryption happens on the joiner side
/// (join CLI, separate binary) using whatever AES-GCM + HKDF-SHA512
/// implementation it has on hand. Keeping this here lets the Rust
/// unit + property tests prove roundtrip correctness without crossing
/// the Python boundary.
#[cfg(test)]
pub(crate) fn hkdf_derive_and_aes_gcm_decrypt_aad(
    parent_key: &[u8],
    info: &[u8],
    wrapped: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    validate_hkdf_wrap_context(parent_key, info, aad)?;
    let hk = Hkdf::<Sha512>::new(None, parent_key);
    let mut derived = [0u8; 32];
    let result = (|| {
        hk.expand(info, &mut derived)
            .map_err(|e| format!("HKDF expand failed: {e}"))?;
        aes_gcm_decrypt_aad(&derived, wrapped, aad)
    })();
    derived.zeroize();
    result
}

/// AES-256-GCM wrap key: lives entirely in Rust, mlock'd.
/// Python never sees the raw key material.
///
/// pub(crate): BackupCryptoContext::rotate_secret (backup_context.rs)
/// takes a `PyRef<'_, WrapKey>` so a dual-context backup restore can
/// unwrap the CURRENT vault's dek_key without it ever crossing into
/// Python, matching how it is already unwrapped for every live
/// create/update/rollback/rotation call.
#[pyclass]
pub(crate) struct WrapKey {
    key: Vec<u8>,
    locked: bool,
}

impl Drop for WrapKey {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl WrapKey {
    /// Rust-to-Rust unwrap of an encrypted dek_key subkey, deliberately
    /// NOT a `#[pymethods]` entry: called only from
    /// BackupCryptoContext::rotate_secret (backup_context.rs) so the
    /// CURRENT vault's dek_key never has a reason to cross into Python
    /// during a dual-context restore. Same operation as the `decrypt`
    /// pymethod below, kept separate so that one is Python-facing API
    /// and this one is an internal building block.
    pub(crate) fn unwrap_dek_key(
        &self,
        encrypted_dek_subkey: &[u8],
    ) -> Result<SecureBuffer, String> {
        aes_gcm_decrypt_aad_locked(&self.key, encrypted_dek_subkey, &[])
    }
}

#[pymethods]
impl WrapKey {
    #[new]
    fn py_new() -> PyResult<Self> {
        let mut key = vec![0u8; 32];
        let locked = lock_secret_memory(&mut key, "WrapKey").map_err(PyValueError::new_err)?;
        let mut wrap_key = WrapKey { key, locked };
        try_os_fill(&mut wrap_key.key).map_err(PyValueError::new_err)?;
        Ok(wrap_key)
    }

    /// Encrypt plaintext. Returns nonce(12) || ciphertext.
    fn encrypt<'py>(&self, py: Python<'py>, plaintext: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        let result = aes_gcm_encrypt(&self.key, plaintext).map_err(PyValueError::new_err)?;
        Ok(PyBytes::new(py, &result))
    }

    /// Encrypt a mutable Python buffer without copying it into Python bytes.
    /// The caller remains responsible for wiping the bytearray.
    fn encrypt_bytearray<'py>(
        &self,
        py: Python<'py>,
        plaintext: &Bound<'py, PyByteArray>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        // The GIL remains held and no Python code runs while this slice is
        // borrowed, so the bytearray cannot be resized.
        let plaintext = unsafe { plaintext.as_bytes() };
        let result = aes_gcm_encrypt_aad_locked_input(&self.key, plaintext, &[])
            .map_err(PyValueError::new_err)?;
        Ok(PyBytes::new(py, &result))
    }

    /// Decrypt wrapped data (nonce(12) || ciphertext). Returns a SecureBuffer.
    fn decrypt(&self, wrapped: &[u8]) -> PyResult<SecureBuffer> {
        aes_gcm_decrypt_aad_locked(&self.key, wrapped, &[]).map_err(PyValueError::new_err)
    }

    /// Generate an X25519 keypair and wrap its private key before returning.
    /// Python receives only the public key and AES-GCM ciphertext.
    fn generate_rekey_keypair<'py>(
        &self,
        py: Python<'py>,
    ) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
        let mut private = [0u8; 32];
        try_os_fill(&mut private).map_err(PyValueError::new_err)?;
        let public = x25519_public_from_private(&private);
        let wrapped = aes_gcm_encrypt_aad_locked_input(&self.key, &private, &[])
            .map_err(PyValueError::new_err);
        private.zeroize();
        Ok((PyBytes::new(py, &public), PyBytes::new(py, &wrapped?)))
    }

    /// Unwrap this process' X25519 private key and open a libsodium-compatible
    /// sealed box without exposing the private key to Python.
    fn rekey_seal_open<'py>(
        &self,
        py: Python<'py>,
        encrypted_private: &[u8],
        ciphertext: &[u8],
    ) -> PyResult<Bound<'py, PyByteArray>> {
        let private = self.decrypt(encrypted_private)?;
        let plaintext = sealed_box_open_locked(&private.data, ciphertext)?;
        Ok(PyByteArray::new(py, &plaintext.data))
    }

    /// Generate and wrap a fresh DEK, then encrypt a secret under it. Returns
    /// encrypted_dek, dek_nonce, ciphertext, secret_nonce.
    fn chained_secret_encrypt<'py>(
        &self,
        py: Python<'py>,
        encrypted_dek_subkey: &[u8],
        plaintext: &[u8],
        dek_aad: &[u8],
        secret_aad: &[u8],
    ) -> PyResult<PyChainedSecretCiphertext<'py>> {
        let dek_key = self.decrypt(encrypted_dek_subkey)?;
        let result = chained_secret_encrypt(&dek_key.data, plaintext, dek_aad, secret_aad);
        let result = result.map_err(PyValueError::new_err)?;
        Ok(chained_secret_to_python(py, &result))
    }

    /// Unwrap a DEK and decrypt its secret without returning the DEK to Python.
    // PyO3 exposes each persisted field explicitly. Grouping them would only
    // move concatenation and copying into Python.
    #[allow(clippy::too_many_arguments)]
    fn chained_secret_decrypt<'py>(
        &self,
        py: Python<'py>,
        encrypted_dek_subkey: &[u8],
        encrypted_dek: &[u8],
        dek_nonce: &[u8],
        dek_aad: &[u8],
        ciphertext: &[u8],
        secret_nonce: &[u8],
        secret_aad: &[u8],
    ) -> PyResult<Bound<'py, PyByteArray>> {
        let dek_key = self.decrypt(encrypted_dek_subkey)?;
        let mut wrapped_dek = Vec::with_capacity(dek_nonce.len() + encrypted_dek.len());
        wrapped_dek.extend_from_slice(dek_nonce);
        wrapped_dek.extend_from_slice(encrypted_dek);
        let result = chained_secret_decrypt(
            &dek_key.data,
            &wrapped_dek,
            dek_aad,
            ciphertext,
            secret_nonce,
            secret_aad,
        );
        let plaintext = result.map_err(PyValueError::new_err)?;
        Ok(PyByteArray::new(py, plaintext.as_slice()))
    }

    /// Decrypt an existing secret and re-encrypt it under a fresh DEK without
    /// returning either DEK or the plaintext to Python.
    // PyO3 exposes each persisted field explicitly. Grouping them would only
    // move concatenation and copying into Python.
    #[allow(clippy::too_many_arguments)]
    fn chained_secret_reencrypt<'py>(
        &self,
        py: Python<'py>,
        encrypted_dek_subkey: &[u8],
        old_encrypted_dek: &[u8],
        old_dek_nonce: &[u8],
        old_dek_aad: &[u8],
        old_ciphertext: &[u8],
        old_secret_nonce: &[u8],
        old_secret_aad: &[u8],
        new_dek_aad: &[u8],
        new_secret_aad: &[u8],
    ) -> PyResult<PyChainedSecretCiphertext<'py>> {
        let dek_key = self.decrypt(encrypted_dek_subkey)?;
        let mut old_wrapped_dek = Vec::with_capacity(old_dek_nonce.len() + old_encrypted_dek.len());
        old_wrapped_dek.extend_from_slice(old_dek_nonce);
        old_wrapped_dek.extend_from_slice(old_encrypted_dek);
        let result = chained_secret_reencrypt(
            &dek_key.data,
            ChainedSecretReencryptInput {
                old_wrapped_dek: &old_wrapped_dek,
                old_dek_aad,
                old_ciphertext,
                old_secret_nonce,
                old_secret_aad,
                new_dek_aad,
                new_secret_aad,
            },
        );
        let result = result.map_err(PyValueError::new_err)?;
        Ok(chained_secret_to_python(py, &result))
    }

    /// Decrypt `encrypted_subkey`, then HMAC-SHA512(decrypted_subkey, message).
    /// The decrypted subkey stays in locked memory, is wiped automatically,
    /// and never crosses the Rust/Python boundary.
    fn hmac_sha512<'py>(
        &self,
        py: Python<'py>,
        encrypted_subkey: &[u8],
        message: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        let plain_key = self.decrypt(encrypted_subkey)?;
        let mut mac = <HmacSha512 as Mac>::new_from_slice(&plain_key.data)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        mac.update(message);
        let result = mac.finalize().into_bytes();
        Ok(PyBytes::new(py, &result))
    }

    /// Decrypt `encrypted_subkey` (an AES-256 key wrapped under WrapKey),
    /// then AES-256-GCM-encrypt `plaintext` under that subkey with `aad`.
    /// Returns nonce(12) || ciphertext.
    fn aesgcm_subkey_encrypt<'py>(
        &self,
        py: Python<'py>,
        encrypted_subkey: &[u8],
        plaintext: &[u8],
        aad: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        let plain_key = self.decrypt(encrypted_subkey)?;
        let result = aes_gcm_encrypt_aad(&plain_key.data, plaintext, aad);
        let result = result.map_err(PyValueError::new_err)?;
        Ok(PyBytes::new(py, &result))
    }

    /// Variant for sensitive mutable input. The caller retains and must wipe
    /// the bytearray; Rust encrypts only from a locked transient copy.
    fn aesgcm_subkey_encrypt_bytearray<'py>(
        &self,
        py: Python<'py>,
        encrypted_subkey: &[u8],
        plaintext: &Bound<'py, PyByteArray>,
        aad: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        let plain_key = self.decrypt(encrypted_subkey)?;
        let plaintext = unsafe { plaintext.as_bytes() };
        let result = aes_gcm_encrypt_aad_locked_input(&plain_key.data, plaintext, aad)
            .map_err(PyValueError::new_err)?;
        Ok(PyBytes::new(py, &result))
    }

    /// Decrypt `encrypted_subkey`, then AES-256-GCM-decrypt `wrapped`
    /// (nonce(12) || ciphertext) under that subkey with `aad`.
    fn aesgcm_subkey_decrypt<'py>(
        &self,
        py: Python<'py>,
        encrypted_subkey: &[u8],
        wrapped: &[u8],
        aad: &[u8],
    ) -> PyResult<Bound<'py, PyByteArray>> {
        let plain_key = self.decrypt(encrypted_subkey)?;
        let plaintext = aes_gcm_decrypt_aad_locked(&plain_key.data, wrapped, aad)
            .map_err(PyValueError::new_err)?;
        Ok(PyByteArray::new(py, &plaintext.data))
    }

    /// Wrap a payload under a key derived from an encrypted subkey +
    /// per-call `info`. Three-step operation, all steps held entirely
    /// in Rust :
    ///
    ///   1. AES-GCM-decrypt `encrypted_subkey` under our WrapKey to
    ///      recover the parent subkey bytes (e.g. the cluster
    ///      ha_password buffer cached on VaultState).
    ///   2. HKDF-SHA512(salt=None, ikm=parent, info, L=32) -> 32B
    ///      derived AES-256-GCM key.
    ///   3. AES-256-GCM-encrypt `plaintext` under the derived key with
    ///      `aad`. Returns nonce(12) || ciphertext.
    ///
    /// Both the parent subkey and the derived key are zeroized before
    /// return -- neither ever crosses the Rust/Python boundary, which
    /// keeps the project doctrine "no key material in Python heap"
    /// intact.
    ///
    /// Joiner-side counterpart (join CLI, separate binary) :
    ///
    /// ```text
    /// # input : ha_password (>= 32 bytes), node_uuid (str),
    /// #         wrapped (bytes returned by this primitive)
    /// info  = b"cluster-node-key-wrap:" + node_uuid.encode()
    /// aad   = b"vault-cluster:node-key:" + node_uuid.encode()
    /// derived = HKDF-SHA512(None, ha_password, info, L=32)
    /// nonce, ct = wrapped[:12], wrapped[12:]
    /// plain = AES-256-GCM(derived).decrypt(nonce, ct, aad)
    /// ```
    fn derive_and_aesgcm_encrypt<'py>(
        &self,
        py: Python<'py>,
        encrypted_subkey: &[u8],
        info: &[u8],
        plaintext: &[u8],
        aad: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        let parent_key = self.decrypt(encrypted_subkey)?;
        let result = hkdf_derive_and_aes_gcm_encrypt_aad(&parent_key.data, info, plaintext, aad)
            .map_err(PyValueError::new_err)?;
        Ok(PyBytes::new(py, &result))
    }

    /// Wrap an audit signer's seed under this process WrapKey for the master
    /// RPC listener. Both objects stay in Rust; Python receives ciphertext only.
    fn wrap_audit_signer_seed<'py>(
        &self,
        py: Python<'py>,
        signer: PyRef<'_, AuditSigner>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let wrapped = aes_gcm_encrypt_aad_locked_input(&self.key, &signer.seed, &[])
            .map_err(PyValueError::new_err)?;
        Ok(PyBytes::new(py, &wrapped))
    }

    #[getter]
    fn is_locked(&self) -> bool {
        self.locked
    }

    /// Build a master RPC server bound to `self.key`.
    ///
    /// The master AES key never crosses the Rust/Python boundary -
    /// Python calls this factory with the (public-ciphertext) encrypted
    /// subkeys + owner UID, the WrapKey hands its internal key bytes
    /// directly to MasterRpcServer's state on the Rust side.
    fn create_master_rpc_server(
        &self,
        socket_path: &str,
        hmac_enc: &[u8],
        dek_enc: &[u8],
        audit_enc: &[u8],
        owner_uid: u32,
    ) -> PyResult<master_rpc::MasterRpcServer> {
        master_rpc::MasterRpcServer::new_from_key_bytes(
            socket_path,
            &self.key,
            hmac_enc,
            dek_enc,
            audit_enc,
            owner_uid,
        )
    }
}

/// Ed25519 (RFC 8032) audit-chain signer. Once constructed, the 32-byte seed
/// lives in Rust, mlock'd + zeroized on drop. Production generation, database
/// load, rotation rewrap, and WrapKey wrapping keep it behind this boundary;
/// `from_seed` remains a low-level interop/test constructor. The public key is
/// public material. The chain message is `prev_signature || payload` (UTF-8),
/// signed with PureEd25519 directly (no pre-hash), byte-identical to
/// `api/app/crypto.py::sign_audit_ed25519`, gated by the parity test.
#[pyclass]
struct AuditSigner {
    seed: Vec<u8>,
}

impl AuditSigner {
    fn from_locked_seed(mut seed: SecureBuffer) -> PyResult<Self> {
        if seed.data.len() != 32 {
            return Err(PyValueError::new_err(
                "Resurgamus Horizon: Ed25519 seed must be a 32-byte secure buffer",
            ));
        }
        let data = std::mem::take(&mut seed.data);
        seed.locked = false;
        Ok(AuditSigner { seed: data })
    }

    fn new_locked(seed: &[u8]) -> PyResult<Self> {
        if seed.len() != 32 {
            return Err(PyValueError::new_err(
                "Resurgamus Horizon: Ed25519 seed must be exactly 32 bytes",
            ));
        }
        let mut buf = vec![0u8; 32];
        lock_secret_memory(&mut buf, "AuditSigner").map_err(PyValueError::new_err)?;
        buf.copy_from_slice(seed);
        Ok(AuditSigner { seed: buf })
    }

    fn public_key_bytes(&self) -> [u8; 32] {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&self.seed);
        let sk = SigningKey::from_bytes(&arr);
        arr.zeroize();
        sk.verifying_key().to_bytes()
    }
}

impl Drop for AuditSigner {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}

#[pymethods]
impl AuditSigner {
    /// Copy a raw 32-byte Ed25519 seed into a locked Rust allocation.
    /// The caller remains responsible for its original input buffer.
    #[staticmethod]
    fn from_seed(seed: &[u8]) -> PyResult<Self> {
        AuditSigner::new_locked(seed)
    }

    /// Sign `prev_signature || payload` and return the 64-byte signature hex.
    /// The SigningKey is rebuilt from the mlock'd seed per call; the transient
    /// seed copy and SigningKey are zeroized before return (only the seed lives on).
    #[pyo3(signature = (payload, prev_signature=""))]
    fn sign(&self, payload: &str, prev_signature: &str) -> PyResult<String> {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&self.seed);
        let sk = SigningKey::from_bytes(&arr);
        arr.zeroize();
        let mut message = String::with_capacity(prev_signature.len() + payload.len());
        message.push_str(prev_signature);
        message.push_str(payload);
        let sig: Signature = sk.sign(message.as_bytes());
        Ok(hex::encode(sig.to_bytes()))
    }

    /// Ed25519-sign arbitrary raw bytes and return the 64-byte signature.
    /// Used to self-sign the standalone audit cert's TBSCertificate (DER) so the
    /// seed never enters Python -- the X.509 cert is then reassembled in Python
    /// from (tbs, sig). Distinct from `sign`, which signs the `prev||payload`
    /// UTF-8 chain message; this signs the bytes verbatim (PureEd25519, no
    /// pre-hash). The transient SigningKey is zeroized; only the seed lives on.
    fn sign_raw<'py>(&self, py: Python<'py>, message: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&self.seed);
        let sk = SigningKey::from_bytes(&arr);
        arr.zeroize();
        let sig: Signature = sk.sign(message);
        Ok(PyBytes::new(py, &sig.to_bytes()))
    }

    /// Raw 32-byte Ed25519 public key for this signer.
    fn public_key<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        Ok(PyBytes::new(py, &self.public_key_bytes()))
    }
}

/// ML-DSA-65 (FIPS 204) post-quantum signer for the PKI CA. Seed-based: a
/// 32-byte keygen seed (xi) lives mlock'd + zeroize-on-drop in Rust (Python
/// never sees it); the public key is cached and the expanded key is rebuilt per
/// sign then dropped. The seed form is the OpenSSL/RFC 9881 PKCS8 encoding, so
/// issued keys interoperate. fips204 is pure-Rust, constant-time-by-design but
/// UNAUDITED -- gated by the NIST ACVP KAT in the test module.
#[pyclass]
struct MlDsaSigner {
    seed: Vec<u8>, // 32-byte FIPS 204 keygen seed (xi), mlock'd
    pk: Vec<u8>,   // cached ML-DSA-65 public key (PK_LEN) -- public material
    // Result of the lock attempt. Read by tests only: drop no longer
    // consumes it since munlock was removed (locked pages stay locked).
    #[cfg_attr(not(test), allow(dead_code))]
    locked: bool,
}

impl Drop for MlDsaSigner {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}

/// One-shot RNG that yields a fixed 32-byte seed as the FIPS 204 keygen xi.
/// ML-DSA.KeyGen draws xi as a single 32-byte read, so keygen becomes
/// deterministic in the stored seed (enabling seed-form custody + PKCS8).
struct SeedRng {
    seed: [u8; 32],
    offset: usize,
}

impl SeedRng {
    fn read_once(&mut self, dest: &mut [u8]) -> Result<(), fips204::RngError> {
        let end = self.offset.checked_add(dest.len());
        if end.is_none_or(|end| end > self.seed.len()) {
            dest.zeroize();
            let code = std::num::NonZeroU32::new(fips204::RngError::CUSTOM_START)
                .unwrap_or(std::num::NonZeroU32::MIN);
            return Err(fips204::RngError::from(code));
        }
        let end = end.unwrap_or(self.seed.len());
        dest.copy_from_slice(&self.seed[self.offset..end]);
        self.seed[self.offset..end].zeroize();
        self.offset = end;
        Ok(())
    }
}

impl Drop for SeedRng {
    fn drop(&mut self) {
        self.seed.zeroize();
        self.offset = 0;
    }
}

impl fips204::RngCore for SeedRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.read_once(&mut b).expect("ML-DSA seed RNG exhausted");
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.read_once(&mut b).expect("ML-DSA seed RNG exhausted");
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.read_once(dest).expect("ML-DSA seed RNG exhausted");
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), fips204::RngError> {
        self.read_once(dest)
    }
}
impl fips204::CryptoRng for SeedRng {}

impl MlDsaSigner {
    /// Deterministic keygen from the seed. Returns public bytes plus the expanded
    /// private key object, which is ZeroizeOnDrop in fips204.
    fn keygen_from_seed(seed: &[u8; 32]) -> Result<(Vec<u8>, ml_dsa_65::PrivateKey), String> {
        let mut rng = SeedRng {
            seed: *seed,
            offset: 0,
        };
        let keypair = ml_dsa_65::try_keygen_with_rng(&mut rng)
            .map_err(|e| format!("ML-DSA keygen failed: {e}"));
        drop(rng);
        let (pk, sk) = keypair?;
        Ok((pk.into_bytes().to_vec(), sk))
    }

    fn lock_seed(seed: &[u8], pk: Vec<u8>) -> PyResult<Self> {
        if seed.len() != 32 {
            return Err(PyValueError::new_err(
                "ML-DSA seed must be exactly 32 bytes",
            ));
        }
        let mut locked_seed = vec![0u8; seed.len()];
        let locked =
            lock_secret_memory(&mut locked_seed, "MlDsaSigner").map_err(PyValueError::new_err)?;
        locked_seed.copy_from_slice(seed);
        Ok(MlDsaSigner {
            seed: locked_seed,
            pk,
            locked,
        })
    }

    fn from_seed_bytes(seed: &[u8]) -> PyResult<Self> {
        let mut arr: [u8; 32] = seed
            .try_into()
            .map_err(|_| PyValueError::new_err("ML-DSA seed must be exactly 32 bytes"))?;
        let keypair = Self::keygen_from_seed(&arr).map_err(PyValueError::new_err);
        arr.zeroize();
        let (pk, sk) = keypair?;
        drop(sk);
        Self::lock_seed(seed, pk)
    }
}

#[pymethods]
impl MlDsaSigner {
    /// Generate a signer from a fresh random 32-byte seed (mlock'd).
    #[staticmethod]
    fn generate() -> PyResult<Self> {
        let mut seed = Zeroizing::new([0u8; 32]);
        try_os_fill(seed.as_mut()).map_err(PyValueError::new_err)?;
        let (pk, sk) = Self::keygen_from_seed(&seed).map_err(PyValueError::new_err)?;
        drop(sk);
        let out = Self::lock_seed(seed.as_slice(), pk);
        out
    }

    /// Copy a 32-byte seed into a locked Rust signer.
    #[staticmethod]
    fn from_seed(seed: &[u8]) -> PyResult<Self> {
        Self::from_seed_bytes(seed)
    }

    /// Rebuild from a wipeable Python bytearray without creating Python bytes.
    #[staticmethod]
    fn from_seed_bytearray(seed: &Bound<'_, PyByteArray>) -> PyResult<Self> {
        // The GIL remains held and no Python code runs while this is borrowed.
        let seed = unsafe { seed.as_bytes() };
        Self::from_seed_bytes(seed)
    }

    /// ML-DSA-sign raw bytes (a cert TBSCertificate DER), empty context. The
    /// expanded key is rebuilt from the seed for this call and zeroized; only the
    /// seed persists. The cert is reassembled in Python from (tbs, sig).
    fn sign_raw<'py>(&self, py: Python<'py>, message: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        let mut arr: [u8; 32] = self
            .seed
            .as_slice()
            .try_into()
            .map_err(|_| PyValueError::new_err("corrupt ML-DSA seed buffer"))?;
        let keypair = Self::keygen_from_seed(&arr).map_err(PyValueError::new_err);
        arr.zeroize();
        let (_pk, sk) = keypair?;
        let sig = sk
            .try_sign(message, &[])
            .map_err(|e| PyValueError::new_err(format!("ML-DSA sign failed: {e}")));
        Ok(PyBytes::new(py, &sig?))
    }

    /// Raw ML-DSA-65 public key bytes (PK_LEN) -- public material.
    fn public_key<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        Ok(PyBytes::new(py, &self.pk))
    }

    /// Return a wipeable copy of the 32-byte FIPS 204 keygen seed for at-rest
    /// wrapping or seed-form PKCS8 export. The caller must wipe it immediately.
    fn seed<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyByteArray>> {
        Ok(PyByteArray::new(py, &self.seed))
    }
}

/// Verify an ML-DSA-65 signature over `message` with a raw public key.
/// Public-only (no secret) -> callable while sealed. Returns False on any
/// malformed input rather than raising.
#[pyfunction]
fn verify_ml_dsa(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let pk_arr: [u8; ml_dsa_65::PK_LEN] = match public_key.try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let sig_arr: [u8; ml_dsa_65::SIG_LEN] = match signature.try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    match ml_dsa_65::PublicKey::try_from_bytes(pk_arr) {
        Ok(pk) => pk.verify(message, &sig_arr, &[]),
        Err(_) => false,
    }
}

// --- ML-KEM-768 (FIPS 203) key encapsulation for PKI KEM certificates -------

/// Reject any parameter set other than ML-KEM-768. The ASN.1 layer knows the
/// 512/1024 OIDs too, but this build wires only the NIST-cat-3 set that matches
/// the TLS X25519MLKEM768 handshake -- keeping one KAT-gated code path.
fn require_mlkem768(algorithm: &str) -> PyResult<()> {
    if algorithm != "ml-kem-768" {
        return Err(PyValueError::new_err(format!(
            "unsupported ML-KEM parameter set {algorithm:?}; this build provides ml-kem-768 only"
        )));
    }
    Ok(())
}

/// One-shot RNG over a fixed byte pool, consumed sequentially. FIPS 203 KeyGen
/// draws (d, z) = 64 bytes and Encaps draws m = 32 bytes as ordered reads, so
/// seeding the pool makes those ops deterministic in the stored bytes -- this
/// enables the NIST ACVP known-answer tests and turns fresh-entropy keygen into
/// "fill the pool from OsRng, then keygen from the pool". A compliant operation
/// consumes the pool exactly; over-read and reuse fail closed. Consumed bytes
/// and any remainder are zeroized.
struct KemSeedRng {
    pool: SecureBuffer,
    pos: usize,
}

impl KemSeedRng {
    fn new_locked(pool: &[u8]) -> Result<Self, String> {
        Ok(Self {
            pool: SecureBuffer::try_from_slice_locked(pool)?,
            pos: 0,
        })
    }

    fn read_once(&mut self, dest: &mut [u8]) -> Result<(), fips203::RngError> {
        let end = self.pos.checked_add(dest.len());
        if end.is_none_or(|end| end > self.pool.data.len()) {
            dest.zeroize();
            let code = std::num::NonZeroU32::new(fips203::RngError::CUSTOM_START)
                .unwrap_or(std::num::NonZeroU32::MIN);
            return Err(fips203::RngError::from(code));
        }
        let end = end.unwrap_or(self.pool.data.len());
        dest.copy_from_slice(&self.pool.data[self.pos..end]);
        self.pool.data[self.pos..end].zeroize();
        self.pos = end;
        Ok(())
    }
}

impl fips203::RngCore for KemSeedRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.read_once(&mut b).expect("ML-KEM seed RNG exhausted");
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.read_once(&mut b).expect("ML-KEM seed RNG exhausted");
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.read_once(dest).expect("ML-KEM seed RNG exhausted");
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), fips203::RngError> {
        self.read_once(dest)
    }
}
impl fips203::CryptoRng for KemSeedRng {}

/// ML-KEM-768 (FIPS 203) key-encapsulation keypair for PKI KEM certificates.
///
/// The decapsulation (secret) key is mlock'd + zeroized on drop, mirroring
/// MlDsaSigner; the encapsulation (public) key is plain. A KEM cert carries the
/// encaps key as its opaque subject key (KeyUsage=keyEncipherment) and is signed
/// by the CA; the decaps key is returned ONCE to the requester and never stored,
/// so this adds no server-side key-custody surface. fips203 is pure-Rust,
/// constant-time-by-design but UNAUDITED -- gated by the NIST ACVP KAT in tests.
#[pyclass]
struct MlKemKeypair {
    ek: Vec<u8>, // ML-KEM-768 encaps key (EK_LEN) -- public material
    dk: Vec<u8>, // ML-KEM-768 decaps key (DK_LEN), mlock'd -- secret
}

impl Drop for MlKemKeypair {
    fn drop(&mut self) {
        self.dk.zeroize();
    }
}

impl MlKemKeypair {
    /// Deterministic keygen from a 64-byte (d || z) seed, mlock'ing the decaps
    /// key. Errs if the seed is not 64 bytes or mlock fails.
    fn keygen_from_seed(seed: &[u8]) -> PyResult<Self> {
        if seed.len() != 64 {
            return Err(PyValueError::new_err(
                "ML-KEM keygen seed must be 64 bytes (d||z)",
            ));
        }
        // rng owns a copy of the seed; it is zeroized when the block ends.
        let (ek, dk) = {
            let mut rng = KemSeedRng::new_locked(seed).map_err(PyValueError::new_err)?;
            ml_kem_768::KG::try_keygen_with_rng(&mut rng)
                .map_err(|e| PyValueError::new_err(format!("ML-KEM keygen failed: {e}")))?
        };
        let ek_bytes = ek.into_bytes().to_vec();
        let mut dk_arr = dk.into_bytes();
        let mut dk_bytes = vec![0u8; dk_arr.len()];
        if let Err(error) = lock_secret_memory(&mut dk_bytes, "MlKemKeypair") {
            dk_arr.zeroize();
            return Err(PyValueError::new_err(error));
        }
        dk_bytes.copy_from_slice(&dk_arr);
        dk_arr.zeroize();
        Ok(MlKemKeypair {
            ek: ek_bytes,
            dk: dk_bytes,
        })
    }
}

#[pymethods]
impl MlKemKeypair {
    /// Generate an ML-KEM-768 keypair from fresh OS entropy (decaps key mlock'd).
    #[staticmethod]
    #[pyo3(signature = (algorithm = "ml-kem-768"))]
    fn generate(algorithm: &str) -> PyResult<Self> {
        require_mlkem768(algorithm)?;
        let mut seed = Zeroizing::new([0u8; 64]);
        try_os_fill(seed.as_mut()).map_err(PyValueError::new_err)?;
        let out = Self::keygen_from_seed(seed.as_ref());
        out
    }

    /// Raw ML-KEM-768 encapsulation (public) key bytes (EK_LEN) -- the KEM cert
    /// subject key.
    fn public_key<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        Ok(PyBytes::new(py, &self.ek))
    }

    /// Return a wipeable copy of the ML-KEM-768 decapsulation key (DK_LEN).
    /// The caller must wipe it immediately after wrapping or PKCS8 export.
    fn secret_key<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyByteArray>> {
        Ok(PyByteArray::new(py, &self.dk))
    }

    fn algorithm(&self) -> &'static str {
        "ml-kem-768"
    }
}

/// ML-KEM-768 encapsulate against a raw encaps (public) key. Returns
/// (shared_secret 32 B, ciphertext CT_LEN). Public-only -> callable while
/// sealed. The shared secret is the SENDER's copy; the receiver recovers the
/// identical value via :func:`mlkem_decaps`. Randomness m is fresh OS entropy.
#[pyfunction]
#[pyo3(signature = (encaps_key, algorithm = "ml-kem-768"))]
fn mlkem_encaps<'py>(
    py: Python<'py>,
    encaps_key: &[u8],
    algorithm: &str,
) -> PyResult<(Bound<'py, PyByteArray>, Bound<'py, PyBytes>)> {
    require_mlkem768(algorithm)?;
    let ek_arr: [u8; ml_kem_768::EK_LEN] = encaps_key.try_into().map_err(|_| {
        PyValueError::new_err(format!(
            "ML-KEM-768 encaps key must be {} bytes",
            ml_kem_768::EK_LEN
        ))
    })?;
    let ek = ml_kem_768::EncapsKey::try_from_bytes(ek_arr)
        .map_err(|e| PyValueError::new_err(format!("invalid ML-KEM-768 encaps key: {e}")))?;
    let mut m = Zeroizing::new([0u8; 32]);
    try_os_fill(m.as_mut()).map_err(PyValueError::new_err)?;
    // rng owns a locked copy of m; both are zeroized when their scopes end.
    let (ss, ct) = {
        let mut rng = KemSeedRng::new_locked(m.as_slice()).map_err(PyValueError::new_err)?;
        ek.try_encaps_with_rng(&mut rng)
            .map_err(|e| PyValueError::new_err(format!("ML-KEM encaps failed: {e}")))?
    };
    let ct_bytes = ct.into_bytes().to_vec();
    let mut ss_arr = ss.into_bytes();
    let ss_py = PyByteArray::new(py, &ss_arr);
    ss_arr.zeroize();
    Ok((ss_py, PyBytes::new(py, &ct_bytes)))
}

/// ML-KEM-768 decapsulate: recover the 32-byte shared secret from a decaps
/// (secret) key + ciphertext. FIPS 203 implicit rejection means a tampered
/// ciphertext yields a deterministic pseudo-random secret (never an error), so
/// this returns 32 bytes for any correctly-sized input. The caller must possess
/// the return-once decapsulation key; this native function has no vault state.
#[pyfunction]
#[pyo3(signature = (decaps_key, ciphertext, algorithm = "ml-kem-768"))]
fn mlkem_decaps<'py>(
    py: Python<'py>,
    decaps_key: &Bound<'_, PyAny>,
    ciphertext: &[u8],
    algorithm: &str,
) -> PyResult<Bound<'py, PyByteArray>> {
    require_mlkem768(algorithm)?;
    let decaps_key = if let Ok(bytes) = decaps_key.cast::<PyBytes>() {
        bytes.as_bytes()
    } else if let Ok(bytes) = decaps_key.cast::<PyByteArray>() {
        // SAFETY: the GIL remains held and no Python code runs while this
        // slice is borrowed, so the bytearray cannot be resized.
        unsafe { bytes.as_bytes() }
    } else {
        return Err(PyTypeError::new_err(
            "ML-KEM decapsulation key must be bytes or bytearray",
        ));
    };
    if decaps_key.len() != ml_kem_768::DK_LEN {
        return Err(PyValueError::new_err(format!(
            "ML-KEM-768 decaps key must be {} bytes",
            ml_kem_768::DK_LEN
        )));
    }
    let ct_arr: [u8; ml_kem_768::CT_LEN] = ciphertext.try_into().map_err(|_| {
        PyValueError::new_err(format!(
            "ML-KEM-768 ciphertext must be {} bytes",
            ml_kem_768::CT_LEN
        ))
    })?;
    let mut dk_arr = Zeroizing::new([0u8; ml_kem_768::DK_LEN]);
    dk_arr.copy_from_slice(decaps_key);
    let dk = ml_kem_768::DecapsKey::try_from_bytes(*dk_arr)
        .map_err(|e| PyValueError::new_err(format!("invalid ML-KEM-768 decaps key: {e}")))?;
    let ct = ml_kem_768::CipherText::try_from_bytes(ct_arr)
        .map_err(|e| PyValueError::new_err(format!("invalid ML-KEM-768 ciphertext: {e}")))?;
    let ss = dk
        .try_decaps(&ct)
        .map_err(|e| PyValueError::new_err(format!("ML-KEM decaps failed: {e}")))?;
    let ss_arr = Zeroizing::new(ss.into_bytes());
    let out = PyByteArray::new(py, ss_arr.as_ref());
    Ok(out)
}

/// Fixed HKDF salt for the hybrid KEM combiner -- a domain-separation constant,
/// NOT a secret (a salt need not be secret; it separates this construction from
/// any other HKDF use in the codebase). Version-suffixed so a future combiner
/// change (leg order, KDF, info layout) gets a fresh label instead of silently
/// producing colliding secrets.
const HYBRID_KEM_SALT: &[u8] = b"rhorizon-hybrid-kem-v1";
const HYBRID_KEM_LABEL: &[u8] = b"x25519-ml-kem-768";

/// Pure-Rust core of the hybrid-KEM combiner (no Python token), so the unit
/// tests and `cargo miri` can exercise the real SHA-512 / HKDF / zeroize memory
/// operations -- the `#[pyfunction]` wrapper below only adds the PyBytes marshal
/// (which Miri cannot run through libpython). Returns the 32-byte combined secret
/// or an error string on a wrong-sized fixed leg. See :func:`hybrid_kdf` for the
/// frozen contract.
#[allow(clippy::too_many_arguments)]
fn hybrid_kdf_core(
    ss_x25519: &[u8],
    ss_mlkem: &[u8],
    ct_x25519: &[u8],
    ct_mlkem: &[u8],
    pk_x25519: &[u8],
    pk_mlkem: &[u8],
    label: &[u8],
) -> Result<[u8; 32], String> {
    use sha2::Digest;
    // Fixed-size legs: guard against a caller wiring an empty / wrong buffer,
    // which would silently weaken the combined secret.
    if ss_x25519.len() != 32 {
        return Err("ss_x25519 must be 32 bytes".to_string());
    }
    if ss_mlkem.len() != 32 {
        return Err("ss_mlkem must be 32 bytes".to_string());
    }
    if ct_x25519.len() != 32 {
        return Err("ct_x25519 must be 32 bytes".to_string());
    }
    if pk_x25519.len() != 32 {
        return Err("pk_x25519 must be 32 bytes".to_string());
    }
    if ct_mlkem.len() != ml_kem_768::CT_LEN {
        return Err(format!(
            "ct_mlkem must be {} bytes for ML-KEM-768",
            ml_kem_768::CT_LEN
        ));
    }
    if pk_mlkem.len() != ml_kem_768::EK_LEN {
        return Err(format!(
            "pk_mlkem must be {} bytes for ML-KEM-768",
            ml_kem_768::EK_LEN
        ));
    }
    if label != HYBRID_KEM_LABEL {
        return Err("unsupported hybrid KEM label".to_string());
    }
    // info = SHA512(label || cts || pks). Fixed field order binds the transcript.
    let mut h = Sha512::new();
    h.update(label);
    h.update(ct_x25519);
    h.update(ct_mlkem);
    h.update(pk_x25519);
    h.update(pk_mlkem);
    let info = h.finalize();
    // IKM = ss_x25519 || ss_mlkem -- the leg order is the domain separator.
    let mut ikm = Zeroizing::new(Vec::with_capacity(64));
    ikm.extend_from_slice(ss_x25519);
    ikm.extend_from_slice(ss_mlkem);
    let hk = Hkdf::<Sha512>::new(Some(HYBRID_KEM_SALT), &ikm);
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(&info, okm.as_mut())
        .map_err(|e| format!("hybrid KDF expand failed: {e}"))?;
    Ok(*okm)
}

/// HKDF-SHA512 hybrid-KEM combiner (ETSI TS 103 744 / Giacon-Heuer-Poettering
/// shape). Combines the X25519 and ML-KEM leg shared secrets into ONE 32-byte
/// secret that stays secure as long as EITHER leg is unbroken -- the ANSSI/BSI
/// hybridation guarantee. Binds both ciphertexts and both recipient public keys
/// into the KDF context (`info`) so a secret cannot be transplanted across
/// sessions or key pairs (re-encapsulation / binding resistance).
///
/// Contract (frozen; changing any line requires a new HYBRID_KEM_SALT version):
///   IKM  = ss_x25519 || ss_mlkem            (x25519 leg FIRST = domain separator)
///   info = SHA512(label || ct_x25519 || ct_mlkem || pk_x25519 || pk_mlkem)
///   out  = HKDF-Expand(HKDF-Extract(salt=HYBRID_KEM_SALT, IKM), info, 32)
///
/// Both leg shared secrets are 32 bytes (X25519 DH output, ML-KEM-768 shared
/// secret); the X25519 ciphertext (ephemeral public) and public key are 32 bytes.
/// The ML-KEM-768 ciphertext and encaps key are exactly CT_LEN and EK_LEN; the
/// label is fixed to `x25519-ml-kem-768`. Wrong-suite inputs fail closed.
/// The concatenated IKM copy is zeroized before returning. The combiner handles
/// transient shared secrets but never receives a long-term private key.
#[pyfunction]
#[pyo3(signature = (ss_x25519, ss_mlkem, ct_x25519, ct_mlkem, pk_x25519, pk_mlkem, label))]
#[allow(clippy::too_many_arguments)]
fn hybrid_kdf<'py>(
    py: Python<'py>,
    ss_x25519: &[u8],
    ss_mlkem: &Bound<'_, PyAny>,
    ct_x25519: &[u8],
    ct_mlkem: &[u8],
    pk_x25519: &[u8],
    pk_mlkem: &[u8],
    label: &[u8],
) -> PyResult<Bound<'py, PyByteArray>> {
    let ss_mlkem = if let Ok(bytes) = ss_mlkem.cast::<PyBytes>() {
        bytes.as_bytes()
    } else if let Ok(bytes) = ss_mlkem.cast::<PyByteArray>() {
        // SAFETY: the GIL remains held and no Python code runs while this
        // slice is borrowed, so the bytearray cannot be resized.
        unsafe { bytes.as_bytes() }
    } else {
        return Err(PyTypeError::new_err(
            "ML-KEM shared secret must be bytes or bytearray",
        ));
    };
    let okm = Zeroizing::new(
        hybrid_kdf_core(
            ss_x25519, ss_mlkem, ct_x25519, ct_mlkem, pk_x25519, pk_mlkem, label,
        )
        .map_err(PyValueError::new_err)?,
    );
    let out = PyByteArray::new(py, okm.as_ref());
    Ok(out)
}

/// Verify an Ed25519 audit signature with a raw 32-byte public key.
/// Public-only: holds no secret, so it is callable while the vault is sealed.
/// `verify_strict` rejects non-canonical / small-order keys + malleable sigs.
/// Returns False on any malformed input rather than raising.
#[pyfunction]
#[pyo3(signature = (public_key, payload, prev_signature, signature_hex))]
fn ed25519_audit_verify(
    public_key: &[u8],
    payload: &str,
    prev_signature: &str,
    signature_hex: &str,
) -> bool {
    let pk_arr: [u8; 32] = match public_key.try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let vk = match VerifyingKey::from_bytes(&pk_arr) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let sig_arr: [u8; 64] = match hex::decode(signature_hex)
        .ok()
        .and_then(|b| b.try_into().ok())
    {
        Some(a) => a,
        None => return false,
    };
    let sig = Signature::from_bytes(&sig_arr);
    let mut message = String::with_capacity(prev_signature.len() + payload.len());
    message.push_str(prev_signature);
    message.push_str(payload);
    vk.verify_strict(message.as_bytes(), &sig).is_ok()
}

/// Zero a Python bytearray in place using `zeroize`.
///
/// The buffer length is unchanged, only the contents are wiped.
/// Designed to replace `ctypes.memset` for sensitive Python-side buffers
/// (e.g. derived master_key during unseal/rotate), with a documented
/// soundness contract.
#[pyfunction]
fn secure_zero(data: &Bound<'_, pyo3::types::PyByteArray>) -> PyResult<()> {
    let len = data.len();
    if len == 0 {
        return Ok(());
    }
    // SAFETY: We hold the GIL via the `Bound<'_, _>` lifetime, Python code
    // cannot run on this thread between borrow and zeroize. Slice `zeroize`
    // is straight-line: it does not allocate, call into Python, or release
    // the GIL, so the underlying bytearray buffer cannot be resized or freed
    // during the slice's lifetime. The slice is dropped before return.
    unsafe {
        let slice = std::slice::from_raw_parts_mut(data.data(), len);
        slice.zeroize();
    }
    Ok(())
}

/// Seal mutable plaintext to an X25519 public key in libsodium wire format
/// without first making an immutable Python plaintext copy.
#[pyfunction]
fn rekey_seal<'py>(
    py: Python<'py>,
    public_key: &[u8],
    plaintext: &Bound<'_, PyByteArray>,
) -> PyResult<Bound<'py, PyBytes>> {
    // SAFETY: the GIL is held and this function does not release it or invoke
    // Python while the bytearray slice is borrowed.
    let plaintext_slice = unsafe { std::slice::from_raw_parts(plaintext.data(), plaintext.len()) };
    let ciphertext =
        sealed_box_seal_locked(public_key, plaintext_slice).map_err(PyValueError::new_err)?;
    Ok(PyBytes::new(py, &ciphertext))
}

/// AES-256-GCM cipher holding the dek_key mlock'd in Rust -- a drop-in for
/// `cryptography.AESGCM`: encrypt/decrypt take an EXTERNAL 12-byte nonce and the
/// ciphertext is tag-appended (no nonce prepended), matching the DEK storage
/// format (nonce stored in its own column). Replaces the Python AESGCM(dek_key)
/// session cache so the dek_key -- which unwraps every DEK, hence every secret
/// -- is mlock'd against swap for the whole unsealed session, like the other
/// sub-keys. The round-key schedule is rebuilt per op (transient); only the
/// persistent key bytes are mlock'd. `aad=None` matches AESGCM's None AAD.
#[pyclass]
struct DekCipher {
    key: Vec<u8>,
}

impl Drop for DekCipher {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

#[pymethods]
impl DekCipher {
    #[new]
    fn py_new(key: &Bound<'_, PyAny>) -> PyResult<Self> {
        let key = if let Ok(bytes) = key.cast::<PyBytes>() {
            bytes.as_bytes()
        } else if let Ok(bytes) = key.cast::<PyByteArray>() {
            // SAFETY: the GIL remains held and no Python code runs while this
            // slice is borrowed, so the bytearray cannot be resized.
            unsafe { bytes.as_bytes() }
        } else {
            return Err(PyTypeError::new_err(
                "DekCipher key must be bytes or bytearray",
            ));
        };
        if key.len() != 32 {
            return Err(PyValueError::new_err("DekCipher key must be 32 bytes"));
        }
        let mut k = vec![0u8; key.len()];
        lock_secret_memory(&mut k, "DekCipher").map_err(PyValueError::new_err)?;
        k.copy_from_slice(key);
        Ok(DekCipher { key: k })
    }

    #[pyo3(signature = (nonce, data, aad=None))]
    fn encrypt<'py>(
        &self,
        py: Python<'py>,
        nonce: &[u8],
        data: &Bound<'_, PyAny>,
        aad: Option<&[u8]>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        if nonce.len() != 12 {
            return Err(PyValueError::new_err("nonce must be 12 bytes"));
        }
        let cipher = Aes256Gcm::new_from_slice(&self.key)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        let data = if let Ok(bytes) = data.cast::<PyBytes>() {
            bytes.as_bytes()
        } else if let Ok(bytes) = data.cast::<PyByteArray>() {
            // SAFETY: the GIL remains held and no Python code runs while this
            // slice is borrowed, so the bytearray cannot be resized.
            unsafe { bytes.as_bytes() }
        } else {
            return Err(PyTypeError::new_err(
                "DekCipher plaintext must be bytes or bytearray",
            ));
        };
        let mut protected =
            SecureBuffer::try_from_slice_locked(data).map_err(PyValueError::new_err)?;
        let tag = cipher
            .encrypt_in_place_detached(
                Nonce::from_slice(nonce),
                aad.unwrap_or(&[]),
                &mut protected.data,
            )
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        let capacity = protected
            .data
            .len()
            .checked_add(AES_GCM_TAG_BYTES)
            .ok_or_else(|| PyValueError::new_err("plaintext is too large"))?;
        let mut ct = Vec::with_capacity(capacity);
        ct.extend_from_slice(&protected.data);
        ct.extend_from_slice(&tag);
        Ok(PyBytes::new(py, &ct))
    }

    /// Legacy compatibility path returning immutable Python bytes. Sensitive
    /// callers must use `decrypt_bytearray` so Python can wipe the plaintext.
    /// The transient Rust plaintext is zeroized before return.
    #[pyo3(signature = (nonce, data, aad=None))]
    fn decrypt<'py>(
        &self,
        py: Python<'py>,
        nonce: &[u8],
        data: &[u8],
        aad: Option<&[u8]>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        if nonce.len() != 12 {
            return Err(PyValueError::new_err("nonce must be 12 bytes"));
        }
        let cipher = Aes256Gcm::new_from_slice(&self.key)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        let payload = Payload {
            msg: data,
            aad: aad.unwrap_or(&[]),
        };
        let mut pt = cipher
            .decrypt(Nonce::from_slice(nonce), payload)
            .map_err(|_| PyValueError::new_err("Decryption failed - wrong key or tampered data"))?;
        let output = PyBytes::new(py, &pt);
        pt.zeroize();
        Ok(output)
    }

    /// Decrypt sensitive material into a mutable Python buffer. The transient
    /// Rust plaintext is zeroized before return.
    #[pyo3(signature = (nonce, data, aad=None))]
    fn decrypt_bytearray<'py>(
        &self,
        py: Python<'py>,
        nonce: &[u8],
        data: &[u8],
        aad: Option<&[u8]>,
    ) -> PyResult<Bound<'py, PyByteArray>> {
        if nonce.len() != 12 {
            return Err(PyValueError::new_err("nonce must be 12 bytes"));
        }
        let capacity = nonce
            .len()
            .checked_add(data.len())
            .ok_or_else(|| PyValueError::new_err("ciphertext is too large"))?;
        let mut wrapped = Vec::with_capacity(capacity);
        wrapped.extend_from_slice(nonce);
        wrapped.extend_from_slice(data);
        let plaintext = aes_gcm_decrypt_aad_locked(&self.key, &wrapped, aad.unwrap_or(&[]))
            .map_err(|_| PyValueError::new_err("Decryption failed - wrong key or tampered data"))?;
        let output = PyByteArray::new(py, &plaintext.data);
        Ok(output)
    }

    /// Decrypt a nonce-prefixed audit seed in locked memory and move that
    /// allocation directly into a Rust AuditSigner.
    fn load_audit_signer(&self, wrapped: &[u8]) -> PyResult<AuditSigner> {
        let seed =
            aes_gcm_decrypt_aad_locked(&self.key, wrapped, &[]).map_err(PyValueError::new_err)?;
        AuditSigner::from_locked_seed(seed)
    }

    /// Generate an audit identity entirely in Rust. Returns the locked signer,
    /// nonce-prefixed seed ciphertext for PostgreSQL, and the public key.
    fn generate_audit_identity<'py>(
        &self,
        py: Python<'py>,
    ) -> PyResult<(AuditSigner, Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
        let mut seed =
            SecureBuffer::try_new_locked(vec![0u8; 32]).map_err(PyValueError::new_err)?;
        try_os_fill(&mut seed.data).map_err(PyValueError::new_err)?;
        let wrapped = aes_gcm_encrypt_aad_locked_input(&self.key, &seed.data, &[])
            .map_err(PyValueError::new_err)?;
        let signer = AuditSigner::from_locked_seed(seed)?;
        let public_key = signer.public_key_bytes();
        Ok((
            signer,
            PyBytes::new(py, &wrapped),
            PyBytes::new(py, &public_key),
        ))
    }

    /// Re-wrap a nonce-prefixed AES-GCM blob under another locked DekCipher.
    /// Plaintext remains in locked Rust memory and never crosses into Python.
    #[pyo3(signature = (new_cipher, wrapped, aad=None))]
    fn rewrap_to<'py>(
        &self,
        py: Python<'py>,
        new_cipher: PyRef<'_, DekCipher>,
        wrapped: &[u8],
        aad: Option<&[u8]>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let aad = aad.unwrap_or(&[]);
        let plaintext =
            aes_gcm_decrypt_aad_locked(&self.key, wrapped, aad).map_err(PyValueError::new_err)?;
        let result = aes_gcm_encrypt_aad_locked_input(&new_cipher.key, &plaintext.data, aad)
            .map_err(PyValueError::new_err)?;
        Ok(PyBytes::new(py, &result))
    }
}

#[pymodule]
fn rhorizon_crypto(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<SecureBuffer>()?;
    m.add_class::<WrapKey>()?;
    m.add_class::<DekCipher>()?;
    m.add_class::<key_share::ShamirShare>()?;
    m.add_class::<key_share::KeyServer>()?;
    m.add_class::<key_share::KeyClient>()?;
    m.add_class::<master_rpc::MasterRpcServer>()?;
    m.add_class::<backup_context::BackupCryptoContext>()?;
    m.add_class::<AuditSigner>()?;
    m.add_class::<MlDsaSigner>()?;
    m.add_class::<MlKemKeypair>()?;
    m.add_function(wrap_pyfunction!(memory_lock_status, m)?)?;
    m.add_function(wrap_pyfunction!(secure_zero, m)?)?;
    m.add_function(wrap_pyfunction!(rekey_seal, m)?)?;
    m.add_function(wrap_pyfunction!(ed25519_audit_verify, m)?)?;
    m.add_function(wrap_pyfunction!(verify_ml_dsa, m)?)?;
    m.add_function(wrap_pyfunction!(mlkem_encaps, m)?)?;
    m.add_function(wrap_pyfunction!(mlkem_decaps, m)?)?;
    m.add_function(wrap_pyfunction!(hybrid_kdf, m)?)?;
    m.add_function(wrap_pyfunction!(key_share::shamir_split_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(
        key_share::shamir_split_opaque_bytearray,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(key_share::shamir_combine_bytes, m)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_lock_policy_parsing_is_explicit() {
        assert_eq!(
            parse_memory_lock_policy(None).unwrap(),
            MemoryLockPolicy::BestEffort
        );
        assert_eq!(
            parse_memory_lock_policy(Some("BEST_EFFORT")).unwrap(),
            MemoryLockPolicy::BestEffort
        );
        assert_eq!(
            parse_memory_lock_policy(Some("required")).unwrap(),
            MemoryLockPolicy::Required
        );
        assert!(parse_memory_lock_policy(Some("disabled")).is_err());
    }

    #[test]
    fn memory_lock_failure_obeys_operator_policy() {
        let mut best_effort = [0xA5u8; 8];
        assert!(!apply_memory_lock_result(
            &mut best_effort,
            "test buffer",
            MemoryLockPolicy::BestEffort,
            false,
        )
        .unwrap());
        assert_eq!(best_effort, [0xA5u8; 8]);

        let mut required = [0x5Au8; 8];
        assert!(apply_memory_lock_result(
            &mut required,
            "test buffer",
            MemoryLockPolicy::Required,
            false,
        )
        .is_err());
        assert_eq!(required, [0u8; 8]);
    }

    // --- Ed25519 audit signer (RFC 8032 section 7.1 vectors) ----------------
    // Anchors the Rust impl to the standard; the parity test
    // (tests/test_audit_ed25519_parity.py) then proves byte-equality with the
    // Python reference. AuditSigner::from_seed mlock's -> miri-ignored like the
    // other mlock tests. msg is the RFC message routed through the payload arg
    // (prev_signature=""), so the signed message equals the RFC message.
    const RFC_SEED_1: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    const RFC_PUB_1: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    const RFC_SIG_1: &str = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";
    const RFC_SEED_2: &str = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";
    const RFC_PUB_2: &str = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";
    const RFC_SIG_2: &str = "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00";

    #[test]
    #[cfg_attr(miri, ignore)]
    fn ed25519_rfc8032_vectors() {
        for (seed_hex, pub_hex, msg, sig_hex) in [
            (RFC_SEED_1, RFC_PUB_1, "", RFC_SIG_1),
            (RFC_SEED_2, RFC_PUB_2, "r", RFC_SIG_2), // 0x72
        ] {
            let seed = hex::decode(seed_hex).unwrap();
            // Public key derivation matches RFC (the value public_key() returns).
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&seed);
            let pub_bytes = SigningKey::from_bytes(&arr).verifying_key().to_bytes();
            assert_eq!(hex::encode(pub_bytes), pub_hex);
            // Signature matches RFC.
            let signer = AuditSigner::from_seed(&seed).unwrap();
            assert_eq!(signer.sign(msg, "").unwrap(), sig_hex);
            // Public-key verify accepts it.
            let pubk = hex::decode(pub_hex).unwrap();
            assert!(ed25519_audit_verify(&pubk, msg, "", sig_hex));
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn ed25519_verify_rejects_tampering() {
        let pubk = hex::decode(RFC_PUB_1).unwrap();
        // Flip first nibble of the signature.
        let bad = format!(
            "{}{}",
            if &RFC_SIG_1[0..1] != "f" { "f" } else { "0" },
            &RFC_SIG_1[1..]
        );
        assert!(!ed25519_audit_verify(&pubk, "", "", &bad));
        // Wrong message.
        assert!(!ed25519_audit_verify(&pubk, "x", "", RFC_SIG_1));
        // Wrong signer's pubkey.
        let other = hex::decode(RFC_PUB_2).unwrap();
        assert!(!ed25519_audit_verify(&other, "", "", RFC_SIG_1));
        // Malformed: non-hex, short sig, short key -> false, never panics.
        assert!(!ed25519_audit_verify(&pubk, "", "", "zz"));
        assert!(!ed25519_audit_verify(&pubk, "", "", "ab"));
        assert!(!ed25519_audit_verify(&[0u8; 8], "", "", RFC_SIG_1));
    }

    // --- ML-DSA-65 (FIPS 204) round-trip + negative cases. The NIST ACVP
    // known-answer vectors (the spec anchor for the unaudited fips204 crate)
    // are gated separately; this covers sizes, valid round-trip, and rejection
    // of tampered / wrong / malformed inputs.
    #[test]
    fn ml_dsa_seed_rng_streams_once_and_rejects_reuse() {
        let seed = core::array::from_fn(|index| index as u8);
        let mut rng = SeedRng { seed, offset: 0 };

        assert_eq!(fips204::RngCore::next_u32(&mut rng), 0x0302_0100);
        assert_eq!(fips204::RngCore::next_u64(&mut rng), 0x0b0a_0908_0706_0504);
        let mut tail = [0u8; 20];
        fips204::RngCore::try_fill_bytes(&mut rng, &mut tail).unwrap();
        assert_eq!(tail, core::array::from_fn(|index| (index + 12) as u8));

        let mut reused = [0xAAu8; 1];
        assert!(fips204::RngCore::try_fill_bytes(&mut rng, &mut reused).is_err());
        assert_eq!(reused, [0]);
    }

    #[test]
    fn ml_dsa_65_sizes() {
        assert_eq!(ml_dsa_65::PK_LEN, 1952);
        assert_eq!(ml_dsa_65::SK_LEN, 4032);
        assert_eq!(ml_dsa_65::SIG_LEN, 3309);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn ml_dsa_65_roundtrip_and_rejection() {
        let (pk, sk) = ml_dsa_65::try_keygen().unwrap();
        let msg = b"rhorizon ml-dsa tbsCertificate";
        let sig = sk.try_sign(msg, &[]).unwrap();
        assert!(pk.verify(msg, &sig, &[]), "valid ML-DSA sig must verify");
        let mut bad = sig;
        bad[0] ^= 0x01;
        assert!(!pk.verify(msg, &bad, &[]), "tampered sig must be rejected");
        assert!(
            !pk.verify(b"other message", &sig, &[]),
            "wrong message must be rejected"
        );
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn ml_dsa_signer_rebuilds_key_and_signs() {
        pyo3::Python::attach(|py| {
            let seed = [0x42u8; 32];
            let signer = MlDsaSigner::from_seed_bytes(&seed).unwrap();
            assert!(signer.locked);
            let pk = signer.pk.clone();
            let msg = b"rhorizon ml-dsa signer path";
            let sig = signer.sign_raw(py, msg).unwrap();
            assert!(verify_ml_dsa(&pk, msg, sig.as_bytes()));
        });
    }

    #[test]
    fn verify_ml_dsa_rejects_malformed() {
        // wrong-length pubkey / signature -> false, never panics.
        assert!(!verify_ml_dsa(&[0u8; 8], b"m", &[0u8; ml_dsa_65::SIG_LEN]));
        assert!(!verify_ml_dsa(&[0u8; ml_dsa_65::PK_LEN], b"m", &[0u8; 8]));
    }

    // NIST ACVP ML-DSA-65 sigVer known-answer vectors (FIPS 204 final, from
    // usnistgov/ACVP-Server -- see tests/vectors/SOURCE.txt). This is the SPEC
    // anchor for the unaudited fips204 crate: no trusted Python ML-DSA exists for
    // a parity test, so conformance is gated against NIST's own vectors. A
    // supply-chain swap or a non-conformant fips204 trips this test.
    #[test]
    #[cfg_attr(miri, ignore)]
    // fips204 marks _internal_verify #[deprecated] ("temporary, will be removed"),
    // but it is the exact ML-DSA.Verify_internal the ACVP internalProjection vectors
    // target -- the deliberate, documented use below. Scope the allow to this test so
    // the deprecation warning does not noise up every build (and stays a warning, not
    // a future -D-warnings break), without blanket-allowing deprecations crate-wide.
    #[allow(deprecated)]
    fn ml_dsa_65_nist_acvp_sigver_kat() {
        let pk =
            hex::decode(include_str!("../tests/vectors/ml_dsa65_sigver_pk.hex").trim()).unwrap();
        let pmsg =
            hex::decode(include_str!("../tests/vectors/ml_dsa65_sigver_pass_msg.hex").trim())
                .unwrap();
        let psig =
            hex::decode(include_str!("../tests/vectors/ml_dsa65_sigver_pass_sig.hex").trim())
                .unwrap();
        let fmsg =
            hex::decode(include_str!("../tests/vectors/ml_dsa65_sigver_fail_msg.hex").trim())
                .unwrap();
        let fsig =
            hex::decode(include_str!("../tests/vectors/ml_dsa65_sigver_fail_sig.hex").trim())
                .unwrap();
        // ACVP internalProjection vectors exercise ML-DSA.Verify_internal (the
        // core algorithm, no external ctx/domain wrapper). fips204 exposes it as
        // _internal_verify -- the same call its own ACVP harness uses. The PKI's
        // external verify (RFC 9881, empty ctx) = internal(M') and is gated by
        // the independent Wycheproof vectors below.
        let pk_arr: [u8; ml_dsa_65::PK_LEN] = pk.as_slice().try_into().unwrap();
        let pk_obj = ml_dsa_65::PublicKey::try_from_bytes(pk_arr).unwrap();
        let psig_arr: [u8; ml_dsa_65::SIG_LEN] = psig.as_slice().try_into().unwrap();
        let fsig_arr: [u8; ml_dsa_65::SIG_LEN] = fsig.as_slice().try_into().unwrap();
        // tcId 20 (testPassed=true): a NIST-valid ML-DSA-65 signature MUST verify.
        assert!(
            ml_dsa_65::_internal_verify(&pk_obj, &pmsg, &psig_arr, &[]),
            "NIST ACVP ML-DSA-65 valid sigVer rejected -- fips204 non-conformant / swapped",
        );
        // tcId 16 ('too many hints', testPassed=false): MUST be rejected. The
        // invalid sig is full length (3309B), so this hits the real reject logic.
        assert!(
            !ml_dsa_65::_internal_verify(&pk_obj, &fmsg, &fsig_arr, &[]),
            "NIST ACVP ML-DSA-65 invalid sigVer accepted -- broken reject path",
        );
    }

    /// Independent public-interface gate for the FIPS 204 external message
    /// wrapper used by Rhorizon (empty context). Wycheproof tcId 1 is valid;
    /// tcId 19 carries a repeated hint and must be rejected.
    #[test]
    fn ml_dsa_65_wycheproof_external_verify() {
        let pk = hex::decode(include_str!("../tests/vectors/ml_dsa65_wycheproof_pk.hex").trim())
            .unwrap();
        let valid_msg =
            hex::decode(include_str!("../tests/vectors/ml_dsa65_wycheproof_valid_msg.hex").trim())
                .unwrap();
        let valid_sig =
            hex::decode(include_str!("../tests/vectors/ml_dsa65_wycheproof_valid_sig.hex").trim())
                .unwrap();
        let repeated_hint_msg = hex::decode(
            include_str!("../tests/vectors/ml_dsa65_wycheproof_repeated_hint_msg.hex").trim(),
        )
        .unwrap();
        let repeated_hint_sig = hex::decode(
            include_str!("../tests/vectors/ml_dsa65_wycheproof_repeated_hint_sig.hex").trim(),
        )
        .unwrap();

        assert!(
            verify_ml_dsa(&pk, &valid_msg, &valid_sig),
            "Wycheproof ML-DSA-65 external valid signature rejected",
        );
        assert!(
            !verify_ml_dsa(&pk, &repeated_hint_msg, &repeated_hint_sig),
            "Wycheproof ML-DSA-65 repeated-hint signature accepted",
        );
    }

    // --- ML-KEM-768 (FIPS 203) sizes + NIST ACVP known-answer vectors --------
    #[test]
    fn ml_kem_seed_rng_streams_once_and_rejects_reuse() {
        let pool: Vec<u8> = (0u8..32).collect();
        let mut rng = KemSeedRng::new_locked(&pool).unwrap();

        assert_eq!(fips203::RngCore::next_u32(&mut rng), 0x0302_0100);
        assert_eq!(fips203::RngCore::next_u64(&mut rng), 0x0b0a_0908_0706_0504);
        let mut tail = [0u8; 20];
        fips203::RngCore::try_fill_bytes(&mut rng, &mut tail).unwrap();
        assert_eq!(tail, core::array::from_fn(|index| (index + 12) as u8));

        let mut reused = [0xAAu8; 1];
        assert!(fips203::RngCore::try_fill_bytes(&mut rng, &mut reused).is_err());
        assert_eq!(reused, [0]);
    }

    #[test]
    fn ml_kem_768_sizes() {
        assert_eq!(ml_kem_768::EK_LEN, 1184);
        assert_eq!(ml_kem_768::DK_LEN, 2400);
        assert_eq!(ml_kem_768::CT_LEN, 1088);
    }

    // NIST ACVP ML-KEM-768 keyGen + encaps + decaps known-answer vectors (FIPS
    // 203 final, from usnistgov/ACVP-Server -- see tests/vectors/SOURCE.txt).
    // This is the SPEC anchor for the unaudited fips203 crate: no trusted Python
    // ML-KEM exists for a parity test, so conformance is gated against NIST's own
    // vectors. All three operations are deterministic in the ACVP seeds (keyGen
    // in d||z, encaps in m, decaps by construction), so a supply-chain swap or a
    // non-conformant fips203 -- including a broken implicit-reject path -- trips
    // this test.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn ml_kem_768_nist_acvp_kat() {
        // keyGen: (d || z) -> (ek, dk).
        let d =
            hex::decode(include_str!("../tests/vectors/ml_kem768_keygen_d.hex").trim()).unwrap();
        let z =
            hex::decode(include_str!("../tests/vectors/ml_kem768_keygen_z.hex").trim()).unwrap();
        let ek_exp =
            hex::decode(include_str!("../tests/vectors/ml_kem768_keygen_ek.hex").trim()).unwrap();
        let dk_exp =
            hex::decode(include_str!("../tests/vectors/ml_kem768_keygen_dk.hex").trim()).unwrap();
        let mut seed = d.clone();
        seed.extend_from_slice(&z);
        let kp = MlKemKeypair::keygen_from_seed(&seed).unwrap();
        assert_eq!(
            kp.ek, ek_exp,
            "NIST ACVP ML-KEM-768 keyGen ek mismatch -- fips203 non-conformant / swapped",
        );
        assert_eq!(
            kp.dk, dk_exp,
            "NIST ACVP ML-KEM-768 keyGen dk mismatch -- fips203 non-conformant / swapped",
        );

        // Encaps: (ek, m) -> (k, c), deterministic in the message randomness m.
        let ek_in =
            hex::decode(include_str!("../tests/vectors/ml_kem768_encap_ek.hex").trim()).unwrap();
        let m = hex::decode(include_str!("../tests/vectors/ml_kem768_encap_m.hex").trim()).unwrap();
        let c_exp =
            hex::decode(include_str!("../tests/vectors/ml_kem768_encap_c.hex").trim()).unwrap();
        let k_exp =
            hex::decode(include_str!("../tests/vectors/ml_kem768_encap_k.hex").trim()).unwrap();
        let ek_arr: [u8; ml_kem_768::EK_LEN] = ek_in.as_slice().try_into().unwrap();
        let ek = ml_kem_768::EncapsKey::try_from_bytes(ek_arr).unwrap();
        let (ss, ct) = {
            let mut rng = KemSeedRng::new_locked(&m).unwrap();
            ek.try_encaps_with_rng(&mut rng).unwrap()
        };
        assert_eq!(
            ct.into_bytes().to_vec(),
            c_exp,
            "NIST ACVP ML-KEM-768 encaps ciphertext mismatch",
        );
        assert_eq!(
            ss.into_bytes().to_vec(),
            k_exp,
            "NIST ACVP ML-KEM-768 encaps shared secret mismatch",
        );

        // Decaps: (dk, c) -> k, both a valid ciphertext and an implicit-reject
        // (modified) one. The reject case gates the hardest ML-KEM branch: a
        // tampered ciphertext must return the deterministic z-derived secret.
        let dk_in =
            hex::decode(include_str!("../tests/vectors/ml_kem768_decap_dk.hex").trim()).unwrap();
        let dk_arr: [u8; ml_kem_768::DK_LEN] = dk_in.as_slice().try_into().unwrap();
        let c_valid =
            hex::decode(include_str!("../tests/vectors/ml_kem768_decap_valid_c.hex").trim())
                .unwrap();
        let k_valid =
            hex::decode(include_str!("../tests/vectors/ml_kem768_decap_valid_k.hex").trim())
                .unwrap();
        let c_rej =
            hex::decode(include_str!("../tests/vectors/ml_kem768_decap_c.hex").trim()).unwrap();
        let k_rej =
            hex::decode(include_str!("../tests/vectors/ml_kem768_decap_k.hex").trim()).unwrap();
        let decaps = |c: &[u8]| -> Vec<u8> {
            let dk = ml_kem_768::DecapsKey::try_from_bytes(dk_arr).unwrap();
            let ct_arr: [u8; ml_kem_768::CT_LEN] = c.try_into().unwrap();
            let ct = ml_kem_768::CipherText::try_from_bytes(ct_arr).unwrap();
            dk.try_decaps(&ct).unwrap().into_bytes().to_vec()
        };
        assert_eq!(
            decaps(&c_valid),
            k_valid,
            "NIST ACVP ML-KEM-768 decaps (valid) mismatch",
        );
        assert_eq!(
            decaps(&c_rej),
            k_rej,
            "NIST ACVP ML-KEM-768 decaps (implicit reject) mismatch -- fips203 reject path broken",
        );
    }

    // End-to-end through the Python-facing surface: generate -> encaps(ek) ->
    // decaps(dk, ct) yields the same shared secret, and a tampered ciphertext
    // (implicit reject) yields a different one. generate() mlock's -> miri-ignored.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn ml_kem_768_generate_encaps_decaps_roundtrip() {
        pyo3::Python::attach(|py| {
            let kp = MlKemKeypair::generate("ml-kem-768").unwrap();
            let ek = kp.public_key(py).unwrap().as_bytes().to_vec();
            let dk = kp.secret_key(py).unwrap();
            assert_eq!(ek.len(), ml_kem_768::EK_LEN);
            assert_eq!(unsafe { dk.as_bytes() }.len(), ml_kem_768::DK_LEN);
            let (ss_send, ct) = mlkem_encaps(py, &ek, "ml-kem-768").unwrap();
            let ss_recv = mlkem_decaps(py, dk.as_any(), ct.as_bytes(), "ml-kem-768").unwrap();
            assert_eq!(unsafe { ss_recv.as_bytes() }.len(), 32);
            assert_eq!(
                unsafe { ss_send.as_bytes() },
                unsafe { ss_recv.as_bytes() },
                "KEM sender/receiver shared secrets must agree",
            );
            let mut bad = ct.as_bytes().to_vec();
            bad[0] ^= 0x01;
            let ss_bad = mlkem_decaps(py, dk.as_any(), &bad, "ml-kem-768").unwrap();
            assert_ne!(
                unsafe { ss_bad.as_bytes() },
                unsafe { ss_recv.as_bytes() },
                "tampered ciphertext must not yield the agreed secret",
            );
            secure_zero(&dk).unwrap();
            secure_zero(&ss_send).unwrap();
            secure_zero(&ss_recv).unwrap();
            secure_zero(&ss_bad).unwrap();
        });
    }

    // Hybrid-KEM combiner (hybrid_kdf) known-answer test. The expected value is
    // computed INDEPENDENTLY by OpenSSL's HKDF-SHA512 (pyca/cryptography) over
    // the exact frozen byte layout -- a genuine cross-implementation KAT, not a
    // tautology. If the rust-crypto `hkdf`/`sha2` crates ever deviate from the
    // standard (supply-chain compromise or a semantics change), this fires. A
    // matching Python-side parity test (test_pki.py) checks the live extension
    // against OpenSSL too, so both ends are pinned to the same anchor.
    // Runs against hybrid_kdf_core (pure Rust) so it also executes under
    // `cargo miri` -- the #[pyfunction] wrapper needs libpython, which Miri can't.
    #[test]
    fn hybrid_kdf_openssl_kat() {
        let ss_x = [0x11u8; 32];
        let ss_m = [0x22u8; 32];
        let ct_x = [0x33u8; 32];
        let ct_m = [0x44u8; ml_kem_768::CT_LEN];
        let pk_x = [0x55u8; 32];
        let pk_m = [0x66u8; ml_kem_768::EK_LEN];
        let label = HYBRID_KEM_LABEL;
        let out = hybrid_kdf_core(&ss_x, &ss_m, &ct_x, &ct_m, &pk_x, &pk_m, label).unwrap();
        let expected =
            hex::decode("22766b5730ae6f0d2e16a2261208ca1986731733934ffe2e135b5e0c193c9ebf")
                .unwrap();
        assert_eq!(
            &out[..],
            expected.as_slice(),
            "hybrid_kdf diverged from the OpenSSL HKDF-SHA512 anchor -- \
             hkdf/sha2 crate compromise or combiner-contract change",
        );
    }

    // Combiner robustness: flipping ANY bound input (either shared secret, either
    // ciphertext, either public key, or the label) changes the output. This is
    // the transcript-binding property -- a secret cannot be replayed across a
    // different session or key pair. Also gates the leg-order domain separator
    // (swapping the two shared secrets must change the result).
    #[test]
    fn hybrid_kdf_binds_every_input() {
        let ss_x = [0x11u8; 32];
        let ss_m = [0x22u8; 32];
        let ct_x = [0x33u8; 32];
        let ct_m = [0x44u8; ml_kem_768::CT_LEN];
        let pk_x = [0x55u8; 32];
        let pk_m = [0x66u8; ml_kem_768::EK_LEN];
        let label = HYBRID_KEM_LABEL;
        let kdf = |ss0: &[u8], ss1: &[u8], c0: &[u8], c1: &[u8], p0: &[u8], p1: &[u8], l: &[u8]| {
            hybrid_kdf_core(ss0, ss1, c0, c1, p0, p1, l).unwrap()
        };
        let base = kdf(&ss_x, &ss_m, &ct_x, &ct_m, &pk_x, &pk_m, label);
        let flip = |b: &[u8; 32]| {
            let mut c = *b;
            c[0] ^= 0x01;
            c
        };
        let variants: Vec<[u8; 32]> = vec![
            kdf(&flip(&ss_x), &ss_m, &ct_x, &ct_m, &pk_x, &pk_m, label),
            kdf(&ss_x, &flip(&ss_m), &ct_x, &ct_m, &pk_x, &pk_m, label),
            kdf(&ss_x, &ss_m, &flip(&ct_x), &ct_m, &pk_x, &pk_m, label),
            kdf(
                &ss_x,
                &ss_m,
                &ct_x,
                &[0x45u8; ml_kem_768::CT_LEN],
                &pk_x,
                &pk_m,
                label,
            ),
            kdf(&ss_x, &ss_m, &ct_x, &ct_m, &flip(&pk_x), &pk_m, label),
            kdf(
                &ss_x,
                &ss_m,
                &ct_x,
                &ct_m,
                &pk_x,
                &[0x67u8; ml_kem_768::EK_LEN],
                label,
            ),
            // leg-order swap: ss_mlkem first must differ (domain separation)
            kdf(&ss_m, &ss_x, &ct_x, &ct_m, &pk_x, &pk_m, label),
        ];
        for (i, v) in variants.iter().enumerate() {
            assert_ne!(v, &base, "hybrid_kdf failed to bind input variant #{i}");
        }
    }

    // Wrong-sized or wrong-suite legs error, never panic or silently truncate.
    #[test]
    fn hybrid_kdf_rejects_bad_lengths() {
        let ok = [0u8; 32];
        let short = [0u8; 8];
        let ct_m = [0u8; ml_kem_768::CT_LEN];
        let pk_m = [0u8; ml_kem_768::EK_LEN];
        let l = HYBRID_KEM_LABEL;
        assert!(hybrid_kdf_core(&short, &ok, &ok, &ct_m, &ok, &pk_m, l).is_err());
        assert!(hybrid_kdf_core(&ok, &short, &ok, &ct_m, &ok, &pk_m, l).is_err());
        assert!(hybrid_kdf_core(&ok, &ok, &short, &ct_m, &ok, &pk_m, l).is_err());
        assert!(hybrid_kdf_core(&ok, &ok, &ok, &ct_m, &short, &pk_m, l).is_err());
        assert!(hybrid_kdf_core(&ok, &ok, &ok, &short, &ok, &pk_m, l).is_err());
        assert!(hybrid_kdf_core(&ok, &ok, &ok, &ct_m, &ok, &short, l).is_err());
        assert!(hybrid_kdf_core(&ok, &ok, &ok, &ct_m, &ok, &pk_m, b"other").is_err());
    }

    // Malformed-length inputs and unsupported parameter sets error, never panic.
    // Uses the #[pyfunction] surface (Python::attach) -> libpython FFI, which Miri
    // cannot run, like the other pyo3 tests here. Regular cargo test covers it.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn ml_kem_768_rejects_malformed() {
        pyo3::Python::attach(|py| {
            let short_dk = PyBytes::new(py, &[0u8; 8]);
            let full_dk = PyBytes::new(py, &[0u8; ml_kem_768::DK_LEN]);
            assert!(mlkem_encaps(py, &[0u8; 8], "ml-kem-768").is_err());
            assert!(mlkem_decaps(
                py,
                short_dk.as_any(),
                &[0u8; ml_kem_768::CT_LEN],
                "ml-kem-768"
            )
            .is_err());
            assert!(mlkem_decaps(py, full_dk.as_any(), &[0u8; 8], "ml-kem-768").is_err());
            assert!(mlkem_encaps(py, &[0u8; ml_kem_768::EK_LEN], "ml-kem-1024").is_err());
            assert!(MlKemKeypair::generate("ml-kem-512").is_err());
        });
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn ed25519_chain_binding() {
        let seed = hex::decode(RFC_SEED_1).unwrap();
        let signer = AuditSigner::from_seed(&seed).unwrap();
        let payload = "root|create_secret|db|{}";
        let prev = "a".repeat(128);
        let sig = signer.sign(payload, &prev).unwrap();
        let pubk = hex::decode(RFC_PUB_1).unwrap();
        assert!(ed25519_audit_verify(&pubk, payload, &prev, &sig));
        // Wrong prev (broken link) does not verify.
        assert!(!ed25519_audit_verify(
            &pubk,
            payload,
            &"b".repeat(128),
            &sig
        ));
        // Changing prev changes the signature.
        assert_ne!(signer.sign(payload, &"b".repeat(128)).unwrap(), sig);
    }

    // SecureBuffer::new_locked() with non-empty data invokes
    // memsec::mlock which calls madvise(MADV_DONTDUMP), miri's
    // sandbox can't emulate that syscall. We mark these tests
    // miri-ignore (the mlock path is exercised by `cargo test`
    // on real Linux ; miri stays useful for UB detection on the
    // pure-logic paths above).
    #[test]
    #[cfg_attr(miri, ignore)]
    fn secure_buffer_stores_data() {
        let buf = SecureBuffer::new_locked(vec![1, 2, 3, 4]).unwrap();
        assert!(buf.locked);
        assert_eq!(buf.data, vec![1, 2, 3, 4]);
        assert_eq!(buf.data.len(), 4);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn secure_buffer_zeroize() {
        let mut buf = SecureBuffer::new_locked(vec![0xAA; 32]).unwrap();
        assert!(buf.locked);
        buf.data.zeroize();
        assert!(buf.data.iter().all(|&b| b == 0));
    }

    #[test]
    fn secure_buffer_empty() {
        let buf = SecureBuffer::new_locked(vec![]).unwrap();
        assert_eq!(buf.data.len(), 0);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn wrap_key_decrypt_returns_locked_plaintext() {
        let wrap_key = WrapKey::py_new().unwrap();
        let wrapped = aes_gcm_encrypt(&wrap_key.key, b"secret").unwrap();
        let recovered = wrap_key.decrypt(&wrapped).unwrap();

        assert!(recovered.locked);
        assert_eq!(recovered.data, b"secret");
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn locked_input_aes_gcm_matches_standard_decrypt() {
        let key = [0x42u8; 32];
        let wrapped =
            aes_gcm_encrypt_aad_locked_input(&key, b"sensitive seed", b"audit:aad").unwrap();

        assert_eq!(
            aes_gcm_decrypt_aad(&key, &wrapped, b"audit:aad").unwrap(),
            b"sensitive seed"
        );
    }

    #[test]
    fn x25519_public_derivation_matches_crypto_box() {
        let private = [0x42u8; 32];
        let expected = BoxSecretKey::from_bytes(private).public_key().to_bytes();

        assert_eq!(x25519_public_from_private(&private), expected);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn locked_sealed_box_seal_matches_crypto_box() {
        let secret_key = BoxSecretKey::from_bytes([0x42u8; 32]);
        let public_key = secret_key.public_key().to_bytes();
        let ciphertext = sealed_box_seal_locked(&public_key, b"cluster rekey secret").unwrap();

        assert_eq!(
            secret_key.unseal(&ciphertext).unwrap(),
            b"cluster rekey secret"
        );
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn locked_sealed_box_open_matches_crypto_box() {
        let private = [0x42u8; 32];
        let secret_key = BoxSecretKey::from_bytes(private);
        let ciphertext = secret_key
            .public_key()
            .seal(&mut OsRng, b"cluster rekey secret")
            .unwrap();

        let plaintext = sealed_box_open_locked(&private, &ciphertext).unwrap();

        assert!(plaintext.locked);
        assert_eq!(plaintext.data, b"cluster rekey secret");
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn chained_secret_decrypt_returns_locked_plaintext() {
        let dek_key = [0x42u8; 32];
        let encrypted =
            chained_secret_encrypt(&dek_key, b"vault secret", b"dek:aad", b"secret:aad").unwrap();

        let plaintext = chained_secret_decrypt(
            &dek_key,
            &encrypted.wrapped_dek,
            b"dek:aad",
            &encrypted.ciphertext,
            &encrypted.secret_nonce,
            b"secret:aad",
        )
        .unwrap();

        assert!(plaintext.is_locked());
        assert_eq!(plaintext.as_slice(), b"vault secret");
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn chained_secret_decrypt_rejects_tampering() {
        let dek_key = [0x42u8; 32];
        let mut encrypted =
            chained_secret_encrypt(&dek_key, b"vault secret", b"dek:aad", b"secret:aad").unwrap();
        encrypted.ciphertext[0] ^= 1;

        assert!(chained_secret_decrypt(
            &dek_key,
            &encrypted.wrapped_dek,
            b"dek:aad",
            &encrypted.ciphertext,
            &encrypted.secret_nonce,
            b"secret:aad",
        )
        .is_err());
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn chained_secret_reencrypt_preserves_plaintext() {
        let dek_key = [0x42u8; 32];
        let encrypted =
            chained_secret_encrypt(&dek_key, b"vault secret", b"dek:old", b"secret:old").unwrap();
        let rotated = chained_secret_reencrypt(
            &dek_key,
            ChainedSecretReencryptInput {
                old_wrapped_dek: &encrypted.wrapped_dek,
                old_dek_aad: b"dek:old",
                old_ciphertext: &encrypted.ciphertext,
                old_secret_nonce: &encrypted.secret_nonce,
                old_secret_aad: b"secret:old",
                new_dek_aad: b"dek:new",
                new_secret_aad: b"secret:new",
            },
        )
        .unwrap();

        let plaintext = chained_secret_decrypt(
            &dek_key,
            &rotated.wrapped_dek,
            b"dek:new",
            &rotated.ciphertext,
            &rotated.secret_nonce,
            b"secret:new",
        )
        .unwrap();

        assert!(plaintext.is_locked());
        assert_eq!(plaintext.as_slice(), b"vault secret");
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = [0x42u8; 32];
        let plaintext = b"rhorizon secret data";
        let wrapped = aes_gcm_encrypt(&key, plaintext).unwrap();
        let recovered = aes_gcm_decrypt(&key, &wrapped).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn encrypt_produces_different_ciphertexts() {
        let key = [0x42u8; 32];
        let plaintext = b"same input";
        let a = aes_gcm_encrypt(&key, plaintext).unwrap();
        let b = aes_gcm_encrypt(&key, plaintext).unwrap();
        // Random nonce, ciphertexts must differ
        assert_ne!(a, b);
    }

    #[test]
    fn decrypt_wrong_key_fails() {
        let key_a = [0x42u8; 32];
        let key_b = [0x43u8; 32];
        let wrapped = aes_gcm_encrypt(&key_a, b"secret").unwrap();
        assert!(aes_gcm_decrypt(&key_b, &wrapped).is_err());
    }

    #[test]
    fn decrypt_tampered_data_fails() {
        let key = [0x42u8; 32];
        let mut wrapped = aes_gcm_encrypt(&key, b"secret").unwrap();
        // Flip a byte in the ciphertext
        let last = wrapped.len() - 1;
        wrapped[last] ^= 0xFF;
        assert!(aes_gcm_decrypt(&key, &wrapped).is_err());
    }

    #[test]
    fn decrypt_too_short_fails() {
        let key = [0x42u8; 32];
        for length in [0, 12, AES_GCM_MIN_WRAPPED_BYTES - 1] {
            assert_eq!(
                aes_gcm_decrypt(&key, &vec![0u8; length]).unwrap_err(),
                "Wrapped data too short"
            );
        }
        assert_eq!(
            aes_gcm_decrypt(&key, &[0u8; AES_GCM_MIN_WRAPPED_BYTES]).unwrap_err(),
            "Decryption failed - wrong key or tampered data"
        );
    }

    #[test]
    fn encrypt_empty_plaintext() {
        let key = [0x42u8; 32];
        let wrapped = aes_gcm_encrypt(&key, b"").unwrap();
        let recovered = aes_gcm_decrypt(&key, &wrapped).unwrap();
        assert!(recovered.is_empty());
    }

    #[test]
    fn encrypt_large_payload() {
        let key = [0x42u8; 32];
        let plaintext = vec![0xBB; 64 * 1024]; // 64 KB
        let wrapped = aes_gcm_encrypt(&key, &plaintext).unwrap();
        let recovered = aes_gcm_decrypt(&key, &wrapped).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn wrapped_format_nonce_12_bytes() {
        let key = [0x42u8; 32];
        let wrapped = aes_gcm_encrypt(&key, b"test").unwrap();
        // nonce(12) + ciphertext(4 plaintext + 16 tag)
        assert_eq!(wrapped.len(), 12 + 4 + 16);
    }

    #[test]
    fn slice_zeroize_preserves_length() {
        // Mirrors the in-place zero performed by secure_zero on a
        // PyByteArray-backed buffer: contents wiped, length unchanged.
        let mut buf = vec![0xAAu8; 32];
        let original_len = buf.len();
        let original_cap = buf.capacity();
        buf.as_mut_slice().zeroize();
        assert!(buf.iter().all(|&b| b == 0));
        assert_eq!(buf.len(), original_len);
        assert_eq!(buf.capacity(), original_cap);
    }

    #[test]
    fn slice_zeroize_empty_is_noop() {
        let mut buf: Vec<u8> = vec![];
        buf.as_mut_slice().zeroize();
        assert_eq!(buf.len(), 0);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn secure_buffer_locked_after_construction() {
        // Non-empty buffer must succeed *and* report locked=true.
        // If mlock() is failing on the test host, this exposes the
        // RLIMIT_MEMLOCK / capability shortfall instead of hiding it.
        //
        // Skipped under miri : memsec::mlock invokes madvise(MADV_DONTDUMP)
        // which miri's sandbox does not emulate. The mlock path itself
        // is exercised by `cargo test` on real Linux ; miri stays
        // useful for UB detection on the pure-logic crypto paths
        // (encrypt/decrypt, hmac, aes_gcm_aad, all green here).
        let buf = SecureBuffer::new_locked(vec![0xAA; 32]).unwrap();
        assert!(buf.locked, "mlock failed - RLIMIT_MEMLOCK insufficient?");
    }

    #[test]
    fn secure_buffer_empty_is_not_locked() {
        // Empty buffer skips mlock entirely (nothing to lock).
        let buf = SecureBuffer::new_locked(vec![]).unwrap();
        assert!(!buf.locked);
    }

    // -- subkey-based ops in Rust --

    #[test]
    fn aes_gcm_aad_roundtrip() {
        let key = [0x42u8; 32];
        let plaintext = b"subkey-bound payload";
        let aad = b"row:42";
        let wrapped = aes_gcm_encrypt_aad(&key, plaintext, aad).unwrap();
        let recovered = aes_gcm_decrypt_aad(&key, &wrapped, aad).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn aes_gcm_aad_mismatch_fails() {
        let key = [0x42u8; 32];
        let wrapped = aes_gcm_encrypt_aad(&key, b"data", b"aad-A").unwrap();
        assert!(aes_gcm_decrypt_aad(&key, &wrapped, b"aad-B").is_err());
    }

    #[test]
    fn hmac_sha512_signature_length() {
        // Standard HMAC-SHA512 output is 64 bytes.
        let key = [0x11u8; 32];
        let mut mac = <HmacSha512 as Mac>::new_from_slice(&key).unwrap();
        mac.update(b"some message");
        let result = mac.finalize().into_bytes();
        assert_eq!(result.len(), 64);
    }

    #[test]
    fn hmac_sha512_deterministic() {
        let key = [0x11u8; 32];
        let make_sig = || {
            let mut mac = <HmacSha512 as Mac>::new_from_slice(&key).unwrap();
            mac.update(b"same message");
            mac.finalize().into_bytes()
        };
        assert_eq!(make_sig(), make_sig());
    }

    // -- HKDF-derive + AES-GCM-wrap primitive --

    #[test]
    fn hkdf_derive_aes_gcm_roundtrip() {
        let parent = [0x33u8; 48];
        let info = b"cluster-node-key-wrap:abc123";
        let aad = b"vault-cluster:node-key:abc123";
        let plain = b"-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n";
        let wrapped = hkdf_derive_and_aes_gcm_encrypt_aad(&parent, info, plain, aad).unwrap();
        let recovered = hkdf_derive_and_aes_gcm_decrypt_aad(&parent, info, &wrapped, aad).unwrap();
        assert_eq!(recovered, plain);
    }

    #[test]
    fn hkdf_derive_aes_gcm_info_isolation() {
        // Same parent, different info -> different derived keys ->
        // ciphertext made with info_a MUST NOT decrypt under info_b.
        // This prevents accidental cross-node key reuse and ciphertext
        // substitution. It does not isolate nodes that possess the shared
        // parent secret: they can derive any node's subkey when given its info.
        let parent = [0x44u8; 32];
        let info_a = b"cluster-node-key-wrap:node-a";
        let info_b = b"cluster-node-key-wrap:node-b";
        let aad = b"vault-cluster:node-key:node-a";
        let plain = b"node a's private key";
        let wrapped = hkdf_derive_and_aes_gcm_encrypt_aad(&parent, info_a, plain, aad).unwrap();
        assert!(
            hkdf_derive_and_aes_gcm_decrypt_aad(&parent, info_b, &wrapped, aad).is_err(),
            "different info MUST yield independent subkeys"
        );
    }

    #[test]
    fn hkdf_derive_aes_gcm_aad_binding() {
        let parent = [0x55u8; 32];
        let info = b"cluster-node-key-wrap:n";
        let plain = b"payload";
        let wrapped = hkdf_derive_and_aes_gcm_encrypt_aad(&parent, info, plain, b"aad-A").unwrap();
        assert!(hkdf_derive_and_aes_gcm_decrypt_aad(&parent, info, &wrapped, b"aad-B").is_err());
    }

    #[test]
    fn hkdf_derive_aes_gcm_parent_isolation() {
        // Ciphertext wrapped under one parent MUST reject a different parent.
        // After rotation, this protects ciphertext rewrapped under the new
        // parent; it does not protect old ciphertext captured together with
        // the old parent secret.
        let parent_a = [0x66u8; 32];
        let parent_b = [0x77u8; 32];
        let info = b"info";
        let aad = b"aad";
        let plain = b"payload";
        let wrapped = hkdf_derive_and_aes_gcm_encrypt_aad(&parent_a, info, plain, aad).unwrap();
        assert!(hkdf_derive_and_aes_gcm_decrypt_aad(&parent_b, info, &wrapped, aad).is_err());
    }

    #[test]
    fn hkdf_derive_aes_gcm_wrap_length() {
        // Output = nonce(12) + plain.len() + tag(16). Same shape as
        // aes_gcm_encrypt_aad ; the HKDF stage doesn't add framing.
        let parent = [0x88u8; 32];
        let plain = vec![0xCCu8; 256];
        let wrapped =
            hkdf_derive_and_aes_gcm_encrypt_aad(&parent, b"info", &plain, b"aad").unwrap();
        assert_eq!(wrapped.len(), 12 + plain.len() + 16);
    }

    #[test]
    fn hkdf_derive_aes_gcm_invalid_context_rejected() {
        let parent = [0x99u8; 32];
        let short_parent = [0x99u8; 31];
        assert_eq!(
            hkdf_derive_and_aes_gcm_encrypt_aad(&short_parent, b"info", b"x", b"aad").unwrap_err(),
            "HKDF parent key must be at least 32 bytes"
        );
        assert_eq!(
            hkdf_derive_and_aes_gcm_decrypt_aad(&short_parent, b"info", b"wrapped", b"aad")
                .unwrap_err(),
            "HKDF parent key must be at least 32 bytes"
        );
        assert_eq!(
            hkdf_derive_and_aes_gcm_encrypt_aad(&parent, b"", b"x", b"aad").unwrap_err(),
            "HKDF info must not be empty"
        );
        assert_eq!(
            hkdf_derive_and_aes_gcm_decrypt_aad(&parent, b"", b"wrapped", b"aad").unwrap_err(),
            "HKDF info must not be empty"
        );
        assert_eq!(
            hkdf_derive_and_aes_gcm_encrypt_aad(&parent, b"info", b"x", b"").unwrap_err(),
            "AES-GCM AAD must not be empty"
        );
        assert_eq!(
            hkdf_derive_and_aes_gcm_decrypt_aad(&parent, b"info", b"wrapped", b"").unwrap_err(),
            "AES-GCM AAD must not be empty"
        );
    }

    #[test]
    fn hkdf_derive_aes_gcm_empty_plaintext() {
        let parent = [0xAAu8; 32];
        let wrapped = hkdf_derive_and_aes_gcm_encrypt_aad(&parent, b"info", b"", b"aad").unwrap();
        let recovered =
            hkdf_derive_and_aes_gcm_decrypt_aad(&parent, b"info", &wrapped, b"aad").unwrap();
        assert!(recovered.is_empty());
    }

    #[test]
    fn hkdf_derive_aes_gcm_freshness() {
        // Same parent + info + plain + aad must still yield distinct
        // ciphertexts (random nonce per call) -- mirrors the property
        // of the underlying AES-GCM layer.
        let parent = [0xBBu8; 32];
        let info = b"info";
        let aad = b"aad";
        let plain = b"plain";
        let ct1 = hkdf_derive_and_aes_gcm_encrypt_aad(&parent, info, plain, aad).unwrap();
        let ct2 = hkdf_derive_and_aes_gcm_encrypt_aad(&parent, info, plain, aad).unwrap();
        assert_ne!(ct1, ct2);
    }

    // -- HKDF composition check against a manual RFC 5869 path --

    #[test]
    fn hkdf_matches_manual_rfc5869_composition() {
        // RFC 5869 HKDF-SHA512 with salt=None and L=32 simplifies to :
        //   PRK = HMAC-SHA512(salt = [0u8; 64], ikm)
        //   T(1) = HMAC-SHA512(PRK, info || 0x01)
        //   OKM  = T(1)[..32]
        // Compute that path using only `hmac` + `sha2` (no `hkdf`
        // crate) and compare to what the `hkdf` crate produces. This
        // detects composition and integration regressions. It is not
        // an independent supply-chain check because both paths share
        // the same HMAC-SHA512 implementation.
        let ikm = b"a particular high-entropy parent key for the test";
        let info = b"cluster-node-key-wrap:0123abcd";

        // Manual path -- HMAC-SHA512 only.
        let salt = [0u8; 64];
        let mut mac = <HmacSha512 as Mac>::new_from_slice(&salt).unwrap();
        mac.update(ikm);
        let prk = mac.finalize().into_bytes();
        let mut mac = <HmacSha512 as Mac>::new_from_slice(&prk).unwrap();
        mac.update(info);
        mac.update(&[0x01u8]);
        let t1 = mac.finalize().into_bytes();
        let expected: [u8; 32] = t1[..32].try_into().unwrap();

        // hkdf crate path -- the production derivation primitive.
        let hk = Hkdf::<Sha512>::new(None, ikm);
        let mut actual = [0u8; 32];
        hk.expand(info, &mut actual).unwrap();

        assert_eq!(
            expected, actual,
            "HKDF-SHA512 diverges from the manual RFC 5869 composition"
        );
    }
}

// =====================================================================
// Fuzzing: public wrappers gated by `fuzzing` feature.
//
// `cargo-fuzz` harnesses live in `api/rust/fuzz/` and need to call
// our internal AES-GCM + AAD helpers (which are `pub(crate)`). Rather
// than promoting those to `pub` permanently (widening the Rust API
// surface for downstream crates), we expose them only
// when the `fuzzing` cargo feature is enabled. Normal builds don't
// see these wrappers at all.
// =====================================================================

#[cfg(feature = "fuzzing")]
#[allow(dead_code)] // exposed for the cargo-fuzz harness only, may look unused
                    // when building lib stand-alone with the feature on.
pub mod fuzz_api {
    /// Public wrapper for `aes_gcm_encrypt_aad`, fuzzing only.
    /// Same behaviour, same error type ; routes straight to the
    /// internal helper.
    pub fn aes_gcm_encrypt_aad(
        key: &[u8],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, String> {
        super::aes_gcm_encrypt_aad(key, plaintext, aad)
    }

    /// Public wrapper for `aes_gcm_decrypt_aad`, fuzzing only.
    pub fn aes_gcm_decrypt_aad(key: &[u8], wrapped: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
        super::aes_gcm_decrypt_aad(key, wrapped, aad)
    }
}

// =====================================================================
// Property-based tests, invariants over randomised inputs.
//
// Hand-written unit tests above cover the happy path and a few obvious
// failure modes. Property tests below randomise key/plaintext/AAD across
// hundreds of cases per run to catch the bugs hand-written tests miss :
// length-boundary issues, NUL bytes in AAD, all-zero keys, empty
// plaintext, weird unicode, etc.
//
// Skipped under miri: its interpretation overhead makes hundreds of
// randomized cases prohibitively expensive. Native release tests retain
// the property coverage, while focused hand-written cases exercise the
// same invariants under miri.
// =====================================================================

#[cfg(test)]
#[cfg(not(miri))]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        // Roundtrip identity : every plaintext + AAD pair that encrypts
        // correctly must decrypt back byte-for-byte under the same key.
        // Counterexamples here would mean a corrupt nonce, a wrong
        // tag-length cut, or an aes-gcm crate regression.
        #[test]
        fn prop_aes_gcm_roundtrip_identity(
            key in proptest::array::uniform32(any::<u8>()),
            plaintext in proptest::collection::vec(any::<u8>(), 0..1024),
            aad in proptest::collection::vec(any::<u8>(), 0..256),
        ) {
            let wrapped = aes_gcm_encrypt_aad(&key, &plaintext, &aad).unwrap();
            let recovered = aes_gcm_decrypt_aad(&key, &wrapped, &aad).unwrap();
            prop_assert_eq!(recovered, plaintext);
        }

        // AAD binding : changing even one byte of AAD between encrypt
        // and decrypt MUST fail authentication. This is the property
        // AES-GCM is supposed to give us ; if it ever returned Ok on
        // a different AAD, the entire vault audit binding would be
        // broken (we use AAD to bind a ciphertext to its row id /
        // namespace / version).
        #[test]
        fn prop_aes_gcm_aad_binding(
            key in proptest::array::uniform32(any::<u8>()),
            plaintext in proptest::collection::vec(any::<u8>(), 1..256),
            aad_a in proptest::collection::vec(any::<u8>(), 1..64),
            aad_b in proptest::collection::vec(any::<u8>(), 1..64),
        ) {
            prop_assume!(aad_a != aad_b);
            let wrapped = aes_gcm_encrypt_aad(&key, &plaintext, &aad_a).unwrap();
            prop_assert!(aes_gcm_decrypt_aad(&key, &wrapped, &aad_b).is_err());
        }

        // Ciphertext freshness : encrypting the same plaintext + AAD
        // twice must produce different ciphertexts (random nonce per
        // call). Otherwise nonce reuse breaks GCM catastrophically.
        #[test]
        fn prop_aes_gcm_nonce_uniqueness(
            key in proptest::array::uniform32(any::<u8>()),
            plaintext in proptest::collection::vec(any::<u8>(), 1..256),
            aad in proptest::collection::vec(any::<u8>(), 0..64),
        ) {
            let ct1 = aes_gcm_encrypt_aad(&key, &plaintext, &aad).unwrap();
            let ct2 = aes_gcm_encrypt_aad(&key, &plaintext, &aad).unwrap();
            prop_assert_ne!(ct1, ct2);
        }

        // HMAC determinism : same key + same message yields the same
        // signature regardless of when it's computed. The audit chain
        // depends on this (we hash row N's payload, persist sig N,
        // hash row N+1's payload + sig N, persist sig N+1 ; if HMAC
        // were non-deterministic the chain would never verify).
        #[test]
        fn prop_hmac_deterministic(
            key in proptest::array::uniform32(any::<u8>()),
            msg in proptest::collection::vec(any::<u8>(), 0..2048),
        ) {
            let compute = || {
                let mut mac = <HmacSha512 as Mac>::new_from_slice(&key).unwrap();
                mac.update(&msg);
                mac.finalize().into_bytes().to_vec()
            };
            prop_assert_eq!(compute(), compute());
        }

        // HMAC output length stable : HMAC-SHA512 always 64 bytes,
        // regardless of message length (including empty). Useful guard
        // against accidentally swapping in a different hash function.
        #[test]
        fn prop_hmac_sha512_output_length(
            key in proptest::array::uniform32(any::<u8>()),
            msg in proptest::collection::vec(any::<u8>(), 0..2048),
        ) {
            let mut mac = <HmacSha512 as Mac>::new_from_slice(&key).unwrap();
            mac.update(&msg);
            prop_assert_eq!(mac.finalize().into_bytes().len(), 64);
        }

        // HMAC chunking invariance : updating in N chunks of arbitrary
        // sizes must yield the same MAC as a single update with the
        // concatenation. This validates the incremental API and protects
        // future callers that may stream a message in chunks.
        #[test]
        fn prop_hmac_chunking_invariance(
            key in proptest::array::uniform32(any::<u8>()),
            chunks in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..128), 1..16),
        ) {
            let single = {
                let mut mac = <HmacSha512 as Mac>::new_from_slice(&key).unwrap();
                let flat: Vec<u8> = chunks.iter().flatten().copied().collect();
                mac.update(&flat);
                mac.finalize().into_bytes().to_vec()
            };
            let chunked = {
                let mut mac = <HmacSha512 as Mac>::new_from_slice(&key).unwrap();
                for c in &chunks { mac.update(c); }
                mac.finalize().into_bytes().to_vec()
            };
            prop_assert_eq!(single, chunked);
        }

        // Ciphertext-length invariant : AES-256-GCM wraps as
        // [nonce 12B] [ciphertext same-len-as-plaintext] [tag 16B].
        // Total = plaintext.len() + 28. Catches accidental
        // truncation / extra-padding bugs in our wrap layer.
        #[test]
        fn prop_aes_gcm_wrap_length(
            key in proptest::array::uniform32(any::<u8>()),
            plaintext in proptest::collection::vec(any::<u8>(), 0..512),
            aad in proptest::collection::vec(any::<u8>(), 0..64),
        ) {
            let wrapped = aes_gcm_encrypt_aad(&key, &plaintext, &aad).unwrap();
            prop_assert_eq!(wrapped.len(), plaintext.len() + 12 + 16);
        }

        // Tampered-ciphertext detection : flipping any single bit
        // anywhere in the wrapped payload (nonce, ciphertext, or tag)
        // must make decryption fail. This is the AEAD integrity
        // property protecting encrypted secrets and wrapped keys.
        #[test]
        fn prop_aes_gcm_tamper_detection(
            key in proptest::array::uniform32(any::<u8>()),
            plaintext in proptest::collection::vec(any::<u8>(), 1..256),
            aad in proptest::collection::vec(any::<u8>(), 0..64),
            byte_idx in any::<u32>(),
            bit_idx in 0u8..8,
        ) {
            let mut wrapped = aes_gcm_encrypt_aad(&key, &plaintext, &aad).unwrap();
            let idx = (byte_idx as usize) % wrapped.len();
            wrapped[idx] ^= 1u8 << bit_idx;
            prop_assert!(aes_gcm_decrypt_aad(&key, &wrapped, &aad).is_err());
        }

        // Wrong-key rejection : decrypting with a different key must
        // fail authentication, never produce garbage plaintext.
        #[test]
        fn prop_aes_gcm_wrong_key_rejection(
            key_a in proptest::array::uniform32(any::<u8>()),
            key_b in proptest::array::uniform32(any::<u8>()),
            plaintext in proptest::collection::vec(any::<u8>(), 1..256),
            aad in proptest::collection::vec(any::<u8>(), 0..64),
        ) {
            prop_assume!(key_a != key_b);
            let wrapped = aes_gcm_encrypt_aad(&key_a, &plaintext, &aad).unwrap();
            prop_assert!(aes_gcm_decrypt_aad(&key_b, &wrapped, &aad).is_err());
        }

        // Empty plaintext is a valid AES-GCM edge case and must
        // round-trip without weakening authentication.
        #[test]
        fn prop_aes_gcm_empty_plaintext(
            key in proptest::array::uniform32(any::<u8>()),
            aad in proptest::collection::vec(any::<u8>(), 0..64),
        ) {
            let wrapped = aes_gcm_encrypt_aad(&key, &[], &aad).unwrap();
            let recovered = aes_gcm_decrypt_aad(&key, &wrapped, &aad).unwrap();
            prop_assert!(recovered.is_empty());
        }

        // -- HKDF-derive + AES-GCM primitive --

        // Roundtrip identity : re-deriving the subkey from the same
        // (parent, info) and decrypting the wrapped payload under the
        // same aad must recover the original plaintext byte-for-byte.
        // The hkdf+aes-gcm composition either preserves the message
        // or it's broken at the chain level -- counterexamples here
        // signal a layering bug, not a primitive bug.
        #[test]
        fn prop_hkdf_derive_aes_gcm_roundtrip(
            parent in proptest::collection::vec(any::<u8>(), 32..96),
            info in proptest::collection::vec(any::<u8>(), 1..128),
            plain in proptest::collection::vec(any::<u8>(), 0..1024),
            aad in proptest::collection::vec(any::<u8>(), 1..128),
        ) {
            let wrapped = hkdf_derive_and_aes_gcm_encrypt_aad(&parent, &info, &plain, &aad).unwrap();
            let recovered = hkdf_derive_and_aes_gcm_decrypt_aad(&parent, &info, &wrapped, &aad).unwrap();
            prop_assert_eq!(recovered, plain);
        }

        // Info isolation : ciphertext computed with `info_a` MUST NOT
        // decrypt when we try `info_b != info_a`. This is the whole
        // point of the HKDF stage -- one ha_password, many independent
        // wrap keys keyed by node_uuid.
        #[test]
        fn prop_hkdf_derive_info_isolation(
            parent in proptest::collection::vec(any::<u8>(), 32..64),
            info_a in proptest::collection::vec(any::<u8>(), 1..64),
            info_b in proptest::collection::vec(any::<u8>(), 1..64),
            plain in proptest::collection::vec(any::<u8>(), 1..256),
            aad in proptest::collection::vec(any::<u8>(), 1..64),
        ) {
            prop_assume!(info_a != info_b);
            let wrapped = hkdf_derive_and_aes_gcm_encrypt_aad(&parent, &info_a, &plain, &aad).unwrap();
            prop_assert!(hkdf_derive_and_aes_gcm_decrypt_aad(&parent, &info_b, &wrapped, &aad).is_err());
        }

        // Parent separation: ciphertext wrapped under ha_password_a MUST
        // reject ha_password_b. Rotation gains this protection only after
        // ciphertext is rewrapped; old ciphertext remains decryptable with
        // its old parent secret.
        #[test]
        fn prop_hkdf_derive_parent_isolation(
            parent_a in proptest::collection::vec(any::<u8>(), 32..64),
            parent_b in proptest::collection::vec(any::<u8>(), 32..64),
            info in proptest::collection::vec(any::<u8>(), 1..64),
            plain in proptest::collection::vec(any::<u8>(), 1..256),
            aad in proptest::collection::vec(any::<u8>(), 1..64),
        ) {
            prop_assume!(parent_a != parent_b);
            let wrapped = hkdf_derive_and_aes_gcm_encrypt_aad(&parent_a, &info, &plain, &aad).unwrap();
            prop_assert!(hkdf_derive_and_aes_gcm_decrypt_aad(&parent_b, &info, &wrapped, &aad).is_err());
        }

        // AAD binding : changing the AAD between encrypt and decrypt
        // MUST fail. AES-GCM property carried through the derivation.
        #[test]
        fn prop_hkdf_derive_aad_binding(
            parent in proptest::collection::vec(any::<u8>(), 32..64),
            info in proptest::collection::vec(any::<u8>(), 1..64),
            plain in proptest::collection::vec(any::<u8>(), 1..256),
            aad_a in proptest::collection::vec(any::<u8>(), 1..64),
            aad_b in proptest::collection::vec(any::<u8>(), 1..64),
        ) {
            prop_assume!(aad_a != aad_b);
            let wrapped = hkdf_derive_and_aes_gcm_encrypt_aad(&parent, &info, &plain, &aad_a).unwrap();
            prop_assert!(hkdf_derive_and_aes_gcm_decrypt_aad(&parent, &info, &wrapped, &aad_b).is_err());
        }

        // Wrap length stable across the composition : derivation is
        // a fixed-length transform of the key material, so the wrap
        // layout is still nonce(12) || ct(|plain| + tag 16).
        #[test]
        fn prop_hkdf_derive_wrap_length(
            parent in proptest::collection::vec(any::<u8>(), 32..64),
            info in proptest::collection::vec(any::<u8>(), 1..64),
            plain in proptest::collection::vec(any::<u8>(), 0..512),
            aad in proptest::collection::vec(any::<u8>(), 1..64),
        ) {
            let wrapped = hkdf_derive_and_aes_gcm_encrypt_aad(&parent, &info, &plain, &aad).unwrap();
            prop_assert_eq!(wrapped.len(), plain.len() + 12 + 16);
        }
    }
}

// =====================================================================
// RFC / NIST known-answer conformance tests.
//
// These tests embed known-good vectors from public standards.
// They detect accidental regressions and broad output changes, but are
// not a supply-chain compromise detector: malicious code could preserve
// published vector outputs while changing behavior for other inputs.
//
// HMAC-SHA512 vectors are from RFC 4231 section 4 (the standard reference
// suite). AES-256-GCM vectors are from NIST CAVP gcmEncryptExtIV256.
// =====================================================================

#[cfg(test)]
mod rfc_vectors {
    use super::*;

    // RFC 4231 section 4.2 Test Case 1, HMAC-SHA512
    //   Key  = 0x0b x 20
    //   Data = "Hi There"
    #[test]
    fn rfc4231_case1_hmac_sha512() {
        let key = [0x0bu8; 20];
        let data = b"Hi There";
        let expected = hex::decode(
            "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
        ).unwrap();
        let mut mac = <HmacSha512 as Mac>::new_from_slice(&key).unwrap();
        mac.update(data);
        let result = mac.finalize().into_bytes();
        assert_eq!(
            result.as_slice(),
            expected.as_slice(),
            "HMAC-SHA512 does not match RFC 4231 Case 1"
        );
    }

    // RFC 4231 section 4.3 Test Case 2, HMAC-SHA512
    //   Key  = "Jefe"
    //   Data = "what do ya want for nothing?"
    #[test]
    fn rfc4231_case2_hmac_sha512() {
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let expected = hex::decode(
            "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"
        ).unwrap();
        let mut mac = <HmacSha512 as Mac>::new_from_slice(key).unwrap();
        mac.update(data);
        let result = mac.finalize().into_bytes();
        assert_eq!(
            result.as_slice(),
            expected.as_slice(),
            "HMAC-SHA512 does not match RFC 4231 Case 2"
        );
    }

    // RFC 4231 section 4.4 Test Case 3, HMAC-SHA512
    //   Key  = 0xaa x 20
    //   Data = 0xdd x 50
    #[test]
    fn rfc4231_case3_hmac_sha512() {
        let key = [0xaau8; 20];
        let data = [0xddu8; 50];
        let expected = hex::decode(
            "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb"
        ).unwrap();
        let mut mac = <HmacSha512 as Mac>::new_from_slice(&key).unwrap();
        mac.update(&data);
        let result = mac.finalize().into_bytes();
        assert_eq!(
            result.as_slice(),
            expected.as_slice(),
            "HMAC-SHA512 does not match RFC 4231 Case 3"
        );
    }

    // RFC 4231 section 4.7 Test Case 6, HMAC-SHA512 with oversized key
    //   Key  = 0xaa x 131 (larger than block size, will be pre-hashed)
    //   Data = "Test Using Larger Than Block-Size Key - Hash Key First"
    #[test]
    fn rfc4231_case6_hmac_sha512_oversized_key() {
        let key = [0xaau8; 131];
        let data = b"Test Using Larger Than Block-Size Key - Hash Key First";
        let expected = hex::decode(
            "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598"
        ).unwrap();
        let mut mac = <HmacSha512 as Mac>::new_from_slice(&key).unwrap();
        mac.update(data);
        let result = mac.finalize().into_bytes();
        assert_eq!(
            result.as_slice(),
            expected.as_slice(),
            "HMAC-SHA512 does not match RFC 4231 Case 6"
        );
    }

    // NIST CAVP gcmEncryptExtIV256, Test Case [Keylen=256, IVlen=96]
    //   Key       = 0x...all zeros (32 bytes)
    //   IV        = 0x...all zeros (12 bytes)
    //   PT        = empty
    //   AAD       = empty
    //   CT        = empty
    //   Tag       = 530f8afbc74536b9a963b4f1c4cb738b
    // Verified against the well-known NIST GCM zero-vector.
    #[test]
    fn nist_aes256_gcm_zero_vector() {
        use aes_gcm::aead::{Aead, KeyInit};
        use aes_gcm::{Aes256Gcm, Nonce};

        let key = [0u8; 32];
        let nonce_bytes = [0u8; 12];
        let cipher = Aes256Gcm::new((&key).into());
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ct = cipher.encrypt(nonce, b"".as_ref()).unwrap();
        // ct = [] (empty PT) || tag(16 bytes)
        let expected_tag = hex::decode("530f8afbc74536b9a963b4f1c4cb738b").unwrap();
        assert_eq!(
            ct.as_slice(),
            expected_tag.as_slice(),
            "AES-256-GCM does not match the NIST zero vector"
        );
    }

    // NIST CSRC AES_GCM.pdf, GCM-AES256 Example #5.
    #[test]
    fn nist_aes256_gcm_nonempty_plaintext_and_aad() {
        use aes_gcm::aead::{Aead, KeyInit, Payload};
        use aes_gcm::{Aes256Gcm, Nonce};

        let key = hex::decode("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")
            .unwrap();
        let nonce_bytes = hex::decode("cafebabefacedbaddecaf888").unwrap();
        let aad = hex::decode("3ad77bb40d7a3660a89ecaf32466ef97f5d3d585").unwrap();
        let plaintext = hex::decode(concat!(
            "d9313225f88406e5a55909c5aff5269a",
            "86a7a9531534f7da2e4c303d8a318a72",
            "1c3c0c95956809532fcf0e2449a6b525",
            "b16aedf5aa0de657ba637b39",
        ))
        .unwrap();
        let expected = hex::decode(concat!(
            "522dc1f099567d07f47f37a32a84427d",
            "643a8cdcbfe5c0c97598a2bd2555d1aa",
            "8cb08e48590dbb3da7b08b1056828838",
            "c5f61e6393ba7a0abcc9f662",
            "e097195f4532da895fb917a5a55c6aa0",
        ))
        .unwrap();

        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let nonce = Nonce::from_slice(&nonce_bytes);
        let encrypted = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: &plaintext,
                    aad: &aad,
                },
            )
            .unwrap();
        assert_eq!(encrypted, expected, "AES-256-GCM encryption mismatch");

        let recovered = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &expected,
                    aad: &aad,
                },
            )
            .unwrap();
        assert_eq!(recovered, plaintext, "AES-256-GCM decryption mismatch");
    }
}
