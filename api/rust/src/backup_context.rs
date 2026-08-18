// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
//! BackupCryptoContext, dual-context crypto for restore.
//!
//! When a backup is restored, secrets and DEKs were encrypted under a
//! master_key derived from the password and salt **at backup time**, which
//! may not match the current vault's KDF (e.g. dek_key_version bumped or
//! argon2_salt rotated). This struct holds the BACKUP-side master_key +
//! dek_key, policy-locked in Rust heap and zeroized on drop, exposing a single
//! `decrypt_secret()` method that chains DEK unwrap (AES-GCM) + secret
//! decrypt (XChaCha20-Poly1305 IETF) entirely in Rust. The DEK plaintext
//! never crosses the Rust/Python boundary.
//!
//! Symmetric to `WrapKey` but for an ephemeral one-shot context: lives
//! only during a restore call, dropped immediately after. The Python
//! caller never derives or sees the BACKUP master_key, only the password.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use hmac::Mac;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyByteArray, PyBytes};
use sha2::Sha512;
use zeroize::Zeroize;

use crate::{aes_gcm_decrypt_aad, chained_secret_encrypt, lock_secret_memory, HmacSha512, WrapKey};

// Argon2id parameters, must match libsodium `crypto_pwhash_alg` with
// ALG_ARGON2ID13, opslimit=3, memlimit=256 MB (see api/app/crypto.py:34-37).
// A mismatch here means the BACKUP master_check never validates, even
// with the correct password, which would make the dual-context restore
// silently impossible to use. Cross-language self-consistency is
// validated by tests/test_backup_crypto_cross_lang.py at CI time.
const ARGON2_T_COST: u32 = 3;
const ARGON2_M_COST_KIB: u32 = 262_144;
const ARGON2_P_COST: u32 = 1;
const ARGON2_SALT_LEN: usize = 16;
const MASTER_KEY_BYTES: usize = 32;
const SUBKEY_BYTES: usize = 32;
const XCHACHA_NONCE_BYTES: usize = 24;

/// RAII helper: Vec<u8> that follows the configured memory-lock policy,
/// zeroizes on drop, and unlocks only when locking succeeded.
///
/// Centralises the cleanup paths so the BackupCryptoContext build code
/// stays linear instead of replicating zeroize+munlock on every error
/// branch.
struct LockedBuf {
    data: Vec<u8>,
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
        let locked = lock_secret_memory(&mut data, "BackupCryptoContext buffer")
            .map_err(PyValueError::new_err)?;
        Ok(LockedBuf { data, locked })
    }

    fn as_slice(&self) -> &[u8] {
        &self.data
    }
}

impl Drop for LockedBuf {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

/// Constant-time hex string comparison. master_check is public-by-design
/// (stored in vault_config), but we keep the comparison constant-time as
/// a defence against any future evolution where the check value might
/// become more sensitive (e.g. derived material).
fn ct_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.as_bytes().iter().zip(b.as_bytes().iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[pyclass]
pub struct BackupCryptoContext {
    // master_key follows the lock policy for the lifetime of the context so that
    // (1) future operations can re-derive sub-keys if needed and
    // (2) the Python caller never sees the raw key material.
    master_key: LockedBuf,
    dek_key: LockedBuf,
}

impl BackupCryptoContext {
    fn build(
        password: &[u8],
        salt: &[u8],
        master_check_hex: &str,
        dek_key_version: u32,
    ) -> PyResult<Self> {
        if salt.len() != ARGON2_SALT_LEN {
            return Err(PyValueError::new_err(format!(
                "Resurgamus Horizon: invalid backup argon2_salt length (expected {}, got {})",
                ARGON2_SALT_LEN,
                salt.len()
            )));
        }

        // Step 1 : derive Argon2id master_key from password+salt.
        // The Vec<u8> goes into a LockedBuf as soon as it is filled
        // so Drop covers all subsequent error paths.
        let params = Params::new(
            ARGON2_M_COST_KIB,
            ARGON2_T_COST,
            ARGON2_P_COST,
            Some(MASTER_KEY_BYTES),
        )
        .map_err(|e| PyValueError::new_err(format!("Argon2 params: {}", e)))?;
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut master_raw = vec![0u8; MASTER_KEY_BYTES];
        if let Err(e) = argon.hash_password_into(password, salt, &mut master_raw) {
            master_raw.zeroize();
            return Err(PyValueError::new_err(format!(
                "Argon2id derivation failed: {}",
                e
            )));
        }
        let master_key = LockedBuf::new(master_raw)?;

        // Step 2 : derive hmac_key via HKDF-SHA512 (info = "hmac-tokens"),
        // since master_check is computed as HMAC-SHA512(hmac_key,
        // "master-check-value"): see api/app/routes/vault.py:755 +
        // api/app/crypto.py:hmac_token. hmac_key is mlock'd for symmetry
        // with the runtime invariant (sub-keys live in mlock'd buffers
        // only) and zeroized on drop via LockedBuf.
        let hk_master = Hkdf::<Sha512>::new(None, master_key.as_slice());
        let mut hmac_raw = vec![0u8; SUBKEY_BYTES];
        if let Err(e) = hk_master.expand(b"hmac-tokens", &mut hmac_raw) {
            hmac_raw.zeroize();
            return Err(PyValueError::new_err(format!(
                "HKDF hmac_key expansion failed: {}",
                e
            )));
        }
        let hmac_key = LockedBuf::new(hmac_raw)?;

        // Step 3 : validate master_check = HMAC-SHA512(hmac_key,
        // "master-check-value").hex(): see vault.py:755 +
        // crypto.py:hmac_token. Constant-time comparison.
        let mut mac = <HmacSha512 as Mac>::new_from_slice(hmac_key.as_slice())
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        mac.update(b"master-check-value");
        let computed_check = hex::encode(mac.finalize().into_bytes());
        if !ct_eq(&computed_check, master_check_hex) {
            // master_key + hmac_key Drop will zeroize+munlock automatically.
            return Err(PyValueError::new_err(
                "Resurgamus Horizon: backup master password is incorrect \
                 (master_check mismatch - wrong password, or backup is corrupted)",
            ));
        }

        // Step 4 : derive dek_key via HKDF-SHA512. Info string must
        // match api/app/crypto.py:_hkdf_derive (no extra salt, info =
        // "dek-encrypt" for v<=1 or "dek-encrypt-v{N}" for higher).
        let dek_info = if dek_key_version <= 1 {
            "dek-encrypt".to_string()
        } else {
            format!("dek-encrypt-v{}", dek_key_version)
        };
        let hk_dek = Hkdf::<Sha512>::new(None, master_key.as_slice());
        let mut dek_raw = vec![0u8; SUBKEY_BYTES];
        if let Err(e) = hk_dek.expand(dek_info.as_bytes(), &mut dek_raw) {
            dek_raw.zeroize();
            return Err(PyValueError::new_err(format!(
                "HKDF dek_key expansion failed: {}",
                e
            )));
        }
        let dek_key = LockedBuf::new(dek_raw)?;

        // hmac_key is dropped here (after master_check validation), its
        // zeroize+munlock runs as `hmac_key` goes out of scope. It's NOT
        // stored on the context because the only operation we need it
        // for (master_check verify) is done.
        Ok(BackupCryptoContext {
            master_key,
            dek_key,
        })
    }

    /// Unwrap a backup DEK then decrypt the secret, exactly as
    /// `decrypt_secret` (the pymethod) does -- factored out so
    /// `rotate_secret` can reuse the identical BACKUP-side logic
    /// without ever handing the plaintext to Python in between.
    /// Returns a plain `Vec<u8>` (the caller owns wiping it).
    fn decrypt_secret_raw(
        &self,
        dek_wrapped: &[u8],
        dek_id_aad: &[u8],
        ciphertext: &[u8],
        nonce: &[u8],
        secret_aad: &[u8],
    ) -> PyResult<Vec<u8>> {
        if nonce.len() != XCHACHA_NONCE_BYTES {
            return Err(PyValueError::new_err(format!(
                "XChaCha20-Poly1305 IETF nonce must be {} bytes (got {})",
                XCHACHA_NONCE_BYTES,
                nonce.len()
            )));
        }

        let mut dek_clear = aes_gcm_decrypt_aad(self.dek_key.as_slice(), dek_wrapped, dek_id_aad)
            .map_err(PyValueError::new_err)?;

        let cipher = match XChaCha20Poly1305::new_from_slice(&dek_clear) {
            Ok(c) => c,
            Err(e) => {
                dek_clear.zeroize();
                return Err(PyValueError::new_err(format!(
                    "XChaCha20 key load failed: {}",
                    e
                )));
            }
        };
        let xnonce = XNonce::from_slice(nonce);
        let plaintext = match cipher.decrypt(
            xnonce,
            Payload {
                msg: ciphertext,
                aad: secret_aad,
            },
        ) {
            Ok(pt) => pt,
            Err(_) => {
                dek_clear.zeroize();
                return Err(PyValueError::new_err(
                    "Resurgamus Horizon: backup secret decryption failed \
                     - wrong DEK or tampered ciphertext",
                ));
            }
        };
        dek_clear.zeroize();
        Ok(plaintext)
    }
}

#[pymethods]
impl BackupCryptoContext {
    /// Construct a BACKUP-side crypto context from the inputs found in
    /// the backup payload's `vault_config` section :
    ///   - `password`         : the master password used at backup time
    ///   - `salt`             : `argon2_salt` from backup (16 bytes)
    ///   - `master_check_hex` : `master_check` from backup (hex string)
    ///   - `dek_key_version`  : `dek_key_version` from backup (default 1)
    ///
    /// On success, master_key and dek_key live in policy-locked Rust buffers
    /// until Drop. On wrong password the error is raised before any
    /// derived material can leak.
    #[new]
    fn py_new(
        password: &[u8],
        salt: &[u8],
        master_check_hex: &str,
        dek_key_version: u32,
    ) -> PyResult<Self> {
        BackupCryptoContext::build(password, salt, master_check_hex, dek_key_version)
    }

    /// Unwrap a backup DEK (AES-GCM under backup dek_key with AAD
    /// = f"dek:{dek_id}") then decrypt the secret (XChaCha20-Poly1305
    /// IETF under the unwrapped DEK with AAD = f"secret:{name}:{ns}")
    /// in a single Rust call.
    ///
    /// The unwrapped DEK lives only on the Rust stack and is zeroized
    /// before this function returns. Python never sees it.
    ///
    /// Returns the secret plaintext as a `PyByteArray` (mutable -
    /// the Python caller should pass it through `secure_zero()` after
    /// use).
    ///
    /// Kept as a standalone entry point for callers that only need the
    /// BACKUP-side plaintext (or want to re-encrypt via a path other
    /// than the CURRENT vault's live dek_key). For the restore's actual
    /// re-encryption step, prefer `rotate_secret` below: it chains
    /// decrypt(BACKUP) + encrypt(CURRENT) entirely in Rust so the
    /// plaintext never touches Python at all.
    fn decrypt_secret<'py>(
        &self,
        py: Python<'py>,
        dek_wrapped: &[u8],
        dek_id_aad: &[u8],
        ciphertext: &[u8],
        nonce: &[u8],
        secret_aad: &[u8],
    ) -> PyResult<Bound<'py, PyByteArray>> {
        let mut plaintext =
            self.decrypt_secret_raw(dek_wrapped, dek_id_aad, ciphertext, nonce, secret_aad)?;

        // Copy the plaintext into the PyByteArray the caller will
        // secure_zero(), then wipe our transient Rust-side copy so the aead
        // output buffer does not linger in the Rust heap after we return.
        let out = PyByteArray::new(py, &plaintext);
        plaintext.zeroize();
        Ok(out)
    }

    /// Decrypt a secret under the BACKUP context and immediately
    /// re-encrypt it under a fresh DEK wrapped by the CURRENT vault's
    /// dek_key -- the `rotate_secret()` this module's own doc comment
    /// (above, on `decrypt_secret`) named as planned future hardening.
    /// Neither the BACKUP DEK, the CURRENT DEK, nor the plaintext ever
    /// crosses into Python: `current_wrap` unwraps the CURRENT dek_key
    /// via `WrapKey::unwrap_dek_key` (a Rust-only sibling of the
    /// `decrypt` pymethod), and `chained_secret_encrypt` generates +
    /// wraps the fresh DEK the same way the live create/update path
    /// does. Only the four ciphertext outputs return to Python.
    #[allow(clippy::too_many_arguments)]
    fn rotate_secret<'py>(
        &self,
        py: Python<'py>,
        // BACKUP-side inputs, same shape as decrypt_secret.
        dek_wrapped: &[u8],
        dek_id_aad: &[u8],
        ciphertext: &[u8],
        nonce: &[u8],
        secret_aad: &[u8],
        // CURRENT-side inputs.
        current_wrap: PyRef<'_, WrapKey>,
        current_encrypted_dek_subkey: &[u8],
        new_dek_aad: &[u8],
        new_secret_aad: &[u8],
    ) -> PyResult<crate::PyChainedSecretCiphertext<'py>> {
        let mut plaintext =
            self.decrypt_secret_raw(dek_wrapped, dek_id_aad, ciphertext, nonce, secret_aad)?;

        let current_dek_key = match current_wrap.unwrap_dek_key(current_encrypted_dek_subkey) {
            Ok(k) => k,
            Err(e) => {
                plaintext.zeroize();
                return Err(PyValueError::new_err(e));
            }
        };

        let result = chained_secret_encrypt(
            &current_dek_key.data,
            &plaintext,
            new_dek_aad,
            new_secret_aad,
        );
        plaintext.zeroize();
        let result = result.map_err(PyValueError::new_err)?;

        Ok((
            PyBytes::new(py, &result.wrapped_dek[12..]),
            PyBytes::new(py, &result.wrapped_dek[..12]),
            PyBytes::new(py, &result.ciphertext),
            PyBytes::new(py, &result.secret_nonce),
        ))
    }

    /// Decrypt a config blob (notification channel config, dynamic
    /// engine config, ...) that was encrypted under the backup's
    /// `dek_key` directly via AES-GCM with an AAD binding. No DEK
    /// indirection: the dek_key is used as the AEAD key directly.
    ///
    /// Returned as `PyByteArray` for the same secure_zero ergonomics
    /// as `decrypt_secret`.
    fn decrypt_config<'py>(
        &self,
        py: Python<'py>,
        wrapped: &[u8],
        aad: &[u8],
    ) -> PyResult<Bound<'py, PyByteArray>> {
        let mut plaintext = aes_gcm_decrypt_aad(self.dek_key.as_slice(), wrapped, aad)
            .map_err(PyValueError::new_err)?;
        // Same reasoning as decrypt_secret above: wipe our transient
        // Rust-side copy so the aead output buffer does not linger in
        // the Rust heap after we return.
        let out = PyByteArray::new(py, &plaintext);
        plaintext.zeroize();
        Ok(out)
    }

    #[getter]
    fn is_locked(&self) -> bool {
        self.master_key.locked && self.dek_key.locked
    }
}

// =====================================================================
// Tests
//
// Skipped under miri : memsec::mlock invokes madvise(MADV_DONTDUMP)
// which miri's sandbox does not emulate (same constraint as
// SecureBuffer and WrapKey tests in lib.rs).
//
// Argon2id at production params (m=256MB, t=3) takes ~0.5-1.5s per
// derivation. We use it sparingly in the test suite : only the
// `argon2id_*` tests trigger a real derivation. The crypto roundtrip
// tests bypass Argon2id by constructing the context via a
// `for_test_only` helper that takes pre-derived master_key bytes.
// =====================================================================

/// Test-only constructor that skips Argon2id derivation and accepts
/// pre-derived material directly. Lives behind `#[cfg(test)]` so it
/// cannot be reached from the Python side. Used by the crypto
/// roundtrip tests + proptests below to keep them fast (no 1s
/// Argon2 per case). Lifted out of `mod tests` so `mod proptests`
/// can reach it too.
#[cfg(test)]
impl BackupCryptoContext {
    pub(crate) fn for_test_only(master_raw: Vec<u8>, dek_raw: Vec<u8>) -> Self {
        let master_key = LockedBuf::new(master_raw).expect("mlock master in test");
        let dek_key = LockedBuf::new(dek_raw).expect("mlock dek in test");
        BackupCryptoContext {
            master_key,
            dek_key,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::aead::OsRng;
    use chacha20poly1305::aead::rand_core::RngCore;

    fn rand_bytes(n: usize) -> Vec<u8> {
        use aes_gcm::aead::rand_core::RngCore;
        let mut v = vec![0u8; n];
        OsRng.fill_bytes(&mut v);
        v
    }

    #[test]
    fn ct_eq_basic() {
        assert!(ct_eq("abcdef", "abcdef"));
        assert!(!ct_eq("abcdef", "abcdeg"));
        assert!(!ct_eq("abc", "abcd"));
        assert!(ct_eq("", ""));
    }

    // RFC 9106 section 5.3 Argon2id (v0x13) known-answer vector -- supply-chain
    // tripwire for the `argon2` crate. m=32 KiB, t=3, p=4, secret[8]=0x03,
    // AD[12]=0x04; expected tag is RFC 9106's own.
    #[test]
    fn argon2id_rfc9106_kat() {
        use argon2::{AssociatedData, ParamsBuilder};
        let params = ParamsBuilder::new()
            .m_cost(32)
            .t_cost(3)
            .p_cost(4)
            .data(AssociatedData::new(&[0x04; 12]).unwrap())
            .build()
            .unwrap();
        let ctx = Argon2::new_with_secret(&[0x03; 8], Algorithm::Argon2id, Version::V0x13, params)
            .unwrap();
        let mut out = [0u8; 32];
        ctx.hash_password_into(&[0x01; 32], &[0x02; 16], &mut out)
            .unwrap();
        let expected =
            hex::decode("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659")
                .unwrap();
        assert_eq!(
            out.as_slice(),
            expected.as_slice(),
            "RFC 9106 Argon2id KAT failed -- argon2 crate non-conformant or swapped"
        );
    }

    // draft-irtf-cfrg-xchacha20poly1305-03 section A.3 KAT -- supply-chain
    // tripwire for the `chacha20poly1305` crate (XChaCha20-Poly1305 IETF).
    // Cross-checked against libsodium (the X-variant reference impl).
    #[test]
    fn xchacha20poly1305_draft_kat() {
        let key: Vec<u8> = (0x80u8..0xa0).collect();
        let nonce = hex::decode("404142434445464748494a4b4c4d4e4f5051525354555657").unwrap();
        let aad = hex::decode("50515253c0c1c2c3c4c5c6c7").unwrap();
        let pt = b"Ladies and Gentlemen of the class of '99: If I could offer \
                   you only one tip for the future, sunscreen would be it.";
        let cipher = XChaCha20Poly1305::new_from_slice(&key).unwrap();
        let ct = cipher
            .encrypt(XNonce::from_slice(&nonce), Payload { msg: pt, aad: &aad })
            .unwrap();
        let expected = hex::decode(
            "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb\
             731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452\
             2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9\
             21f9664c97637da9768812f615c68b13b52ec0875924c1c7987947deafd8780a\
             cf49",
        )
        .unwrap();
        assert_eq!(
            ct, expected,
            "XChaCha20-Poly1305 draft A.3 KAT failed -- crate non-conformant or swapped"
        );
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn argon2id_self_consistency() {
        // Self-consistency : same inputs produce same output.
        // Cross-language compat (Rust output == libsodium output) is
        // tested separately in tests/test_backup_crypto_cross_lang.py.
        let params = Params::new(
            ARGON2_M_COST_KIB,
            ARGON2_T_COST,
            ARGON2_P_COST,
            Some(MASTER_KEY_BYTES),
        )
        .unwrap();
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let password = b"backup-password-1234";
        let salt = [0x42u8; ARGON2_SALT_LEN];
        let mut out_a = [0u8; MASTER_KEY_BYTES];
        let mut out_b = [0u8; MASTER_KEY_BYTES];
        argon
            .hash_password_into(password, &salt, &mut out_a)
            .unwrap();
        argon
            .hash_password_into(password, &salt, &mut out_b)
            .unwrap();
        assert_eq!(out_a, out_b);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn argon2id_different_password_different_output() {
        let params = Params::new(
            ARGON2_M_COST_KIB,
            ARGON2_T_COST,
            ARGON2_P_COST,
            Some(MASTER_KEY_BYTES),
        )
        .unwrap();
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let salt = [0x42u8; ARGON2_SALT_LEN];
        let mut out_a = [0u8; MASTER_KEY_BYTES];
        let mut out_b = [0u8; MASTER_KEY_BYTES];
        argon
            .hash_password_into(b"password-a", &salt, &mut out_a)
            .unwrap();
        argon
            .hash_password_into(b"password-b", &salt, &mut out_b)
            .unwrap();
        assert_ne!(out_a, out_b);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn hkdf_dek_info_matches_python() {
        // HKDF-SHA512(master_key, info="dek-encrypt") for v<=1
        // must give the same bytes as Python's _hkdf_derive in
        // api/app/crypto.py:64-71. This is a self-consistency check ;
        // the Python-Rust byte-equality is enforced by the cross-lang
        // pytest in commit 5.
        let master_key = [0x11u8; 32];
        let hk = Hkdf::<Sha512>::new(None, &master_key);
        let mut v1 = [0u8; SUBKEY_BYTES];
        hk.expand(b"dek-encrypt", &mut v1).unwrap();

        let hk2 = Hkdf::<Sha512>::new(None, &master_key);
        let mut v2 = [0u8; SUBKEY_BYTES];
        hk2.expand(b"dek-encrypt-v2", &mut v2).unwrap();

        // v1 != v2 : version bumping changes the dek_key as designed.
        assert_ne!(v1, v2);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn decrypt_secret_roundtrip() {
        // Build a backup context from pre-derived material, encrypt a
        // (DEK, secret) pair on the Python side (simulated here in
        // Rust), and verify decrypt_secret recovers the plaintext.
        let master = rand_bytes(MASTER_KEY_BYTES);
        let dek_key_backup = rand_bytes(SUBKEY_BYTES);
        let dek_id = "11111111-1111-1111-1111-111111111111";
        let secret_name = "db-password";
        let namespace = "prod";
        let plaintext = b"super-secret-value-with-special-chars-x'fancy";

        // Generate a random DEK and wrap it under dek_key_backup
        // (AES-GCM + AAD = "dek:<id>").
        let dek = rand_bytes(32);
        let dek_aad = format!("dek:{}", dek_id);
        let dek_wrapped =
            crate::aes_gcm_encrypt_aad(&dek_key_backup, &dek, dek_aad.as_bytes()).unwrap();

        // XChaCha20-Poly1305 IETF encrypt the secret with the DEK
        // and AAD = "secret:<name>:<namespace>".
        let secret_aad = format!("secret:{}:{}", secret_name, namespace);
        let mut nonce_bytes = [0u8; XCHACHA_NONCE_BYTES];
        OsRng.fill_bytes(&mut nonce_bytes);
        let cipher = XChaCha20Poly1305::new_from_slice(&dek).unwrap();
        let xnonce = XNonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(
                xnonce,
                Payload {
                    msg: plaintext.as_ref(),
                    aad: secret_aad.as_bytes(),
                },
            )
            .unwrap();

        // Now use the context to recover the plaintext via the
        // dual decrypt path.
        let ctx = BackupCryptoContext::for_test_only(master, dek_key_backup);

        pyo3::Python::attach(|py| {
            let result = ctx
                .decrypt_secret(
                    py,
                    &dek_wrapped,
                    dek_aad.as_bytes(),
                    &ciphertext,
                    &nonce_bytes,
                    secret_aad.as_bytes(),
                )
                .expect("decrypt_secret should succeed");
            // Buffer contents == plaintext.
            // SAFETY: `result` is a `Bound<PyByteArray>` returned by
            // decrypt_secret and held live for this whole block (the
            // borrow checker enforces `result` outlives `slice`), so
            // `data()` points at `len()` valid, initialised bytes. The
            // GIL is held for the whole closure (`Python::attach`), so
            // no other Python code can resize/free the bytearray
            // concurrently.
            unsafe {
                let slice = std::slice::from_raw_parts(result.data(), result.len());
                assert_eq!(slice, plaintext);
            }
        });
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn rotate_secret_roundtrip() {
        // Same BACKUP-side fixture as decrypt_secret_roundtrip, plus a
        // CURRENT-side WrapKey + dek_key, exactly like a real restore:
        // backup.py holds vault._wrap (a WrapKey) and vault._dek_enc
        // (the CURRENT dek_key wrapped under it).
        let master = rand_bytes(MASTER_KEY_BYTES);
        let dek_key_backup = rand_bytes(SUBKEY_BYTES);
        let dek_id = "22222222-2222-2222-2222-222222222222";
        let secret_name = "rotate-me";
        let namespace = "prod";
        let plaintext = b"rotate-secret-roundtrip-plaintext";

        let dek = rand_bytes(32);
        let dek_aad = format!("dek:{}", dek_id);
        let dek_wrapped =
            crate::aes_gcm_encrypt_aad(&dek_key_backup, &dek, dek_aad.as_bytes()).unwrap();

        let secret_aad = format!("secret:{}:{}", secret_name, namespace);
        let mut nonce_bytes = [0u8; XCHACHA_NONCE_BYTES];
        OsRng.fill_bytes(&mut nonce_bytes);
        let cipher = XChaCha20Poly1305::new_from_slice(&dek).unwrap();
        let xnonce = XNonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(
                xnonce,
                Payload {
                    msg: plaintext.as_ref(),
                    aad: secret_aad.as_bytes(),
                },
            )
            .unwrap();

        let ctx = BackupCryptoContext::for_test_only(master, dek_key_backup);
        let current_dek_key = rand_bytes(32);
        let new_dek_id = "33333333-3333-3333-3333-333333333333";
        let new_dek_aad = format!("dek:{}", new_dek_id);
        let new_secret_aad = format!("secret:{}:{}", secret_name, namespace);

        pyo3::Python::attach(|py| {
            let wrap_key = crate::WrapKey::py_new().expect("WrapKey::py_new");
            let wrap_bound = pyo3::Bound::new(py, wrap_key).expect("wrap WrapKey in Bound");
            let encrypted_dek_subkey: Vec<u8> = wrap_bound
                .borrow()
                .encrypt(py, &current_dek_key)
                .expect("wrap current dek_key")
                .extract()
                .expect("extract encrypted dek_key bytes");

            let (new_encrypted_dek, new_dek_nonce, new_ciphertext, new_secret_nonce) = ctx
                .rotate_secret(
                    py,
                    &dek_wrapped,
                    dek_aad.as_bytes(),
                    &ciphertext,
                    &nonce_bytes,
                    secret_aad.as_bytes(),
                    wrap_bound.borrow(),
                    &encrypted_dek_subkey,
                    new_dek_aad.as_bytes(),
                    new_secret_aad.as_bytes(),
                )
                .expect("rotate_secret should succeed");

            let new_encrypted_dek: Vec<u8> = new_encrypted_dek.extract().unwrap();
            let new_dek_nonce: Vec<u8> = new_dek_nonce.extract().unwrap();
            let new_ciphertext: Vec<u8> = new_ciphertext.extract().unwrap();
            let new_secret_nonce: Vec<u8> = new_secret_nonce.extract().unwrap();

            // Recombine into the nonce||ciphertext wire format
            // chained_secret_decrypt expects, and verify the result
            // decrypts to the SAME plaintext under the CURRENT dek_key -
            // proving rotate_secret actually re-wrapped under the
            // current context, not just echoed the backup ciphertext.
            let mut new_wrapped_dek =
                Vec::with_capacity(new_dek_nonce.len() + new_encrypted_dek.len());
            new_wrapped_dek.extend_from_slice(&new_dek_nonce);
            new_wrapped_dek.extend_from_slice(&new_encrypted_dek);
            let recovered = crate::chained_secret_decrypt(
                &current_dek_key,
                &new_wrapped_dek,
                new_dek_aad.as_bytes(),
                &new_ciphertext,
                &new_secret_nonce,
                new_secret_aad.as_bytes(),
            )
            .expect("re-decrypt under CURRENT context should succeed");
            assert_eq!(recovered.as_slice(), plaintext);

            // The BACKUP ciphertext and the new CURRENT ciphertext must
            // differ - a fresh DEK and fresh nonce were actually used,
            // not a passthrough of the backup's own ciphertext.
            assert_ne!(new_ciphertext, ciphertext);
        });
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn decrypt_secret_wrong_dek_aad_fails() {
        let dek_key_backup = rand_bytes(SUBKEY_BYTES);
        let dek = rand_bytes(32);
        let correct_aad = b"dek:correct-id";
        let wrong_aad = b"dek:wrong-id";

        let dek_wrapped = crate::aes_gcm_encrypt_aad(&dek_key_backup, &dek, correct_aad).unwrap();
        let secret_aad = b"secret:foo:bar";
        let mut nonce_bytes = [0u8; XCHACHA_NONCE_BYTES];
        OsRng.fill_bytes(&mut nonce_bytes);
        let cipher = XChaCha20Poly1305::new_from_slice(&dek).unwrap();
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce_bytes),
                Payload {
                    msg: b"data".as_ref(),
                    aad: secret_aad,
                },
            )
            .unwrap();

        let ctx = BackupCryptoContext::for_test_only(rand_bytes(MASTER_KEY_BYTES), dek_key_backup);

        pyo3::Python::attach(|py| {
            let result = ctx.decrypt_secret(
                py,
                &dek_wrapped,
                wrong_aad,
                &ciphertext,
                &nonce_bytes,
                secret_aad,
            );
            assert!(result.is_err(), "Wrong dek_id AAD must fail DEK unwrap");
        });
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn decrypt_secret_wrong_secret_aad_fails() {
        let dek_key_backup = rand_bytes(SUBKEY_BYTES);
        let dek = rand_bytes(32);
        let dek_aad = b"dek:some-id";
        let correct_secret_aad = b"secret:foo:bar";
        let wrong_secret_aad = b"secret:baz:bar";

        let dek_wrapped = crate::aes_gcm_encrypt_aad(&dek_key_backup, &dek, dek_aad).unwrap();
        let mut nonce_bytes = [0u8; XCHACHA_NONCE_BYTES];
        OsRng.fill_bytes(&mut nonce_bytes);
        let cipher = XChaCha20Poly1305::new_from_slice(&dek).unwrap();
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce_bytes),
                Payload {
                    msg: b"data".as_ref(),
                    aad: correct_secret_aad,
                },
            )
            .unwrap();

        let ctx = BackupCryptoContext::for_test_only(rand_bytes(MASTER_KEY_BYTES), dek_key_backup);

        pyo3::Python::attach(|py| {
            let result = ctx.decrypt_secret(
                py,
                &dek_wrapped,
                dek_aad,
                &ciphertext,
                &nonce_bytes,
                wrong_secret_aad,
            );
            assert!(result.is_err(), "Wrong secret AAD must fail secret decrypt");
        });
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn decrypt_secret_invalid_nonce_length() {
        let ctx = BackupCryptoContext::for_test_only(
            rand_bytes(MASTER_KEY_BYTES),
            rand_bytes(SUBKEY_BYTES),
        );
        pyo3::Python::attach(|py| {
            // 12-byte nonce (AES-GCM size) instead of 24, must reject.
            let result = ctx.decrypt_secret(
                py,
                b"unused",
                b"dek:x",
                b"unused",
                &[0u8; 12],
                b"secret:n:s",
            );
            assert!(result.is_err());
        });
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn decrypt_config_roundtrip() {
        // Channel config style : AES-GCM under dek_key directly,
        // no DEK indirection. AAD binds to the row identity.
        let dek_key_backup = rand_bytes(SUBKEY_BYTES);
        let plaintext = b"{\"matrix_token\": \"xyz\", \"room\": \"!abc:example.com\"}";
        let aad = b"channel:42";
        let wrapped = crate::aes_gcm_encrypt_aad(&dek_key_backup, plaintext, aad).unwrap();

        let ctx = BackupCryptoContext::for_test_only(rand_bytes(MASTER_KEY_BYTES), dek_key_backup);

        pyo3::Python::attach(|py| {
            let result = ctx.decrypt_config(py, &wrapped, aad).unwrap();
            // SAFETY: same reasoning as decrypt_secret_roundtrip above --
            // `result` (Bound<PyByteArray>) outlives `slice`, and the GIL
            // held by `Python::attach` prevents concurrent mutation.
            unsafe {
                let slice = std::slice::from_raw_parts(result.data(), result.len());
                assert_eq!(slice, plaintext);
            }
        });
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn build_rejects_wrong_salt_length() {
        let result = BackupCryptoContext::build(
            b"password",
            &[0u8; 15], // 15 instead of 16
            "deadbeef".repeat(16).as_str(),
            1,
        );
        assert!(result.is_err());
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn build_rejects_wrong_master_check() {
        // Real Argon2id derivation, then check master_check mismatch
        // returns an error without leaking the derived material.
        let password = b"correct-password";
        let salt = [0x99u8; ARGON2_SALT_LEN];
        // Pass a master_check that cannot possibly match.
        let bogus_check = "00".repeat(64);
        let result = BackupCryptoContext::build(password, &salt, &bogus_check, 1);
        match result {
            Err(e) => {
                let msg = format!("{}", e);
                assert!(
                    msg.contains("master_check") || msg.contains("master password"),
                    "Error should mention master_check mismatch, got: {}",
                    msg
                );
            }
            Ok(_) => panic!("Expected master_check mismatch error"),
        }
    }
}

// =====================================================================
// Property tests, randomised invariants over the dual-context paths.
//
// All proptests use the test-only constructor so they do not pay
// Argon2id's 1s cost per case. Argon2id correctness is covered by the
// hand-written tests above + the cross-language pytest in commit 5.
// =====================================================================

#[cfg(test)]
#[cfg(not(miri))]
mod proptests {
    use super::*;
    use chacha20poly1305::aead::rand_core::RngCore;
    use proptest::prelude::*;

    fn make_ctx(master: Vec<u8>, dek_key: Vec<u8>) -> BackupCryptoContext {
        BackupCryptoContext::for_test_only(master, dek_key)
    }

    proptest! {
        // Roundtrip identity : for any random key + DEK + plaintext +
        // dek_id + (name, namespace), the dual-decrypt path recovers
        // the plaintext byte-for-byte.
        #[test]
        fn prop_decrypt_secret_roundtrip(
            dek_key_backup in proptest::collection::vec(any::<u8>(), 32..=32),
            dek in proptest::collection::vec(any::<u8>(), 32..=32),
            plaintext in proptest::collection::vec(any::<u8>(), 0..2048),
            dek_id in "[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}",
            name in "[a-z]{1,32}",
            namespace in "[a-z]{1,32}",
        ) {
            let dek_aad_str = format!("dek:{}", dek_id);
            let secret_aad_str = format!("secret:{}:{}", name, namespace);

            let dek_wrapped = crate::aes_gcm_encrypt_aad(
                &dek_key_backup, &dek, dek_aad_str.as_bytes(),
            ).unwrap();

            let mut nonce_bytes = [0u8; XCHACHA_NONCE_BYTES];
            chacha20poly1305::aead::OsRng.fill_bytes(&mut nonce_bytes);
            let cipher = XChaCha20Poly1305::new_from_slice(&dek).unwrap();
            let ciphertext = cipher.encrypt(
                XNonce::from_slice(&nonce_bytes),
                Payload { msg: plaintext.as_slice(), aad: secret_aad_str.as_bytes() },
            ).unwrap();

            let ctx = make_ctx(vec![0u8; 32], dek_key_backup);

            pyo3::Python::attach(|py| {
                let result = ctx.decrypt_secret(
                    py,
                    &dek_wrapped,
                    dek_aad_str.as_bytes(),
                    &ciphertext,
                    &nonce_bytes,
                    secret_aad_str.as_bytes(),
                ).unwrap();
                // SAFETY: same reasoning as decrypt_secret_roundtrip above --
                // `result` (Bound<PyByteArray>) outlives `slice`, and the
                // GIL held by `Python::attach` prevents concurrent mutation.
                unsafe {
                    let slice = std::slice::from_raw_parts(result.data(), result.len());
                    prop_assert_eq!(slice, plaintext.as_slice());
                }
                Ok(())
            })?;
        }

        // AAD binding on secret layer : flipping the namespace in the
        // AAD between encrypt and decrypt must fail authentication.
        // Cross-row swap of a ciphertext (same DEK, different
        // (name, namespace)) cannot succeed.
        #[test]
        fn prop_secret_aad_cross_row_binding(
            dek_key_backup in proptest::collection::vec(any::<u8>(), 32..=32),
            dek in proptest::collection::vec(any::<u8>(), 32..=32),
            plaintext in proptest::collection::vec(any::<u8>(), 1..256),
            dek_id in "[a-f0-9]{32}",
            name_a in "[a-z]{1,32}",
            name_b in "[a-z]{1,32}",
        ) {
            prop_assume!(name_a != name_b);

            let dek_aad_str = format!("dek:{}", dek_id);
            let aad_a = format!("secret:{}:ns", name_a);
            let aad_b = format!("secret:{}:ns", name_b);

            let dek_wrapped = crate::aes_gcm_encrypt_aad(
                &dek_key_backup, &dek, dek_aad_str.as_bytes(),
            ).unwrap();

            let mut nonce_bytes = [0u8; XCHACHA_NONCE_BYTES];
            chacha20poly1305::aead::OsRng.fill_bytes(&mut nonce_bytes);
            let cipher = XChaCha20Poly1305::new_from_slice(&dek).unwrap();
            let ciphertext = cipher.encrypt(
                XNonce::from_slice(&nonce_bytes),
                Payload { msg: plaintext.as_slice(), aad: aad_a.as_bytes() },
            ).unwrap();

            let ctx = make_ctx(vec![0u8; 32], dek_key_backup);

            pyo3::Python::attach(|py| {
                let result = ctx.decrypt_secret(
                    py,
                    &dek_wrapped,
                    dek_aad_str.as_bytes(),
                    &ciphertext,
                    &nonce_bytes,
                    aad_b.as_bytes(),
                );
                prop_assert!(result.is_err(), "secret AAD mismatch must fail");
                Ok(())
            })?;
        }

        // Tampered ciphertext detection on the secret layer.
        #[test]
        fn prop_secret_tamper_detection(
            dek_key_backup in proptest::collection::vec(any::<u8>(), 32..=32),
            dek in proptest::collection::vec(any::<u8>(), 32..=32),
            plaintext in proptest::collection::vec(any::<u8>(), 1..256),
            byte_idx in any::<u32>(),
            bit_idx in 0u8..8,
        ) {
            let dek_id = "deadbeef-dead-beef-dead-beefdeadbeef";
            let dek_aad_str = format!("dek:{}", dek_id);
            let secret_aad_str = "secret:n:s";

            let dek_wrapped = crate::aes_gcm_encrypt_aad(
                &dek_key_backup, &dek, dek_aad_str.as_bytes(),
            ).unwrap();

            let mut nonce_bytes = [0u8; XCHACHA_NONCE_BYTES];
            chacha20poly1305::aead::OsRng.fill_bytes(&mut nonce_bytes);
            let cipher = XChaCha20Poly1305::new_from_slice(&dek).unwrap();
            let mut ciphertext = cipher.encrypt(
                XNonce::from_slice(&nonce_bytes),
                Payload { msg: plaintext.as_slice(), aad: secret_aad_str.as_bytes() },
            ).unwrap();

            let idx = (byte_idx as usize) % ciphertext.len();
            ciphertext[idx] ^= 1u8 << bit_idx;

            let ctx = make_ctx(vec![0u8; 32], dek_key_backup);

            pyo3::Python::attach(|py| {
                let result = ctx.decrypt_secret(
                    py,
                    &dek_wrapped,
                    dek_aad_str.as_bytes(),
                    &ciphertext,
                    &nonce_bytes,
                    secret_aad_str.as_bytes(),
                );
                prop_assert!(result.is_err(), "tampered ciphertext must fail");
                Ok(())
            })?;
        }
    }
}
