// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
//! Locked ownership and explicit lifecycle of one reconstructed runtime bundle.

use std::sync::Mutex;

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::operations::{
    aes256_gcm_decrypt_locked, aes256_gcm_encrypt, audit_ed25519_public_key, audit_ed25519_sign,
    audit_ed25519_sign_raw, audit_hmac_sha512, chained_secret_decrypt, chained_secret_encrypt,
    chained_secret_reencrypt, generate_audit_identity_envelope, hkdf_sha512_aes256_gcm_encrypt,
    hmac_sha512, AuditIdentityEnvelope, ChainedSecretCiphertext, ChainedSecretReencryptInput,
    ED25519_SEED_BYTES, ED25519_SIGNATURE_BYTES, HMAC_SHA512_BYTES,
};
use crate::secure_memory::LockedSecret;
use crate::CUSTODY_V1_RUNTIME_BUNDLE_BYTES;

pub const RUNTIME_KEY_BYTES: usize = 32;
pub const HA_PASSWORD_MIN_BYTES: usize = 32;
pub const HA_PASSWORD_AAD: &[u8] = b"vault-cluster:ha_password";
const NODE_KEY_INFO_PREFIX: &[u8] = b"cluster-node-key-wrap:";
const NODE_KEY_AAD_PREFIX: &[u8] = b"vault-cluster:node-key:";
const SERVER_KEY_INFO_PREFIX: &[u8] = b"cluster-server-key-wrap:";
const SERVER_KEY_AAD_PREFIX: &[u8] = b"vault-cluster:server-key:";

/// Stable bundle order shared with `VaultState.current_subkey_bundle()`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeKeyKind {
    Hmac,
    Dek,
    Audit,
    HaWrap,
    PkiWrap,
}

impl RuntimeKeyKind {
    const fn offset(self) -> usize {
        match self {
            Self::Hmac => 0,
            Self::Dek => RUNTIME_KEY_BYTES,
            Self::Audit => 2 * RUNTIME_KEY_BYTES,
            Self::HaWrap => 3 * RUNTIME_KEY_BYTES,
            Self::PkiWrap => 4 * RUNTIME_KEY_BYTES,
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Hmac => "runtime hmac_key snapshot",
            Self::Dek => "runtime dek_key snapshot",
            Self::Audit => "runtime audit_key snapshot",
            Self::HaWrap => "runtime ha_wrap_key snapshot",
            Self::PkiWrap => "runtime pki_wrap_key snapshot",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeInstallOutcome {
    Loaded,
    AlreadyLoaded,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditIdentityInstallOutcome {
    Loaded,
    AlreadyLoaded,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HaPasswordInstallOutcome {
    Loaded,
    AlreadyLoaded,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreviousHmacInstallOutcome {
    Loaded,
    AlreadyLoaded,
}

struct LoadedRuntime {
    generation: u64,
    bytes: LockedSecret,
    audit_seed: Option<LockedSecret>,
    ha_password: Option<LockedSecret>,
    previous_hmac_key: Option<LockedSecret>,
    previous_hmac_envelope_fingerprint: Option<[u8; 32]>,
}

/// The seal latch and runtime-key ownership are the same state: no separate
/// boolean can claim the vault is unsealed after the locked keys are dropped.
pub struct RuntimeBundleSlot {
    current: Mutex<Option<LoadedRuntime>>,
}

impl RuntimeBundleSlot {
    pub const fn empty() -> Self {
        Self {
            current: Mutex::new(None),
        }
    }

    pub fn install(
        &self,
        generation: u64,
        bytes: LockedSecret,
    ) -> Result<RuntimeInstallOutcome, String> {
        if generation == 0 {
            return Err("custody generation zero is reserved".to_string());
        }
        if bytes.len() != CUSTODY_V1_RUNTIME_BUNDLE_BYTES {
            return Err(format!(
                "runtime bundle must be exactly {CUSTODY_V1_RUNTIME_BUNDLE_BYTES} bytes"
            ));
        }
        let mut current = self
            .current
            .lock()
            .map_err(|error| format!("runtime bundle lock poisoned: {error}"))?;
        if let Some(loaded) = current.as_ref() {
            if generation != loaded.generation {
                return Err("seal before loading a different custody generation".to_string());
            }
            return if bool::from(bytes.as_slice().ct_eq(loaded.bytes.as_slice())) {
                Ok(RuntimeInstallOutcome::AlreadyLoaded)
            } else {
                Err("conflicting runtime bundle for loaded custody generation".to_string())
            };
        }
        *current = Some(LoadedRuntime {
            generation,
            bytes,
            audit_seed: None,
            ha_password: None,
            previous_hmac_key: None,
            previous_hmac_envelope_fingerprint: None,
        });
        Ok(RuntimeInstallOutcome::Loaded)
    }

    pub fn is_loaded(&self) -> Result<bool, String> {
        Ok(self
            .current
            .lock()
            .map_err(|error| format!("runtime bundle lock poisoned: {error}"))?
            .is_some())
    }

    pub fn generation(&self) -> Result<Option<u64>, String> {
        Ok(self
            .current
            .lock()
            .map_err(|error| format!("runtime bundle lock poisoned: {error}"))?
            .as_ref()
            .map(|loaded| loaded.generation))
    }

    pub fn snapshot(&self) -> Result<Option<(u64, LockedSecret)>, String> {
        let current = self
            .current
            .lock()
            .map_err(|error| format!("runtime bundle lock poisoned: {error}"))?;
        current
            .as_ref()
            .map(|loaded| {
                LockedSecret::from_slice(loaded.bytes.as_slice(), "runtime bundle snapshot")
                    .map(|bytes| (loaded.generation, bytes))
            })
            .transpose()
    }

    /// Return one independently locked key selected by its semantic name.
    /// Callers never calculate byte offsets themselves.
    pub fn key_snapshot(&self, kind: RuntimeKeyKind) -> Result<LockedSecret, String> {
        let current = self
            .current
            .lock()
            .map_err(|error| format!("runtime bundle lock poisoned: {error}"))?;
        let loaded = current.as_ref().ok_or_else(|| "vault sealed".to_string())?;
        let start = kind.offset();
        LockedSecret::from_slice(
            &loaded.bytes.as_slice()[start..start + RUNTIME_KEY_BYTES],
            kind.label(),
        )
    }

    pub fn hmac_sha512(&self, message: &[u8]) -> Result<[u8; HMAC_SHA512_BYTES], String> {
        let key = self.key_snapshot(RuntimeKeyKind::Hmac)?;
        hmac_sha512(key.as_slice(), message)
    }

    /// Install the `vault_config.prev_hmac_key` envelope. It is already
    /// AES-256-GCM wrapped under the current runtime DEK with empty AAD.
    pub fn install_previous_hmac_envelope(
        &self,
        wrapped_key: &[u8],
    ) -> Result<PreviousHmacInstallOutcome, String> {
        let mut current = self
            .current
            .lock()
            .map_err(|error| format!("runtime bundle lock poisoned: {error}"))?;
        let loaded = current.as_mut().ok_or_else(|| "vault sealed".to_string())?;
        let dek_start = RuntimeKeyKind::Dek.offset();
        let previous_key = aes256_gcm_decrypt_locked(
            &loaded.bytes.as_slice()[dek_start..dek_start + RUNTIME_KEY_BYTES],
            wrapped_key,
            &[],
            "runtime previous HMAC key",
        )?;
        if previous_key.len() != RUNTIME_KEY_BYTES {
            return Err(format!(
                "previous HMAC key must be exactly {RUNTIME_KEY_BYTES} bytes"
            ));
        }
        if let Some(existing) = loaded.previous_hmac_key.as_ref() {
            return if bool::from(existing.as_slice().ct_eq(previous_key.as_slice())) {
                loaded.previous_hmac_envelope_fingerprint =
                    Some(Sha256::digest(wrapped_key).into());
                Ok(PreviousHmacInstallOutcome::AlreadyLoaded)
            } else {
                Err("conflicting previous HMAC key for loaded custody generation".to_string())
            };
        }
        loaded.previous_hmac_key = Some(previous_key);
        loaded.previous_hmac_envelope_fingerprint = Some(Sha256::digest(wrapped_key).into());
        Ok(PreviousHmacInstallOutcome::Loaded)
    }

    pub fn previous_hmac_loaded(&self) -> Result<bool, String> {
        Ok(self
            .current
            .lock()
            .map_err(|error| format!("runtime bundle lock poisoned: {error}"))?
            .as_ref()
            .is_some_and(|loaded| loaded.previous_hmac_key.is_some()))
    }

    pub fn previous_hmac_sha512(
        &self,
        message: &[u8],
    ) -> Result<Option<[u8; HMAC_SHA512_BYTES]>, String> {
        let current = self
            .current
            .lock()
            .map_err(|error| format!("runtime bundle lock poisoned: {error}"))?;
        let loaded = current.as_ref().ok_or_else(|| "vault sealed".to_string())?;
        loaded
            .previous_hmac_key
            .as_ref()
            .map(|key| hmac_sha512(key.as_slice(), message))
            .transpose()
    }

    pub fn clear_previous_hmac(&self) -> Result<(), String> {
        let mut current = self
            .current
            .lock()
            .map_err(|error| format!("runtime bundle lock poisoned: {error}"))?;
        let loaded = current.as_mut().ok_or_else(|| "vault sealed".to_string())?;
        loaded.previous_hmac_key = None;
        loaded.previous_hmac_envelope_fingerprint = None;
        Ok(())
    }

    /// Clear only when the caller observed the same authenticated database
    /// envelope that populated the slot. A cleanup racing a newer rotation
    /// therefore leaves the newer migration key intact.
    pub fn clear_previous_hmac_if_envelope(
        &self,
        expected_wrapped_key: &[u8],
    ) -> Result<bool, String> {
        let expected_fingerprint: [u8; 32] = Sha256::digest(expected_wrapped_key).into();
        let mut current = self
            .current
            .lock()
            .map_err(|error| format!("runtime bundle lock poisoned: {error}"))?;
        let loaded = current.as_mut().ok_or_else(|| "vault sealed".to_string())?;
        let matches = loaded
            .previous_hmac_envelope_fingerprint
            .as_ref()
            .is_some_and(|actual| bool::from(actual.ct_eq(&expected_fingerprint)));
        if matches {
            loaded.previous_hmac_key = None;
            loaded.previous_hmac_envelope_fingerprint = None;
        }
        Ok(matches)
    }

    pub fn audit_sign(
        &self,
        payload: &str,
        prev_signature: &str,
    ) -> Result<[u8; HMAC_SHA512_BYTES], String> {
        let key = self.key_snapshot(RuntimeKeyKind::Audit)?;
        audit_hmac_sha512(key.as_slice(), payload, prev_signature)
    }

    /// Install the existing at-rest Ed25519 seed envelope. The envelope is
    /// already AES-256-GCM wrapped under the runtime DEK key by Python's
    /// `audit_identity` path, so the plaintext seed never crosses this API.
    pub fn install_audit_identity(
        &self,
        wrapped_seed: &[u8],
        expected_public_key: &[u8],
    ) -> Result<AuditIdentityInstallOutcome, String> {
        let mut current = self
            .current
            .lock()
            .map_err(|error| format!("runtime bundle lock poisoned: {error}"))?;
        let loaded = current.as_mut().ok_or_else(|| "vault sealed".to_string())?;
        let dek_start = RuntimeKeyKind::Dek.offset();
        let seed = aes256_gcm_decrypt_locked(
            &loaded.bytes.as_slice()[dek_start..dek_start + RUNTIME_KEY_BYTES],
            wrapped_seed,
            &[],
            "runtime audit identity seed",
        )?;
        if seed.len() != ED25519_SEED_BYTES {
            return Err(format!("audit_seed must be {ED25519_SEED_BYTES} bytes"));
        }
        if expected_public_key.len() != ED25519_SEED_BYTES {
            return Err(format!(
                "expected audit public key must be {ED25519_SEED_BYTES} bytes"
            ));
        }
        let public_key = audit_ed25519_public_key(seed.as_slice())?;
        if !bool::from(public_key.as_slice().ct_eq(expected_public_key)) {
            return Err("audit identity does not match stored public key".to_string());
        }
        if let Some(existing) = loaded.audit_seed.as_ref() {
            return if bool::from(existing.as_slice().ct_eq(seed.as_slice())) {
                Ok(AuditIdentityInstallOutcome::AlreadyLoaded)
            } else {
                Err("conflicting audit identity for loaded custody generation".to_string())
            };
        }
        loaded.audit_seed = Some(seed);
        Ok(AuditIdentityInstallOutcome::Loaded)
    }

    /// Generate a persistable identity envelope without changing live signer
    /// state. The caller must durably commit the returned envelope/public key,
    /// then install that exact pair through `install_audit_identity`.
    pub fn generate_audit_identity_envelope(&self) -> Result<AuditIdentityEnvelope, String> {
        let current = self
            .current
            .lock()
            .map_err(|error| format!("runtime bundle lock poisoned: {error}"))?;
        let loaded = current.as_ref().ok_or_else(|| "vault sealed".to_string())?;
        if loaded.audit_seed.is_some() {
            return Err("audit identity is already loaded".to_string());
        }
        let dek_start = RuntimeKeyKind::Dek.offset();
        generate_audit_identity_envelope(
            &loaded.bytes.as_slice()[dek_start..dek_start + RUNTIME_KEY_BYTES],
        )
    }

    pub fn audit_identity_loaded(&self) -> Result<bool, String> {
        Ok(self
            .current
            .lock()
            .map_err(|error| format!("runtime bundle lock poisoned: {error}"))?
            .as_ref()
            .is_some_and(|loaded| loaded.audit_seed.is_some()))
    }

    pub fn audit_identity_public_key(&self) -> Result<[u8; ED25519_SEED_BYTES], String> {
        let current = self
            .current
            .lock()
            .map_err(|error| format!("runtime bundle lock poisoned: {error}"))?;
        let loaded = current.as_ref().ok_or_else(|| "vault sealed".to_string())?;
        let seed = loaded
            .audit_seed
            .as_ref()
            .ok_or_else(|| "audit_seed not loaded".to_string())?;
        audit_ed25519_public_key(seed.as_slice())
    }

    pub fn audit_sign_identity(
        &self,
        payload: &str,
        prev_signature: &str,
    ) -> Result<[u8; ED25519_SIGNATURE_BYTES], String> {
        let current = self
            .current
            .lock()
            .map_err(|error| format!("runtime bundle lock poisoned: {error}"))?;
        let loaded = current.as_ref().ok_or_else(|| "vault sealed".to_string())?;
        let seed = loaded
            .audit_seed
            .as_ref()
            .ok_or_else(|| "audit_seed not loaded".to_string())?;
        audit_ed25519_sign(seed.as_slice(), payload, prev_signature)
    }

    pub fn audit_sign_identity_raw(
        &self,
        message: &[u8],
    ) -> Result<[u8; ED25519_SIGNATURE_BYTES], String> {
        let current = self
            .current
            .lock()
            .map_err(|error| format!("runtime bundle lock poisoned: {error}"))?;
        let loaded = current.as_ref().ok_or_else(|| "vault sealed".to_string())?;
        let seed = loaded
            .audit_seed
            .as_ref()
            .ok_or_else(|| "audit_seed not loaded".to_string())?;
        audit_ed25519_sign_raw(seed.as_slice(), message)
    }

    /// Authenticate the existing database envelope with the dedicated HA-wrap
    /// key and install its plaintext directly into locked memory.
    pub fn install_ha_password_envelope(
        &self,
        wrapped_password: &[u8],
    ) -> Result<HaPasswordInstallOutcome, String> {
        let mut current = self
            .current
            .lock()
            .map_err(|error| format!("runtime bundle lock poisoned: {error}"))?;
        let loaded = current.as_mut().ok_or_else(|| "vault sealed".to_string())?;
        let key_start = RuntimeKeyKind::HaWrap.offset();
        let password = aes256_gcm_decrypt_locked(
            &loaded.bytes.as_slice()[key_start..key_start + RUNTIME_KEY_BYTES],
            wrapped_password,
            HA_PASSWORD_AAD,
            "runtime HA password",
        )?;
        validate_ha_password(password.as_slice())?;
        if let Some(existing) = loaded.ha_password.as_ref() {
            return if bool::from(existing.as_slice().ct_eq(password.as_slice())) {
                Ok(HaPasswordInstallOutcome::AlreadyLoaded)
            } else {
                Err("conflicting HA password for loaded custody generation".to_string())
            };
        }
        loaded.ha_password = Some(password);
        Ok(HaPasswordInstallOutcome::Loaded)
    }

    /// Authenticate a database envelope and atomically replace the currently
    /// loaded HA password. Rotation uses a distinct operation from install so
    /// restart loading continues to reject conflicting persisted state.
    pub fn replace_ha_password_envelope(&self, wrapped_password: &[u8]) -> Result<(), String> {
        let mut current = self
            .current
            .lock()
            .map_err(|error| format!("runtime bundle lock poisoned: {error}"))?;
        let loaded = current.as_mut().ok_or_else(|| "vault sealed".to_string())?;
        let key_start = RuntimeKeyKind::HaWrap.offset();
        let replacement = aes256_gcm_decrypt_locked(
            &loaded.bytes.as_slice()[key_start..key_start + RUNTIME_KEY_BYTES],
            wrapped_password,
            HA_PASSWORD_AAD,
            "runtime HA password",
        )?;
        validate_ha_password(replacement.as_slice())?;
        loaded.ha_password = Some(replacement);
        Ok(())
    }

    /// Compatibility input for HA-password creation and rotation. The caller
    /// must protect this mutation with the custodian control capability.
    pub fn replace_ha_password(&self, password: &[u8]) -> Result<(), String> {
        validate_ha_password(password)?;
        let replacement = LockedSecret::from_slice(password, "runtime HA password")?;
        let mut current = self
            .current
            .lock()
            .map_err(|error| format!("runtime bundle lock poisoned: {error}"))?;
        let loaded = current.as_mut().ok_or_else(|| "vault sealed".to_string())?;
        loaded.ha_password = Some(replacement);
        Ok(())
    }

    pub fn clear_ha_password(&self) -> Result<(), String> {
        let mut current = self
            .current
            .lock()
            .map_err(|error| format!("runtime bundle lock poisoned: {error}"))?;
        let loaded = current.as_mut().ok_or_else(|| "vault sealed".to_string())?;
        loaded.ha_password = None;
        Ok(())
    }

    pub fn ha_password_loaded(&self) -> Result<bool, String> {
        Ok(self
            .current
            .lock()
            .map_err(|error| format!("runtime bundle lock poisoned: {error}"))?
            .as_ref()
            .is_some_and(|loaded| loaded.ha_password.is_some()))
    }

    pub fn ha_password_hmac(&self, message: &[u8]) -> Result<[u8; HMAC_SHA512_BYTES], String> {
        let current = self
            .current
            .lock()
            .map_err(|error| format!("runtime bundle lock poisoned: {error}"))?;
        let loaded = current.as_ref().ok_or_else(|| "vault sealed".to_string())?;
        let password = loaded
            .ha_password
            .as_ref()
            .ok_or_else(|| "ha_password not loaded".to_string())?;
        hmac_sha512(password.as_slice(), message)
    }

    pub fn wrap_node_key_for_joiner(
        &self,
        node_key_pem: &[u8],
        node_uuid: &str,
    ) -> Result<Vec<u8>, String> {
        self.wrap_key_for_joiner(
            node_key_pem,
            node_uuid,
            NODE_KEY_INFO_PREFIX,
            NODE_KEY_AAD_PREFIX,
        )
    }

    pub fn wrap_server_key_for_joiner(
        &self,
        server_key_pem: &[u8],
        node_uuid: &str,
    ) -> Result<Vec<u8>, String> {
        self.wrap_key_for_joiner(
            server_key_pem,
            node_uuid,
            SERVER_KEY_INFO_PREFIX,
            SERVER_KEY_AAD_PREFIX,
        )
    }

    fn wrap_key_for_joiner(
        &self,
        key_pem: &[u8],
        node_uuid: &str,
        info_prefix: &[u8],
        aad_prefix: &[u8],
    ) -> Result<Vec<u8>, String> {
        let current = self
            .current
            .lock()
            .map_err(|error| format!("runtime bundle lock poisoned: {error}"))?;
        let loaded = current.as_ref().ok_or_else(|| "vault sealed".to_string())?;
        let password = loaded
            .ha_password
            .as_ref()
            .ok_or_else(|| "ha_password not loaded".to_string())?;
        let mut info = Vec::with_capacity(info_prefix.len() + node_uuid.len());
        info.extend_from_slice(info_prefix);
        info.extend_from_slice(node_uuid.as_bytes());
        let mut aad = Vec::with_capacity(aad_prefix.len() + node_uuid.len());
        aad.extend_from_slice(aad_prefix);
        aad.extend_from_slice(node_uuid.as_bytes());
        hkdf_sha512_aes256_gcm_encrypt(password.as_slice(), &info, key_pem, &aad)
    }

    pub fn aesgcm_encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
        self.wrap_encrypt(RuntimeKeyKind::Dek, plaintext, aad)
    }

    pub fn aesgcm_decrypt(&self, wrapped: &[u8], aad: &[u8]) -> Result<LockedSecret, String> {
        self.wrap_decrypt(
            RuntimeKeyKind::Dek,
            wrapped,
            aad,
            "runtime AES-GCM plaintext",
        )
    }

    pub fn ha_wrap_encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
        self.wrap_encrypt(RuntimeKeyKind::HaWrap, plaintext, aad)
    }

    pub fn ha_wrap_decrypt(&self, wrapped: &[u8], aad: &[u8]) -> Result<LockedSecret, String> {
        self.wrap_decrypt(
            RuntimeKeyKind::HaWrap,
            wrapped,
            aad,
            "runtime HA-wrap plaintext",
        )
    }

    pub fn pki_wrap_encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
        self.wrap_encrypt(RuntimeKeyKind::PkiWrap, plaintext, aad)
    }

    pub fn pki_wrap_decrypt(&self, wrapped: &[u8], aad: &[u8]) -> Result<LockedSecret, String> {
        self.wrap_decrypt(
            RuntimeKeyKind::PkiWrap,
            wrapped,
            aad,
            "runtime PKI-wrap plaintext",
        )
    }

    fn wrap_encrypt(
        &self,
        kind: RuntimeKeyKind,
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, String> {
        let key = self.key_snapshot(kind)?;
        aes256_gcm_encrypt(key.as_slice(), plaintext, aad)
    }

    fn wrap_decrypt(
        &self,
        kind: RuntimeKeyKind,
        wrapped: &[u8],
        aad: &[u8],
        label: &str,
    ) -> Result<LockedSecret, String> {
        let key = self.key_snapshot(kind)?;
        aes256_gcm_decrypt_locked(key.as_slice(), wrapped, aad, label)
    }

    pub fn chained_secret_encrypt(
        &self,
        plaintext: &[u8],
        dek_aad: &[u8],
        secret_aad: &[u8],
    ) -> Result<ChainedSecretCiphertext, String> {
        let key = self.key_snapshot(RuntimeKeyKind::Dek)?;
        chained_secret_encrypt(key.as_slice(), plaintext, dek_aad, secret_aad)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn chained_secret_decrypt(
        &self,
        wrapped_dek: &[u8],
        dek_aad: &[u8],
        ciphertext: &[u8],
        secret_nonce: &[u8],
        secret_aad: &[u8],
    ) -> Result<LockedSecret, String> {
        let key = self.key_snapshot(RuntimeKeyKind::Dek)?;
        chained_secret_decrypt(
            key.as_slice(),
            wrapped_dek,
            dek_aad,
            ciphertext,
            secret_nonce,
            secret_aad,
        )
    }

    pub fn chained_secret_reencrypt(
        &self,
        input: ChainedSecretReencryptInput<'_>,
    ) -> Result<ChainedSecretCiphertext, String> {
        let key = self.key_snapshot(RuntimeKeyKind::Dek)?;
        chained_secret_reencrypt(key.as_slice(), input)
    }

    pub fn clear(&self) -> Result<(), String> {
        let mut current = self
            .current
            .lock()
            .map_err(|error| format!("runtime bundle lock poisoned: {error}"))?;
        *current = None;
        Ok(())
    }
}

fn validate_ha_password(password: &[u8]) -> Result<(), String> {
    if password.len() < HA_PASSWORD_MIN_BYTES {
        return Err(format!(
            "ha_password must be at least {HA_PASSWORD_MIN_BYTES} bytes"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hkdf::Hkdf;
    use sha2::Sha512;

    fn bundle(byte: u8) -> LockedSecret {
        LockedSecret::from_slice(
            &[byte; CUSTODY_V1_RUNTIME_BUNDLE_BYTES],
            "test runtime bundle",
        )
        .expect("lock bundle")
    }

    #[test]
    fn loaded_keys_are_the_seal_latch_and_clear_atomically() {
        let slot = RuntimeBundleSlot::empty();
        assert!(!slot.is_loaded().expect("runtime state"));
        assert_eq!(slot.generation().expect("runtime state"), None);
        assert_eq!(
            slot.install(7, bundle(0xA5)),
            Ok(RuntimeInstallOutcome::Loaded)
        );
        assert!(slot.is_loaded().expect("runtime state"));
        assert_eq!(slot.generation().expect("runtime state"), Some(7));
        slot.clear().expect("seal runtime");
        assert!(!slot.is_loaded().expect("runtime state"));
    }

    #[test]
    fn idempotent_load_accepts_only_the_identical_generation_and_bytes() {
        let slot = RuntimeBundleSlot::empty();
        slot.install(7, bundle(0xA5)).expect("initial load");
        assert_eq!(
            slot.install(7, bundle(0xA5)),
            Ok(RuntimeInstallOutcome::AlreadyLoaded)
        );
        assert!(slot.install(7, bundle(0x5A)).is_err());
        assert!(slot.install(8, bundle(0xA5)).is_err());
        assert!(slot.install(0, bundle(0xA5)).is_err());
    }

    #[test]
    fn snapshots_are_independently_locked_and_wrong_sizes_fail() {
        let slot = RuntimeBundleSlot::empty();
        slot.install(3, bundle(0x33)).expect("load runtime");
        let (generation, snapshot) = slot
            .snapshot()
            .expect("runtime state")
            .expect("runtime loaded");
        assert_eq!(generation, 3);
        assert_eq!(snapshot.as_slice(), bundle(0x33).as_slice());
        slot.clear().expect("clear runtime");
        assert_eq!(snapshot.as_slice(), bundle(0x33).as_slice());
        let short = LockedSecret::from_slice(b"short", "short bundle").expect("lock short");
        assert!(slot.install(3, short).is_err());
    }

    #[test]
    fn typed_key_views_preserve_the_python_bundle_order() {
        let mut bytes = Vec::with_capacity(CUSTODY_V1_RUNTIME_BUNDLE_BYTES);
        for marker in 1..=5 {
            bytes.extend_from_slice(&[marker; RUNTIME_KEY_BYTES]);
        }
        let slot = RuntimeBundleSlot::empty();
        slot.install(
            4,
            LockedSecret::from_vec(bytes, "ordered runtime bundle").expect("lock bundle"),
        )
        .expect("load bundle");
        for (kind, marker) in [
            (RuntimeKeyKind::Hmac, 1),
            (RuntimeKeyKind::Dek, 2),
            (RuntimeKeyKind::Audit, 3),
            (RuntimeKeyKind::HaWrap, 4),
            (RuntimeKeyKind::PkiWrap, 5),
        ] {
            assert_eq!(
                slot.key_snapshot(kind).expect("typed key").as_slice(),
                &[marker; RUNTIME_KEY_BYTES]
            );
        }
    }

    #[test]
    fn runtime_hmac_refuses_sealed_state_and_uses_only_hmac_key() {
        let slot = RuntimeBundleSlot::empty();
        assert_eq!(
            slot.hmac_sha512(b"message"),
            Err("vault sealed".to_string())
        );
        let mut bytes = vec![0xA5; CUSTODY_V1_RUNTIME_BUNDLE_BYTES];
        bytes[..RUNTIME_KEY_BYTES].copy_from_slice(&[0x11; RUNTIME_KEY_BYTES]);
        slot.install(
            8,
            LockedSecret::from_vec(bytes, "runtime HMAC test").expect("lock bundle"),
        )
        .expect("load bundle");
        assert_eq!(
            slot.hmac_sha512(b"message").expect("runtime HMAC"),
            hmac_sha512(&[0x11; RUNTIME_KEY_BYTES], b"message").expect("reference HMAC")
        );
    }

    #[test]
    fn previous_hmac_envelope_preserves_lazy_token_migration_contract() {
        let dek_key = [0x22; RUNTIME_KEY_BYTES];
        let previous_key = [0x19; RUNTIME_KEY_BYTES];
        let mut bytes = vec![0xA5; CUSTODY_V1_RUNTIME_BUNDLE_BYTES];
        bytes[RUNTIME_KEY_BYTES..2 * RUNTIME_KEY_BYTES].copy_from_slice(&dek_key);
        let slot = RuntimeBundleSlot::empty();
        slot.install(
            8,
            LockedSecret::from_vec(bytes, "previous HMAC test bundle").expect("lock bundle"),
        )
        .expect("load bundle");
        assert_eq!(
            slot.previous_hmac_sha512(b"token").expect("empty slot"),
            None
        );
        let wrapped =
            aes256_gcm_encrypt(&dek_key, &previous_key, &[]).expect("wrap previous HMAC key");
        assert_eq!(
            slot.install_previous_hmac_envelope(&wrapped),
            Ok(PreviousHmacInstallOutcome::Loaded)
        );
        assert_eq!(
            slot.install_previous_hmac_envelope(&wrapped),
            Ok(PreviousHmacInstallOutcome::AlreadyLoaded)
        );
        assert!(slot.previous_hmac_loaded().expect("previous-key state"));
        assert_eq!(
            slot.previous_hmac_sha512(b"token").expect("previous HMAC"),
            Some(hmac_sha512(&previous_key, b"token").expect("reference HMAC"))
        );
        let short = aes256_gcm_encrypt(&dek_key, &[0x20; RUNTIME_KEY_BYTES - 1], &[])
            .expect("short envelope");
        assert!(slot.install_previous_hmac_envelope(&short).is_err());
        let conflicting = aes256_gcm_encrypt(&dek_key, &[0x21; RUNTIME_KEY_BYTES], &[])
            .expect("conflicting envelope");
        assert!(slot.install_previous_hmac_envelope(&conflicting).is_err());
        assert!(!slot
            .clear_previous_hmac_if_envelope(&conflicting)
            .expect("stale cleanup"));
        assert!(slot.previous_hmac_loaded().expect("newer key preserved"));
        assert!(slot
            .clear_previous_hmac_if_envelope(&wrapped)
            .expect("matching cleanup"));
        assert_eq!(
            slot.previous_hmac_sha512(b"token").expect("empty slot"),
            None
        );
        slot.clear().expect("seal");
        assert_eq!(
            slot.previous_hmac_sha512(b"token"),
            Err("vault sealed".to_string())
        );
    }

    #[test]
    fn runtime_audit_sign_uses_only_the_typed_audit_key() {
        let mut bytes = vec![0x11; CUSTODY_V1_RUNTIME_BUNDLE_BYTES];
        bytes[2 * RUNTIME_KEY_BYTES..3 * RUNTIME_KEY_BYTES]
            .copy_from_slice(&[0x33; RUNTIME_KEY_BYTES]);
        let slot = RuntimeBundleSlot::empty();
        slot.install(
            8,
            LockedSecret::from_vec(bytes, "runtime audit test").expect("lock bundle"),
        )
        .expect("load bundle");
        assert_eq!(
            slot.audit_sign("payload", "prev").expect("runtime audit"),
            audit_hmac_sha512(&[0x33; RUNTIME_KEY_BYTES], "payload", "prev")
                .expect("reference audit")
        );
        assert_ne!(
            slot.audit_sign("payload", "prev").expect("runtime audit"),
            audit_hmac_sha512(&[0x11; RUNTIME_KEY_BYTES], "payload", "prev")
                .expect("wrong-key audit")
        );
    }

    #[test]
    fn encrypted_audit_identity_is_generation_bound_and_cleared_by_seal() {
        let dek_key = [0x22; RUNTIME_KEY_BYTES];
        let seed = hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
            .expect("RFC seed");
        let mut bytes = vec![0xA5; CUSTODY_V1_RUNTIME_BUNDLE_BYTES];
        bytes[RUNTIME_KEY_BYTES..2 * RUNTIME_KEY_BYTES].copy_from_slice(&dek_key);
        let slot = RuntimeBundleSlot::empty();
        slot.install(
            9,
            LockedSecret::from_vec(bytes, "runtime identity test").expect("lock bundle"),
        )
        .expect("load bundle");
        let generated = slot
            .generate_audit_identity_envelope()
            .expect("generate persistable identity");
        assert_eq!(generated.public_key.len(), ED25519_SEED_BYTES);
        assert!(!slot
            .audit_identity_loaded()
            .expect("generation is not install"));
        let wrapped = aes256_gcm_encrypt(&dek_key, &seed, &[]).expect("wrap seed");
        let expected_public_key =
            hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
                .expect("RFC public key");
        assert_eq!(
            slot.install_audit_identity(&wrapped, &expected_public_key),
            Ok(AuditIdentityInstallOutcome::Loaded)
        );
        assert_eq!(
            slot.install_audit_identity(&wrapped, &expected_public_key),
            Ok(AuditIdentityInstallOutcome::AlreadyLoaded)
        );
        assert!(slot.audit_identity_loaded().expect("identity state"));
        assert!(slot.generate_audit_identity_envelope().is_err());
        assert_eq!(
            hex::encode(slot.audit_identity_public_key().expect("public key")),
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        );
        assert_eq!(
            hex::encode(slot.audit_sign_identity("", "").expect("signature")),
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555\
             fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
                .replace(char::is_whitespace, "")
        );
        assert_eq!(
            slot.audit_sign_identity_raw(b"").expect("raw signature"),
            slot.audit_sign_identity("", "").expect("chain signature")
        );
        let conflicting =
            aes256_gcm_encrypt(&dek_key, &[0x44; ED25519_SEED_BYTES], &[]).expect("wrap other");
        assert!(slot
            .install_audit_identity(&conflicting, &expected_public_key)
            .is_err());
        assert!(slot
            .install_audit_identity(&wrapped, &[0x99; ED25519_SEED_BYTES])
            .is_err());
        slot.clear().expect("seal");
        assert!(!slot.audit_identity_loaded().expect("identity cleared"));
        assert_eq!(
            slot.audit_sign_identity("payload", "prev"),
            Err("vault sealed".to_string())
        );
    }

    #[test]
    fn runtime_aes_uses_only_dek_key_and_binds_aad() {
        let mut bytes = vec![0xA5; CUSTODY_V1_RUNTIME_BUNDLE_BYTES];
        bytes[RUNTIME_KEY_BYTES..2 * RUNTIME_KEY_BYTES].copy_from_slice(&[0x22; RUNTIME_KEY_BYTES]);
        let slot = RuntimeBundleSlot::empty();
        slot.install(
            9,
            LockedSecret::from_vec(bytes, "runtime AES test").expect("lock bundle"),
        )
        .expect("load bundle");
        let wrapped = slot
            .aesgcm_encrypt(b"secret", b"namespace:name")
            .expect("runtime encrypt");
        assert_eq!(
            slot.aesgcm_decrypt(&wrapped, b"namespace:name")
                .expect("runtime decrypt")
                .as_slice(),
            b"secret"
        );
        assert!(slot.aesgcm_decrypt(&wrapped, b"wrong").is_err());
        slot.clear().expect("seal");
        assert!(slot.aesgcm_encrypt(b"secret", b"aad").is_err());
    }

    #[test]
    fn ha_and_pki_wrap_keys_are_distinct_and_bind_aad() {
        let mut bytes = vec![0xA5; CUSTODY_V1_RUNTIME_BUNDLE_BYTES];
        bytes[3 * RUNTIME_KEY_BYTES..4 * RUNTIME_KEY_BYTES]
            .copy_from_slice(&[0x44; RUNTIME_KEY_BYTES]);
        bytes[4 * RUNTIME_KEY_BYTES..5 * RUNTIME_KEY_BYTES]
            .copy_from_slice(&[0x55; RUNTIME_KEY_BYTES]);
        let slot = RuntimeBundleSlot::empty();
        slot.install(
            10,
            LockedSecret::from_vec(bytes, "runtime wrap test").expect("lock bundle"),
        )
        .expect("load bundle");
        let ha = slot
            .ha_wrap_encrypt(b"HA secret", b"ha:row")
            .expect("HA wrap");
        let pki = slot
            .pki_wrap_encrypt(b"PKI secret", b"pki:row")
            .expect("PKI wrap");
        assert_eq!(
            slot.ha_wrap_decrypt(&ha, b"ha:row")
                .expect("HA unwrap")
                .as_slice(),
            b"HA secret"
        );
        assert_eq!(
            slot.pki_wrap_decrypt(&pki, b"pki:row")
                .expect("PKI unwrap")
                .as_slice(),
            b"PKI secret"
        );
        assert!(slot.pki_wrap_decrypt(&ha, b"ha:row").is_err());
        assert!(slot.ha_wrap_decrypt(&ha, b"ha:wrong").is_err());
    }

    #[test]
    fn ha_password_envelope_is_authenticated_locked_and_seal_bound() {
        let ha_wrap_key = [0x44; RUNTIME_KEY_BYTES];
        let password = [0x71; HA_PASSWORD_MIN_BYTES];
        let mut bytes = vec![0xA5; CUSTODY_V1_RUNTIME_BUNDLE_BYTES];
        bytes[3 * RUNTIME_KEY_BYTES..4 * RUNTIME_KEY_BYTES].copy_from_slice(&ha_wrap_key);
        let slot = RuntimeBundleSlot::empty();
        slot.install(
            12,
            LockedSecret::from_vec(bytes, "HA password test bundle").expect("lock bundle"),
        )
        .expect("load bundle");
        let wrapped = aes256_gcm_encrypt(&ha_wrap_key, &password, HA_PASSWORD_AAD)
            .expect("database envelope");
        assert_eq!(
            slot.install_ha_password_envelope(&wrapped),
            Ok(HaPasswordInstallOutcome::Loaded)
        );
        assert_eq!(
            slot.install_ha_password_envelope(&wrapped),
            Ok(HaPasswordInstallOutcome::AlreadyLoaded)
        );
        assert!(slot.ha_password_loaded().expect("password state"));
        assert_eq!(
            slot.ha_password_hmac(b"join proof").expect("HA HMAC"),
            hmac_sha512(&password, b"join proof").expect("reference HMAC")
        );

        let conflicting = aes256_gcm_encrypt(
            &ha_wrap_key,
            &[0x72; HA_PASSWORD_MIN_BYTES],
            HA_PASSWORD_AAD,
        )
        .expect("conflicting envelope");
        assert!(slot.install_ha_password_envelope(&conflicting).is_err());
        slot.replace_ha_password_envelope(&conflicting)
            .expect("replace from authenticated database envelope");
        assert_eq!(
            slot.ha_password_hmac(b"join proof")
                .expect("rotated HA HMAC"),
            hmac_sha512(&[0x72; HA_PASSWORD_MIN_BYTES], b"join proof")
                .expect("rotated reference HMAC")
        );
        let wrong_aad =
            aes256_gcm_encrypt(&ha_wrap_key, &password, b"wrong").expect("wrong-AAD envelope");
        assert!(slot.replace_ha_password_envelope(&wrong_aad).is_err());
        assert_eq!(
            slot.ha_password_hmac(b"join proof")
                .expect("unchanged HA HMAC"),
            hmac_sha512(&[0x72; HA_PASSWORD_MIN_BYTES], b"join proof")
                .expect("unchanged reference HMAC")
        );

        slot.clear().expect("seal");
        assert!(!slot.ha_password_loaded().expect("password cleared"));
        assert_eq!(
            slot.ha_password_hmac(b"join proof"),
            Err("vault sealed".to_string())
        );
    }

    #[test]
    fn ha_password_rotation_and_joiner_domains_preserve_wire_recipe() {
        let slot = RuntimeBundleSlot::empty();
        slot.install(13, bundle(0x33)).expect("load bundle");
        assert!(slot
            .replace_ha_password(&[0x11; HA_PASSWORD_MIN_BYTES - 1])
            .is_err());
        let first = [0x81; HA_PASSWORD_MIN_BYTES];
        let second = [0x82; HA_PASSWORD_MIN_BYTES];
        slot.replace_ha_password(&first).expect("initial password");
        slot.replace_ha_password(&second).expect("rotate password");

        let node_uuid = "deadbeef";
        let node_wrapped = slot
            .wrap_node_key_for_joiner(b"node private key", node_uuid)
            .expect("node-key wrap");
        let server_wrapped = slot
            .wrap_server_key_for_joiner(b"server private key", node_uuid)
            .expect("server-key wrap");
        let node_info = b"cluster-node-key-wrap:deadbeef";
        let node_aad = b"vault-cluster:node-key:deadbeef";
        let server_info = b"cluster-server-key-wrap:deadbeef";
        let server_aad = b"vault-cluster:server-key:deadbeef";
        let derive = |info: &[u8]| {
            let hkdf = Hkdf::<Sha512>::new(None, &second);
            let mut key = [0u8; RUNTIME_KEY_BYTES];
            hkdf.expand(info, &mut key).expect("HKDF recipe");
            key
        };
        assert_eq!(
            crate::operations::aes256_gcm_decrypt(&derive(node_info), &node_wrapped, node_aad)
                .expect("node unwrap"),
            b"node private key"
        );
        assert_eq!(
            crate::operations::aes256_gcm_decrypt(
                &derive(server_info),
                &server_wrapped,
                server_aad,
            )
            .expect("server unwrap"),
            b"server private key"
        );
        assert!(crate::operations::aes256_gcm_decrypt(
            &derive(node_info),
            &server_wrapped,
            node_aad,
        )
        .is_err());
        slot.clear_ha_password().expect("clear password");
        assert!(!slot.ha_password_loaded().expect("password state"));
        assert!(slot
            .wrap_node_key_for_joiner(b"node private key", node_uuid)
            .is_err());
    }
}
