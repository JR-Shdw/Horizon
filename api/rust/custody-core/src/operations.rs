// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
//! Crypto operations shared by the existing master RPC and Rust custodian.

use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::aead::{Aead, AeadInPlace, KeyInit, OsRng, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signer, SigningKey};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha512;
use zeroize::Zeroize;

use crate::secure_memory::LockedSecret;

pub const HMAC_SHA512_BYTES: usize = 64;
pub const AES_256_KEY_BYTES: usize = 32;
pub const AES_GCM_NONCE_BYTES: usize = 12;
pub const AES_GCM_TAG_BYTES: usize = 16;
pub const AES_GCM_MIN_WRAPPED_BYTES: usize = AES_GCM_NONCE_BYTES + AES_GCM_TAG_BYTES;
pub const DEK_WRAPPED_BYTES: usize = AES_GCM_NONCE_BYTES + AES_256_KEY_BYTES + AES_GCM_TAG_BYTES;
pub const XCHACHA_NONCE_BYTES: usize = 24;
pub const XCHACHA_TAG_BYTES: usize = 16;
pub const ED25519_SEED_BYTES: usize = 32;
pub const ED25519_SIGNATURE_BYTES: usize = 64;

pub struct ChainedSecretCiphertext {
    pub wrapped_dek: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub secret_nonce: [u8; XCHACHA_NONCE_BYTES],
}

pub struct ChainedSecretReencryptInput<'a> {
    pub old_wrapped_dek: &'a [u8],
    pub old_dek_aad: &'a [u8],
    pub old_ciphertext: &'a [u8],
    pub old_secret_nonce: &'a [u8],
    pub old_secret_aad: &'a [u8],
    pub new_dek_aad: &'a [u8],
    pub new_secret_aad: &'a [u8],
}

pub struct AuditIdentityEnvelope {
    pub wrapped_seed: Vec<u8>,
    pub public_key: [u8; ED25519_SEED_BYTES],
}

/// HMAC-SHA512 with a fixed-size output. Both Rust custody backends call this
/// function, so the existing Python/Rust master-RPC parity tests also gate the
/// standalone custodian implementation.
pub fn hmac_sha512(key: &[u8], message: &[u8]) -> Result<[u8; HMAC_SHA512_BYTES], String> {
    let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(key).map_err(|error| error.to_string())?;
    mac.update(message);
    Ok(mac.finalize().into_bytes().into())
}

/// Derive a purpose-specific AES-256 key from a high-entropy parent with
/// HKDF-SHA512, then return the established `nonce || ciphertext || tag` wire
/// format. The transient derived key is wiped before return.
pub fn hkdf_sha512_aes256_gcm_encrypt(
    parent_key: &[u8],
    info: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    if parent_key.len() < AES_256_KEY_BYTES {
        return Err(format!(
            "HKDF parent key must be at least {AES_256_KEY_BYTES} bytes"
        ));
    }
    if info.is_empty() {
        return Err("HKDF info must not be empty".to_string());
    }
    if aad.is_empty() {
        return Err("AES-GCM AAD must not be empty".to_string());
    }
    let hkdf = Hkdf::<Sha512>::new(None, parent_key);
    let mut derived = [0u8; AES_256_KEY_BYTES];
    let result = (|| {
        hkdf.expand(info, &mut derived)
            .map_err(|error| format!("HKDF expand failed: {error}"))?;
        aes256_gcm_encrypt(&derived, plaintext, aad)
    })();
    derived.zeroize();
    result
}

/// Legacy audit-chain signature over the exact `prev_signature || payload`
/// UTF-8 byte sequence used by Python and the existing master RPC.
pub fn audit_hmac_sha512(
    key: &[u8],
    payload: &str,
    prev_signature: &str,
) -> Result<[u8; HMAC_SHA512_BYTES], String> {
    let chained = audit_message(payload, prev_signature)?;
    hmac_sha512(key, &chained)
}

fn audit_message(
    payload: &str,
    prev_signature: &str,
) -> Result<zeroize::Zeroizing<Vec<u8>>, String> {
    let capacity = prev_signature
        .len()
        .checked_add(payload.len())
        .ok_or_else(|| "audit message is too large".to_string())?;
    let mut chained = zeroize::Zeroizing::new(Vec::with_capacity(capacity));
    chained.extend_from_slice(prev_signature.as_bytes());
    chained.extend_from_slice(payload.as_bytes());
    Ok(chained)
}

pub fn audit_ed25519_public_key(seed: &[u8]) -> Result<[u8; ED25519_SEED_BYTES], String> {
    if seed.len() != ED25519_SEED_BYTES {
        return Err(format!("audit_seed must be {ED25519_SEED_BYTES} bytes"));
    }
    let mut seed_bytes = [0u8; ED25519_SEED_BYTES];
    seed_bytes.copy_from_slice(seed);
    let signing_key = SigningKey::from_bytes(&seed_bytes);
    seed_bytes.zeroize();
    Ok(signing_key.verifying_key().to_bytes())
}

pub fn audit_ed25519_sign(
    seed: &[u8],
    payload: &str,
    prev_signature: &str,
) -> Result<[u8; ED25519_SIGNATURE_BYTES], String> {
    let chained = audit_message(payload, prev_signature)?;
    audit_ed25519_sign_raw(seed, &chained)
}

pub fn audit_ed25519_sign_raw(
    seed: &[u8],
    message: &[u8],
) -> Result<[u8; ED25519_SIGNATURE_BYTES], String> {
    if seed.len() != ED25519_SEED_BYTES {
        return Err(format!("audit_seed must be {ED25519_SEED_BYTES} bytes"));
    }
    let mut seed_bytes = [0u8; ED25519_SEED_BYTES];
    seed_bytes.copy_from_slice(seed);
    let signing_key = SigningKey::from_bytes(&seed_bytes);
    seed_bytes.zeroize();
    Ok(signing_key.sign(message).to_bytes())
}

/// Generate an Ed25519 identity and return only its public key and an
/// AES-256-GCM envelope of the seed. The seed is allocated in locked memory
/// before randomness enters it and is zeroized on every return path.
pub fn generate_audit_identity_envelope(dek_key: &[u8]) -> Result<AuditIdentityEnvelope, String> {
    let mut seed = LockedSecret::from_vec(
        vec![0u8; ED25519_SEED_BYTES],
        "generated audit identity seed",
    )?;
    if OsRng.try_fill_bytes(seed.as_mut_slice()).is_err() {
        return Err("operating-system random number generation failed".to_string());
    }
    let public_key = audit_ed25519_public_key(seed.as_slice())?;
    let wrapped_seed = aes256_gcm_encrypt(dek_key, seed.as_slice(), &[])?;
    Ok(AuditIdentityEnvelope {
        wrapped_seed,
        public_key,
    })
}

/// AES-256-GCM with the established `nonce || ciphertext || tag` layout.
pub fn aes256_gcm_encrypt(key: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
    let mut nonce = [0u8; AES_GCM_NONCE_BYTES];
    if OsRng.try_fill_bytes(&mut nonce).is_err() {
        nonce.zeroize();
        return Err("operating-system random number generation failed".to_string());
    }
    let ciphertext = aes256_gcm_encrypt_with_nonce(key, &nonce, plaintext, aad)?;
    let mut wrapped = Vec::with_capacity(AES_GCM_NONCE_BYTES + ciphertext.len());
    wrapped.extend_from_slice(&nonce);
    wrapped.extend_from_slice(&ciphertext);
    Ok(wrapped)
}

/// AES-256-GCM encryption with an external nonce, returning `ciphertext || tag`.
/// This is the existing `DekCipher` and master-RPC wire layout.
pub fn aes256_gcm_encrypt_with_nonce(
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    if key.len() != AES_256_KEY_BYTES {
        return Err(format!(
            "AES-256 key must be exactly {AES_256_KEY_BYTES} bytes"
        ));
    }
    if nonce.len() != AES_GCM_NONCE_BYTES {
        return Err(format!("nonce must be exactly {AES_GCM_NONCE_BYTES} bytes"));
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|error| error.to_string())?;
    cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|error| error.to_string())
}

pub fn aes256_gcm_decrypt(key: &[u8], wrapped: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
    if wrapped.len() < AES_GCM_MIN_WRAPPED_BYTES {
        return Err("Wrapped data too short".to_string());
    }
    aes256_gcm_decrypt_with_nonce(
        key,
        &wrapped[..AES_GCM_NONCE_BYTES],
        &wrapped[AES_GCM_NONCE_BYTES..],
        aad,
    )
}

pub fn aes256_gcm_decrypt_with_nonce(
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    if key.len() != AES_256_KEY_BYTES {
        return Err(format!(
            "AES-256 key must be exactly {AES_256_KEY_BYTES} bytes"
        ));
    }
    if nonce.len() != AES_GCM_NONCE_BYTES {
        return Err(format!("nonce must be exactly {AES_GCM_NONCE_BYTES} bytes"));
    }
    if ciphertext.len() < AES_GCM_TAG_BYTES {
        return Err("Wrapped data too short".to_string());
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|error| error.to_string())?;
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| "Decryption failed - wrong key or tampered data".to_string())
}

/// Decrypt directly into an allocation that is locked before it contains
/// plaintext. This is the custody path for DEKs and secret values.
pub fn aes256_gcm_decrypt_locked(
    key: &[u8],
    wrapped: &[u8],
    aad: &[u8],
    label: &str,
) -> Result<LockedSecret, String> {
    if key.len() != AES_256_KEY_BYTES {
        return Err(format!(
            "AES-256 key must be exactly {AES_256_KEY_BYTES} bytes"
        ));
    }
    if wrapped.len() < AES_GCM_MIN_WRAPPED_BYTES {
        return Err("Wrapped data too short".to_string());
    }
    let tag_offset = wrapped.len() - AES_GCM_TAG_BYTES;
    let mut plaintext = LockedSecret::from_slice(&wrapped[AES_GCM_NONCE_BYTES..tag_offset], label)?;
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|error| error.to_string())?;
    let tag = aes_gcm::Tag::from_slice(&wrapped[tag_offset..]);
    cipher
        .decrypt_in_place_detached(
            Nonce::from_slice(&wrapped[..AES_GCM_NONCE_BYTES]),
            aad,
            plaintext.as_mut_slice(),
            tag,
        )
        .map_err(|_| "Decryption failed - wrong key or tampered data".to_string())?;
    Ok(plaintext)
}

/// Generate a per-secret DEK, wrap it under the runtime DEK key, and encrypt
/// the secret with XChaCha20-Poly1305. The plaintext DEK is locked and wiped.
pub fn chained_secret_encrypt(
    dek_key: &[u8],
    plaintext: &[u8],
    dek_aad: &[u8],
    secret_aad: &[u8],
) -> Result<ChainedSecretCiphertext, String> {
    let mut dek = LockedSecret::from_vec(vec![0u8; AES_256_KEY_BYTES], "chained secret DEK")?;
    if OsRng.try_fill_bytes(dek.as_mut_slice()).is_err() {
        return Err("operating-system random number generation failed".to_string());
    }
    let wrapped_dek = aes256_gcm_encrypt(dek_key, dek.as_slice(), dek_aad)?;
    debug_assert_eq!(wrapped_dek.len(), DEK_WRAPPED_BYTES);
    let cipher = XChaCha20Poly1305::new_from_slice(dek.as_slice())
        .map_err(|_| "XChaCha20 key load failed".to_string())?;
    let mut secret_nonce = [0u8; XCHACHA_NONCE_BYTES];
    if OsRng.try_fill_bytes(&mut secret_nonce).is_err() {
        secret_nonce.zeroize();
        return Err("operating-system random number generation failed".to_string());
    }
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&secret_nonce),
            Payload {
                msg: plaintext,
                aad: secret_aad,
            },
        )
        .map_err(|_| "Secret encryption failed".to_string())?;
    Ok(ChainedSecretCiphertext {
        wrapped_dek,
        ciphertext,
        secret_nonce,
    })
}

/// Unwrap a per-secret DEK and decrypt directly into locked, zeroizing memory.
pub fn chained_secret_decrypt(
    dek_key: &[u8],
    wrapped_dek: &[u8],
    dek_aad: &[u8],
    ciphertext: &[u8],
    secret_nonce: &[u8],
    secret_aad: &[u8],
) -> Result<LockedSecret, String> {
    if secret_nonce.len() != XCHACHA_NONCE_BYTES {
        return Err(format!(
            "XChaCha20-Poly1305 nonce must be {XCHACHA_NONCE_BYTES} bytes"
        ));
    }
    if ciphertext.len() < XCHACHA_TAG_BYTES {
        return Err("Secret decryption failed - wrong key or tampered data".to_string());
    }
    let dek = aes256_gcm_decrypt_locked(dek_key, wrapped_dek, dek_aad, "chained secret DEK")?;
    if dek.len() != AES_256_KEY_BYTES {
        return Err(format!("Unwrapped DEK must be {AES_256_KEY_BYTES} bytes"));
    }
    let cipher = XChaCha20Poly1305::new_from_slice(dek.as_slice())
        .map_err(|_| "XChaCha20 key load failed".to_string())?;
    let tag_offset = ciphertext.len() - XCHACHA_TAG_BYTES;
    let mut plaintext =
        LockedSecret::from_slice(&ciphertext[..tag_offset], "chained secret plaintext")?;
    let tag = chacha20poly1305::Tag::from_slice(&ciphertext[tag_offset..]);
    cipher
        .decrypt_in_place_detached(
            XNonce::from_slice(secret_nonce),
            secret_aad,
            plaintext.as_mut_slice(),
            tag,
        )
        .map_err(|_| "Secret decryption failed - wrong key or tampered data".to_string())?;
    Ok(plaintext)
}

/// Decrypt an existing secret and re-encrypt it under a fresh per-secret DEK.
pub fn chained_secret_reencrypt(
    dek_key: &[u8],
    input: ChainedSecretReencryptInput<'_>,
) -> Result<ChainedSecretCiphertext, String> {
    let plaintext = chained_secret_decrypt(
        dek_key,
        input.old_wrapped_dek,
        input.old_dek_aad,
        input.old_ciphertext,
        input.old_secret_nonce,
        input.old_secret_aad,
    )?;
    chained_secret_encrypt(
        dek_key,
        plaintext.as_slice(),
        input.new_dek_aad,
        input.new_secret_aad,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_4231_test_case_two() {
        let actual = hmac_sha512(b"Jefe", b"what do ya want for nothing?").expect("valid HMAC key");
        assert_eq!(
            hex::encode(actual),
            "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554\
             9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"
                .replace(char::is_whitespace, "")
        );
    }

    #[test]
    fn hkdf_joiner_wrap_matches_independent_recipe_and_domains() {
        let parent = [0x31; AES_256_KEY_BYTES];
        let info = b"cluster-node-key-wrap:node-a";
        let aad = b"vault-cluster:node-key:node-a";
        let wrapped = hkdf_sha512_aes256_gcm_encrypt(&parent, info, b"private key", aad)
            .expect("joiner wrap");
        let hkdf = Hkdf::<Sha512>::new(None, &parent);
        let mut derived = [0u8; AES_256_KEY_BYTES];
        hkdf.expand(info, &mut derived).expect("HKDF expand");
        assert_eq!(
            aes256_gcm_decrypt(&derived, &wrapped, aad).expect("independent unwrap"),
            b"private key"
        );
        assert!(
            aes256_gcm_decrypt(&derived, &wrapped, b"vault-cluster:server-key:node-a").is_err()
        );
        derived.zeroize();
        assert!(hkdf_sha512_aes256_gcm_encrypt(&parent[..31], info, b"x", aad).is_err());
        assert!(hkdf_sha512_aes256_gcm_encrypt(&parent, b"", b"x", aad).is_err());
        assert!(hkdf_sha512_aes256_gcm_encrypt(&parent, info, b"x", b"").is_err());
    }

    #[test]
    fn audit_hmac_preserves_prev_then_payload_utf8_contract() {
        let key = [0x17; AES_256_KEY_BYTES];
        let payload = "actor|create|café|漢字";
        let prev = "ab".repeat(64);
        let mut expected_message = prev.as_bytes().to_vec();
        expected_message.extend_from_slice(payload.as_bytes());
        assert_eq!(
            audit_hmac_sha512(&key, payload, &prev),
            hmac_sha512(&key, &expected_message)
        );
        assert_ne!(
            audit_hmac_sha512(&key, payload, &prev),
            audit_hmac_sha512(&key, &prev, payload)
        );
    }

    #[test]
    fn audit_ed25519_matches_rfc_8032_test_one() {
        let seed = hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
            .expect("RFC seed");
        assert_eq!(
            hex::encode(audit_ed25519_public_key(&seed).expect("public key")),
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        );
        assert_eq!(
            hex::encode(audit_ed25519_sign(&seed, "", "").expect("signature")),
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555\
             fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
                .replace(char::is_whitespace, "")
        );
        assert_eq!(
            audit_ed25519_sign_raw(&seed, b"").expect("raw signature"),
            audit_ed25519_sign(&seed, "", "").expect("chain signature")
        );
        assert!(audit_ed25519_sign(&seed[..31], "", "").is_err());
    }

    #[test]
    fn generated_audit_identity_returns_only_matching_envelope_and_public_key() {
        let dek_key = [0x42; AES_256_KEY_BYTES];
        let generated = generate_audit_identity_envelope(&dek_key).expect("generate identity");
        let seed = aes256_gcm_decrypt_locked(
            &dek_key,
            &generated.wrapped_seed,
            &[],
            "generated identity test",
        )
        .expect("decrypt generated seed");
        assert_eq!(seed.len(), ED25519_SEED_BYTES);
        assert_eq!(
            audit_ed25519_public_key(seed.as_slice()).expect("derive generated public key"),
            generated.public_key
        );
    }

    #[test]
    fn nist_aes_256_gcm_empty_plaintext_known_answer() {
        let ciphertext = aes256_gcm_encrypt_with_nonce(
            &[0u8; AES_256_KEY_BYTES],
            &[0u8; AES_GCM_NONCE_BYTES],
            b"",
            b"",
        )
        .expect("NIST AES-GCM encrypt");
        assert_eq!(hex::encode(&ciphertext), "530f8afbc74536b9a963b4f1c4cb738b");
        assert_eq!(
            aes256_gcm_decrypt_with_nonce(
                &[0u8; AES_256_KEY_BYTES],
                &[0u8; AES_GCM_NONCE_BYTES],
                &ciphertext,
                b"",
            ),
            Ok(Vec::new())
        );
    }

    #[test]
    fn aes_256_gcm_roundtrip_binds_aad_and_rejects_invalid_lengths() {
        let key = [0x42; AES_256_KEY_BYTES];
        let wrapped = aes256_gcm_encrypt(&key, b"secret", b"record:7").expect("encrypt");
        assert_eq!(
            aes256_gcm_decrypt(&key, &wrapped, b"record:7"),
            Ok(b"secret".to_vec())
        );
        assert!(aes256_gcm_decrypt(&key, &wrapped, b"record:8").is_err());
        assert!(aes256_gcm_encrypt_with_nonce(&key[..31], &[0u8; 12], b"x", b"").is_err());
        assert!(aes256_gcm_encrypt_with_nonce(&key, &[0u8; 11], b"x", b"").is_err());
        assert!(aes256_gcm_decrypt_with_nonce(&key, &[0u8; 12], &[0u8; 15], b"").is_err());
    }

    #[test]
    fn chained_secret_roundtrip_binds_both_aad_layers() {
        let key = [0x42; AES_256_KEY_BYTES];
        let encrypted = chained_secret_encrypt(&key, b"vault secret", b"dek:7", b"secret:7")
            .expect("chained encrypt");
        assert_eq!(
            chained_secret_decrypt(
                &key,
                &encrypted.wrapped_dek,
                b"dek:7",
                &encrypted.ciphertext,
                &encrypted.secret_nonce,
                b"secret:7",
            )
            .expect("chained decrypt")
            .as_slice(),
            b"vault secret"
        );
        assert!(chained_secret_decrypt(
            &key,
            &encrypted.wrapped_dek,
            b"dek:8",
            &encrypted.ciphertext,
            &encrypted.secret_nonce,
            b"secret:7",
        )
        .is_err());
        assert!(chained_secret_decrypt(
            &key,
            &encrypted.wrapped_dek,
            b"dek:7",
            &encrypted.ciphertext,
            &encrypted.secret_nonce,
            b"secret:8",
        )
        .is_err());
    }

    #[test]
    fn chained_secret_reencrypt_preserves_plaintext_with_new_bindings() {
        let key = [0x42; AES_256_KEY_BYTES];
        let encrypted = chained_secret_encrypt(&key, b"vault secret", b"dek:old", b"secret:old")
            .expect("chained encrypt");
        let rotated = chained_secret_reencrypt(
            &key,
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
        .expect("chained reencrypt");
        assert_ne!(rotated.wrapped_dek, encrypted.wrapped_dek);
        assert_eq!(
            chained_secret_decrypt(
                &key,
                &rotated.wrapped_dek,
                b"dek:new",
                &rotated.ciphertext,
                &rotated.secret_nonce,
                b"secret:new",
            )
            .expect("decrypt rotated")
            .as_slice(),
            b"vault secret"
        );
    }
}
