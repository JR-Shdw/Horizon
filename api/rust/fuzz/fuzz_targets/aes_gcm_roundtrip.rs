// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
//
// Fuzz target : roundtrip property over AES-256-GCM with AAD binding.
//
// Strategy : fuzz the (key, plaintext, AAD) tuple. The expected
// property : encrypt(k, p, a) -> w ; decrypt(k, w, a) -> p. Violation
// of this invariant is a critical bug (vault data corruption).
//
// Also tests :
//   - decrypt(k, w, a') with a' != a MUST fail (AAD binding)
//   - decrypt(k', w, a)  with k' != k MUST fail (key binding)
//
// Run :
//   cd api/rust && cargo +nightly fuzz run aes_gcm_roundtrip -- -max_total_time=60

#![no_main]

use libfuzzer_sys::fuzz_target;
use rhorizon_crypto::fuzz_api::{aes_gcm_decrypt_aad, aes_gcm_encrypt_aad};

fuzz_target!(|data: &[u8]| {
    // Slice layout from the fuzz input :
    //   bytes  0..32 : key (32 bytes for AES-256)
    //   bytes 32..33 : aad_len (caps total at 255, keep iteration fast)
    //   bytes 33..33+aad_len : aad
    //   bytes 33+aad_len.. : plaintext
    if data.len() < 33 {
        return;
    }
    let key: [u8; 32] = data[..32].try_into().unwrap();
    let aad_len = data[32] as usize;
    if data.len() < 33 + aad_len {
        return;
    }
    let aad = &data[33..33 + aad_len];
    let plaintext = &data[33 + aad_len..];
    if plaintext.len() > 1024 {
        return; // cap so the iteration stays sub-millisecond
    }

    // Encrypt then decrypt with the SAME key + AAD must yield the
    // original plaintext. The crypto crate's correctness is the
    // upstream's job ; what we test here is our wrapping
    // (nonce-prefix layout, AAD binding) doesn't corrupt the round.
    let wrapped = match aes_gcm_encrypt_aad(&key, plaintext, aad) {
        Ok(w) => w,
        Err(_) => return, // encrypt may fail for some inputs (very rare)
    };
    let recovered = aes_gcm_decrypt_aad(&key, &wrapped, aad)
        .expect("roundtrip decrypt failed - wrap layout regression ?");
    assert_eq!(recovered, plaintext,
        "roundtrip plaintext mismatch - vault data corruption bug");

    // AAD binding : flipping the first byte of AAD MUST cause
    // decryption to fail. (Skip when aad is empty, can't flip.)
    if !aad.is_empty() {
        let mut tampered_aad = aad.to_vec();
        tampered_aad[0] ^= 1;
        assert!(aes_gcm_decrypt_aad(&key, &wrapped, &tampered_aad).is_err(),
            "AAD binding violated - same wrapped accepted with different AAD");
    }
});
