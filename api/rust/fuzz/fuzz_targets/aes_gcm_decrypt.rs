// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
//
// Fuzz target : adversarial inputs into aes_gcm_decrypt_aad().
//
// Strategy : feed completely random bytes as `wrapped` and watch
// for panics. An honest implementation MUST :
//   - return Err on truncated wrapped (less than 12 nonce + 16 tag = 28 bytes)
//   - return Err on tag-mismatch
//   - never panic on length / alignment / encoding edge cases
//
// This complements `aes_gcm_roundtrip` (which proves the property
// on valid inputs) by stressing the decode-and-reject path.
//
// Run :
//   cd api/rust && cargo +nightly fuzz run aes_gcm_decrypt -- -max_total_time=60

#![no_main]

use libfuzzer_sys::fuzz_target;
use rhorizon_crypto::fuzz_api::aes_gcm_decrypt_aad;

fuzz_target!(|data: &[u8]| {
    // Slice layout :
    //   bytes  0..32 : key
    //   bytes 32..33 : aad_len
    //   bytes 33..33+aad_len : aad
    //   bytes 33+aad_len..   : wrapped (intentionally adversarial)
    if data.len() < 33 {
        return;
    }
    let key: [u8; 32] = data[..32].try_into().unwrap();
    let aad_len = data[32] as usize;
    if data.len() < 33 + aad_len {
        return;
    }
    let aad = &data[33..33 + aad_len];
    let wrapped = &data[33 + aad_len..];
    if wrapped.len() > 4096 {
        return; // cap : 4 KB wrapped is plenty for our use cases
    }

    // The contract : never panic. The function may return Err
    // (almost always will, on random bytes) or, extremely rarely -
    // Ok with garbage (random tag happens to match by chance for
    // 2^-128 of inputs). Both are acceptable. A panic is not.
    let _ = aes_gcm_decrypt_aad(&key, wrapped, aad);
});
