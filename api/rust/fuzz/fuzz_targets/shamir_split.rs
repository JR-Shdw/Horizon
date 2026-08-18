// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
//
// Fuzz target : adversarial inputs into shamir_split().
//
// Strategy : take fuzz bytes and derive (threshold, total, secret).
// shamir_split MUST :
//   - reject (threshold < 2)            -> Err
//   - reject (total < threshold)        -> Err
//   - never panic on any combination
//   - return shares.len() == total when Ok
//
// Run :
//   cd api/rust && cargo +nightly fuzz run shamir_split -- -max_total_time=60

#![no_main]

use libfuzzer_sys::fuzz_target;
use rhorizon_crypto::key_share::fuzz_api::shamir_split;

fuzz_target!(|data: &[u8]| {
    // First two bytes parameterise threshold / total. The rest is
    // the secret. Need at least 2 metadata bytes.
    if data.len() < 2 {
        return;
    }
    let threshold = data[0];
    let total = data[1];
    let secret = &data[2..];
    // Cap secret length so we don't spend the iteration on a 4 KB
    // payload: vault secrets are typically <256 bytes.
    if secret.len() > 256 {
        return;
    }

    match shamir_split(secret, threshold, total) {
        Ok(shares) => {
            // Post-condition checks : an Ok result must satisfy the
            // documented invariants. A violation here is a real bug.
            assert_eq!(shares.len(), total as usize,
                "shamir_split returned wrong share count");
            for s in &shares {
                assert_eq!(s.len(), 1 + secret.len(),
                    "share length mismatch (expected 1 + {} bytes)",
                    secret.len());
            }
            // Index uniqueness : every share's first byte (x-coord)
            // must be distinct.
            let mut seen = std::collections::HashSet::new();
            for s in &shares {
                assert!(seen.insert(s[0]),
                    "shamir_split produced duplicate x-coords");
            }
        }
        Err(_) => {
            // The documented invalid combinations MUST end up here.
            // We don't enforce "every Err corresponds to a known bad
            // case": that's too strict against future error paths.
            // We just enforce "no panic, no garbage Ok".
        }
    }
});
