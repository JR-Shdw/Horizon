// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
//
// Fuzz target : adversarial inputs into shamir_combine().
//
// Strategy : carve the raw fuzz input into a variable number of
// "shares" of variable length, then ask shamir_combine() to
// reconstruct from them. The function MUST :
//   - never panic (no `unwrap` on caller-controlled bytes),
//   - never run unbounded GF(256) loops,
//   - return Err on malformed input rather than miscompute,
//   - free all temporary buffers (zeroize is verified by miri).
//
// Run :
//   cd api/rust && cargo +nightly fuzz run shamir_combine -- -max_total_time=60
//
// Realistic shamir share format in rhorizon : `[x_coord_byte,
// y_byte_0, y_byte_1, ...]` where x_coord is in 1..=254 and the
// y-bytes are 1+secret_len long. Adversarial inputs can :
//   - reuse the same x_coord across two shares (duplicate-index attack)
//   - present shares of mismatched lengths
//   - present zero shares (empty slice list)
//   - present a single share (insufficient for any threshold >= 2)
//   - present 254+ shares (exceeds GF(256) non-zero element count)
//   - inject x_coord = 0 (invalid)

#![no_main]

use libfuzzer_sys::fuzz_target;
use rhorizon_crypto::key_share::fuzz_api::shamir_combine;

fuzz_target!(|data: &[u8]| {
    // Minimum 2 bytes : 1 for n_shares + at least 1 share.
    if data.len() < 4 {
        return;
    }
    // First byte gates how many shares we slice out (cap at 16 so
    // we don't spend the entire fuzz iteration in GF math).
    let n_shares = ((data[0] % 16) as usize).max(1);
    // Second byte gates each share's length (cap at 128 bytes -
    // realistic vault secrets are 96 bytes).
    let share_len = ((data[1] % 128) as usize).max(2);
    let body = &data[2..];

    // Bail out if we don't have enough bytes to carve n_shares of
    // share_len each, short-circuit, not a panic.
    if body.len() < n_shares * share_len {
        return;
    }

    let shares: Vec<&[u8]> = (0..n_shares)
        .map(|i| &body[i * share_len..(i + 1) * share_len])
        .collect();

    // shamir_combine MUST return Result, never panic.
    let _ = shamir_combine(&shares);
});
