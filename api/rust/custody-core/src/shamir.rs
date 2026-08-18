// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
//! Shamir splitting and reconstruction over the constant-time GF(256) core.

use zeroize::{Zeroize, Zeroizing};

use crate::gf256;
use crate::secure_memory::LockedSecret;

fn eval_poly(coefficients: &[u8], x: u8) -> u8 {
    let mut result = 0u8;
    for &coefficient in coefficients.iter().rev() {
        result = gf256::mul(result, x) ^ coefficient;
    }
    result
}

/// Split a secret using randomness supplied by the caller. Keeping entropy
/// acquisition outside this crate lets each supported OS and test harness use
/// its established random source without coupling the core to a runtime.
pub fn split_with_fill<F>(
    secret: &[u8],
    threshold: u8,
    total: u8,
    mut fill_random: F,
) -> Result<Vec<Vec<u8>>, String>
where
    F: FnMut(&mut [u8]) -> Result<(), String>,
{
    validate_split_parameters(secret, threshold, total)?;

    let mut shares: Vec<Vec<u8>> = (0..total)
        .map(|index| {
            let mut share = Vec::with_capacity(1 + secret.len());
            share.push(index + 1);
            share
        })
        .collect();

    let mut coefficients = vec![0u8; threshold as usize];
    for &secret_byte in secret {
        coefficients[0] = secret_byte;
        if let Err(error) = fill_random(&mut coefficients[1..]) {
            coefficients.zeroize();
            for share in &mut shares {
                share.zeroize();
            }
            return Err(error);
        }
        for (index, share) in shares.iter_mut().enumerate().take(total as usize) {
            let x = (index as u8) + 1;
            share.push(eval_poly(&coefficients, x));
        }
    }
    coefficients.zeroize();
    Ok(shares)
}

/// Split directly into locked, zeroizing shares. All output and coefficient
/// allocations are locked while still zero-filled, before secret-derived data
/// is written. This is the custodian reshare path; callers never receive an
/// intermediate ordinary share vector.
pub fn split_locked_with_fill<F>(
    secret: &[u8],
    threshold: u8,
    total: u8,
    mut fill_random: F,
) -> Result<Vec<LockedSecret>, String>
where
    F: FnMut(&mut [u8]) -> Result<(), String>,
{
    validate_split_parameters(secret, threshold, total)?;
    let mut shares = Vec::with_capacity(total as usize);
    for index in 0..total {
        let mut share =
            LockedSecret::from_vec(vec![0u8; 1 + secret.len()], "generated custodian reshare")?;
        share.as_mut_slice()[0] = index + 1;
        shares.push(share);
    }
    let mut coefficients = LockedSecret::from_vec(
        vec![0u8; threshold as usize],
        "custodian reshare coefficients",
    )?;
    for (byte_index, &secret_byte) in secret.iter().enumerate() {
        coefficients.as_mut_slice()[0] = secret_byte;
        fill_random(&mut coefficients.as_mut_slice()[1..])?;
        for (index, share) in shares.iter_mut().enumerate() {
            let x = (index as u8) + 1;
            share.as_mut_slice()[byte_index + 1] = eval_poly(coefficients.as_slice(), x);
        }
    }
    Ok(shares)
}

fn validate_split_parameters(secret: &[u8], threshold: u8, total: u8) -> Result<(), String> {
    if threshold < 2 {
        return Err("Threshold must be >= 2".into());
    }
    if total < threshold {
        return Err("Total shares must be >= threshold".into());
    }
    if secret.is_empty() {
        return Err("Secret must be non-empty".into());
    }
    Ok(())
}

pub fn combine(shares: &[&[u8]]) -> Result<Vec<u8>, String> {
    if shares.len() < 2 {
        return Err("Resurgamus Horizon/AGPL-3.0: need at least 2 shares".into());
    }
    if shares.iter().any(|share| share.len() < 2) {
        return Err(
            "Resurgamus Horizon/AGPL-3.0: each share must include x-coordinate and payload".into(),
        );
    }
    let coordinates: Vec<u8> = shares.iter().map(|share| share[0]).collect();
    if coordinates.contains(&0) {
        return Err("Resurgamus Horizon/AGPL-3.0: share index zero is reserved".into());
    }
    let mut unique_coordinates = coordinates.clone();
    unique_coordinates.sort_unstable();
    unique_coordinates.dedup();
    if unique_coordinates.len() != coordinates.len() {
        return Err("Resurgamus Horizon/AGPL-3.0: duplicate share indices".into());
    }
    let secret_len = shares[0].len() - 1;
    if shares.iter().any(|share| share.len() != shares[0].len()) {
        return Err("Shares have different lengths".into());
    }

    let mut result = vec![0u8; secret_len];
    for byte_index in 0..secret_len {
        let values: Zeroizing<Vec<u8>> =
            Zeroizing::new(shares.iter().map(|share| share[byte_index + 1]).collect());
        let mut value = 0u8;
        for (index, (&coordinate, &share_value)) in
            coordinates.iter().zip(values.iter()).enumerate()
        {
            let mut numerator = 1u8;
            let mut denominator = 1u8;
            for (other_index, &other_coordinate) in coordinates.iter().enumerate() {
                if index == other_index {
                    continue;
                }
                numerator = gf256::mul(numerator, other_coordinate);
                denominator = gf256::mul(denominator, coordinate ^ other_coordinate);
            }
            let basis = gf256::mul(numerator, gf256::inv(denominator).map_err(str::to_string)?);
            value ^= gf256::mul(share_value, basis);
        }
        result[byte_index] = value;
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_two_of_three_roundtrip() {
        let mut next = 1u8;
        let shares = split_with_fill(b"master key", 2, 3, |buffer| {
            for byte in buffer {
                *byte = next;
                next = next.wrapping_add(1);
            }
            Ok(())
        })
        .expect("split succeeds");
        let recovered = combine(&[&shares[0], &shares[2]]).expect("quorum combines");
        assert_eq!(recovered, b"master key");
    }

    #[test]
    fn fill_failure_is_returned() {
        let error = split_with_fill(b"secret", 2, 3, |_| Err("entropy unavailable".into()))
            .expect_err("entropy failure must stop the split");
        assert_eq!(error, "entropy unavailable");
    }

    #[test]
    fn locked_split_roundtrips_without_ordinary_share_outputs() {
        let mut next = 1u8;
        let shares = split_locked_with_fill(b"runtime bundle", 2, 3, |buffer| {
            for byte in buffer {
                *byte = next;
                next = next.wrapping_add(1);
            }
            Ok(())
        })
        .expect("locked split succeeds");
        assert!(shares.iter().all(|share| share.len() == 15));
        let recovered =
            combine(&[shares[0].as_slice(), shares[2].as_slice()]).expect("locked quorum combines");
        assert_eq!(recovered, b"runtime bundle");
    }

    #[test]
    fn locked_split_propagates_entropy_failure() {
        let error = split_locked_with_fill(b"runtime bundle", 2, 3, |_| {
            Err("locked entropy unavailable".into())
        })
        .err()
        .expect("entropy failure must stop locked split");
        assert_eq!(error, "locked entropy unavailable");
    }

    #[test]
    fn mixed_lengths_and_duplicate_slots_are_rejected() {
        assert!(combine(&[&[1, 2], &[2, 3, 4]]).is_err());
        assert!(combine(&[&[1, 2], &[1, 3]]).is_err());
    }
}
