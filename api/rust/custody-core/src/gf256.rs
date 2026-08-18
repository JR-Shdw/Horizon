// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
//
//! Constant-time GF(2^8) arithmetic shared by every custody frontend.
//!
//! ## Provenance
//!
//! Design and algorithms originate in:
//!     geky/gf256 - <https://github.com/geky/gf256>
//!     Copyright C. Haster and contributors
//!     BSD-3-Clause
//!
//! Independently rewritten here and adapted for constant-time operation (see
//! below), then validated against reference arithmetic by exhaustive testing
//! of all 65 536 operand pairs, property tests, fuzzing, and inspection of the
//! compiled output.
//!
//! No code was copied, and re-implementing a published algorithm does not by
//! itself produce a derivative work. The credit is recorded regardless: it
//! documents where the technical choice came from, so an auditor who notices
//! the conceptual resemblance finds the provenance declared rather than
//! unexplained. See NOTICE and source.md.
//!
//! Field: GF(2^8) with reduction polynomial
//!     p(x) = x^8 + x^4 + x^3 + x + 1   = 0x11B
//! (same polynomial as AES Rijndael S-box arithmetic).
//!
//! ## Constant-time intent
//!
//! Replaces the previous table-driven `Gf256Tables` impl (kept in
//! the test module below as the golden reference). Tables expose a
//! cache-timing side channel: the index `LOG_TABLE[a as usize]`
//! depends on a secret byte `a`, leaking information through
//! L1d-cache line evictions to an attacker who can observe timing
//! on the same physical CPU.
//!
//! The implementation here has, by construction :
//!   - no branches on field elements (only fixed-iteration loops),
//!   - no secret-indexed memory access (no `arr[secret as usize]`),
//!   - no early returns on field-element value (only the
//!     `inv(0)` Err path is a control-flow branch on input, and
//!     `0` is unreachable from `shamir_combine` because
//!     `xi ^ xj == 0` would already have been rejected by the
//!     duplicate-index check in `shamir_combine`).
//!
//! Side-channel claims this code does *not* make :
//!   - the compiled assembly is constant-time (LLVM may reshape
//!     branch-free Rust into branched assembly ; mitigated by the
//!     `tools/check-gf-ct.sh` assembly-grep gate in CI),
//!   - microarchitectural channels (branch predictor, port
//!     contention, simultaneous-multithreading siblings) cannot
//!     leak the secret. The deployment model (single-tenant,
//!     VPN-only access, sealed-by-default) is the actual
//!     mitigation against attackers in those threat classes.
//!
//! ## References
//!
//!: D. J. Bernstein, *Cache-timing attacks on AES* (2005).
//!   The canonical paper documenting why GF(2^8) implementations
//!   built on `exp`/`log` tables leak to colocated attackers.
//!   https://cr.yp.to/antiforgery/cachetiming-20050414.pdf
//!
//!: T. Itoh and S. Tsujii, *A fast algorithm for computing
//!   multiplicative inverses in GF(2^m) using normal bases*,
//!   Information and Computation 78(3), 1988.
//!   Square-multiply chain for `inv(a) = a^(2^m, 2)` over GF(2^m).
//!   For m = 8 : `inv(a) = a^254`, computed in 7 squarings and
//!   6 multiplications (no field-element-indexed lookups).
//!
//!: C. Haster (`geky/gf256` v0.3.1, BSD-3-Clause). Used as a
//!   cross-check reference for `mul` and `reduce` during the
//!   2026-05-15 implementation pass. No code copied verbatim ;
//!   our impl is derived directly from the textbook polynomial-ring
//!   definition (clmul + degree-8 reduction).

/// Reduction polynomial : p(x) = x^8 + x^4 + x^3 + x + 1.
/// Stored as a `u16` because its degree (8) requires bit 8 set.
const P: u16 = 0x11B;

/// Carryless multiply on two 8-bit field elements.
///
/// Produces the 16-bit polynomial product `a(x) * b(x)` over
/// GF(2)[x]: i.e. before any reduction by `P`. The implementation
/// is a fixed-bound 8-iteration loop with no early exit and no
/// secret-indexed memory access ; the per-bit selection of
/// `a << i` is folded in via a unconditional mask (a 0/all-ones
/// word derived from one bit of `b`) instead of an `if`.
///
/// ```text
///     bit = (b >> i) & 1       // 0 or 1
///     mask = -bit              // 0x0000 or 0xFFFF (wrapping_neg)
///     r ^= ((a as u16) << i) & mask
/// ```
///
/// LLVM is free in principle to lower this back to a branch ; the
/// `tools/check-gf-ct.sh` CI gate runs `cargo asm` on the release
/// build and fails the pipeline if any conditional jump or `cmov`
/// instruction keyed on the inputs appears in the generated code.
#[inline]
#[doc(hidden)]
pub fn clmul_u8(a: u8, b: u8) -> u16 {
    let mut r: u16 = 0;
    let a16 = a as u16;
    // Fixed-bound `for 0..8` lets LLVM fully unroll the body in
    // release builds, eliminating the loop-counter branch entirely.
    // The asm-gate CI step asserts the unrolled output is
    // branch-free.
    for i in 0..8u32 {
        let bit = ((b >> i) & 1) as u16;
        let mask = 0u16.wrapping_sub(bit);
        r ^= (a16 << i) & mask;
    }
    r
}

/// Reduce a 16-bit polynomial to its 8-bit residue mod `P`.
///
/// Iterates over the 8 high bits of `r` (bits 15 down to 8). For
/// each set bit at position `i`, XOR `P << (i, 8)` into `r`, which
/// clears bit `i`. After 8 iterations all bits above position 7 are
/// zero and the low 8 bits hold `r mod P`.
///
/// Same constant-time pattern as `clmul_u8` : the conditional XOR
/// is implemented via an unconditional AND with a 0/all-ones mask
/// derived from the bit being tested. No early exit, no field-
/// element-indexed memory access.
#[inline]
#[doc(hidden)]
pub fn reduce(r: u16) -> u8 {
    let mut r = r;
    // Fixed-bound `for i in 8..16` (iterated descending via `.rev()`)
    // lets LLVM fully unroll. Direction matters: process high bits
    // first because reducing bit 15 may set bit 14 (when the XOR
    // mask brings new 1s into lower bits), and we want every
    // bit > 7 cleared by the end. Iterating high-to-low ensures
    // each iteration only touches bits we haven't reduced yet.
    for i in (8u32..16).rev() {
        let bit = (r >> i) & 1;
        let mask = 0u16.wrapping_sub(bit);
        r ^= (P << (i - 8)) & mask;
    }
    r as u8
}

/// Multiply two GF(2^8) elements.
#[inline]
pub fn mul(a: u8, b: u8) -> u8 {
    reduce(clmul_u8(a, b))
}

/// Multiplicative inverse in GF(2^8)*.
///
/// Returns `Err` for `a == 0` (zero has no inverse). All other
/// inputs return `a^(-1) = a^254`, computed via a fixed
/// 7-squaring + 6-multiplication chain (Itoh-Tsujii 1988).
/// `254 = 0b11111110`, so :
///
/// ```text
///     a^2     = a * a
///     a^3     = a^2 * a
///     a^6     = a^3 * a^3
///     a^7     = a^6 * a
///     a^14    = a^7 * a^7
///     a^15    = a^14 * a
///     a^30    = a^15 * a^15
///     a^60    = a^30 * a^30
///     a^120   = a^60 * a^60
///     a^126   = a^120 * a^6
///     a^127   = a^126 * a
///     a^254   = a^127 * a^127
/// ```
///
/// The `if a == 0` branch is a control-flow check on input value,
/// not a side channel : valid Shamir reconstruction never invokes
/// `inv(0)` because `shamir_combine` rejects duplicate share x-
/// coordinates before any Lagrange-basis computation. The branch
/// is retained as a defensive assertion ; callers wishing for
/// strict CT in `inv` itself can fail-fast at the share-validation
/// layer instead.
pub fn inv(a: u8) -> Result<u8, &'static str> {
    if a == 0 {
        return Err("Cannot invert zero in GF(256)");
    }
    let a2 = mul(a, a);
    let a3 = mul(a2, a);
    let a6 = mul(a3, a3);
    let a7 = mul(a6, a);
    let a14 = mul(a7, a7);
    let a15 = mul(a14, a);
    let a30 = mul(a15, a15);
    let a60 = mul(a30, a30);
    let a120 = mul(a60, a60);
    let a126 = mul(a120, a6);
    let a127 = mul(a126, a);
    let a254 = mul(a127, a127);
    Ok(a254)
}

// =====================================================================
// Tests: equivalence vs. the previous table-driven impl + invariants.
//
// `Gf256Tables` here is the golden reference : it ships only in the
// test build (#[cfg(test)]), never in the Python wheel or the
// production binary. The equivalence test runs all 65 536 input
// pairs through both `mul` paths and asserts byte-identical output,
// which transitively certifies the new impl against every property
// the previous tests already validated.
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Reference impl : table-driven GF(2^8), polynomial 0x11B,
    /// generator 3. Identical to the previous in-tree `Gf256Tables`
    /// that lived in `key_share.rs` ; preserved here as the golden
    /// equivalence reference for `mul` / `inv`.
    struct RefTables {
        exp: [u8; 512],
        log: [u8; 256],
    }

    impl RefTables {
        fn new() -> Self {
            let mut exp = [0u8; 512];
            let mut log = [0u8; 256];
            let mut x: u16 = 1;
            for (i, slot) in exp[..255].iter_mut().enumerate() {
                *slot = x as u8;
                log[x as usize] = i as u8;
                let mut x2 = x << 1;
                if x2 & 0x100 != 0 {
                    x2 ^= 0x11B;
                }
                x ^= x2;
            }
            for i in 255..512usize {
                exp[i] = exp[i - 255];
            }
            RefTables { exp, log }
        }

        fn mul(&self, a: u8, b: u8) -> u8 {
            if a == 0 || b == 0 {
                return 0;
            }
            self.exp[self.log[a as usize] as usize + self.log[b as usize] as usize]
        }

        fn inv(&self, a: u8) -> Option<u8> {
            if a == 0 {
                return None;
            }
            Some(self.exp[255 - self.log[a as usize] as usize])
        }
    }

    /// Exhaustive equivalence : every (a, b) pair in [0,255] x [0,255].
    /// 65 536 cases, runs in well under a second.
    #[test]
    fn mul_matches_ref_tables_exhaustive() {
        let r = RefTables::new();
        for a in 0u16..=255 {
            for b in 0u16..=255 {
                let a = a as u8;
                let b = b as u8;
                assert_eq!(
                    mul(a, b),
                    r.mul(a, b),
                    "mul mismatch at a={:#04x} b={:#04x}",
                    a,
                    b
                );
            }
        }
    }

    /// Exhaustive inv equivalence over the multiplicative group
    /// GF(2^8)* (every nonzero a).
    #[test]
    fn inv_matches_ref_tables_exhaustive() {
        let r = RefTables::new();
        for a in 1u16..=255 {
            let a = a as u8;
            let lhs = inv(a).expect("nonzero must invert");
            let rhs = r.inv(a).expect("nonzero must invert (ref)");
            assert_eq!(lhs, rhs, "inv mismatch at a={:#04x}", a);
        }
    }

    /// Zero has no inverse.
    #[test]
    fn inv_zero_errors() {
        assert!(inv(0).is_err());
    }

    /// `a * a^(-1) = 1` for every nonzero a.
    #[test]
    fn inv_roundtrip() {
        for a in 1u16..=255 {
            let a = a as u8;
            let ai = inv(a).unwrap();
            assert_eq!(mul(a, ai), 1, "a={:#04x} a^-1={:#04x}", a, ai);
        }
    }

    /// Algebraic invariants : commutativity, identity, annihilator.
    /// Already covered transitively by the exhaustive equivalence,
    /// kept as explicit tests to surface a regression message
    /// pointing at the property that broke.
    #[test]
    fn mul_commutative() {
        for a in 0u16..=255 {
            for b in 0u16..=255 {
                let a = a as u8;
                let b = b as u8;
                assert_eq!(mul(a, b), mul(b, a));
            }
        }
    }

    #[test]
    fn mul_identity_and_annihilator() {
        for a in 0u16..=255 {
            let a = a as u8;
            assert_eq!(mul(a, 1), a, "a * 1 must equal a");
            assert_eq!(mul(1, a), a, "1 * a must equal a");
            assert_eq!(mul(a, 0), 0, "a * 0 must equal 0");
            assert_eq!(mul(0, a), 0, "0 * a must equal 0");
        }
    }

    /// Sanity check : a^255 = 1 for every nonzero a (Fermat in
    /// GF(2^8)*). If this holds we know the multiplicative-group
    /// order is correct and Itoh-Tsujii on `a^254` produces the
    /// inverse by construction.
    #[test]
    fn fermat_order_is_255() {
        for a in 1u16..=255 {
            let a = a as u8;
            // a^255 via square-multiply
            let mut r = a;
            // 255 = 0b11111111, so 8 squarings + 7 multiplications
            r = mul(r, a); // a^2
            let mut acc = a;
            acc = mul(acc, r); // a^3
            r = mul(r, r); // a^4
            acc = mul(acc, r); // a^7
            r = mul(r, r); // a^8
            acc = mul(acc, r); // a^15
            r = mul(r, r); // a^16
            acc = mul(acc, r); // a^31
            r = mul(r, r); // a^32
            acc = mul(acc, r); // a^63
            r = mul(r, r); // a^64
            acc = mul(acc, r); // a^127
            r = mul(r, r); // a^128
            acc = mul(acc, r); // a^255
            assert_eq!(acc, 1, "a^255 must equal 1, a={:#04x}", a);
        }
    }
}

// Property tests co-located with the field. The algebraic laws (identity,
// commutativity, associativity, distributivity, inverse) are exercised in
// key_share.rs against this module ; the props below are the ones NOT covered
// there : the FFI carryless-mul + reduce path, and a direct inverse roundtrip.
//
// Excluded under miri: like every other proptest module in this crate
// (backup_context, master_rpc), proptest's file failure-persistence calls
// std::env::current_dir() (getcwd), which miri forbids under isolation and
// aborts the run. proptest is also far too slow under miri; the GF math is
// safe bit-twiddling (no unsafe for miri to inspect) and is cross-checked
// natively + under the ASAN job.
#[cfg(test)]
#[cfg(not(miri))]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    // Independent reference: Russian-peasant GF(2^8) multiply with the AES
    // reducing polynomial 0x11B (0x1b once the x^8 bit is shifted off). Written
    // deliberately differently from the production `mul` so a table/routine
    // error can't hide behind a shared implementation mistake.
    fn naive_gf_mul(mut a: u8, mut b: u8) -> u8 {
        let mut p: u8 = 0;
        for _ in 0..8 {
            if b & 1 != 0 {
                p ^= a;
            }
            let carry = a & 0x80;
            a <<= 1;
            if carry != 0 {
                a ^= 0x1b;
            }
            b >>= 1;
        }
        p
    }

    proptest! {
        // Cross-implementation check: the production `mul` must equal the naive
        // reference for every input pair. A divergence = a wrong table/routine.
        #[test]
        fn prop_mul_matches_naive_reference(a in any::<u8>(), b in any::<u8>()) {
            prop_assert_eq!(mul(a, b), naive_gf_mul(a, b));
        }

        // inv() is a true multiplicative inverse over the whole non-zero field.
        #[test]
        fn prop_inv_roundtrip(a in 1u8..=255) {
            let ai = inv(a).expect("non-zero has an inverse");
            prop_assert_eq!(mul(a, ai), 1);
            prop_assert_eq!(mul(ai, a), 1);
        }
    }
}
