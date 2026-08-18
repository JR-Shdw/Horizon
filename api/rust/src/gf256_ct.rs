// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
//! Compatibility shim for the GF(256) implementation now owned by the
//! PyO3-free custody core.

#[cfg(any(test, feature = "asm-gate"))]
pub use rhorizon_custody_core::gf256::{inv, mul};

// These stable symbols remain in the extension crate because the existing
// assembly gate reads rhorizon_crypto's emitted assembly. Production builds do
// not enable this feature.
#[cfg(feature = "asm-gate")]
#[no_mangle]
pub extern "C" fn rhorizon_gf256_ct_mul(a: u8, b: u8) -> u8 {
    mul(a, b)
}

#[cfg(feature = "asm-gate")]
#[no_mangle]
pub extern "C" fn rhorizon_gf256_ct_clmul(a: u8, b: u8) -> u16 {
    rhorizon_custody_core::gf256::clmul_u8(a, b)
}

#[cfg(feature = "asm-gate")]
#[no_mangle]
pub extern "C" fn rhorizon_gf256_ct_reduce(value: u16) -> u8 {
    rhorizon_custody_core::gf256::reduce(value)
}
