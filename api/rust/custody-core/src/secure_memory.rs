// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
//! Locked, zeroizing secret ownership without a Python runtime dependency.
//!
//! Lock lifetime: pages are locked on construction and never munlocked.
//! munlock(2) is page-granular and not reference-counted, so unlocking one
//! dropped buffer could unlock a live neighbor's page. Zeroization on drop is
//! the release mechanism; small freed chunks stay locked for the life of the
//! process (bounded by the peak footprint of secret-bearing allocations),
//! while large chunks are returned by the allocator with munmap(2), which
//! releases their lock in the kernel. Size RLIMIT_MEMLOCK for the peak secret
//! footprint, not the in-flight set.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

use zeroize::Zeroize;

pub const MEMORY_LOCK_MODE_ENV: &str = "RH_MEMORY_LOCK_MODE";
pub const LEGACY_MEMORY_LOCK_MODE_ENV: &str = "RHORIZON_MEMORY_LOCK_MODE";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryLockPolicy {
    BestEffort,
    Required,
}

static MEMORY_LOCK_POLICY: OnceLock<Result<MemoryLockPolicy, String>> = OnceLock::new();
static MEMORY_LOCK_DEGRADED: AtomicBool = AtomicBool::new(false);

pub fn parse_memory_lock_policy(value: Option<&str>) -> Result<MemoryLockPolicy, String> {
    match value
        .unwrap_or("best-effort")
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "best-effort" | "best_effort" => Ok(MemoryLockPolicy::BestEffort),
        "required" => Ok(MemoryLockPolicy::Required),
        value => Err(format!(
            "invalid {MEMORY_LOCK_MODE_ENV}={value:?}; expected best-effort or required"
        )),
    }
}

fn memory_lock_policy() -> Result<MemoryLockPolicy, String> {
    MEMORY_LOCK_POLICY
        .get_or_init(|| {
            let configured = std::env::var(MEMORY_LOCK_MODE_ENV)
                .ok()
                .or_else(|| std::env::var(LEGACY_MEMORY_LOCK_MODE_ENV).ok());
            parse_memory_lock_policy(configured.as_deref())
        })
        .clone()
}

fn apply_memory_lock_result(
    buffer: &mut [u8],
    label: &str,
    policy: MemoryLockPolicy,
    locked: bool,
) -> Result<bool, String> {
    if locked {
        return Ok(true);
    }
    if policy == MemoryLockPolicy::Required {
        buffer.zeroize();
        return Err(format!(
            "Resurgamus Horizon: mlock failed for {label}; grant CAP_IPC_LOCK, raise \
             RLIMIT_MEMLOCK, or set {MEMORY_LOCK_MODE_ENV}=best-effort"
        ));
    }
    MEMORY_LOCK_DEGRADED.store(true, Ordering::Release);
    Ok(false)
}

fn lock_secret_memory(buffer: &mut [u8], label: &str) -> Result<bool, String> {
    if buffer.is_empty() {
        return Ok(false);
    }
    let policy = match memory_lock_policy() {
        Ok(policy) => policy,
        Err(error) => {
            buffer.zeroize();
            return Err(error);
        }
    };
    if cfg!(miri) {
        return Ok(true);
    }
    let locked = unsafe { memsec::mlock(buffer.as_mut_ptr(), buffer.len()) };
    apply_memory_lock_result(buffer, label, policy, locked)
}

pub fn memory_lock_status() -> &'static str {
    if MEMORY_LOCK_DEGRADED.load(Ordering::Acquire) {
        "zeroize-only"
    } else {
        "mlock"
    }
}

/// Rust-owned secret bytes. Slice construction locks zero-filled pages before
/// copying input, so the owned allocation never contains secret data unlocked
/// unless the operator selected best-effort mode and locking is unavailable.
pub struct LockedSecret {
    data: Vec<u8>,
    locked: bool,
}

impl LockedSecret {
    pub fn from_slice(data: &[u8], label: &str) -> Result<Self, String> {
        if data.is_empty() {
            return Ok(Self {
                data: Vec::new(),
                locked: false,
            });
        }
        let mut protected = vec![0u8; data.len()];
        let locked = lock_secret_memory(&mut protected, label)?;
        protected.copy_from_slice(data);
        Ok(Self {
            data: protected,
            locked,
        })
    }

    pub fn from_vec(mut data: Vec<u8>, label: &str) -> Result<Self, String> {
        let locked = lock_secret_memory(&mut data, label)?;
        Ok(Self { data, locked })
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn is_locked(&self) -> bool {
        self.locked
    }

    /// Wipe the bytes in place. The length is preserved: a wiped secret reads
    /// as all-zero bytes, not as an empty buffer.
    pub fn zeroize(&mut self) {
        self.data.as_mut_slice().zeroize();
    }
}

impl Drop for LockedSecret {
    // No munlock on purpose: see the module doc. `Vec::zeroize` also clears
    // the length, so a munlock placed after it would receive length zero and
    // silently unlock nothing.
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_parsing_matches_the_existing_operator_contract() {
        assert_eq!(
            parse_memory_lock_policy(None),
            Ok(MemoryLockPolicy::BestEffort)
        );
        assert_eq!(
            parse_memory_lock_policy(Some("BEST_EFFORT")),
            Ok(MemoryLockPolicy::BestEffort)
        );
        assert_eq!(
            parse_memory_lock_policy(Some("required")),
            Ok(MemoryLockPolicy::Required)
        );
        assert!(parse_memory_lock_policy(Some("disabled")).is_err());
    }

    #[test]
    fn required_lock_failure_wipes_and_best_effort_reports_degradation() {
        let mut required = [0xA5; 16];
        assert!(apply_memory_lock_result(
            &mut required,
            "test secret",
            MemoryLockPolicy::Required,
            false,
        )
        .is_err());
        assert!(required.iter().all(|byte| *byte == 0));

        let mut best_effort = [0x5A; 16];
        assert!(!apply_memory_lock_result(
            &mut best_effort,
            "test secret",
            MemoryLockPolicy::BestEffort,
            false,
        )
        .expect("best effort continues"));
    }

    #[test]
    fn locked_secret_owns_mutable_zeroizing_bytes() {
        let mut secret = LockedSecret::from_slice(b"custody-share", "test custody share")
            .expect("small secret buffer");
        assert_eq!(secret.as_slice(), b"custody-share");
        assert_eq!(secret.len(), 13);
        assert!(!secret.is_empty());
        secret.as_mut_slice()[0] = b'C';
        assert_eq!(secret.as_slice(), b"Custody-share");
        secret.zeroize();
        assert_eq!(secret.len(), 13, "zeroize must preserve the length");
        assert!(secret.as_slice().iter().all(|byte| *byte == 0));

        let empty = LockedSecret::from_vec(Vec::new(), "empty").expect("empty buffer");
        assert!(empty.is_empty());
        assert!(!empty.is_locked());
    }
}
