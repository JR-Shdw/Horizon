// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
//! Compatibility-safe custody control operations shared by both servers.

use std::sync::Mutex;

use serde_json::Value;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::secure_memory::LockedSecret;

pub const MIN_CONTROL_CAPABILITY_BYTES: usize = 32;
pub const MAX_CONTROL_CAPABILITY_BYTES: usize = 256;

/// File-backed capability required by state-changing custodian requests.
/// The value stays in a locked, wiping allocation and comparisons are
/// constant-time for correctly sized candidates.
pub struct ControlCapability(LockedSecret);

impl ControlCapability {
    pub fn new(value: &[u8]) -> Result<Self, String> {
        if !(MIN_CONTROL_CAPABILITY_BYTES..=MAX_CONTROL_CAPABILITY_BYTES).contains(&value.len()) {
            return Err(format!(
                "control capability must contain {MIN_CONTROL_CAPABILITY_BYTES}..{MAX_CONTROL_CAPABILITY_BYTES} bytes"
            ));
        }
        LockedSecret::from_slice(value, "custodian control capability").map(Self)
    }

    pub fn authorizes(&self, candidate: Option<&str>) -> bool {
        let Some(candidate) = candidate else {
            return false;
        };
        candidate.as_bytes().ct_eq(self.0.as_slice()).into()
    }
}

/// A replaceable wrapped-secret slot. Replaced and dropped buffers are wiped;
/// callers receive wiping snapshots so a request never borrows across a lock.
pub struct WrappedSecretSlot {
    label: &'static str,
    value: Mutex<Option<Vec<u8>>>,
}

impl WrappedSecretSlot {
    pub const fn empty(label: &'static str) -> Self {
        Self {
            label,
            value: Mutex::new(None),
        }
    }

    pub fn replace_from_slice(&self, value: Option<&[u8]>) -> Result<(), String> {
        self.replace(value.map(<[u8]>::to_vec))
    }

    pub fn replace(&self, mut replacement: Option<Vec<u8>>) -> Result<(), String> {
        let mut slot = match self.value.lock() {
            Ok(slot) => slot,
            Err(error) => {
                if let Some(value) = replacement.as_mut() {
                    value.zeroize();
                }
                return Err(format!("{} lock poisoned: {error}", self.label));
            }
        };
        if let Some(value) = slot.as_mut() {
            value.zeroize();
        }
        *slot = replacement;
        Ok(())
    }

    pub fn clear(&self) -> Result<(), String> {
        self.replace(None)
    }

    pub fn is_loaded(&self) -> Result<bool, String> {
        Ok(self
            .value
            .lock()
            .map_err(|error| format!("{} lock poisoned: {error}", self.label))?
            .is_some())
    }

    pub fn snapshot(&self, missing_label: &str) -> Result<Zeroizing<Vec<u8>>, String> {
        let slot = self
            .value
            .lock()
            .map_err(|error| format!("{} lock poisoned: {error}", self.label))?;
        slot.as_ref()
            .map(|value| Zeroizing::new(value.clone()))
            .ok_or_else(|| format!("{missing_label} not loaded"))
    }
}

impl Drop for WrappedSecretSlot {
    fn drop(&mut self) {
        let slot = self
            .value
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(value) = slot.as_mut() {
            value.zeroize();
        }
    }
}

/// Dispatch operations backed by the shared wrapped HA-password slot.
/// `None` means the caller owns the operation. String results intentionally
/// preserve the existing Python master-RPC wire contract.
pub fn dispatch_compatibility_control(
    sealed: bool,
    ha_password: &WrappedSecretSlot,
    operation: &str,
) -> Option<Result<Value, String>> {
    match operation {
        "has_ha_password" => Some(if sealed {
            Err("vault sealed".to_string())
        } else {
            ha_password
                .is_loaded()
                .map(|loaded| Value::String(if loaded { "1" } else { "0" }.to_string()))
        }),
        "clear_ha_password" => Some(if sealed {
            Err("vault sealed".to_string())
        } else {
            ha_password.clear().map(|()| Value::String(String::new()))
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::dispatch_request;
    use serde_json::json;

    #[test]
    fn control_capability_enforces_length_and_exact_match() {
        assert!(ControlCapability::new(&[b'x'; MIN_CONTROL_CAPABILITY_BYTES - 1]).is_err());
        assert!(ControlCapability::new(&[b'x'; MAX_CONTROL_CAPABILITY_BYTES + 1]).is_err());

        let capability =
            ControlCapability::new(b"0123456789abcdef0123456789abcdef").expect("valid capability");
        assert!(capability.authorizes(Some("0123456789abcdef0123456789abcdef")));
        assert!(!capability.authorizes(Some("0123456789abcdef0123456789abcdeg")));
        assert!(!capability.authorizes(Some("short")));
        assert!(!capability.authorizes(None));
    }

    #[test]
    fn wrapped_slot_replaces_clears_and_returns_wiping_snapshots() {
        let slot = WrappedSecretSlot::empty("ha_password_enc");
        assert!(!slot.is_loaded().expect("slot lock"));
        assert_eq!(
            slot.snapshot("ha_password").unwrap_err(),
            "ha_password not loaded"
        );

        slot.replace_from_slice(Some(b"first")).expect("set slot");
        let snapshot = slot.snapshot("ha_password").expect("loaded slot");
        assert_eq!(snapshot.as_slice(), b"first");
        slot.replace(Some(b"second".to_vec()))
            .expect("replace slot");
        assert_eq!(snapshot.as_slice(), b"first");
        assert_eq!(
            slot.snapshot("ha_password")
                .expect("replacement")
                .as_slice(),
            b"second"
        );

        slot.clear().expect("clear slot");
        assert!(!slot.is_loaded().expect("slot lock"));
    }

    #[test]
    fn ha_password_status_preserves_legacy_result_and_seal_latch() {
        let slot = WrappedSecretSlot::empty("ha_password_enc");
        assert_eq!(
            dispatch_compatibility_control(false, &slot, "has_ha_password"),
            Some(Ok(Value::String("0".to_string())))
        );
        slot.replace_from_slice(Some(b"wrapped"))
            .expect("load slot");
        assert_eq!(
            dispatch_compatibility_control(false, &slot, "has_ha_password"),
            Some(Ok(Value::String("1".to_string())))
        );
        assert_eq!(
            dispatch_compatibility_control(true, &slot, "has_ha_password"),
            Some(Err("vault sealed".to_string()))
        );
        assert_eq!(
            dispatch_compatibility_control(false, &slot, "encrypt"),
            None
        );
    }

    #[test]
    fn clear_ha_password_is_shared_idempotent_and_fail_closed() {
        let slot = WrappedSecretSlot::empty("ha_password_enc");
        slot.replace_from_slice(Some(b"wrapped"))
            .expect("load slot");
        assert_eq!(
            dispatch_compatibility_control(true, &slot, "clear_ha_password"),
            Some(Err("vault sealed".to_string()))
        );
        assert!(slot.is_loaded().expect("sealed clear left slot intact"));
        assert_eq!(
            dispatch_compatibility_control(false, &slot, "clear_ha_password"),
            Some(Ok(Value::String(String::new())))
        );
        assert!(!slot.is_loaded().expect("slot cleared"));
        assert_eq!(
            dispatch_compatibility_control(false, &slot, "clear_ha_password"),
            Some(Ok(Value::String(String::new())))
        );
    }

    #[test]
    fn ha_password_status_has_exact_legacy_wire_bytes() {
        let slot = WrappedSecretSlot::empty("ha_password_enc");
        slot.replace_from_slice(Some(b"wrapped"))
            .expect("load slot");
        let response = dispatch_request(json!({"op": "has_ha_password"}), |operation, _| {
            dispatch_compatibility_control(false, &slot, operation).expect("shared operation")
        });
        assert_eq!(response.to_bytes().as_slice(), br#"{"result":"1"}"#);
    }
}
