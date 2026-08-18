// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
//! Portable protocol and quorum invariants shared by Rhorizon custody clients,
//! custodians, and the existing PyO3 compatibility adapter.

#![deny(unsafe_code)]

use std::error::Error;
use std::fmt::{Display, Formatter};

pub mod control;
pub mod gf256;
pub mod operations;
pub mod peer_cred;
pub mod quorum;
pub mod rpc;
pub mod runtime;
#[allow(unsafe_code)]
pub mod secure_memory;
pub mod shamir;
pub mod share_persistence;
pub mod share_store;
pub mod transport;

/// First version of the Rust custodian control protocol.
pub const CUSTODY_PROTOCOL_VERSION: u16 = 1;

/// Existing master RPC frame ceiling. Keeping it here prevents the Rust daemon
/// and the PyO3 compatibility server from drifting to different wire limits.
pub const MAX_RPC_FRAME_BYTES: usize = 3 * 1024 * 1024;

/// Protocol-v1 custody shares contain one GF(256) coordinate followed by the
/// five 32-byte runtime keys (HMAC, DEK, audit, HA wrap, and PKI wrap).
pub const CUSTODY_V1_SHARE_BYTES: usize = 1 + (5 * 32);
pub const CUSTODY_V1_RUNTIME_BUNDLE_BYTES: usize = CUSTODY_V1_SHARE_BYTES - 1;

/// X25519 public and private keys used only for custodian contribution
/// transport. These keys are separate from API control capabilities.
pub const CUSTODY_TRANSPORT_KEY_BYTES: usize = 32;

/// Shamir uses one non-zero GF(256) coordinate per logical custodian slot.
pub const MAX_CUSTODIAN_SLOTS: u8 = u8::MAX;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TopologyError {
    ThresholdTooSmall,
    ThresholdExceedsSlots,
    GenerationZero,
    SlotZero,
    SlotExceedsTopology,
}

impl Display for TopologyError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::ThresholdTooSmall => "custody threshold must be at least 2",
            Self::ThresholdExceedsSlots => "custody threshold exceeds slot count",
            Self::GenerationZero => "custody generation zero is reserved",
            Self::SlotZero => "custody slot zero is reserved",
            Self::SlotExceedsTopology => "custody slot exceeds configured slot count",
        })
    }
}

impl Error for TopologyError {}

/// Fixed logical slots for one Shamir generation. OS processes may be replaced;
/// the topology changes only through an explicit reshare.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CustodyTopology {
    threshold: u8,
    slots: u8,
}

impl CustodyTopology {
    pub fn new(threshold: u8, slots: u8) -> Result<Self, TopologyError> {
        if threshold < 2 {
            return Err(TopologyError::ThresholdTooSmall);
        }
        if threshold > slots {
            return Err(TopologyError::ThresholdExceedsSlots);
        }
        Ok(Self { threshold, slots })
    }

    pub const fn threshold(self) -> u8 {
        self.threshold
    }

    pub const fn slots(self) -> u8 {
        self.slots
    }
}

/// Identity carried by every share-bearing protocol message. Generation and
/// slot validation prevents a quorum from mixing shares across reshares.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CustodyShareId {
    generation: u64,
    slot: u8,
}

impl CustodyShareId {
    pub fn new(
        generation: u64,
        slot: u8,
        topology: CustodyTopology,
    ) -> Result<Self, TopologyError> {
        if generation == 0 {
            return Err(TopologyError::GenerationZero);
        }
        if slot == 0 {
            return Err(TopologyError::SlotZero);
        }
        if slot > topology.slots {
            return Err(TopologyError::SlotExceedsTopology);
        }
        Ok(Self { generation, slot })
    }

    pub const fn generation(self) -> u64 {
        self.generation
    }

    pub const fn slot(self) -> u8 {
        self.slot
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_two_of_three_topology_is_valid() {
        let topology = CustodyTopology::new(2, 3).expect("2-of-3 must be valid");
        assert_eq!(topology.threshold(), 2);
        assert_eq!(topology.slots(), 3);
    }

    #[test]
    fn one_of_n_and_threshold_above_slots_are_rejected() {
        assert_eq!(
            CustodyTopology::new(1, 3),
            Err(TopologyError::ThresholdTooSmall)
        );
        assert_eq!(
            CustodyTopology::new(4, 3),
            Err(TopologyError::ThresholdExceedsSlots)
        );
    }

    #[test]
    fn share_identity_requires_current_nonzero_coordinates() {
        let topology = CustodyTopology::new(2, 3).expect("valid topology");
        assert_eq!(
            CustodyShareId::new(0, 1, topology),
            Err(TopologyError::GenerationZero)
        );
        assert_eq!(
            CustodyShareId::new(1, 0, topology),
            Err(TopologyError::SlotZero)
        );
        assert_eq!(
            CustodyShareId::new(1, 4, topology),
            Err(TopologyError::SlotExceedsTopology)
        );
        assert_eq!(
            CustodyShareId::new(7, 3, topology)
                .expect("valid identity")
                .generation(),
            7
        );
    }
}
