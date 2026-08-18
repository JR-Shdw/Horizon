// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
//! Generation-safe collection and reconstruction of authenticated shares.

use zeroize::Zeroize;

use crate::secure_memory::LockedSecret;
use crate::shamir;
use crate::{
    CustodyShareId, CustodyTopology, CUSTODY_V1_RUNTIME_BUNDLE_BYTES, CUSTODY_V1_SHARE_BYTES,
};

struct ShareContribution {
    identity: CustodyShareId,
    bytes: LockedSecret,
}

/// Collects contributions whose transport has already authenticated the
/// sending custodian. Consuming reconstruction ensures the collected locked
/// copies cannot be reused accidentally across unseal attempts.
pub struct QuorumCollector {
    topology: CustodyTopology,
    generation: u64,
    contributions: Vec<ShareContribution>,
}

impl QuorumCollector {
    pub fn new(topology: CustodyTopology, generation: u64) -> Result<Self, String> {
        if generation == 0 {
            return Err("custody generation zero is reserved".to_string());
        }
        Ok(Self {
            topology,
            generation,
            contributions: Vec::with_capacity(topology.threshold() as usize),
        })
    }

    pub fn add(
        &mut self,
        topology: CustodyTopology,
        identity: CustodyShareId,
        bytes: LockedSecret,
    ) -> Result<usize, String> {
        if topology != self.topology {
            return Err("quorum contribution topology mismatch".to_string());
        }
        if identity.generation() != self.generation {
            return Err("quorum contribution generation mismatch".to_string());
        }
        if bytes.len() != CUSTODY_V1_SHARE_BYTES {
            return Err(format!(
                "quorum contribution must be exactly {CUSTODY_V1_SHARE_BYTES} bytes"
            ));
        }
        if bytes.as_slice()[0] != identity.slot() {
            return Err("quorum contribution coordinate mismatch".to_string());
        }
        if self
            .contributions
            .iter()
            .any(|contribution| contribution.identity.slot() == identity.slot())
        {
            return Err("duplicate quorum contribution slot".to_string());
        }
        self.contributions
            .push(ShareContribution { identity, bytes });
        Ok(self.contributions.len())
    }

    pub fn len(&self) -> usize {
        self.contributions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.contributions.is_empty()
    }

    pub fn is_ready(&self) -> bool {
        self.contributions.len() >= self.topology.threshold() as usize
    }

    pub fn reconstruct(self) -> Result<LockedSecret, String> {
        if !self.is_ready() {
            return Err(format!(
                "custody quorum requires {} shares, got {}",
                self.topology.threshold(),
                self.contributions.len()
            ));
        }
        let share_slices: Vec<&[u8]> = self
            .contributions
            .iter()
            .map(|contribution| contribution.bytes.as_slice())
            .collect();
        let mut bundle = shamir::combine(&share_slices)?;
        if bundle.len() != CUSTODY_V1_RUNTIME_BUNDLE_BYTES {
            bundle.zeroize();
            return Err("reconstructed runtime bundle has invalid size".to_string());
        }
        LockedSecret::from_vec(bundle, "reconstructed custody runtime bundle")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn topology() -> CustodyTopology {
        CustodyTopology::new(2, 3).expect("valid topology")
    }

    fn shares() -> Vec<Vec<u8>> {
        let secret: Vec<u8> = (0..CUSTODY_V1_RUNTIME_BUNDLE_BYTES)
            .map(|index| index as u8)
            .collect();
        let mut next = 1u8;
        shamir::split_with_fill(&secret, 2, 3, |buffer| {
            for byte in buffer {
                *byte = next;
                next = next.wrapping_add(1);
            }
            Ok(())
        })
        .expect("split runtime bundle")
    }

    fn locked(bytes: &[u8]) -> LockedSecret {
        LockedSecret::from_slice(bytes, "test quorum contribution").expect("lock contribution")
    }

    #[test]
    fn matching_two_of_three_reconstructs_into_locked_memory() {
        let topology = topology();
        let shares = shares();
        let mut collector = QuorumCollector::new(topology, 7).expect("collector");
        assert!(collector.is_empty());
        assert_eq!(
            collector.add(
                topology,
                CustodyShareId::new(7, 1, topology).expect("identity"),
                locked(&shares[0]),
            ),
            Ok(1)
        );
        assert!(!collector.is_ready());
        assert_eq!(
            collector.add(
                topology,
                CustodyShareId::new(7, 3, topology).expect("identity"),
                locked(&shares[2]),
            ),
            Ok(2)
        );
        assert!(collector.is_ready());
        let bundle = collector.reconstruct().expect("reconstruct quorum");
        let expected: Vec<u8> = (0..CUSTODY_V1_RUNTIME_BUNDLE_BYTES)
            .map(|index| index as u8)
            .collect();
        assert_eq!(bundle.as_slice(), expected);
    }

    #[test]
    fn mixed_generation_topology_coordinate_and_duplicates_fail() {
        let topology = topology();
        let shares = shares();
        let mut collector = QuorumCollector::new(topology, 7).expect("collector");
        let identity = CustodyShareId::new(7, 1, topology).expect("identity");
        collector
            .add(topology, identity, locked(&shares[0]))
            .expect("first contribution");
        assert!(collector
            .add(topology, identity, locked(&shares[0]))
            .is_err());
        assert!(collector
            .add(
                topology,
                CustodyShareId::new(8, 2, topology).expect("identity"),
                locked(&shares[1]),
            )
            .is_err());
        let other_topology = CustodyTopology::new(2, 5).expect("topology");
        assert!(collector
            .add(
                other_topology,
                CustodyShareId::new(7, 2, other_topology).expect("identity"),
                locked(&shares[1]),
            )
            .is_err());
        let mut wrong_coordinate = shares[1].clone();
        wrong_coordinate[0] = 3;
        assert!(collector
            .add(
                topology,
                CustodyShareId::new(7, 2, topology).expect("identity"),
                locked(&wrong_coordinate),
            )
            .is_err());
    }

    #[test]
    fn incomplete_quorum_cannot_reconstruct() {
        let topology = topology();
        let shares = shares();
        let mut collector = QuorumCollector::new(topology, 3).expect("collector");
        collector
            .add(
                topology,
                CustodyShareId::new(3, 1, topology).expect("identity"),
                locked(&shares[0]),
            )
            .expect("first contribution");
        assert!(collector.reconstruct().is_err());
    }
}
