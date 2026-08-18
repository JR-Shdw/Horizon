// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
//! Fixed-slot, generation-bound ownership of one locked Shamir share.

use std::sync::Mutex;

use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::secure_memory::LockedSecret;
use crate::{CustodyShareId, CustodyTopology};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShareInstallOutcome {
    Installed,
    AlreadyInstalled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SharePrepareOutcome {
    Prepared,
    AlreadyPrepared,
    AlreadyCommitted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShareCommitOutcome {
    Committed,
    AlreadyCommitted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShareRollbackOutcome {
    RolledBack,
    AlreadyRolledBack,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShareFinalizeOutcome {
    Finalized,
    AlreadyFinalized,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShareGenerationIdentities {
    active: Option<CustodyShareId>,
    prepared: Option<CustodyShareId>,
    previous: Option<CustodyShareId>,
}

impl ShareGenerationIdentities {
    pub const fn active(self) -> Option<CustodyShareId> {
        self.active
    }

    pub const fn prepared(self) -> Option<CustodyShareId> {
        self.prepared
    }

    pub const fn previous(self) -> Option<CustodyShareId> {
        self.previous
    }
}

pub(crate) struct InstalledShare {
    pub(crate) identity: CustodyShareId,
    pub(crate) bytes: LockedSecret,
}

pub struct ShareSlotState {
    pub(crate) topology: CustodyTopology,
    pub(crate) slot: u8,
    pub(crate) share_bytes: usize,
    pub(crate) active: Option<InstalledShare>,
    pub(crate) prepared: Option<InstalledShare>,
    pub(crate) previous: Option<InstalledShare>,
}

#[derive(Default)]
struct ShareGenerations {
    active: Option<InstalledShare>,
    prepared: Option<InstalledShare>,
    previous: Option<InstalledShare>,
}

/// One daemon owns one fixed logical coordinate. A normal install can restore
/// an empty process or repeat the identical current generation; changing the
/// generation uses prepare/commit/finalize. Commit retains the previous share
/// so a database-coordinated recovery can roll backward or forward after a
/// controller crash.
pub struct CustodyShareSlot {
    topology: CustodyTopology,
    slot: u8,
    share_bytes: usize,
    generations: Mutex<ShareGenerations>,
}

impl CustodyShareSlot {
    pub fn new(topology: CustodyTopology, slot: u8, share_bytes: usize) -> Result<Self, String> {
        CustodyShareId::new(1, slot, topology).map_err(|error| error.to_string())?;
        if share_bytes < 2 {
            return Err("custody share size must include coordinate and payload".to_string());
        }
        Ok(Self {
            topology,
            slot,
            share_bytes,
            generations: Mutex::new(ShareGenerations::default()),
        })
    }

    fn validate_candidate(
        &self,
        topology: CustodyTopology,
        identity: CustodyShareId,
        share: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, String> {
        let candidate = Zeroizing::new(share.to_vec());
        if topology != self.topology {
            return Err("share topology does not match custodian topology".to_string());
        }
        if identity.slot() != self.slot {
            return Err("share identity does not match custodian slot".to_string());
        }
        if candidate.len() != self.share_bytes {
            return Err(format!("share must be exactly {} bytes", self.share_bytes));
        }
        if candidate[0] != self.slot {
            return Err("share coordinate does not match custodian slot".to_string());
        }
        Ok(candidate)
    }

    fn matches(installed: &InstalledShare, identity: CustodyShareId, candidate: &[u8]) -> bool {
        installed.identity == identity && bool::from(candidate.ct_eq(installed.bytes.as_slice()))
    }

    pub fn install(
        &self,
        topology: CustodyTopology,
        identity: CustodyShareId,
        share: &[u8],
    ) -> Result<ShareInstallOutcome, String> {
        self.install_inner(topology, identity, share, false)
    }

    /// Install a share that crossed an operator's topology change.
    ///
    /// A topology change is delivered by direct install rather than by
    /// prepare/commit/finalize: the slots of the target shape did not exist in
    /// the shape that produced the envelopes, so there is no transaction for
    /// them to join. That works on an empty slot, which was the whole of the
    /// original design -- a restart under a new shape could reload no old
    /// share. It stopped being the whole of it once persisted state was named
    /// after its topology, because a pool RETURNING to a shape it has run
    /// before now reloads that shape's superseded share and the plain install
    /// path rightly refuses to overwrite an active generation.
    ///
    /// Replacing it is safe precisely because it is superseded. A delivery
    /// only ever lands on a shape the pool is NOT currently running: the
    /// control plane aborts the transition when the launched shape is the live
    /// one, so the live generation is persisted under a different topology's
    /// file and is never what this replaces. Everything else the plain path
    /// refuses is still refused -- an in-flight transaction, a stale
    /// generation, a conflicting share for the current one -- and the replaced
    /// secret is zeroized on drop.
    pub fn install_topology_change(
        &self,
        topology: CustodyTopology,
        identity: CustodyShareId,
        share: &[u8],
    ) -> Result<ShareInstallOutcome, String> {
        self.install_inner(topology, identity, share, true)
    }

    fn install_inner(
        &self,
        topology: CustodyTopology,
        identity: CustodyShareId,
        share: &[u8],
        replace_superseded: bool,
    ) -> Result<ShareInstallOutcome, String> {
        let candidate = self.validate_candidate(topology, identity, share)?;

        let mut generations = self
            .generations
            .lock()
            .map_err(|error| format!("custody share slot lock poisoned: {error}"))?;
        if generations.prepared.is_some() || generations.previous.is_some() {
            return Err("custody share transaction is already in progress".to_string());
        }
        if let Some(installed) = generations.active.as_ref() {
            if identity.generation() < installed.identity.generation() {
                return Err("stale custody share generation".to_string());
            }
            if identity.generation() > installed.identity.generation() {
                if !replace_superseded {
                    return Err("new custody generation requires transactional reshare".to_string());
                }
            } else {
                return if Self::matches(installed, identity, &candidate) {
                    Ok(ShareInstallOutcome::AlreadyInstalled)
                } else {
                    Err("conflicting share for current custody generation".to_string())
                };
            }
        }

        let bytes = LockedSecret::from_slice(&candidate, "custodian Shamir share")?;
        generations.active = Some(InstalledShare { identity, bytes });
        Ok(ShareInstallOutcome::Installed)
    }

    pub fn prepare(
        &self,
        topology: CustodyTopology,
        identity: CustodyShareId,
        share: &[u8],
    ) -> Result<SharePrepareOutcome, String> {
        let candidate = self.validate_candidate(topology, identity, share)?;
        let mut generations = self
            .generations
            .lock()
            .map_err(|error| format!("custody share slot lock poisoned: {error}"))?;

        if let Some(active) = generations.active.as_ref() {
            if identity.generation() < active.identity.generation() {
                return Err("stale custody share generation".to_string());
            }
            if identity.generation() == active.identity.generation() {
                return if Self::matches(active, identity, &candidate) {
                    Ok(SharePrepareOutcome::AlreadyCommitted)
                } else {
                    Err("conflicting share for active custody generation".to_string())
                };
            }
        }
        if generations.previous.is_some() {
            return Err("previous custody generation is not finalized".to_string());
        }
        if let Some(prepared) = generations.prepared.as_ref() {
            return if Self::matches(prepared, identity, &candidate) {
                Ok(SharePrepareOutcome::AlreadyPrepared)
            } else if prepared.identity.generation() == identity.generation() {
                Err("conflicting share for prepared custody generation".to_string())
            } else {
                Err("another custody generation is already prepared".to_string())
            };
        }

        let bytes = LockedSecret::from_slice(&candidate, "prepared custodian Shamir share")?;
        generations.prepared = Some(InstalledShare { identity, bytes });
        Ok(SharePrepareOutcome::Prepared)
    }

    pub fn commit(&self, generation: u64) -> Result<ShareCommitOutcome, String> {
        if generation == 0 {
            return Err("custody generation zero is reserved".to_string());
        }
        let mut generations = self
            .generations
            .lock()
            .map_err(|error| format!("custody share slot lock poisoned: {error}"))?;
        if generations
            .active
            .as_ref()
            .is_some_and(|share| share.identity.generation() == generation)
            && generations.prepared.is_none()
        {
            return Ok(ShareCommitOutcome::AlreadyCommitted);
        }
        let prepared_generation = generations
            .prepared
            .as_ref()
            .map(|share| share.identity.generation())
            .ok_or_else(|| "custody share generation is not prepared".to_string())?;
        if prepared_generation != generation {
            return Err("prepared custody share generation does not match commit".to_string());
        }
        if generations.previous.is_some() {
            return Err("previous custody generation is not finalized".to_string());
        }
        let prepared = generations
            .prepared
            .take()
            .ok_or_else(|| "custody share generation is not prepared".to_string())?;
        generations.previous = generations.active.take();
        generations.active = Some(prepared);
        Ok(ShareCommitOutcome::Committed)
    }

    pub fn rollback(&self, generation: u64) -> Result<ShareRollbackOutcome, String> {
        if generation == 0 {
            return Err("custody generation zero is reserved".to_string());
        }
        let mut generations = self
            .generations
            .lock()
            .map_err(|error| format!("custody share slot lock poisoned: {error}"))?;
        if generations
            .prepared
            .as_ref()
            .is_some_and(|share| share.identity.generation() == generation)
        {
            generations.prepared = None;
            return Ok(ShareRollbackOutcome::RolledBack);
        }
        if generations
            .active
            .as_ref()
            .is_some_and(|share| share.identity.generation() == generation)
        {
            let previous = generations
                .previous
                .take()
                .ok_or_else(|| "committed custody generation has no rollback share".to_string())?;
            generations.active = Some(previous);
            return Ok(ShareRollbackOutcome::RolledBack);
        }
        if generations.previous.is_none() && generations.prepared.is_none() {
            return match generations
                .active
                .as_ref()
                .map(|share| share.identity.generation())
            {
                Some(active) if active > generation => {
                    Err("stale custody share generation rollback".to_string())
                }
                _ => Ok(ShareRollbackOutcome::AlreadyRolledBack),
            };
        }
        Err("custody share generation does not match rollback".to_string())
    }

    pub fn finalize(&self, generation: u64) -> Result<ShareFinalizeOutcome, String> {
        if generation == 0 {
            return Err("custody generation zero is reserved".to_string());
        }
        let mut generations = self
            .generations
            .lock()
            .map_err(|error| format!("custody share slot lock poisoned: {error}"))?;
        if generations
            .active
            .as_ref()
            .map(|share| share.identity.generation())
            != Some(generation)
        {
            return Err("active custody share generation does not match finalize".to_string());
        }
        if generations.prepared.is_some() {
            return Err("prepared custody generation cannot be finalized".to_string());
        }
        if generations.previous.take().is_some() {
            Ok(ShareFinalizeOutcome::Finalized)
        } else {
            Ok(ShareFinalizeOutcome::AlreadyFinalized)
        }
    }

    pub const fn topology(&self) -> CustodyTopology {
        self.topology
    }

    pub const fn slot(&self) -> u8 {
        self.slot
    }

    pub fn identity(&self) -> Result<Option<CustodyShareId>, String> {
        Ok(self
            .generations
            .lock()
            .map_err(|error| format!("custody share slot lock poisoned: {error}"))?
            .active
            .as_ref()
            .map(|share| share.identity))
    }

    pub fn identities(&self) -> Result<ShareGenerationIdentities, String> {
        let generations = self
            .generations
            .lock()
            .map_err(|error| format!("custody share slot lock poisoned: {error}"))?;
        Ok(ShareGenerationIdentities {
            active: generations.active.as_ref().map(|share| share.identity),
            prepared: generations.prepared.as_ref().map(|share| share.identity),
            previous: generations.previous.as_ref().map(|share| share.identity),
        })
    }

    pub fn snapshot(&self) -> Result<Option<(CustodyShareId, LockedSecret)>, String> {
        let generations = self
            .generations
            .lock()
            .map_err(|error| format!("custody share slot lock poisoned: {error}"))?;
        generations
            .active
            .as_ref()
            .map(|share| {
                LockedSecret::from_slice(share.bytes.as_slice(), "custodian share snapshot")
                    .map(|bytes| (share.identity, bytes))
            })
            .transpose()
    }

    pub fn snapshot_generation(
        &self,
        generation: u64,
    ) -> Result<Option<(CustodyShareId, LockedSecret)>, String> {
        let generations = self
            .generations
            .lock()
            .map_err(|error| format!("custody share slot lock poisoned: {error}"))?;
        generations
            .active
            .iter()
            .chain(generations.prepared.iter())
            .chain(generations.previous.iter())
            .find(|share| share.identity.generation() == generation)
            .map(|share| {
                LockedSecret::from_slice(share.bytes.as_slice(), "custodian share snapshot")
                    .map(|bytes| (share.identity, bytes))
            })
            .transpose()
    }

    pub fn snapshot_state(&self) -> Result<ShareSlotState, String> {
        let generations = self
            .generations
            .lock()
            .map_err(|error| format!("custody share slot lock poisoned: {error}"))?;
        let copy = |share: &InstalledShare, label: &str| {
            LockedSecret::from_slice(share.bytes.as_slice(), label).map(|bytes| InstalledShare {
                identity: share.identity,
                bytes,
            })
        };
        Ok(ShareSlotState {
            topology: self.topology,
            slot: self.slot,
            share_bytes: self.share_bytes,
            active: generations
                .active
                .as_ref()
                .map(|share| copy(share, "active custodian share state"))
                .transpose()?,
            prepared: generations
                .prepared
                .as_ref()
                .map(|share| copy(share, "prepared custodian share state"))
                .transpose()?,
            previous: generations
                .previous
                .as_ref()
                .map(|share| copy(share, "previous custodian share state"))
                .transpose()?,
        })
    }

    pub fn restore_state(&self, state: ShareSlotState) -> Result<(), String> {
        if state.topology != self.topology
            || state.slot != self.slot
            || state.share_bytes != self.share_bytes
        {
            return Err("persisted share state does not match custodian configuration".to_string());
        }
        let validate = |share: &InstalledShare| {
            if share.identity.slot() != self.slot {
                return Err("persisted share identity does not match custodian slot".to_string());
            }
            if share.bytes.as_slice().len() != self.share_bytes {
                return Err("persisted share has invalid size".to_string());
            }
            if share.bytes.as_slice()[0] != self.slot {
                return Err("persisted share coordinate does not match custodian slot".to_string());
            }
            Ok(())
        };
        for share in state
            .active
            .iter()
            .chain(state.prepared.iter())
            .chain(state.previous.iter())
        {
            validate(share)?;
        }
        if state.prepared.is_some() && state.previous.is_some() {
            return Err(
                "persisted share state contains incompatible transaction phases".to_string(),
            );
        }
        if let (Some(active), Some(prepared)) = (&state.active, &state.prepared) {
            if prepared.identity.generation() <= active.identity.generation() {
                return Err("prepared share generation must follow active generation".to_string());
            }
        }
        if let (Some(active), Some(previous)) = (&state.active, &state.previous) {
            if active.identity.generation() <= previous.identity.generation() {
                return Err("active share generation must follow previous generation".to_string());
            }
        }
        if state.previous.is_some() && state.active.is_none() {
            return Err("previous share generation requires an active generation".to_string());
        }
        let mut generations = self
            .generations
            .lock()
            .map_err(|error| format!("custody share slot lock poisoned: {error}"))?;
        *generations = ShareGenerations {
            active: state.active,
            prepared: state.prepared,
            previous: state.previous,
        };
        Ok(())
    }

    pub fn clear(&self) -> Result<(), String> {
        let mut generations = self
            .generations
            .lock()
            .map_err(|error| format!("custody share slot lock poisoned: {error}"))?;
        *generations = ShareGenerations::default();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn topology() -> CustodyTopology {
        CustodyTopology::new(2, 3).expect("valid topology")
    }

    #[test]
    fn fixed_slot_accepts_only_its_coordinate_and_topology() {
        let topology = topology();
        let slot = CustodyShareSlot::new(topology, 2, 3).expect("valid slot");
        let identity = CustodyShareId::new(7, 2, topology).expect("valid identity");
        assert_eq!(
            slot.install(topology, identity, &[2, 0xAA, 0xBB]),
            Ok(ShareInstallOutcome::Installed)
        );
        assert_eq!(slot.identity().expect("slot lock"), Some(identity));

        let wrong_identity = CustodyShareId::new(7, 1, topology).expect("valid identity");
        assert!(slot
            .install(topology, wrong_identity, &[1, 0xAA, 0xBB])
            .is_err());
        assert!(slot.install(topology, identity, &[1, 0xAA, 0xBB]).is_err());
        assert!(slot.install(topology, identity, &[2, 0xAA]).is_err());
        let other_topology = CustodyTopology::new(2, 5).expect("valid topology");
        let other_identity = CustodyShareId::new(7, 2, other_topology).expect("valid identity");
        assert!(slot
            .install(other_topology, other_identity, &[2, 0xAA, 0xBB])
            .is_err());
    }

    #[test]
    fn repeat_is_idempotent_but_conflict_and_generation_change_fail() {
        let topology = topology();
        let slot = CustodyShareSlot::new(topology, 1, 3).expect("valid slot");
        let current = CustodyShareId::new(9, 1, topology).expect("valid identity");
        slot.install(topology, current, &[1, 2, 3])
            .expect("initial install");
        assert_eq!(
            slot.install(topology, current, &[1, 2, 3]),
            Ok(ShareInstallOutcome::AlreadyInstalled)
        );
        assert!(slot.install(topology, current, &[1, 2, 4]).is_err());

        let stale = CustodyShareId::new(8, 1, topology).expect("valid identity");
        let future = CustodyShareId::new(10, 1, topology).expect("valid identity");
        assert!(slot.install(topology, stale, &[1, 2, 3]).is_err());
        assert!(slot.install(topology, future, &[1, 2, 3]).is_err());
    }

    #[test]
    fn topology_change_replaces_a_superseded_share_the_plain_path_refuses() {
        let topology = topology();
        let slot = CustodyShareSlot::new(topology, 1, 3).expect("valid slot");
        let superseded = CustodyShareId::new(4, 1, topology).expect("valid identity");
        let delivered = CustodyShareId::new(9, 1, topology).expect("valid identity");
        slot.install(topology, superseded, &[1, 2, 3])
            .expect("initial install");

        // The exact wedge this exists for: a pool returning to a shape it has
        // run before reloads that shape's old share, and the plain path stops
        // the delivery dead.
        assert_eq!(
            slot.install(topology, delivered, &[1, 7, 7]),
            Err("new custody generation requires transactional reshare".to_string())
        );

        assert_eq!(
            slot.install_topology_change(topology, delivered, &[1, 7, 7]),
            Ok(ShareInstallOutcome::Installed)
        );
        assert_eq!(slot.identity().expect("slot lock"), Some(delivered));
        assert_eq!(
            slot.snapshot()
                .expect("slot lock")
                .expect("share")
                .1
                .as_slice(),
            &[1, 7, 7]
        );
    }

    #[test]
    fn topology_change_still_refuses_stale_conflicting_and_in_flight_shares() {
        let topology = topology();
        let slot = CustodyShareSlot::new(topology, 1, 3).expect("valid slot");
        let current = CustodyShareId::new(9, 1, topology).expect("valid identity");
        slot.install(topology, current, &[1, 2, 3])
            .expect("initial install");

        let stale = CustodyShareId::new(8, 1, topology).expect("valid identity");
        assert_eq!(
            slot.install_topology_change(topology, stale, &[1, 2, 3]),
            Err("stale custody share generation".to_string())
        );
        // Same generation is not a replacement decision at all: identical is
        // idempotent, different is a conflict, exactly as the plain path.
        assert_eq!(
            slot.install_topology_change(topology, current, &[1, 2, 3]),
            Ok(ShareInstallOutcome::AlreadyInstalled)
        );
        assert_eq!(
            slot.install_topology_change(topology, current, &[1, 2, 4]),
            Err("conflicting share for current custody generation".to_string())
        );

        let prepared = CustodyShareId::new(10, 1, topology).expect("valid identity");
        slot.prepare(topology, prepared, &[1, 4, 5])
            .expect("prepare a transactional reshare");
        let delivered = CustodyShareId::new(11, 1, topology).expect("valid identity");
        assert_eq!(
            slot.install_topology_change(topology, delivered, &[1, 6, 6]),
            Err("custody share transaction is already in progress".to_string())
        );
    }

    #[test]
    fn snapshot_is_a_locked_copy_and_clear_drops_the_generation() {
        let topology = topology();
        let slot = CustodyShareSlot::new(topology, 3, 3).expect("valid slot");
        let identity = CustodyShareId::new(4, 3, topology).expect("valid identity");
        slot.install(topology, identity, &[3, 4, 5])
            .expect("initial install");
        let (snapshot_identity, snapshot) = slot
            .snapshot()
            .expect("slot lock")
            .expect("installed share");
        assert_eq!(snapshot_identity, identity);
        assert_eq!(snapshot.as_slice(), &[3, 4, 5]);
        slot.clear().expect("clear slot");
        assert_eq!(slot.identity().expect("slot lock"), None);
        assert_eq!(snapshot.as_slice(), &[3, 4, 5]);
    }

    #[test]
    fn reshare_prepare_is_idempotent_and_rejects_conflicts() {
        let topology = topology();
        let slot = CustodyShareSlot::new(topology, 1, 3).expect("valid slot");
        let old = CustodyShareId::new(4, 1, topology).expect("valid identity");
        let new = CustodyShareId::new(5, 1, topology).expect("valid identity");
        slot.install(topology, old, &[1, 2, 3])
            .expect("initial install");

        assert_eq!(
            slot.prepare(topology, new, &[1, 7, 8]),
            Ok(SharePrepareOutcome::Prepared)
        );
        assert_eq!(
            slot.prepare(topology, new, &[1, 7, 8]),
            Ok(SharePrepareOutcome::AlreadyPrepared)
        );
        assert!(slot.prepare(topology, new, &[1, 7, 9]).is_err());
        let another = CustodyShareId::new(6, 1, topology).expect("valid identity");
        assert!(slot.prepare(topology, another, &[1, 9, 9]).is_err());

        let (old_id, old_copy) = slot
            .snapshot_generation(4)
            .expect("slot lock")
            .expect("old generation");
        let (new_id, new_copy) = slot
            .snapshot_generation(5)
            .expect("slot lock")
            .expect("prepared generation");
        assert_eq!((old_id, old_copy.as_slice()), (old, &[1, 2, 3][..]));
        assert_eq!((new_id, new_copy.as_slice()), (new, &[1, 7, 8][..]));
        assert_eq!(slot.identity().expect("slot lock"), Some(old));
    }

    #[test]
    fn committed_reshare_can_roll_back_to_previous_generation() {
        let topology = topology();
        let slot = CustodyShareSlot::new(topology, 2, 3).expect("valid slot");
        let old = CustodyShareId::new(10, 2, topology).expect("valid identity");
        let new = CustodyShareId::new(11, 2, topology).expect("valid identity");
        slot.install(topology, old, &[2, 3, 4])
            .expect("initial install");
        slot.prepare(topology, new, &[2, 8, 9])
            .expect("prepare generation");

        assert_eq!(slot.commit(11), Ok(ShareCommitOutcome::Committed));
        assert_eq!(slot.identity().expect("slot lock"), Some(new));
        assert!(slot.snapshot_generation(10).expect("slot lock").is_some());
        assert!(slot.snapshot_generation(11).expect("slot lock").is_some());
        assert_eq!(slot.commit(11), Ok(ShareCommitOutcome::AlreadyCommitted));

        assert_eq!(slot.rollback(11), Ok(ShareRollbackOutcome::RolledBack));
        assert_eq!(slot.identity().expect("slot lock"), Some(old));
        assert!(slot.snapshot_generation(11).expect("slot lock").is_none());
        assert_eq!(
            slot.rollback(11),
            Ok(ShareRollbackOutcome::AlreadyRolledBack)
        );
    }

    #[test]
    fn finalized_reshare_drops_old_generation_and_blocks_rollback() {
        let topology = topology();
        let slot = CustodyShareSlot::new(topology, 3, 3).expect("valid slot");
        let old = CustodyShareId::new(20, 3, topology).expect("valid identity");
        let new = CustodyShareId::new(21, 3, topology).expect("valid identity");
        slot.install(topology, old, &[3, 4, 5])
            .expect("initial install");
        slot.prepare(topology, new, &[3, 8, 9])
            .expect("prepare generation");
        slot.commit(21).expect("commit generation");

        assert_eq!(slot.finalize(21), Ok(ShareFinalizeOutcome::Finalized));
        assert!(slot.snapshot_generation(20).expect("slot lock").is_none());
        assert_eq!(
            slot.finalize(21),
            Ok(ShareFinalizeOutcome::AlreadyFinalized)
        );
        assert!(slot.rollback(21).is_err());
        assert_eq!(
            slot.prepare(topology, new, &[3, 8, 9]),
            Ok(SharePrepareOutcome::AlreadyCommitted)
        );
    }

    #[test]
    fn prepared_generation_can_be_aborted_without_changing_active_share() {
        let topology = topology();
        let slot = CustodyShareSlot::new(topology, 1, 3).expect("valid slot");
        let old = CustodyShareId::new(30, 1, topology).expect("valid identity");
        let new = CustodyShareId::new(31, 1, topology).expect("valid identity");
        slot.install(topology, old, &[1, 2, 3])
            .expect("initial install");
        slot.prepare(topology, new, &[1, 6, 7])
            .expect("prepare generation");

        assert_eq!(slot.rollback(31), Ok(ShareRollbackOutcome::RolledBack));
        assert_eq!(slot.identity().expect("slot lock"), Some(old));
        assert!(slot.snapshot_generation(31).expect("slot lock").is_none());
        assert!(slot.commit(31).is_err());
    }
}
