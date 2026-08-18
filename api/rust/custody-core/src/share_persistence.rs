// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
//! Encrypted, fixed-size persistence for one custodian's transactional shares.

use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::secure_memory::LockedSecret;
use crate::share_store::{InstalledShare, ShareSlotState};
use crate::transport::TransportPrivateKey;
use crate::{CustodyShareId, CustodyTopology, CUSTODY_PROTOCOL_VERSION, CUSTODY_V1_SHARE_BYTES};

const FILE_MAGIC: &[u8; 4] = b"RHSS";
const FILE_VERSION: u16 = 1;
const STATE_MAGIC: &[u8; 4] = b"RHSP";
const NONCE_BYTES: usize = 24;
const TAG_BYTES: usize = 16;
const HEADER_BYTES: usize = 4 + 2 + 1 + 1 + 1 + 1;
const ENTRY_BYTES: usize = 8 + CUSTODY_V1_SHARE_BYTES;
const PLAINTEXT_BYTES: usize = HEADER_BYTES + (3 * ENTRY_BYTES);
pub const SHARE_STATE_FILE_BYTES: usize = 4 + 2 + NONCE_BYTES + PLAINTEXT_BYTES + TAG_BYTES;

fn storage_key(
    transport_key: &TransportPrivateKey,
    topology: CustodyTopology,
    slot: u8,
) -> Result<LockedSecret, String> {
    let hkdf = Hkdf::<Sha256>::new(
        Some(b"rhorizon/custody/share-state/v1"),
        transport_key.secret_bytes(),
    );
    let mut key = LockedSecret::from_vec(vec![0u8; 32], "custodian share-state key")?;
    let context = [
        topology.threshold(),
        topology.slots(),
        slot,
        CUSTODY_PROTOCOL_VERSION.to_be_bytes()[0],
        CUSTODY_PROTOCOL_VERSION.to_be_bytes()[1],
    ];
    hkdf.expand(&context, key.as_mut_slice())
        .map_err(|_| "could not derive custodian share-state key".to_string())?;
    Ok(key)
}

fn encode_entry(output: &mut [u8], entry: Option<&InstalledShare>) {
    if let Some(entry) = entry {
        output[..8].copy_from_slice(&entry.identity.generation().to_be_bytes());
        output[8..].copy_from_slice(entry.bytes.as_slice());
    }
}

pub fn seal_share_state(
    transport_key: &TransportPrivateKey,
    state: &ShareSlotState,
) -> Result<Zeroizing<Vec<u8>>, String> {
    if state.share_bytes != CUSTODY_V1_SHARE_BYTES {
        return Err("unsupported persisted custody share size".to_string());
    }
    let mut flags = 0u8;
    flags |= u8::from(state.active.is_some());
    flags |= u8::from(state.prepared.is_some()) << 1;
    flags |= u8::from(state.previous.is_some()) << 2;
    let mut plaintext = LockedSecret::from_vec(
        vec![0u8; PLAINTEXT_BYTES],
        "serialized custodian share state",
    )?;
    plaintext.as_mut_slice()[..4].copy_from_slice(STATE_MAGIC);
    plaintext.as_mut_slice()[4..6].copy_from_slice(&CUSTODY_PROTOCOL_VERSION.to_be_bytes());
    plaintext.as_mut_slice()[6] = state.topology.threshold();
    plaintext.as_mut_slice()[7] = state.topology.slots();
    plaintext.as_mut_slice()[8] = state.slot;
    plaintext.as_mut_slice()[9] = flags;
    for (index, entry) in [
        state.active.as_ref(),
        state.prepared.as_ref(),
        state.previous.as_ref(),
    ]
    .into_iter()
    .enumerate()
    {
        let start = HEADER_BYTES + (index * ENTRY_BYTES);
        encode_entry(
            &mut plaintext.as_mut_slice()[start..start + ENTRY_BYTES],
            entry,
        );
    }

    let key = storage_key(transport_key, state.topology, state.slot)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_slice())
        .map_err(|_| "could not initialize custodian share-state cipher".to_string())?;
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_slice())
        .map_err(|_| "could not encrypt custodian share state".to_string())?;
    let mut envelope = Zeroizing::new(Vec::with_capacity(SHARE_STATE_FILE_BYTES));
    envelope.extend_from_slice(FILE_MAGIC);
    envelope.extend_from_slice(&FILE_VERSION.to_be_bytes());
    envelope.extend_from_slice(&nonce);
    envelope.extend_from_slice(&ciphertext);
    if envelope.len() != SHARE_STATE_FILE_BYTES {
        return Err("custodian share-state envelope has invalid size".to_string());
    }
    Ok(envelope)
}

fn decode_entry(
    input: &[u8],
    present: bool,
    topology: CustodyTopology,
    slot: u8,
    label: &str,
) -> Result<Option<InstalledShare>, String> {
    if !present {
        if input.iter().any(|byte| *byte != 0) {
            return Err("absent persisted share entry contains data".to_string());
        }
        return Ok(None);
    }
    let generation = u64::from_be_bytes(
        input[..8]
            .try_into()
            .map_err(|_| "persisted share generation is truncated".to_string())?,
    );
    let identity = CustodyShareId::new(generation, slot, topology)
        .map_err(|error| format!("invalid persisted share identity: {error}"))?;
    let bytes = LockedSecret::from_slice(&input[8..], label)?;
    Ok(Some(InstalledShare { identity, bytes }))
}

pub fn open_share_state(
    transport_key: &TransportPrivateKey,
    expected_topology: CustodyTopology,
    expected_slot: u8,
    envelope: &[u8],
) -> Result<ShareSlotState, String> {
    CustodyShareId::new(1, expected_slot, expected_topology).map_err(|error| error.to_string())?;
    if envelope.len() != SHARE_STATE_FILE_BYTES {
        return Err(format!(
            "custodian share-state file must be exactly {SHARE_STATE_FILE_BYTES} bytes"
        ));
    }
    if &envelope[..4] != FILE_MAGIC || envelope[4..6] != FILE_VERSION.to_be_bytes() {
        return Err("unsupported custodian share-state file format".to_string());
    }
    let key = storage_key(transport_key, expected_topology, expected_slot)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_slice())
        .map_err(|_| "could not initialize custodian share-state cipher".to_string())?;
    let nonce = XNonce::from_slice(&envelope[6..6 + NONCE_BYTES]);
    let plaintext = cipher
        .decrypt(nonce, &envelope[6 + NONCE_BYTES..])
        .map_err(|_| "custodian share-state authentication failed".to_string())?;
    let plaintext = LockedSecret::from_vec(plaintext, "decrypted custodian share state")?;
    let plaintext_bytes = plaintext.as_slice();
    if plaintext_bytes.len() != PLAINTEXT_BYTES
        || &plaintext_bytes[..4] != STATE_MAGIC
        || plaintext_bytes[4..6] != CUSTODY_PROTOCOL_VERSION.to_be_bytes()
    {
        return Err("invalid custodian share-state plaintext".to_string());
    }
    let topology = CustodyTopology::new(plaintext_bytes[6], plaintext_bytes[7])
        .map_err(|error| format!("invalid persisted topology: {error}"))?;
    let slot = plaintext_bytes[8];
    if topology != expected_topology || slot != expected_slot {
        return Err("persisted share state does not match custodian configuration".to_string());
    }
    let flags = plaintext_bytes[9];
    if flags & !0b111 != 0 {
        return Err("persisted share state contains unknown flags".to_string());
    }
    let entry = |index: usize, present: bool, label: &str| {
        let start = HEADER_BYTES + (index * ENTRY_BYTES);
        decode_entry(
            &plaintext_bytes[start..start + ENTRY_BYTES],
            present,
            topology,
            slot,
            label,
        )
    };
    Ok(ShareSlotState {
        topology,
        slot,
        share_bytes: CUSTODY_V1_SHARE_BYTES,
        active: entry(0, flags & 1 != 0, "persisted active custodian share")?,
        prepared: entry(1, flags & 2 != 0, "persisted prepared custodian share")?,
        previous: entry(2, flags & 4 != 0, "persisted previous custodian share")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::share_store::CustodyShareSlot;

    fn key(byte: u8) -> TransportPrivateKey {
        TransportPrivateKey::from_slice(&[byte; 32]).expect("test transport key")
    }

    #[test]
    fn encrypted_state_roundtrips_every_transaction_phase() {
        let topology = CustodyTopology::new(2, 3).expect("topology");
        let slot = CustodyShareSlot::new(topology, 2, CUSTODY_V1_SHARE_BYTES).expect("slot");
        let mut old = vec![0x11; CUSTODY_V1_SHARE_BYTES];
        old[0] = 2;
        let mut new = vec![0x22; CUSTODY_V1_SHARE_BYTES];
        new[0] = 2;
        slot.install(
            topology,
            CustodyShareId::new(7, 2, topology).expect("identity"),
            &old,
        )
        .expect("install");
        slot.prepare(
            topology,
            CustodyShareId::new(8, 2, topology).expect("identity"),
            &new,
        )
        .expect("prepare");
        slot.commit(8).expect("commit");

        let envelope = seal_share_state(&key(0x42), &slot.snapshot_state().expect("snapshot"))
            .expect("seal state");
        assert_eq!(envelope.len(), SHARE_STATE_FILE_BYTES);
        assert!(!envelope.windows(old.len()).any(|window| window == old));
        let restored = CustodyShareSlot::new(topology, 2, CUSTODY_V1_SHARE_BYTES).expect("slot");
        restored
            .restore_state(
                open_share_state(&key(0x42), topology, 2, &envelope).expect("open state"),
            )
            .expect("restore state");
        let identities = restored.identities().expect("identities");
        assert_eq!(identities.active().map(CustodyShareId::generation), Some(8));
        assert_eq!(
            identities.previous().map(CustodyShareId::generation),
            Some(7)
        );
        assert_eq!(identities.prepared(), None);
    }

    #[test]
    fn tamper_wrong_key_and_wrong_slot_fail_closed() {
        let topology = CustodyTopology::new(2, 3).expect("topology");
        let slot = CustodyShareSlot::new(topology, 1, CUSTODY_V1_SHARE_BYTES).expect("slot");
        let mut envelope = seal_share_state(&key(0x31), &slot.snapshot_state().expect("snapshot"))
            .expect("seal state");
        assert!(open_share_state(&key(0x32), topology, 1, &envelope).is_err());
        assert!(open_share_state(&key(0x31), topology, 2, &envelope).is_err());
        let last = envelope.len() - 1;
        envelope[last] ^= 1;
        assert!(open_share_state(&key(0x31), topology, 1, &envelope).is_err());
    }
}
