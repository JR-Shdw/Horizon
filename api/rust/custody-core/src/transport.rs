// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
//! Authenticated and encrypted share contributions between fixed custodians.

use crypto_box::aead::{Aead, AeadCore, OsRng};
use crypto_box::{ChaChaBox, PublicKey, SecretKey};
use curve25519_dalek::MontgomeryPoint;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::secure_memory::LockedSecret;
use crate::{
    CustodyShareId, CustodyTopology, CUSTODY_PROTOCOL_VERSION, CUSTODY_TRANSPORT_KEY_BYTES,
    CUSTODY_V1_SHARE_BYTES,
};

const TRANSPORT_MAGIC: &[u8; 4] = b"RHCQ";
const RESHARE_MAGIC: &[u8; 4] = b"RHRS";
const TOPOLOGY_RESHARE_MAGIC: &[u8; 4] = b"RHTR";
const NONCE_BYTES: usize = 24;
const TAG_BYTES: usize = 16;
const CLEAR_HEADER_BYTES: usize = 1;
const SEALED_HEADER_BYTES: usize = 4 + 2 + 1 + 1 + 8 + 1 + 1;
pub const CUSTODY_SHARE_ENVELOPE_BYTES: usize =
    CLEAR_HEADER_BYTES + NONCE_BYTES + SEALED_HEADER_BYTES + CUSTODY_V1_SHARE_BYTES + TAG_BYTES;
pub const CUSTODY_RESHARE_ENVELOPE_BYTES: usize = CUSTODY_SHARE_ENVELOPE_BYTES;
pub const CUSTODY_TOPOLOGY_RESHARE_ENVELOPE_BYTES: usize = CUSTODY_SHARE_ENVELOPE_BYTES;

/// A public key assigned to one fixed custodian slot by trusted bootstrap
/// configuration. It is safe to copy and expose.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransportPublicKey([u8; CUSTODY_TRANSPORT_KEY_BYTES]);

impl TransportPublicKey {
    pub fn from_bytes(bytes: [u8; CUSTODY_TRANSPORT_KEY_BYTES]) -> Result<Self, String> {
        // X25519 low-order points produce an all-zero shared secret for every
        // clamped scalar. Reject them before a key can enter the peer allowlist.
        let probe = MontgomeryPoint(bytes).mul_clamped([0x42; CUSTODY_TRANSPORT_KEY_BYTES]);
        if bool::from(probe.as_bytes().ct_eq(&[0u8; CUSTODY_TRANSPORT_KEY_BYTES])) {
            return Err("custodian transport public key has low order".to_string());
        }
        Ok(Self(bytes))
    }

    pub const fn as_bytes(&self) -> &[u8; CUSTODY_TRANSPORT_KEY_BYTES] {
        &self.0
    }
}

/// Locked ownership of one custodian's X25519 private transport key.
pub struct TransportPrivateKey(LockedSecret);

impl TransportPrivateKey {
    pub fn from_slice(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != CUSTODY_TRANSPORT_KEY_BYTES {
            return Err(format!(
                "custodian transport private key must be exactly {CUSTODY_TRANSPORT_KEY_BYTES} bytes"
            ));
        }
        if bool::from(bytes.ct_eq(&[0u8; CUSTODY_TRANSPORT_KEY_BYTES])) {
            return Err("custodian transport private key must not be all zero".to_string());
        }
        LockedSecret::from_slice(bytes, "custodian transport private key").map(Self)
    }

    pub fn public_key(&self) -> TransportPublicKey {
        let secret = transient_secret_key(&self.0);
        // A public key derived from a clamped private key cannot be low order.
        TransportPublicKey(*secret.public_key().as_bytes())
    }

    pub(crate) fn secret_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}

/// Complete bootstrap-time binding from every remote logical slot to its
/// transport public key. Contribution functions accept this set instead of a
/// caller-supplied key, so an API request cannot redirect a share to an
/// arbitrary recipient key.
pub struct TransportPeerSet {
    topology: CustodyTopology,
    local_slot: u8,
    peers: Vec<(u8, TransportPublicKey)>,
}

impl TransportPeerSet {
    pub fn new(
        topology: CustodyTopology,
        local_slot: u8,
        peers: &[(u8, TransportPublicKey)],
    ) -> Result<Self, String> {
        CustodyShareId::new(1, local_slot, topology).map_err(|error| error.to_string())?;
        let expected = topology.slots() as usize - 1;
        if peers.len() != expected {
            return Err(format!(
                "custodian transport peer set requires {expected} remote slots"
            ));
        }
        let mut accepted = Vec::with_capacity(expected);
        for &(slot, key) in peers {
            CustodyShareId::new(1, slot, topology).map_err(|error| error.to_string())?;
            if slot == local_slot {
                return Err("custodian transport peer set contains the local slot".to_string());
            }
            if accepted
                .iter()
                .any(|(accepted_slot, _)| *accepted_slot == slot)
            {
                return Err("duplicate custodian transport peer slot".to_string());
            }
            if accepted
                .iter()
                .any(|(_, accepted_key)| *accepted_key == key)
            {
                return Err("duplicate custodian transport peer public key".to_string());
            }
            accepted.push((slot, key));
        }
        Ok(Self {
            topology,
            local_slot,
            peers: accepted,
        })
    }

    pub const fn topology(&self) -> CustodyTopology {
        self.topology
    }

    pub const fn local_slot(&self) -> u8 {
        self.local_slot
    }

    fn peer(&self, slot: u8) -> Result<TransportPublicKey, String> {
        self.peers
            .iter()
            .find_map(|(peer_slot, key)| (*peer_slot == slot).then_some(*key))
            .ok_or_else(|| "custodian transport peer slot is not allowlisted".to_string())
    }
}

/// The complete recipient map of one topology-changing reshare, expressed in
/// the TARGET topology.
///
/// It includes the coordinator's own slot, unlike `TransportPeerSet`. A
/// coordinator cannot install a target-topology share into its launch-topology
/// slot -- the fixed slot binds its launch topology and refuses anything else
/// -- so its own new share must travel as an opaque envelope across the
/// operator restart exactly like every other slot's.
///
/// Every slot that exists in both the launch and the target topology keeps its
/// launch transport key. Only a slot the target ADDS may introduce a new key,
/// so a caller can widen or narrow the pool but can never re-point a surviving
/// custodian at a key of its own choosing.
pub struct ReshareTargetPeers {
    topology: CustodyTopology,
    local_slot: u8,
    recipients: Vec<(u8, TransportPublicKey)>,
}

impl ReshareTargetPeers {
    pub fn new(
        current: &TransportPeerSet,
        local_key: &TransportPrivateKey,
        topology: CustodyTopology,
        recipients: &[(u8, TransportPublicKey)],
    ) -> Result<Self, String> {
        if topology == current.topology() {
            return Err("topology reshare target must differ from the launch topology".to_string());
        }
        let local_slot = current.local_slot();
        // A coordinator outside the target topology could not be authenticated
        // by any recipient, because its slot would not be in their peer set.
        CustodyShareId::new(1, local_slot, topology).map_err(|_| {
            "topology reshare coordinator must keep a slot in the target topology".to_string()
        })?;
        let expected = topology.slots() as usize;
        if recipients.len() != expected {
            return Err(format!(
                "topology reshare target requires all {expected} slots"
            ));
        }
        let local_public = local_key.public_key();
        let mut accepted: Vec<(u8, TransportPublicKey)> = Vec::with_capacity(expected);
        for &(slot, key) in recipients {
            CustodyShareId::new(1, slot, topology).map_err(|error| error.to_string())?;
            if accepted.iter().any(|(taken, _)| *taken == slot) {
                return Err("duplicate topology reshare target slot".to_string());
            }
            if accepted.iter().any(|(_, taken)| *taken == key) {
                return Err("duplicate topology reshare target public key".to_string());
            }
            if slot == local_slot {
                if key != local_public {
                    return Err(
                        "topology reshare target must keep the coordinator's transport key"
                            .to_string(),
                    );
                }
            } else if let Ok(existing) = current.peer(slot) {
                if key != existing {
                    return Err(
                        "topology reshare target must keep a surviving slot's transport key"
                            .to_string(),
                    );
                }
            }
            accepted.push((slot, key));
        }
        Ok(Self {
            topology,
            local_slot,
            recipients: accepted,
        })
    }

    pub const fn topology(&self) -> CustodyTopology {
        self.topology
    }

    pub const fn local_slot(&self) -> u8 {
        self.local_slot
    }

    pub fn recipient_slots(&self) -> impl Iterator<Item = u8> + '_ {
        self.recipients.iter().map(|(slot, _)| *slot)
    }

    fn recipient(&self, slot: u8) -> Result<TransportPublicKey, String> {
        self.recipients
            .iter()
            .find_map(|(target_slot, key)| (*target_slot == slot).then_some(*key))
            .ok_or_else(|| "topology reshare recipient slot is not a target slot".to_string())
    }
}

/// Encrypt a fixed-generation share for one allowlisted recipient. The
/// transport key authenticates the sending custodian independently of the API
/// control capability. The clear sender slot only selects an allowlisted key;
/// the same slot is authenticated inside the ciphertext.
pub fn seal_share_contribution(
    sender_key: &TransportPrivateKey,
    peers: &TransportPeerSet,
    identity: CustodyShareId,
    recipient_slot: u8,
    share: &LockedSecret,
) -> Result<Zeroizing<Vec<u8>>, String> {
    let topology = peers.topology();
    if identity.slot() != peers.local_slot() {
        return Err("custodian transport identity does not match local slot".to_string());
    }
    validate_route(topology, identity, recipient_slot, share.as_slice())?;
    let recipient_key = peers.peer(recipient_slot)?;

    let mut plaintext = Zeroizing::new(Vec::with_capacity(
        SEALED_HEADER_BYTES + CUSTODY_V1_SHARE_BYTES,
    ));
    plaintext.extend_from_slice(TRANSPORT_MAGIC);
    plaintext.extend_from_slice(&CUSTODY_PROTOCOL_VERSION.to_be_bytes());
    plaintext.push(topology.threshold());
    plaintext.push(topology.slots());
    plaintext.extend_from_slice(&identity.generation().to_be_bytes());
    plaintext.push(identity.slot());
    plaintext.push(recipient_slot);
    plaintext.extend_from_slice(share.as_slice());

    let sender_secret = transient_secret_key(&sender_key.0);
    let cipher = ChaChaBox::new(&PublicKey::from(*recipient_key.as_bytes()), &sender_secret);
    let nonce = ChaChaBox::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_slice())
        .map_err(|_| "could not encrypt custody share contribution".to_string())?;

    let mut envelope = Zeroizing::new(Vec::with_capacity(CUSTODY_SHARE_ENVELOPE_BYTES));
    envelope.push(identity.slot());
    envelope.extend_from_slice(&nonce);
    envelope.extend_from_slice(&ciphertext);
    if envelope.len() != CUSTODY_SHARE_ENVELOPE_BYTES {
        return Err("custody share envelope has invalid size".to_string());
    }
    Ok(envelope)
}

/// Authenticate and decrypt a contribution. The clear sender-slot hint selects
/// a public key only from the bootstrap allowlist; the authenticated copy inside
/// the ciphertext must match it.
pub fn open_share_contribution(
    recipient_key: &TransportPrivateKey,
    peers: &TransportPeerSet,
    generation: u64,
    envelope: &[u8],
) -> Result<(CustodyShareId, LockedSecret), String> {
    let topology = peers.topology();
    let recipient_slot = peers.local_slot();
    if envelope.len() != CUSTODY_SHARE_ENVELOPE_BYTES {
        return Err(format!(
            "custody share envelope must be exactly {CUSTODY_SHARE_ENVELOPE_BYTES} bytes"
        ));
    }
    let expected_sender_slot = envelope[0];
    let recipient_identity = CustodyShareId::new(generation, recipient_slot, topology)
        .map_err(|error| error.to_string())?;
    let sender_identity = CustodyShareId::new(generation, expected_sender_slot, topology)
        .map_err(|error| error.to_string())?;
    if recipient_identity.slot() == sender_identity.slot() {
        return Err("custodian contribution sender and recipient must differ".to_string());
    }
    let expected_sender_key = peers.peer(expected_sender_slot)?;

    let nonce = crypto_box::Nonce::from_slice(&envelope[1..1 + NONCE_BYTES]);
    let recipient_secret = transient_secret_key(&recipient_key.0);
    let cipher = ChaChaBox::new(
        &PublicKey::from(*expected_sender_key.as_bytes()),
        &recipient_secret,
    );
    let plaintext = cipher
        .decrypt(nonce, &envelope[1 + NONCE_BYTES..])
        .map(Zeroizing::new)
        .map_err(|_| "custody share contribution authentication failed".to_string())?;

    if plaintext.len() != SEALED_HEADER_BYTES + CUSTODY_V1_SHARE_BYTES
        || &plaintext[0..4] != TRANSPORT_MAGIC
        || u16::from_be_bytes([plaintext[4], plaintext[5]]) != CUSTODY_PROTOCOL_VERSION
        || plaintext[6] != topology.threshold()
        || plaintext[7] != topology.slots()
        || u64::from_be_bytes(
            plaintext[8..16]
                .try_into()
                .map_err(|_| "custody share envelope metadata is truncated".to_string())?,
        ) != generation
        || plaintext[16] != expected_sender_slot
        || plaintext[17] != recipient_slot
    {
        return Err("custody share contribution metadata mismatch".to_string());
    }

    let share = &plaintext[SEALED_HEADER_BYTES..];
    validate_route(topology, sender_identity, recipient_slot, share)?;
    let share = LockedSecret::from_slice(share, "authenticated custodian contribution")?;
    Ok((sender_identity, share))
}

/// Encrypt a newly generated share for its coordinate-matched custodian. The
/// unsealed coordinator is the authenticated sender, but the share coordinate
/// belongs to the recipient. A distinct magic value prevents a reshare
/// delivery from being accepted as an ordinary quorum contribution.
pub fn seal_reshare_delivery(
    sender_key: &TransportPrivateKey,
    peers: &TransportPeerSet,
    generation: u64,
    recipient_slot: u8,
    share: &LockedSecret,
) -> Result<Zeroizing<Vec<u8>>, String> {
    let topology = peers.topology();
    let sender_slot = peers.local_slot();
    let sender_identity = CustodyShareId::new(generation, sender_slot, topology)
        .map_err(|error| error.to_string())?;
    let recipient_identity = CustodyShareId::new(generation, recipient_slot, topology)
        .map_err(|error| error.to_string())?;
    if sender_identity.slot() == recipient_identity.slot() {
        return Err("reshare sender and recipient must differ".to_string());
    }
    validate_reshare_recipient(recipient_identity, share.as_slice())?;
    let recipient_key = peers.peer(recipient_slot)?;

    let mut plaintext = Zeroizing::new(Vec::with_capacity(
        SEALED_HEADER_BYTES + CUSTODY_V1_SHARE_BYTES,
    ));
    plaintext.extend_from_slice(RESHARE_MAGIC);
    plaintext.extend_from_slice(&CUSTODY_PROTOCOL_VERSION.to_be_bytes());
    plaintext.push(topology.threshold());
    plaintext.push(topology.slots());
    plaintext.extend_from_slice(&generation.to_be_bytes());
    plaintext.push(sender_slot);
    plaintext.push(recipient_slot);
    plaintext.extend_from_slice(share.as_slice());

    let sender_secret = transient_secret_key(&sender_key.0);
    let cipher = ChaChaBox::new(&PublicKey::from(*recipient_key.as_bytes()), &sender_secret);
    let nonce = ChaChaBox::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_slice())
        .map_err(|_| "could not encrypt custody reshare delivery".to_string())?;
    let mut envelope = Zeroizing::new(Vec::with_capacity(CUSTODY_RESHARE_ENVELOPE_BYTES));
    envelope.push(sender_slot);
    envelope.extend_from_slice(&nonce);
    envelope.extend_from_slice(&ciphertext);
    if envelope.len() != CUSTODY_RESHARE_ENVELOPE_BYTES {
        return Err("custody reshare envelope has invalid size".to_string());
    }
    Ok(envelope)
}

/// Authenticate one coordinator-generated share delivery and return it in
/// locked ownership. Only the bootstrap-allowlisted sender key is accepted.
pub fn open_reshare_delivery(
    recipient_key: &TransportPrivateKey,
    peers: &TransportPeerSet,
    generation: u64,
    envelope: &[u8],
) -> Result<(CustodyShareId, LockedSecret), String> {
    let topology = peers.topology();
    let recipient_slot = peers.local_slot();
    if envelope.len() != CUSTODY_RESHARE_ENVELOPE_BYTES {
        return Err(format!(
            "custody reshare envelope must be exactly {CUSTODY_RESHARE_ENVELOPE_BYTES} bytes"
        ));
    }
    let expected_sender_slot = envelope[0];
    let sender_identity = CustodyShareId::new(generation, expected_sender_slot, topology)
        .map_err(|error| error.to_string())?;
    let recipient_identity = CustodyShareId::new(generation, recipient_slot, topology)
        .map_err(|error| error.to_string())?;
    if sender_identity.slot() == recipient_identity.slot() {
        return Err("reshare sender and recipient must differ".to_string());
    }
    let expected_sender_key = peers.peer(expected_sender_slot)?;

    let nonce = crypto_box::Nonce::from_slice(&envelope[1..1 + NONCE_BYTES]);
    let recipient_secret = transient_secret_key(&recipient_key.0);
    let cipher = ChaChaBox::new(
        &PublicKey::from(*expected_sender_key.as_bytes()),
        &recipient_secret,
    );
    let plaintext = cipher
        .decrypt(nonce, &envelope[1 + NONCE_BYTES..])
        .map(Zeroizing::new)
        .map_err(|_| "custody reshare delivery authentication failed".to_string())?;
    if plaintext.len() != SEALED_HEADER_BYTES + CUSTODY_V1_SHARE_BYTES
        || &plaintext[0..4] != RESHARE_MAGIC
        || u16::from_be_bytes([plaintext[4], plaintext[5]]) != CUSTODY_PROTOCOL_VERSION
        || plaintext[6] != topology.threshold()
        || plaintext[7] != topology.slots()
        || u64::from_be_bytes(
            plaintext[8..16]
                .try_into()
                .map_err(|_| "custody reshare envelope metadata is truncated".to_string())?,
        ) != generation
        || plaintext[16] != expected_sender_slot
        || plaintext[17] != recipient_slot
    {
        return Err("custody reshare delivery metadata mismatch".to_string());
    }
    let share = &plaintext[SEALED_HEADER_BYTES..];
    validate_reshare_recipient(recipient_identity, share)?;
    let share = LockedSecret::from_slice(share, "authenticated custodian reshare delivery")?;
    Ok((recipient_identity, share))
}

/// Encrypt one share of the TARGET topology for the slot that will own it.
///
/// The authenticated header carries the target threshold and slot count, so a
/// recipient launched under any other shape rejects the delivery. Unlike every
/// other domain here, sender and recipient may be the same slot: the
/// coordinator's own new share cannot enter its launch-topology slot either,
/// so it is sealed to the coordinator's own transport key and installed only
/// after the operator restarts the pool under the target topology.
pub fn seal_topology_reshare_delivery(
    sender_key: &TransportPrivateKey,
    target: &ReshareTargetPeers,
    generation: u64,
    recipient_slot: u8,
    share: &LockedSecret,
) -> Result<Zeroizing<Vec<u8>>, String> {
    let topology = target.topology();
    let sender_slot = target.local_slot();
    let recipient_identity = CustodyShareId::new(generation, recipient_slot, topology)
        .map_err(|error| error.to_string())?;
    validate_reshare_recipient(recipient_identity, share.as_slice())?;
    let recipient_key = target.recipient(recipient_slot)?;

    let mut plaintext = Zeroizing::new(Vec::with_capacity(
        SEALED_HEADER_BYTES + CUSTODY_V1_SHARE_BYTES,
    ));
    plaintext.extend_from_slice(TOPOLOGY_RESHARE_MAGIC);
    plaintext.extend_from_slice(&CUSTODY_PROTOCOL_VERSION.to_be_bytes());
    plaintext.push(topology.threshold());
    plaintext.push(topology.slots());
    plaintext.extend_from_slice(&generation.to_be_bytes());
    plaintext.push(sender_slot);
    plaintext.push(recipient_slot);
    plaintext.extend_from_slice(share.as_slice());

    let sender_secret = transient_secret_key(&sender_key.0);
    let cipher = ChaChaBox::new(&PublicKey::from(*recipient_key.as_bytes()), &sender_secret);
    let nonce = ChaChaBox::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_slice())
        .map_err(|_| "could not encrypt custody topology reshare delivery".to_string())?;
    let mut envelope = Zeroizing::new(Vec::with_capacity(CUSTODY_TOPOLOGY_RESHARE_ENVELOPE_BYTES));
    envelope.push(sender_slot);
    envelope.extend_from_slice(&nonce);
    envelope.extend_from_slice(&ciphertext);
    if envelope.len() != CUSTODY_TOPOLOGY_RESHARE_ENVELOPE_BYTES {
        return Err("custody topology reshare envelope has invalid size".to_string());
    }
    Ok(envelope)
}

/// Authenticate one topology-reshare delivery against the recipient's own
/// launch topology. `peers` is the peer set the daemon was started with AFTER
/// the topology change, so a delivery only opens once the operator actually
/// restarted the pool into the shape the coordinator sealed for.
pub fn open_topology_reshare_delivery(
    recipient_key: &TransportPrivateKey,
    peers: &TransportPeerSet,
    generation: u64,
    envelope: &[u8],
) -> Result<(CustodyShareId, LockedSecret), String> {
    let topology = peers.topology();
    let recipient_slot = peers.local_slot();
    if envelope.len() != CUSTODY_TOPOLOGY_RESHARE_ENVELOPE_BYTES {
        return Err(format!(
            "custody topology reshare envelope must be exactly \
             {CUSTODY_TOPOLOGY_RESHARE_ENVELOPE_BYTES} bytes"
        ));
    }
    let expected_sender_slot = envelope[0];
    CustodyShareId::new(generation, expected_sender_slot, topology)
        .map_err(|error| error.to_string())?;
    let recipient_identity = CustodyShareId::new(generation, recipient_slot, topology)
        .map_err(|error| error.to_string())?;
    let expected_sender_key = if expected_sender_slot == recipient_slot {
        recipient_key.public_key()
    } else {
        peers.peer(expected_sender_slot)?
    };

    let nonce = crypto_box::Nonce::from_slice(&envelope[1..1 + NONCE_BYTES]);
    let recipient_secret = transient_secret_key(&recipient_key.0);
    let cipher = ChaChaBox::new(
        &PublicKey::from(*expected_sender_key.as_bytes()),
        &recipient_secret,
    );
    let plaintext = cipher
        .decrypt(nonce, &envelope[1 + NONCE_BYTES..])
        .map(Zeroizing::new)
        .map_err(|_| "custody topology reshare authentication failed".to_string())?;
    if plaintext.len() != SEALED_HEADER_BYTES + CUSTODY_V1_SHARE_BYTES
        || &plaintext[0..4] != TOPOLOGY_RESHARE_MAGIC
        || u16::from_be_bytes([plaintext[4], plaintext[5]]) != CUSTODY_PROTOCOL_VERSION
        || plaintext[6] != topology.threshold()
        || plaintext[7] != topology.slots()
        || u64::from_be_bytes(
            plaintext[8..16]
                .try_into()
                .map_err(|_| "custody topology reshare metadata is truncated".to_string())?,
        ) != generation
        || plaintext[16] != expected_sender_slot
        || plaintext[17] != recipient_slot
    {
        return Err("custody topology reshare metadata mismatch".to_string());
    }
    let share = &plaintext[SEALED_HEADER_BYTES..];
    validate_reshare_recipient(recipient_identity, share)?;
    let share = LockedSecret::from_slice(share, "authenticated custodian topology reshare")?;
    Ok((recipient_identity, share))
}

fn validate_route(
    topology: CustodyTopology,
    sender: CustodyShareId,
    recipient_slot: u8,
    share: &[u8],
) -> Result<(), String> {
    CustodyShareId::new(sender.generation(), sender.slot(), topology)
        .map_err(|error| error.to_string())?;
    CustodyShareId::new(sender.generation(), recipient_slot, topology)
        .map_err(|error| error.to_string())?;
    if sender.slot() == recipient_slot {
        return Err("custodian contribution sender and recipient must differ".to_string());
    }
    if share.len() != CUSTODY_V1_SHARE_BYTES {
        return Err(format!(
            "custody contribution share must be exactly {CUSTODY_V1_SHARE_BYTES} bytes"
        ));
    }
    if share[0] != sender.slot() {
        return Err("custody contribution coordinate mismatch".to_string());
    }
    Ok(())
}

fn validate_reshare_recipient(recipient: CustodyShareId, share: &[u8]) -> Result<(), String> {
    if share.len() != CUSTODY_V1_SHARE_BYTES {
        return Err(format!(
            "custody reshare share must be exactly {CUSTODY_V1_SHARE_BYTES} bytes"
        ));
    }
    if share[0] != recipient.slot() {
        return Err("custody reshare coordinate mismatch".to_string());
    }
    Ok(())
}

fn transient_secret_key(locked: &LockedSecret) -> SecretKey {
    let mut bytes = Zeroizing::new([0u8; CUSTODY_TRANSPORT_KEY_BYTES]);
    bytes.copy_from_slice(locked.as_slice());
    SecretKey::from(*bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn private(byte: u8) -> TransportPrivateKey {
        TransportPrivateKey::from_slice(&[byte; CUSTODY_TRANSPORT_KEY_BYTES])
            .expect("valid private key")
    }

    fn locked_share(slot: u8) -> LockedSecret {
        let mut bytes = vec![0xA5; CUSTODY_V1_SHARE_BYTES];
        bytes[0] = slot;
        LockedSecret::from_vec(bytes, "test share").expect("lock share")
    }

    fn peer_set(local_slot: u8, keys: &[(u8, &TransportPrivateKey)]) -> TransportPeerSet {
        let topology = CustodyTopology::new(2, 3).expect("topology");
        let peers: Vec<(u8, TransportPublicKey)> = keys
            .iter()
            .map(|(slot, key)| (*slot, key.public_key()))
            .collect();
        TransportPeerSet::new(topology, local_slot, &peers).expect("complete peer set")
    }

    #[test]
    fn authenticated_envelope_roundtrips_between_fixed_slots() {
        let topology = CustodyTopology::new(2, 3).expect("topology");
        let sender = private(0x11);
        let recipient = private(0x22);
        let third = private(0x33);
        let sender_peers = peer_set(1, &[(2, &recipient), (3, &third)]);
        let recipient_peers = peer_set(2, &[(1, &sender), (3, &third)]);
        let identity = CustodyShareId::new(9, 1, topology).expect("identity");
        let envelope =
            seal_share_contribution(&sender, &sender_peers, identity, 2, &locked_share(1))
                .expect("seal contribution");
        assert_eq!(envelope.len(), CUSTODY_SHARE_ENVELOPE_BYTES);

        let (opened_identity, opened_share) =
            open_share_contribution(&recipient, &recipient_peers, 9, &envelope)
                .expect("open contribution");
        assert_eq!(opened_identity, identity);
        assert_eq!(opened_share.as_slice(), locked_share(1).as_slice());
    }

    #[test]
    fn reshare_delivery_binds_sender_recipient_generation_and_coordinate() {
        let coordinator = private(0x22);
        let recipient = private(0x11);
        let third = private(0x33);
        let coordinator_peers = peer_set(2, &[(1, &recipient), (3, &third)]);
        let recipient_peers = peer_set(1, &[(2, &coordinator), (3, &third)]);
        let envelope =
            seal_reshare_delivery(&coordinator, &coordinator_peers, 12, 1, &locked_share(1))
                .expect("seal reshare delivery");
        assert_eq!(envelope.len(), CUSTODY_RESHARE_ENVELOPE_BYTES);

        let (identity, opened) = open_reshare_delivery(&recipient, &recipient_peers, 12, &envelope)
            .expect("open reshare delivery");
        assert_eq!(identity.slot(), 1);
        assert_eq!(identity.generation(), 12);
        assert_eq!(opened.as_slice(), locked_share(1).as_slice());
        assert!(open_share_contribution(&recipient, &recipient_peers, 12, &envelope).is_err());
        assert!(open_reshare_delivery(&recipient, &recipient_peers, 11, &envelope).is_err());
    }

    #[test]
    fn reshare_delivery_rejects_redirects_tampering_and_wrong_coordinates() {
        let coordinator = private(0x22);
        let recipient = private(0x11);
        let third = private(0x33);
        let coordinator_peers = peer_set(2, &[(1, &recipient), (3, &third)]);
        let recipient_peers = peer_set(1, &[(2, &coordinator), (3, &third)]);
        let third_peers = peer_set(3, &[(1, &recipient), (2, &coordinator)]);
        assert!(
            seal_reshare_delivery(&coordinator, &coordinator_peers, 12, 2, &locked_share(2),)
                .is_err()
        );
        assert!(
            seal_reshare_delivery(&coordinator, &coordinator_peers, 12, 1, &locked_share(3),)
                .is_err()
        );

        let envelope =
            seal_reshare_delivery(&coordinator, &coordinator_peers, 12, 1, &locked_share(1))
                .expect("seal reshare delivery");
        assert!(open_reshare_delivery(&third, &third_peers, 12, &envelope).is_err());
        let mut tampered = envelope.to_vec();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(open_reshare_delivery(&recipient, &recipient_peers, 12, &tampered).is_err());
    }

    #[test]
    fn wrong_sender_recipient_and_tampering_fail_authentication() {
        let topology = CustodyTopology::new(2, 3).expect("topology");
        let sender = private(0x11);
        let recipient = private(0x22);
        let wrong = private(0x33);
        let sender_peers = peer_set(1, &[(2, &recipient), (3, &wrong)]);
        let recipient_peers = peer_set(2, &[(1, &sender), (3, &wrong)]);
        let wrong_peers = peer_set(3, &[(1, &sender), (2, &recipient)]);
        let identity = CustodyShareId::new(7, 1, topology).expect("identity");
        let envelope =
            seal_share_contribution(&sender, &sender_peers, identity, 2, &locked_share(1))
                .expect("seal contribution");

        let mut wrong_sender = envelope.to_vec();
        wrong_sender[0] = 3;
        assert!(open_share_contribution(&recipient, &recipient_peers, 7, &wrong_sender).is_err());
        assert!(open_share_contribution(&wrong, &wrong_peers, 7, &envelope).is_err());

        let mut tampered = envelope.to_vec();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(open_share_contribution(&recipient, &recipient_peers, 7, &tampered).is_err());
    }

    #[test]
    fn metadata_and_route_are_bound_inside_ciphertext() {
        let topology = CustodyTopology::new(2, 3).expect("topology");
        let sender = private(0x11);
        let recipient = private(0x22);
        let third = private(0x33);
        let sender_peers = peer_set(1, &[(2, &recipient), (3, &third)]);
        let recipient_peers = peer_set(2, &[(1, &sender), (3, &third)]);
        let third_peers = peer_set(3, &[(1, &sender), (2, &recipient)]);
        let identity = CustodyShareId::new(7, 1, topology).expect("identity");
        let envelope =
            seal_share_contribution(&sender, &sender_peers, identity, 2, &locked_share(1))
                .expect("seal contribution");

        assert!(open_share_contribution(&recipient, &recipient_peers, 8, &envelope).is_err());
        assert!(open_share_contribution(&third, &third_peers, 7, &envelope).is_err());

        let mut wrong_clear_sender = envelope.to_vec();
        wrong_clear_sender[0] = 3;
        assert!(
            open_share_contribution(&recipient, &recipient_peers, 7, &wrong_clear_sender).is_err()
        );
    }

    #[test]
    fn invalid_keys_coordinates_and_self_routes_fail() {
        assert!(TransportPrivateKey::from_slice(&[0u8; CUSTODY_TRANSPORT_KEY_BYTES]).is_err());
        assert!(TransportPrivateKey::from_slice(&[1u8; 31]).is_err());
        assert!(TransportPublicKey::from_bytes([0u8; CUSTODY_TRANSPORT_KEY_BYTES]).is_err());

        let topology = CustodyTopology::new(2, 3).expect("topology");
        let sender = private(0x11);
        let recipient = private(0x22);
        let third = private(0x33);
        let sender_peers = peer_set(1, &[(2, &recipient), (3, &third)]);
        let identity = CustodyShareId::new(7, 1, topology).expect("identity");
        assert!(
            seal_share_contribution(&sender, &sender_peers, identity, 1, &locked_share(1),)
                .is_err()
        );
        assert!(
            seal_share_contribution(&sender, &sender_peers, identity, 2, &locked_share(2),)
                .is_err()
        );
    }

    fn peer_set_for(
        topology: CustodyTopology,
        local_slot: u8,
        keys: &[(u8, &TransportPrivateKey)],
    ) -> TransportPeerSet {
        let peers: Vec<(u8, TransportPublicKey)> = keys
            .iter()
            .map(|(slot, key)| (*slot, key.public_key()))
            .collect();
        TransportPeerSet::new(topology, local_slot, &peers).expect("complete peer set")
    }

    #[test]
    fn topology_reshare_delivers_to_grown_and_coordinator_slots() {
        let target = CustodyTopology::new(3, 5).expect("target topology");
        let one = private(0x11);
        let two = private(0x22);
        let three = private(0x33);
        let four = private(0x44);
        let five = private(0x55);
        let coordinator_peers = peer_set(1, &[(2, &two), (3, &three)]);
        let target_peers = ReshareTargetPeers::new(
            &coordinator_peers,
            &one,
            target,
            &[
                (1, one.public_key()),
                (2, two.public_key()),
                (3, three.public_key()),
                (4, four.public_key()),
                (5, five.public_key()),
            ],
        )
        .expect("valid target");
        assert_eq!(
            target_peers.recipient_slots().collect::<Vec<u8>>(),
            vec![1, 2, 3, 4, 5]
        );

        // A slot added by the target opens its delivery once it is launched
        // under that target topology.
        let envelope = seal_topology_reshare_delivery(&one, &target_peers, 20, 4, &locked_share(4))
            .expect("seal delivery");
        assert_eq!(envelope.len(), CUSTODY_TOPOLOGY_RESHARE_ENVELOPE_BYTES);
        let four_peers = peer_set_for(target, 4, &[(1, &one), (2, &two), (3, &three), (5, &five)]);
        let (identity, opened) = open_topology_reshare_delivery(&four, &four_peers, 20, &envelope)
            .expect("open delivery");
        assert_eq!((identity.slot(), identity.generation()), (4, 20));
        assert_eq!(opened.as_slice(), locked_share(4).as_slice());

        // The coordinator's own share travels the same way, because its
        // launch-topology slot cannot hold a target-topology share.
        let own = seal_topology_reshare_delivery(&one, &target_peers, 20, 1, &locked_share(1))
            .expect("seal own delivery");
        let one_peers = peer_set_for(target, 1, &[(2, &two), (3, &three), (4, &four), (5, &five)]);
        let (identity, opened) =
            open_topology_reshare_delivery(&one, &one_peers, 20, &own).expect("open own delivery");
        assert_eq!(identity.slot(), 1);
        assert_eq!(opened.as_slice(), locked_share(1).as_slice());
    }

    #[test]
    fn topology_reshare_is_bound_to_its_target_shape_and_domain() {
        let launch = CustodyTopology::new(2, 3).expect("launch topology");
        let target = CustodyTopology::new(3, 5).expect("target topology");
        let one = private(0x11);
        let two = private(0x22);
        let three = private(0x33);
        let four = private(0x44);
        let five = private(0x55);
        let coordinator_peers = peer_set(1, &[(2, &two), (3, &three)]);
        let target_peers = ReshareTargetPeers::new(
            &coordinator_peers,
            &one,
            target,
            &[
                (1, one.public_key()),
                (2, two.public_key()),
                (3, three.public_key()),
                (4, four.public_key()),
                (5, five.public_key()),
            ],
        )
        .expect("valid target");
        let envelope = seal_topology_reshare_delivery(&one, &target_peers, 20, 2, &locked_share(2))
            .expect("seal delivery");

        // Still launched under the old shape: the authenticated target
        // topology does not match, so nothing installs before the restart.
        let stale_two = peer_set_for(launch, 2, &[(1, &one), (3, &three)]);
        assert!(open_topology_reshare_delivery(&two, &stale_two, 20, &envelope).is_err());

        let two_peers = peer_set_for(target, 2, &[(1, &one), (3, &three), (4, &four), (5, &five)]);
        assert!(open_topology_reshare_delivery(&two, &two_peers, 20, &envelope).is_ok());
        assert!(open_topology_reshare_delivery(&two, &two_peers, 21, &envelope).is_err());
        // A separate wire domain: neither ordinary contributions nor
        // same-topology reshare deliveries accept it, and vice versa.
        assert!(open_reshare_delivery(&two, &two_peers, 20, &envelope).is_err());
        assert!(open_share_contribution(&two, &two_peers, 20, &envelope).is_err());
        let same_topology = seal_reshare_delivery(&one, &two_peers, 20, 1, &locked_share(1))
            .expect("seal same-topology delivery");
        let one_target = peer_set_for(target, 1, &[(2, &two), (3, &three), (4, &four), (5, &five)]);
        assert!(open_topology_reshare_delivery(&one, &one_target, 20, &same_topology).is_err());

        let mut redirected = envelope.to_vec();
        redirected[0] = 3;
        assert!(open_topology_reshare_delivery(&two, &two_peers, 20, &redirected).is_err());
        let mut tampered = envelope.to_vec();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(open_topology_reshare_delivery(&two, &two_peers, 20, &tampered).is_err());
        assert!(
            seal_topology_reshare_delivery(&one, &target_peers, 20, 2, &locked_share(3)).is_err()
        );
        assert!(
            seal_topology_reshare_delivery(&one, &target_peers, 20, 6, &locked_share(6)).is_err()
        );
    }

    #[test]
    fn topology_target_keeps_surviving_keys_and_needs_every_slot() {
        let target = CustodyTopology::new(3, 5).expect("target topology");
        let one = private(0x11);
        let two = private(0x22);
        let three = private(0x33);
        let four = private(0x44);
        let five = private(0x55);
        let rogue = private(0x66);
        let coordinator_peers = peer_set(1, &[(2, &two), (3, &three)]);
        let complete = [
            (1, one.public_key()),
            (2, two.public_key()),
            (3, three.public_key()),
            (4, four.public_key()),
            (5, five.public_key()),
        ];
        let target_of = |topology, recipients: &[(u8, TransportPublicKey)]| {
            ReshareTargetPeers::new(&coordinator_peers, &one, topology, recipients)
        };
        assert!(target_of(target, &complete).is_ok());
        // A surviving slot may not be re-pointed at a caller-supplied key, and
        // the coordinator may not disown its own.
        let mut redirected = complete;
        redirected[1].1 = rogue.public_key();
        assert!(target_of(target, &redirected).is_err());
        let mut disowned = complete;
        disowned[0].1 = rogue.public_key();
        assert!(target_of(target, &disowned).is_err());
        // A slot the target ADDS may bring a fresh key, but not a duplicate.
        let mut duplicated = complete;
        duplicated[4].1 = four.public_key();
        assert!(target_of(target, &duplicated).is_err());
        assert!(target_of(target, &complete[..4]).is_err());
        // Same shape is the existing native reshare, not this protocol.
        assert!(target_of(
            CustodyTopology::new(2, 3).expect("launch topology"),
            &complete[..3]
        )
        .is_err());
        // Raising the threshold alone is a target shape like any other.
        assert!(target_of(
            CustodyTopology::new(3, 3).expect("threshold-only target"),
            &complete[..3]
        )
        .is_ok());
        // Shrinking keeps the surviving keys and drops the removed slots.
        let grown_peers =
            peer_set_for(target, 1, &[(2, &two), (3, &three), (4, &four), (5, &five)]);
        assert!(ReshareTargetPeers::new(
            &grown_peers,
            &one,
            CustodyTopology::new(2, 3).expect("shrunk target"),
            &complete[..3],
        )
        .is_ok());
        let mut shrunk_redirect = complete;
        shrunk_redirect[2].1 = rogue.public_key();
        assert!(ReshareTargetPeers::new(
            &grown_peers,
            &one,
            CustodyTopology::new(2, 3).expect("shrunk target"),
            &shrunk_redirect[..3],
        )
        .is_err());
    }

    #[test]
    fn topology_reshare_coordinator_must_survive_the_target() {
        let target = CustodyTopology::new(2, 3).expect("target topology");
        let launch = CustodyTopology::new(3, 5).expect("launch topology");
        let one = private(0x11);
        let two = private(0x22);
        let three = private(0x33);
        let four = private(0x44);
        let five = private(0x55);
        let coordinator_peers =
            peer_set_for(launch, 5, &[(1, &one), (2, &two), (3, &three), (4, &four)]);
        assert!(ReshareTargetPeers::new(
            &coordinator_peers,
            &five,
            target,
            &[
                (1, one.public_key()),
                (2, two.public_key()),
                (3, three.public_key()),
            ],
        )
        .is_err());
    }

    #[test]
    fn peer_set_must_be_complete_unique_and_exclude_local_slot() {
        let topology = CustodyTopology::new(2, 3).expect("topology");
        let one = private(0x11).public_key();
        let two = private(0x22).public_key();
        assert!(TransportPeerSet::new(topology, 1, &[(2, two)]).is_err());
        assert!(TransportPeerSet::new(topology, 1, &[(1, one), (2, two)]).is_err());
        assert!(TransportPeerSet::new(topology, 1, &[(2, two), (2, one)]).is_err());
        assert!(TransportPeerSet::new(topology, 1, &[(2, two), (3, two)]).is_err());
        assert!(TransportPeerSet::new(topology, 1, &[(2, two), (3, one)]).is_ok());
    }
}
