// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
//! Standalone Rust custodian process boundary.
//!
//! The daemon starts sealed, owns one fixed locked share, and emits share
//! contributions only as authenticated ciphertext for bootstrap-allowlisted
//! custodians. Runtime crypto stays on the compatibility backend until explicit
//! unseal and operation parity are complete.

use std::env;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::process;
use std::sync::{Arc, Mutex};
use std::thread;

use rhorizon_custody_core::control::{ControlCapability, MAX_CONTROL_CAPABILITY_BYTES};
use rhorizon_custody_core::operations::{
    ChainedSecretCiphertext, ChainedSecretReencryptInput, AES_GCM_NONCE_BYTES, DEK_WRAPPED_BYTES,
};
#[cfg(test)]
use rhorizon_custody_core::operations::{XCHACHA_NONCE_BYTES, XCHACHA_TAG_BYTES};
use rhorizon_custody_core::peer_cred::read_peer_cred;
use rhorizon_custody_core::quorum::QuorumCollector;
use rhorizon_custody_core::rpc::{dispatch_request, error_response, read_frame, write_frame};
use rhorizon_custody_core::runtime::{
    AuditIdentityInstallOutcome, HaPasswordInstallOutcome, PreviousHmacInstallOutcome,
    RuntimeBundleSlot, RuntimeInstallOutcome,
};
use rhorizon_custody_core::secure_memory::{memory_lock_status, LockedSecret};
use rhorizon_custody_core::shamir;
use rhorizon_custody_core::share_persistence::{
    open_share_state, seal_share_state, SHARE_STATE_FILE_BYTES,
};
use rhorizon_custody_core::share_store::{
    CustodyShareSlot, ShareCommitOutcome, ShareFinalizeOutcome, ShareInstallOutcome,
    SharePrepareOutcome, ShareRollbackOutcome,
};
use rhorizon_custody_core::transport::{
    open_reshare_delivery, open_share_contribution, open_topology_reshare_delivery,
    seal_reshare_delivery, seal_share_contribution, seal_topology_reshare_delivery,
    ReshareTargetPeers, TransportPeerSet, TransportPrivateKey, TransportPublicKey,
    CUSTODY_RESHARE_ENVELOPE_BYTES, CUSTODY_SHARE_ENVELOPE_BYTES,
    CUSTODY_TOPOLOGY_RESHARE_ENVELOPE_BYTES,
};
use rhorizon_custody_core::{
    CustodyShareId, CustodyTopology, CUSTODY_PROTOCOL_VERSION, CUSTODY_TRANSPORT_KEY_BYTES,
    CUSTODY_V1_SHARE_BYTES, MAX_RPC_FRAME_BYTES,
};
use serde_json::{json, Value};
use zeroize::Zeroizing;

#[derive(Debug, Eq, PartialEq)]
struct Config {
    socket_path: PathBuf,
    control_token_file: PathBuf,
    transport_key_file: PathBuf,
    /// Absent = the share is held in RAM only and NEVER written.
    ///
    /// That is the default. The sealed state file is decryptable with a key
    /// derived from the transport key beside it, so persisting it puts
    /// reconstructable sub-key material on disk. It buys only the case where
    /// fewer than `threshold` custodians still hold their share: a surviving
    /// quorum already refills an empty slot on its own. Enabling it therefore
    /// requires an off-disk key provider (TPM2, YubiKey) to wrap the transport
    /// key -- until one exists, this stays None.
    share_state_file: Option<PathBuf>,
    adopt_share_state_file: Option<PathBuf>,
    peer_keys: Vec<(u8, TransportPublicKey)>,
    topology: CustodyTopology,
    slot: u8,
    once: bool,
    threads: u8,
}

/// Accept threads for the control socket. Each connection is a single
/// request/response, and crypto runs outside the runtime lock (the lock is
/// held only to copy a key out), so accept concurrency translates into real
/// parallelism. Kept small on purpose: every operation mlocks a fresh key
/// buffer, and locked pages are only released when the allocator hands them
/// back with munmap, so RLIMIT_MEMLOCK must cover the peak secret footprint,
/// not just the in-flight set. This daemon is sized to be small.
const DEFAULT_SERVE_THREADS: u8 = 4;
const MAX_SERVE_THREADS: u8 = 64;

/// Per-syscall deadline on the control socket. Each connection is one
/// request/response, so a peer idle longer than this is stalled; without a
/// deadline it would pin one of the few accept threads forever.
const SOCKET_IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

#[derive(Debug, Eq, PartialEq)]
enum OfflineCommand {
    GenerateControlToken(PathBuf),
    GenerateTransportKey(PathBuf),
    PrintTransportPublicKey(PathBuf),
}

impl OfflineCommand {
    fn parse(arguments: &[String]) -> Result<Option<Self>, String> {
        let Some(command) = arguments.get(1).map(String::as_str) else {
            return Ok(None);
        };
        let (flag, constructor): (&str, fn(PathBuf) -> Self) = match command {
            "generate-control-token" => (
                "--output",
                Self::GenerateControlToken as fn(PathBuf) -> Self,
            ),
            "generate-transport-key" => (
                "--output",
                Self::GenerateTransportKey as fn(PathBuf) -> Self,
            ),
            "print-transport-public-key" => (
                "--transport-key-file",
                Self::PrintTransportPublicKey as fn(PathBuf) -> Self,
            ),
            _ => return Ok(None),
        };
        if arguments.len() != 4 || arguments[2] != flag || arguments[3].is_empty() {
            return Err(usage());
        }
        Ok(Some(constructor(PathBuf::from(&arguments[3]))))
    }
}

impl Config {
    fn parse<I>(arguments: I) -> Result<Self, String>
    where
        I: IntoIterator<Item = String>,
    {
        let mut arguments = arguments.into_iter();
        let _program = arguments.next();
        let mut socket_path = None;
        let mut control_token_file = None;
        let mut transport_key_file = None;
        let mut share_state_file = None;
        let mut adopt_share_state_file = None;
        let mut peer_keys = Vec::new();
        let mut threshold = None;
        let mut slots = None;
        let mut slot = None;
        let mut once = false;
        let mut threads = None;
        while let Some(argument) = arguments.next() {
            match argument.as_str() {
                "--socket" => {
                    let value = arguments
                        .next()
                        .ok_or_else(|| "--socket requires a path".to_string())?;
                    if value.is_empty() {
                        return Err("--socket requires a non-empty path".into());
                    }
                    socket_path = Some(PathBuf::from(value));
                }
                "--control-token-file" => {
                    let value = arguments
                        .next()
                        .ok_or_else(|| "--control-token-file requires a path".to_string())?;
                    if value.is_empty() {
                        return Err("--control-token-file requires a non-empty path".into());
                    }
                    control_token_file = Some(PathBuf::from(value));
                }
                "--transport-key-file" => {
                    let value = arguments
                        .next()
                        .ok_or_else(|| "--transport-key-file requires a path".to_string())?;
                    if value.is_empty() {
                        return Err("--transport-key-file requires a non-empty path".into());
                    }
                    transport_key_file = Some(PathBuf::from(value));
                }
                "--share-state-file" => {
                    let value = arguments
                        .next()
                        .ok_or_else(|| "--share-state-file requires a path".to_string())?;
                    if value.is_empty() {
                        return Err("--share-state-file requires a non-empty path".into());
                    }
                    share_state_file = Some(PathBuf::from(value));
                }
                "--adopt-share-state-file" => {
                    let value = arguments
                        .next()
                        .ok_or_else(|| "--adopt-share-state-file requires a path".to_string())?;
                    if value.is_empty() {
                        return Err("--adopt-share-state-file requires a non-empty path".into());
                    }
                    adopt_share_state_file = Some(PathBuf::from(value));
                }
                "--peer-key" => {
                    let value = arguments
                        .next()
                        .ok_or_else(|| "--peer-key requires SLOT:PUBLIC_KEY_HEX".to_string())?;
                    peer_keys.push(parse_peer_key(&value)?);
                }
                "--threshold" => {
                    threshold = Some(parse_u8_argument(&mut arguments, "--threshold")?)
                }
                "--slots" => slots = Some(parse_u8_argument(&mut arguments, "--slots")?),
                "--slot" => slot = Some(parse_u8_argument(&mut arguments, "--slot")?),
                "--threads" => threads = Some(parse_u8_argument(&mut arguments, "--threads")?),
                "--once" => once = true,
                "--help" | "-h" => return Err(usage()),
                unknown => return Err(format!("unknown argument {unknown:?}\n{}", usage())),
            }
        }
        let topology = CustodyTopology::new(threshold.ok_or_else(usage)?, slots.ok_or_else(usage)?)
            .map_err(|error| error.to_string())?;
        let slot = slot.ok_or_else(usage)?;
        CustodyShareId::new(1, slot, topology).map_err(|error| error.to_string())?;
        TransportPeerSet::new(topology, slot, &peer_keys)?;
        if share_state_file.is_none() && adopt_share_state_file.is_some() {
            // Adopting a legacy file means writing the adopted state back out.
            // Accepting the pair silently would persist share material after
            // the operator asked for no persistence.
            return Err(
                "--adopt-share-state-file requires --share-state-file; adoption persists".into(),
            );
        }
        let threads = threads.unwrap_or(DEFAULT_SERVE_THREADS);
        if !(1..=MAX_SERVE_THREADS).contains(&threads) {
            return Err(format!("--threads must be from 1 to {MAX_SERVE_THREADS}"));
        }
        Ok(Self {
            socket_path: socket_path.ok_or_else(usage)?,
            control_token_file: control_token_file.ok_or_else(usage)?,
            transport_key_file: transport_key_file.ok_or_else(usage)?,
            share_state_file,
            adopt_share_state_file,
            peer_keys,
            topology,
            slot,
            once,
            threads,
        })
    }
}

fn parse_peer_key(value: &str) -> Result<(u8, TransportPublicKey), String> {
    let (slot, public_key_hex) = value
        .split_once(':')
        .ok_or_else(|| "--peer-key requires SLOT:PUBLIC_KEY_HEX".to_string())?;
    let slot = slot
        .parse::<u8>()
        .map_err(|_| "--peer-key slot must be an integer from 1 to 255".to_string())?;
    if public_key_hex.len() != CUSTODY_TRANSPORT_KEY_BYTES * 2 {
        return Err(format!(
            "--peer-key public key must encode exactly {CUSTODY_TRANSPORT_KEY_BYTES} bytes"
        ));
    }
    let mut public_key = [0u8; CUSTODY_TRANSPORT_KEY_BYTES];
    hex::decode_to_slice(public_key_hex, &mut public_key)
        .map_err(|_| "--peer-key public key must be valid hexadecimal".to_string())?;
    TransportPublicKey::from_bytes(public_key).map(|key| (slot, key))
}

fn parse_u8_argument<I>(arguments: &mut I, name: &str) -> Result<u8, String>
where
    I: Iterator<Item = String>,
{
    let value = arguments
        .next()
        .ok_or_else(|| format!("{name} requires an integer"))?;
    value
        .parse::<u8>()
        .map_err(|_| format!("{name} must be an integer from 1 to 255"))
}

fn usage() -> String {
    "usage:\n  rhorizon-custodian --socket PATH --control-token-file PATH \
     --transport-key-file PATH \
     [--share-state-file PATH] \
     [--adopt-share-state-file PATH] --peer-key SLOT:PUBLIC_KEY_HEX ... \
     --threshold N --slots N --slot N [--threads N] [--once]\n  \
     rhorizon-custodian generate-control-token --output PATH\n  \
     rhorizon-custodian generate-transport-key --output PATH\n  \
     rhorizon-custodian print-transport-public-key --transport-key-file PATH"
        .to_string()
}

struct BoundSocket {
    listener: UnixListener,
    path: PathBuf,
    owner_uid: u32,
}

impl BoundSocket {
    fn bind(path: &Path) -> io::Result<Self> {
        if path.exists() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("refusing to replace existing socket {}", path.display()),
            ));
        }
        // The socket inode must never be group/world accessible, even between
        // bind() and the chmod below. umask is process-global, but bind runs
        // once at startup before any worker thread exists.
        // SAFETY: umask cannot fail; both calls only swap the process mask.
        let previous_umask = unsafe { libc::umask(0o177) };
        let listener = UnixListener::bind(path);
        unsafe { libc::umask(previous_umask) };
        let listener = listener?;
        let mut permissions = fs::metadata(path)?.permissions();
        permissions.set_mode(0o600);
        fs::set_permissions(path, permissions)?;
        let owner_uid = fs::metadata(path)?.uid();
        Ok(Self {
            listener,
            path: path.to_path_buf(),
            owner_uid,
        })
    }
}

impl Drop for BoundSocket {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

struct CustodianState {
    control_capability: ControlCapability,
    share: CustodyShareSlot,
    runtime: RuntimeBundleSlot,
    transport_key: TransportPrivateKey,
    transport_peers: TransportPeerSet,
    reshare: ReshareCache,
    share_state_file: Option<(PathBuf, u32)>,
}

struct PendingReshare {
    generation: u64,
    /// The topology the deliveries were split and sealed for. It equals the
    /// launch topology for an ordinary reshare and differs for a topology
    /// change, so one cache slot keeps the two mutually exclusive: neither
    /// kind can start while the other is pending.
    topology: CustodyTopology,
    deliveries: Vec<(u8, Zeroizing<Vec<u8>>)>,
}

struct ReshareCache {
    pending: Mutex<Option<PendingReshare>>,
}

impl ReshareCache {
    const fn empty() -> Self {
        Self {
            pending: Mutex::new(None),
        }
    }

    fn clear(&self) -> Result<(), String> {
        let mut pending = self
            .pending
            .lock()
            .map_err(|error| format!("custodian reshare cache lock poisoned: {error}"))?;
        *pending = None;
        Ok(())
    }

    fn pending_summary(&self) -> Result<Option<(u64, CustodyTopology)>, String> {
        Ok(self
            .pending
            .lock()
            .map_err(|error| format!("custodian reshare cache lock poisoned: {error}"))?
            .as_ref()
            .map(|pending| (pending.generation, pending.topology)))
    }
}

impl CustodianState {
    fn sealed(
        control_capability: ControlCapability,
        topology: CustodyTopology,
        slot: u8,
        transport_key: TransportPrivateKey,
        transport_peers: TransportPeerSet,
    ) -> Result<Self, String> {
        if transport_peers.topology() != topology || transport_peers.local_slot() != slot {
            return Err("custodian transport peer set does not match local topology".to_string());
        }
        Ok(Self {
            control_capability,
            share: CustodyShareSlot::new(topology, slot, CUSTODY_V1_SHARE_BYTES)?,
            runtime: RuntimeBundleSlot::empty(),
            transport_key,
            transport_peers,
            reshare: ReshareCache::empty(),
            share_state_file: None,
        })
    }

    fn enable_share_persistence(
        &mut self,
        path: PathBuf,
        adopt: Option<PathBuf>,
        owner_uid: u32,
    ) -> Result<(), String> {
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                self.restore_share_state_from(&path, owner_uid)?;
                self.share_state_file = Some((path, owner_uid));
                Ok(())
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                self.share_state_file = Some((path, owner_uid));
                match adopt {
                    Some(adopt) if fs::symlink_metadata(&adopt).is_ok() => {
                        self.adopt_share_state(&adopt, owner_uid)
                    }
                    _ => self.persist_share_state(),
                }
            }
            Err(error) => Err(format!("could not inspect custodian share state: {error}")),
        }
    }

    fn restore_share_state_from(&self, path: &Path, owner_uid: u32) -> Result<(), String> {
        let envelope = read_private_file(
            path,
            owner_uid,
            SHARE_STATE_FILE_BYTES,
            "custodian share state",
        )
        .map_err(|error| format!("could not read custodian share state: {error}"))?;
        let state = open_share_state(
            &self.transport_key,
            self.share.topology(),
            self.share.slot(),
            &envelope,
        )?;
        self.share.restore_state(state)
    }

    /// Take over a share state written before the file name carried the
    /// topology, then retire the old name.
    ///
    /// The state authenticates under the configured topology or the daemon
    /// refuses to start: a file that does not open here belongs to a different
    /// shape, and adopting it into this one would either mix polynomials or
    /// look like an empty slot and trigger a repair. Retiring it after the
    /// topology-scoped copy is written keeps exactly one owner of the state;
    /// reverting to the previous shape finds that shape's own file.
    fn adopt_share_state(&mut self, adopt: &Path, owner_uid: u32) -> Result<(), String> {
        self.restore_share_state_from(adopt, owner_uid)
            .map_err(|error| {
                let topology = self.share.topology();
                format!(
                    "could not adopt {} as a {}-of-{} share state: {error}; a topology \
                     change is a reshare ceremony, not a restart",
                    adopt.display(),
                    topology.threshold(),
                    topology.slots(),
                )
            })?;
        self.persist_share_state()?;
        fs::remove_file(adopt)
            .map_err(|error| format!("could not retire adopted custodian share state: {error}"))
    }

    fn persist_share_state(&self) -> Result<(), String> {
        let Some((path, owner_uid)) = self.share_state_file.as_ref() else {
            return Ok(());
        };
        let snapshot = self.share.snapshot_state()?;
        let envelope = seal_share_state(&self.transport_key, &snapshot)?;
        write_private_file_atomic(path, *owner_uid, &envelope)
            .map_err(|error| format!("could not persist custodian share state: {error}"))
    }

    fn is_sealed(&self) -> Result<bool, String> {
        self.runtime.is_loaded().map(|loaded| !loaded)
    }
}

fn load_control_capability(path: &Path, owner_uid: u32) -> io::Result<ControlCapability> {
    let raw = read_private_file(
        path,
        owner_uid,
        MAX_CONTROL_CAPABILITY_BYTES + 2,
        "control token",
    )?;
    ControlCapability::new(raw.trim_ascii())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))
}

fn load_transport_private_key(path: &Path, owner_uid: u32) -> io::Result<TransportPrivateKey> {
    let raw = read_private_file(
        path,
        owner_uid,
        (CUSTODY_TRANSPORT_KEY_BYTES * 2) + 2,
        "transport private key",
    )?;
    let encoded = raw.trim_ascii();
    if encoded.len() != CUSTODY_TRANSPORT_KEY_BYTES * 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "transport private key must encode exactly {CUSTODY_TRANSPORT_KEY_BYTES} bytes"
            ),
        ));
    }
    let mut decoded = Zeroizing::new([0u8; CUSTODY_TRANSPORT_KEY_BYTES]);
    hex::decode_to_slice(encoded, decoded.as_mut_slice()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "transport private key must be valid hexadecimal",
        )
    })?;
    TransportPrivateKey::from_slice(decoded.as_slice())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))
}

fn generate_private_random_hex_file(
    path: &Path,
    random_bytes: usize,
    label: &str,
) -> io::Result<LockedSecret> {
    generate_private_random_hex_file_with(path, random_bytes, label, |output| {
        getrandom::getrandom(output)
            .map_err(|_| io::Error::other("operating system random source failed"))
    })
}

fn generate_private_random_hex_file_with<F>(
    path: &Path,
    random_bytes: usize,
    label: &str,
    fill_random: F,
) -> io::Result<LockedSecret>
where
    F: FnOnce(&mut [u8]) -> io::Result<()>,
{
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;

    let parent = path
        .parent()
        .filter(|candidate| !candidate.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let result = (|| {
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        let mut private =
            LockedSecret::from_vec(vec![0u8; random_bytes], label).map_err(io::Error::other)?;
        fill_random(private.as_mut_slice())?;
        let mut encoded = LockedSecret::from_vec(
            vec![0u8; random_bytes * 2],
            "encoded private bootstrap value",
        )
        .map_err(io::Error::other)?;
        hex::encode_to_slice(private.as_slice(), encoded.as_mut_slice())
            .map_err(|_| io::Error::other("could not encode transport private key"))?;
        file.write_all(encoded.as_slice())?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        // Durability of a newly-created file also requires the directory
        // entry to reach stable storage. Otherwise a successful bootstrap can
        // disappear after a crash even though its contents were fsync'd.
        fs::File::open(parent)?.sync_all()?;
        Ok(private)
    })();
    if result.is_err() {
        // create_new() makes this inode ours. Never leave a partial bootstrap
        // file that makes the next safe retry fail with AlreadyExists.
        drop(file);
        let _ = fs::remove_file(path);
    }
    result
}

fn generate_control_token_file(path: &Path) -> io::Result<()> {
    generate_private_random_hex_file(path, 32, "new custodian control token").map(drop)
}

fn generate_transport_key_file(path: &Path) -> io::Result<TransportPublicKey> {
    let private = generate_private_random_hex_file(
        path,
        CUSTODY_TRANSPORT_KEY_BYTES,
        "new custodian transport private key",
    )?;
    let private_key = TransportPrivateKey::from_slice(private.as_slice())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    Ok(private_key.public_key())
}

fn current_uid() -> u32 {
    unsafe { libc::geteuid() }
}

fn print_transport_public_key(path: &Path) -> io::Result<TransportPublicKey> {
    load_transport_private_key(path, current_uid()).map(|key| key.public_key())
}

fn read_private_file(
    path: &Path,
    owner_uid: u32,
    max_bytes: usize,
    label: &str,
) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{label} must be a regular file"),
        ));
    }
    if metadata.uid() != owner_uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{label} owner must match custodian owner"),
        ));
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{label} must not be group/world accessible"),
        ));
    }
    if metadata.len() > max_bytes as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{label} file is too large"),
        ));
    }
    let mut raw = Zeroizing::new(Vec::with_capacity(max_bytes + 1));
    Read::by_ref(&mut file)
        .take((max_bytes + 1) as u64)
        .read_to_end(&mut raw)?;
    if raw.len() > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{label} file is too large"),
        ));
    }
    Ok(raw)
}

fn write_private_file_atomic(path: &Path, owner_uid: u32, bytes: &[u8]) -> io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "share-state path has no parent",
        )
    })?;
    let parent_metadata = fs::metadata(parent)?;
    if !parent_metadata.is_dir()
        || parent_metadata.uid() != owner_uid
        || parent_metadata.permissions().mode() & 0o077 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "share-state directory must be a private directory owned by the custodian",
        ));
    }
    match fs::symlink_metadata(path) {
        Ok(metadata)
            if !metadata.file_type().is_file()
                || metadata.uid() != owner_uid
                || metadata.permissions().mode() & 0o077 != 0 =>
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "existing share-state path must be a private regular file owned by the custodian",
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }

    let mut random = [0u8; 8];
    getrandom::getrandom(&mut random)
        .map_err(|_| io::Error::other("operating system random source failed"))?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "invalid share-state filename")
        })?;
    let temporary = parent.join(format!(
        ".{file_name}.tmp-{}-{}",
        std::process::id(),
        hex::encode(random)
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        fs::File::open(parent)?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn required_u64(arguments: &Value, name: &str) -> Result<u64, String> {
    arguments
        .get(name)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("missing or invalid {name}"))
}

fn required_u8(arguments: &Value, name: &str) -> Result<u8, String> {
    u8::try_from(required_u64(arguments, name)?)
        .map_err(|_| format!("{name} must be from 1 to 255"))
}

fn required_str<'a>(arguments: &'a Value, name: &str) -> Result<&'a str, String> {
    arguments
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing arg: {name}"))
}

fn decode_hex(arguments: &Value, name: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    let encoded = arguments
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing arg: {name}"))?;
    hex::decode(encoded)
        .map(Zeroizing::new)
        .map_err(|error| format!("invalid hex for {name}: {error}"))
}

fn wrapped_dek_from_args(
    arguments: &Value,
    encrypted_field: &str,
    nonce_field: &str,
) -> Result<Zeroizing<Vec<u8>>, String> {
    let encrypted = decode_hex(arguments, encrypted_field)?;
    let nonce = decode_hex(arguments, nonce_field)?;
    if nonce.len() != AES_GCM_NONCE_BYTES {
        return Err(format!(
            "{nonce_field} must be exactly {AES_GCM_NONCE_BYTES} bytes"
        ));
    }
    let encrypted_bytes = DEK_WRAPPED_BYTES - AES_GCM_NONCE_BYTES;
    if encrypted.len() != encrypted_bytes {
        return Err(format!(
            "{encrypted_field} must be exactly {encrypted_bytes} bytes"
        ));
    }
    let mut wrapped = Zeroizing::new(Vec::with_capacity(DEK_WRAPPED_BYTES));
    wrapped.extend_from_slice(&nonce);
    wrapped.extend_from_slice(&encrypted);
    Ok(wrapped)
}

fn encode_chained_secret(result: ChainedSecretCiphertext) -> Value {
    let mut wire = Zeroizing::new(Vec::with_capacity(
        result.wrapped_dek.len() + result.secret_nonce.len() + result.ciphertext.len(),
    ));
    wire.extend_from_slice(&result.wrapped_dek);
    wire.extend_from_slice(&result.secret_nonce);
    wire.extend_from_slice(&result.ciphertext);
    Value::String(hex::encode(&wire))
}

fn share_candidate(
    arguments: &Value,
) -> Result<(CustodyTopology, CustodyShareId, Zeroizing<Vec<u8>>), String> {
    let generation = required_u64(arguments, "generation")?;
    let threshold = required_u8(arguments, "threshold")?;
    let slots = required_u8(arguments, "slots")?;
    let slot = required_u8(arguments, "slot")?;
    let share_hex = arguments
        .get("share")
        .and_then(Value::as_str)
        .ok_or_else(|| "missing or invalid share".to_string())?;
    if share_hex.len() != CUSTODY_V1_SHARE_BYTES * 2 {
        return Err(format!(
            "share must encode exactly {CUSTODY_V1_SHARE_BYTES} bytes"
        ));
    }
    let mut share = Zeroizing::new(vec![0u8; CUSTODY_V1_SHARE_BYTES]);
    hex::decode_to_slice(share_hex, share.as_mut_slice())
        .map_err(|_| "share must be valid hexadecimal".to_string())?;
    let topology = CustodyTopology::new(threshold, slots).map_err(|error| error.to_string())?;
    let identity =
        CustodyShareId::new(generation, slot, topology).map_err(|error| error.to_string())?;
    Ok((topology, identity, share))
}

fn install_share(state: &CustodianState, arguments: &Value) -> Result<Value, String> {
    if !state.is_sealed()? {
        return Err("vault must be sealed to install a custody share".to_string());
    }
    let (topology, identity, share) = share_candidate(arguments)?;
    let outcome = state.share.install(topology, identity, &share)?;
    state.persist_share_state()?;
    Ok(Value::String(
        match outcome {
            ShareInstallOutcome::Installed => "installed",
            ShareInstallOutcome::AlreadyInstalled => "already-installed",
        }
        .to_string(),
    ))
}

fn prepare_share(state: &CustodianState, arguments: &Value) -> Result<Value, String> {
    if !state.is_sealed()? {
        return Err("vault must be sealed to prepare a custody share".to_string());
    }
    let (topology, identity, share) = share_candidate(arguments)?;
    let outcome = state.share.prepare(topology, identity, &share)?;
    state.persist_share_state()?;
    Ok(Value::String(
        match outcome {
            SharePrepareOutcome::Prepared => "prepared",
            SharePrepareOutcome::AlreadyPrepared => "already-prepared",
            SharePrepareOutcome::AlreadyCommitted => "already-committed",
        }
        .to_string(),
    ))
}

fn commit_share(state: &CustodianState, arguments: &Value) -> Result<Value, String> {
    if !state.is_sealed()? {
        return Err("vault must be sealed to commit a custody share".to_string());
    }
    let outcome = state.share.commit(required_u64(arguments, "generation")?)?;
    state.persist_share_state()?;
    state.reshare.clear()?;
    Ok(Value::String(
        match outcome {
            ShareCommitOutcome::Committed => "committed",
            ShareCommitOutcome::AlreadyCommitted => "already-committed",
        }
        .to_string(),
    ))
}

fn rollback_share(state: &CustodianState, arguments: &Value) -> Result<Value, String> {
    if !state.is_sealed()? {
        return Err("vault must be sealed to roll back a custody share".to_string());
    }
    let outcome = state
        .share
        .rollback(required_u64(arguments, "generation")?)?;
    state.persist_share_state()?;
    state.reshare.clear()?;
    Ok(Value::String(
        match outcome {
            ShareRollbackOutcome::RolledBack => "rolled-back",
            ShareRollbackOutcome::AlreadyRolledBack => "already-rolled-back",
        }
        .to_string(),
    ))
}

fn finalize_share(state: &CustodianState, arguments: &Value) -> Result<Value, String> {
    if !state.is_sealed()? {
        return Err("vault must be sealed to finalize a custody share".to_string());
    }
    let outcome = state
        .share
        .finalize(required_u64(arguments, "generation")?)?;
    state.persist_share_state()?;
    state.reshare.clear()?;
    Ok(Value::String(
        match outcome {
            ShareFinalizeOutcome::Finalized => "finalized",
            ShareFinalizeOutcome::AlreadyFinalized => "already-finalized",
        }
        .to_string(),
    ))
}

fn pending_reshare_value(pending: &PendingReshare) -> Value {
    let deliveries: Vec<Value> = pending
        .deliveries
        .iter()
        .map(|(slot, envelope)| {
            json!({
                "envelope": hex::encode(envelope.as_slice()),
                "slot": slot,
            })
        })
        .collect();
    json!({
        "deliveries": deliveries,
        "generation": pending.generation,
        "slots": pending.topology.slots(),
        "threshold": pending.topology.threshold(),
    })
}

fn generate_reshare(state: &CustodianState, arguments: &Value) -> Result<Value, String> {
    if state.is_sealed()? {
        return Err("vault must be unsealed to generate a custody reshare".to_string());
    }
    let generation = required_u64(arguments, "generation")?;
    let (runtime_generation, runtime) = state
        .runtime
        .snapshot()?
        .ok_or_else(|| "vault sealed".to_string())?;
    if generation <= runtime_generation {
        return Err("custody reshare generation must be newer than runtime".to_string());
    }
    let mut cached = state
        .reshare
        .pending
        .lock()
        .map_err(|error| format!("custodian reshare cache lock poisoned: {error}"))?;
    let topology = state.share.topology();
    if let Some(pending) = cached.as_ref() {
        if pending.generation != generation || pending.topology != topology {
            return Err("another custody reshare generation is pending".to_string());
        }
        state.persist_share_state()?;
        return Ok(pending_reshare_value(pending));
    }

    let local_slot = state.share.slot();
    let shares = shamir::split_locked_with_fill(
        runtime.as_slice(),
        topology.threshold(),
        topology.slots(),
        |buffer| {
            getrandom::getrandom(buffer)
                .map_err(|_| "operating system random source failed".to_string())
        },
    )?;
    let mut deliveries = Vec::with_capacity(topology.slots() as usize - 1);
    for share in &shares {
        let slot = share.as_slice()[0];
        if slot == local_slot {
            continue;
        }
        let envelope = seal_reshare_delivery(
            &state.transport_key,
            &state.transport_peers,
            generation,
            slot,
            share,
        )?;
        deliveries.push((slot, envelope));
    }
    let local_share = shares
        .iter()
        .find(|share| share.as_slice()[0] == local_slot)
        .ok_or_else(|| "native reshare omitted the coordinator slot".to_string())?;
    let local_identity =
        CustodyShareId::new(generation, local_slot, topology).map_err(|error| error.to_string())?;
    state
        .share
        .prepare(topology, local_identity, local_share.as_slice())?;
    let pending = PendingReshare {
        generation,
        topology,
        deliveries,
    };
    let response = pending_reshare_value(&pending);
    *cached = Some(pending);
    state.persist_share_state()?;
    Ok(response)
}

fn topology_reshare_target(
    state: &CustodianState,
    arguments: &Value,
) -> Result<ReshareTargetPeers, String> {
    let topology = CustodyTopology::new(
        required_u8(arguments, "threshold")?,
        required_u8(arguments, "slots")?,
    )
    .map_err(|error| error.to_string())?;
    let entries = arguments
        .get("peer_keys")
        .and_then(Value::as_array)
        .ok_or_else(|| "missing or invalid peer_keys".to_string())?;
    let mut recipients = Vec::with_capacity(entries.len());
    for entry in entries {
        let slot = required_u8(entry, "slot")?;
        let encoded = required_str(entry, "key")?;
        if encoded.len() != CUSTODY_TRANSPORT_KEY_BYTES * 2 {
            return Err(format!(
                "peer key must encode exactly {CUSTODY_TRANSPORT_KEY_BYTES} bytes"
            ));
        }
        let mut public_key = [0u8; CUSTODY_TRANSPORT_KEY_BYTES];
        hex::decode_to_slice(encoded, &mut public_key)
            .map_err(|_| "peer key must be valid hexadecimal".to_string())?;
        recipients.push((slot, TransportPublicKey::from_bytes(public_key)?));
    }
    ReshareTargetPeers::new(
        &state.transport_peers,
        &state.transport_key,
        topology,
        &recipients,
    )
}

/// Split the runtime bundle for a topology this pool does not run yet.
///
/// Every target slot gets one opaque envelope, the coordinator's own slot
/// included: a fixed slot only accepts shares of its launch topology, so the
/// coordinator can no more install its new share than a peer can. Nothing here
/// touches the local share, which keeps the current generation for the whole
/// ceremony -- reverting the environment and restarting is a complete rollback
/// until the operator relaunches the pool under the target topology.
fn generate_topology_reshare(state: &CustodianState, arguments: &Value) -> Result<Value, String> {
    if state.is_sealed()? {
        return Err("vault must be unsealed to generate a custody topology reshare".to_string());
    }
    let generation = required_u64(arguments, "generation")?;
    let target = topology_reshare_target(state, arguments)?;
    let (runtime_generation, runtime) = state
        .runtime
        .snapshot()?
        .ok_or_else(|| "vault sealed".to_string())?;
    if generation <= runtime_generation {
        return Err("custody reshare generation must be newer than runtime".to_string());
    }
    let identities = state.share.identities()?;
    if identities.prepared().is_some() || identities.previous().is_some() {
        return Err("custody share transaction is already in progress".to_string());
    }
    let mut cached = state
        .reshare
        .pending
        .lock()
        .map_err(|error| format!("custodian reshare cache lock poisoned: {error}"))?;
    if let Some(pending) = cached.as_ref() {
        if pending.generation != generation || pending.topology != target.topology() {
            return Err("another custody reshare generation is pending".to_string());
        }
        return Ok(pending_reshare_value(pending));
    }

    let shares = shamir::split_locked_with_fill(
        runtime.as_slice(),
        target.topology().threshold(),
        target.topology().slots(),
        |buffer| {
            getrandom::getrandom(buffer)
                .map_err(|_| "operating system random source failed".to_string())
        },
    )?;
    let mut deliveries = Vec::with_capacity(target.topology().slots() as usize);
    for share in &shares {
        let slot = share.as_slice()[0];
        let envelope =
            seal_topology_reshare_delivery(&state.transport_key, &target, generation, slot, share)?;
        deliveries.push((slot, envelope));
    }
    if deliveries.len() != target.topology().slots() as usize {
        return Err("native topology reshare produced an incomplete delivery set".to_string());
    }
    let pending = PendingReshare {
        generation,
        topology: target.topology(),
        deliveries,
    };
    let response = pending_reshare_value(&pending);
    *cached = Some(pending);
    Ok(response)
}

/// Install the delivery addressed to this slot after the operator restarted
/// the pool under the target topology.
///
/// The share is one of this daemon's OWN launch topology, so it enters through
/// the ordinary install path and the fixed-slot topology guard never has to be
/// relaxed. There is no prepare/commit here because within the new topology
/// there is nothing to roll back to: rollback is reverting the environment and
/// restarting, which the untouched old share-state files still allow.
fn accept_topology_reshare(state: &CustodianState, arguments: &Value) -> Result<Value, String> {
    if !state.is_sealed()? {
        return Err("vault must be sealed to accept a custody topology reshare".to_string());
    }
    let generation = required_u64(arguments, "generation")?;
    let envelope = decode_hex(arguments, "envelope")?;
    if envelope.len() != CUSTODY_TOPOLOGY_RESHARE_ENVELOPE_BYTES {
        return Err(format!(
            "custody topology reshare envelope must be exactly \
             {CUSTODY_TOPOLOGY_RESHARE_ENVELOPE_BYTES} bytes"
        ));
    }
    let (identity, share) = open_topology_reshare_delivery(
        &state.transport_key,
        &state.transport_peers,
        generation,
        &envelope,
    )?;
    let outcome =
        state
            .share
            .install_topology_change(state.share.topology(), identity, share.as_slice())?;
    state.persist_share_state()?;
    Ok(Value::String(
        match outcome {
            ShareInstallOutcome::Installed => "installed",
            ShareInstallOutcome::AlreadyInstalled => "already-installed",
        }
        .to_string(),
    ))
}

fn accept_reshare(state: &CustodianState, arguments: &Value) -> Result<Value, String> {
    if !state.is_sealed()? {
        return Err("vault must be sealed to accept a custody reshare".to_string());
    }
    let generation = required_u64(arguments, "generation")?;
    let envelope = decode_hex(arguments, "envelope")?;
    if envelope.len() != CUSTODY_RESHARE_ENVELOPE_BYTES {
        return Err(format!(
            "custody reshare envelope must be exactly {CUSTODY_RESHARE_ENVELOPE_BYTES} bytes"
        ));
    }
    let (identity, share) = open_reshare_delivery(
        &state.transport_key,
        &state.transport_peers,
        generation,
        &envelope,
    )?;
    let outcome = state
        .share
        .prepare(state.share.topology(), identity, share.as_slice())?;
    state.persist_share_state()?;
    Ok(Value::String(
        match outcome {
            SharePrepareOutcome::Prepared => "prepared",
            SharePrepareOutcome::AlreadyPrepared => "already-prepared",
            SharePrepareOutcome::AlreadyCommitted => "already-committed",
        }
        .to_string(),
    ))
}

fn share_contribution(state: &CustodianState, arguments: &Value) -> Result<Value, String> {
    if !state.is_sealed()? {
        return Err("vault must be sealed to contribute a custody share".to_string());
    }
    let recipient_slot = required_u8(arguments, "recipient_slot")?;
    let selected = match arguments.get("generation") {
        Some(_) => state
            .share
            .snapshot_generation(required_u64(arguments, "generation")?)?,
        None => state.share.snapshot()?,
    };
    let (identity, share) = selected
        .ok_or_else(|| "requested custodian share generation is not installed".to_string())?;
    let envelope = seal_share_contribution(
        &state.transport_key,
        &state.transport_peers,
        identity,
        recipient_slot,
        &share,
    )?;
    Ok(Value::String(hex::encode(envelope.as_slice())))
}

fn unseal(state: &CustodianState, arguments: &Value) -> Result<Value, String> {
    let selected = match arguments.get("generation") {
        Some(_) => state
            .share
            .snapshot_generation(required_u64(arguments, "generation")?)?,
        None => state.share.snapshot()?,
    };
    let (local_identity, local_share) = selected
        .ok_or_else(|| "requested custodian share generation is not installed".to_string())?;
    let topology = state.share.topology();
    let contributions = arguments
        .get("contributions")
        .and_then(Value::as_array)
        .ok_or_else(|| "missing or invalid contributions".to_string())?;
    let expected = topology.threshold() as usize - 1;
    if contributions.len() != expected {
        return Err(format!(
            "unseal requires exactly {expected} remote contributions"
        ));
    }

    let mut collector = QuorumCollector::new(topology, local_identity.generation())?;
    collector.add(topology, local_identity, local_share)?;
    for contribution in contributions {
        let encoded = contribution
            .as_str()
            .ok_or_else(|| "custody contribution must be hexadecimal".to_string())?;
        if encoded.len() != CUSTODY_SHARE_ENVELOPE_BYTES * 2 {
            return Err(format!(
                "custody contribution must encode exactly {CUSTODY_SHARE_ENVELOPE_BYTES} bytes"
            ));
        }
        let mut envelope = Zeroizing::new(vec![0u8; CUSTODY_SHARE_ENVELOPE_BYTES]);
        hex::decode_to_slice(encoded, envelope.as_mut_slice())
            .map_err(|_| "custody contribution must be valid hexadecimal".to_string())?;
        let (identity, share) = open_share_contribution(
            &state.transport_key,
            &state.transport_peers,
            local_identity.generation(),
            &envelope,
        )?;
        collector.add(topology, identity, share)?;
    }

    let runtime = collector.reconstruct()?;
    let outcome = state
        .runtime
        .install(local_identity.generation(), runtime)?;
    Ok(json!({
        "generation": local_identity.generation(),
        "state": match outcome {
            RuntimeInstallOutcome::Loaded => "unsealed",
            RuntimeInstallOutcome::AlreadyLoaded => "already-unsealed"
        }
    }))
}

fn seal(state: &CustodianState) -> Result<Value, String> {
    state.runtime.clear()?;
    Ok(Value::String(String::new()))
}

fn clear_share(state: &CustodianState) -> Result<Value, String> {
    if !state.is_sealed()? {
        return Err("vault must be sealed to clear a custody share".to_string());
    }
    state.share.clear()?;
    state.persist_share_state()?;
    state.reshare.clear()?;
    Ok(Value::String(String::new()))
}

fn dispatch_operation(
    state: &CustodianState,
    control_authorized: bool,
    operation: &str,
    arguments: &Value,
) -> Result<Value, String> {
    if matches!(
        operation,
        "clear_ha_password"
            | "clear_prev_hmac"
            | "clear_prev_hmac_if_envelope"
            | "install_ha_password"
            | "install_prev_hmac"
            | "replace_ha_password"
            | "set_ha_password_from_plain"
            | "install_share"
            | "prepare_share"
            | "generate_reshare"
            | "accept_reshare"
            | "generate_topology_reshare"
            | "accept_topology_reshare"
            | "commit_share"
            | "rollback_share"
            | "finalize_share"
            | "clear_share"
            | "share_contribution"
            | "unseal"
            | "seal"
            | "install_audit_identity"
            | "generate_audit_identity"
    ) && !control_authorized
    {
        return Err("invalid control capability".to_string());
    }
    let runtime_generation = state.runtime.generation()?;
    let sealed = runtime_generation.is_none();
    match operation {
        "status" => Ok(json!({
            "audit_identity_loaded": state.runtime.audit_identity_loaded()?,
            "generation": runtime_generation,
            "ha_password_loaded": state.runtime.ha_password_loaded()?,
            "previous_hmac_loaded": state.runtime.previous_hmac_loaded()?,
            "protocol_version": CUSTODY_PROTOCOL_VERSION,
            "state": if sealed { "sealed" } else { "unsealed" }
        })),
        "share_status" => {
            let identities = state.share.identities()?;
            let topology = state.share.topology();
            let reshare = state.reshare.pending_summary()?;
            Ok(json!({
                "generation": identities.active().map(CustodyShareId::generation),
                "memory_protection": memory_lock_status(),
                "prepared_generation": identities.prepared().map(CustodyShareId::generation),
                "previous_generation": identities.previous().map(CustodyShareId::generation),
                "reshare_generation": reshare.map(|(generation, _)| generation),
                "reshare_slots": reshare.map(|(_, target)| target.slots()),
                "reshare_threshold": reshare.map(|(_, target)| target.threshold()),
                "slot": state.share.slot(),
                "slots": topology.slots(),
                "threshold": topology.threshold(),
                "transport_public_key": hex::encode(state.transport_key.public_key().as_bytes())
            }))
        }
        "install_share" => install_share(state, arguments),
        "prepare_share" => prepare_share(state, arguments),
        "generate_reshare" => generate_reshare(state, arguments),
        "accept_reshare" => accept_reshare(state, arguments),
        "generate_topology_reshare" => generate_topology_reshare(state, arguments),
        "accept_topology_reshare" => accept_topology_reshare(state, arguments),
        "commit_share" => commit_share(state, arguments),
        "rollback_share" => rollback_share(state, arguments),
        "finalize_share" => finalize_share(state, arguments),
        "clear_share" => clear_share(state),
        "share_contribution" => share_contribution(state, arguments),
        "unseal" => unseal(state, arguments),
        "seal" => seal(state),
        "generate_audit_identity" => {
            if sealed {
                return Err("vault must be unsealed to generate an audit identity".to_string());
            }
            let generated = state.runtime.generate_audit_identity_envelope()?;
            Ok(json!({
                "public_key": hex::encode(generated.public_key),
                "wrapped_seed": hex::encode(generated.wrapped_seed),
            }))
        }
        "install_audit_identity" => {
            if sealed {
                return Err("vault must be unsealed to install an audit identity".to_string());
            }
            let wrapped_seed = decode_hex(arguments, "wrapped_seed")?;
            let expected_public_key = decode_hex(arguments, "expected_public_key")?;
            let outcome = state
                .runtime
                .install_audit_identity(&wrapped_seed, &expected_public_key)?;
            let install_state = match outcome {
                AuditIdentityInstallOutcome::Loaded => "installed",
                AuditIdentityInstallOutcome::AlreadyLoaded => "already-installed",
            };
            Ok(json!({
                "public_key": hex::encode(state.runtime.audit_identity_public_key()?),
                "state": install_state
            }))
        }
        "install_prev_hmac" => {
            if sealed {
                return Err("vault must be unsealed to install a previous HMAC key".to_string());
            }
            let wrapped_key = decode_hex(arguments, "wrapped_key")?;
            let outcome = state.runtime.install_previous_hmac_envelope(&wrapped_key)?;
            Ok(Value::String(
                match outcome {
                    PreviousHmacInstallOutcome::Loaded => "installed",
                    PreviousHmacInstallOutcome::AlreadyLoaded => "already-installed",
                }
                .to_string(),
            ))
        }
        "clear_prev_hmac" => state
            .runtime
            .clear_previous_hmac()
            .map(|()| Value::String(String::new())),
        "clear_prev_hmac_if_envelope" => {
            let expected_wrapped_key = decode_hex(arguments, "wrapped_key")?;
            let cleared = state
                .runtime
                .clear_previous_hmac_if_envelope(&expected_wrapped_key)?;
            Ok(Value::String(
                if cleared { "cleared" } else { "stale" }.to_string(),
            ))
        }
        "install_ha_password" => {
            if sealed {
                return Err("vault must be unsealed to install an HA password".to_string());
            }
            let wrapped = decode_hex(arguments, "wrapped")?;
            let outcome = state.runtime.install_ha_password_envelope(&wrapped)?;
            Ok(Value::String(
                match outcome {
                    HaPasswordInstallOutcome::Loaded => "installed",
                    HaPasswordInstallOutcome::AlreadyLoaded => "already-installed",
                }
                .to_string(),
            ))
        }
        "replace_ha_password" => {
            if sealed {
                return Err("vault must be unsealed to replace an HA password".to_string());
            }
            let wrapped = decode_hex(arguments, "wrapped")?;
            state.runtime.replace_ha_password_envelope(&wrapped)?;
            Ok(Value::String(String::new()))
        }
        "set_ha_password_from_plain" => {
            let plain = decode_hex(arguments, "plain")?;
            state.runtime.replace_ha_password(&plain)?;
            Ok(Value::String(String::new()))
        }
        "has_ha_password" => {
            if sealed {
                return Err("vault sealed".to_string());
            }
            state
                .runtime
                .ha_password_loaded()
                .map(|loaded| Value::String(if loaded { "1" } else { "0" }.to_string()))
        }
        "clear_ha_password" => state
            .runtime
            .clear_ha_password()
            .map(|()| Value::String(String::new())),
        "ha_password_hmac" => {
            let message = decode_hex(arguments, "message")?;
            state
                .runtime
                .ha_password_hmac(&message)
                .map(hex::encode)
                .map(Value::String)
        }
        "wrap_node_key_for_joiner" => {
            let key_pem = decode_hex(arguments, "node_key_pem")?;
            let node_uuid = required_str(arguments, "node_uuid")?;
            state
                .runtime
                .wrap_node_key_for_joiner(&key_pem, node_uuid)
                .map(hex::encode)
                .map(Value::String)
        }
        "wrap_server_key_for_joiner" => {
            let key_pem = decode_hex(arguments, "server_key_pem")?;
            let node_uuid = required_str(arguments, "node_uuid")?;
            state
                .runtime
                .wrap_server_key_for_joiner(&key_pem, node_uuid)
                .map(hex::encode)
                .map(Value::String)
        }
        "hmac_sha512" => {
            if sealed {
                return Err("vault sealed".to_string());
            }
            let message = decode_hex(arguments, "message")?;
            state
                .runtime
                .hmac_sha512(&message)
                .map(hex::encode)
                .map(Value::String)
        }
        "hmac_sha512_prev" => {
            if sealed {
                return Err("vault sealed".to_string());
            }
            let message = decode_hex(arguments, "message")?;
            state
                .runtime
                .previous_hmac_sha512(&message)
                .map(|signature| {
                    Value::String(signature.map(hex::encode).unwrap_or_else(String::new))
                })
        }
        "audit_sign" => {
            if sealed {
                return Err("vault sealed".to_string());
            }
            let payload = arguments
                .get("payload")
                .and_then(Value::as_str)
                .ok_or_else(|| "missing payload".to_string())?;
            let prev_signature = arguments
                .get("prev_signature")
                .and_then(Value::as_str)
                .unwrap_or("");
            state
                .runtime
                .audit_sign(payload, prev_signature)
                .map(hex::encode)
                .map(Value::String)
        }
        "audit_sign_identity" => {
            if sealed {
                return Err("vault sealed".to_string());
            }
            let payload = arguments
                .get("payload")
                .and_then(Value::as_str)
                .ok_or_else(|| "missing payload".to_string())?;
            let prev_signature = arguments
                .get("prev_signature")
                .and_then(Value::as_str)
                .unwrap_or("");
            state
                .runtime
                .audit_sign_identity(payload, prev_signature)
                .map(hex::encode)
                .map(Value::String)
        }
        "audit_sign_raw" => {
            if sealed {
                return Err("vault sealed".to_string());
            }
            let message = decode_hex(arguments, "message")?;
            state
                .runtime
                .audit_sign_identity_raw(&message)
                .map(hex::encode)
                .map(Value::String)
        }
        "aesgcm_encrypt" => {
            if sealed {
                return Err("vault sealed".to_string());
            }
            let plaintext = decode_hex(arguments, "plaintext")?;
            let aad = decode_hex(arguments, "aad")?;
            state
                .runtime
                .aesgcm_encrypt(&plaintext, &aad)
                .map(hex::encode)
                .map(Value::String)
        }
        "aesgcm_decrypt" => {
            if sealed {
                return Err("vault sealed".to_string());
            }
            let ciphertext = decode_hex(arguments, "ciphertext")?;
            let nonce = decode_hex(arguments, "nonce")?;
            if nonce.len() != AES_GCM_NONCE_BYTES {
                return Err(format!("nonce must be exactly {AES_GCM_NONCE_BYTES} bytes"));
            }
            let aad = decode_hex(arguments, "aad")?;
            let capacity = nonce
                .len()
                .checked_add(ciphertext.len())
                .ok_or_else(|| "ciphertext is too large".to_string())?;
            let mut wrapped = Zeroizing::new(Vec::with_capacity(capacity));
            wrapped.extend_from_slice(&nonce);
            wrapped.extend_from_slice(&ciphertext);
            state
                .runtime
                .aesgcm_decrypt(&wrapped, &aad)
                .map(|plaintext| Value::String(hex::encode(plaintext.as_slice())))
        }
        "ha_wrap_encrypt" => {
            if sealed {
                return Err("vault sealed".to_string());
            }
            let plaintext = decode_hex(arguments, "plaintext")?;
            let aad = decode_hex(arguments, "aad")?;
            state
                .runtime
                .ha_wrap_encrypt(&plaintext, &aad)
                .map(hex::encode)
                .map(Value::String)
        }
        "ha_wrap_decrypt" => {
            if sealed {
                return Err("vault sealed".to_string());
            }
            let wrapped = decode_hex(arguments, "wrapped")?;
            let aad = decode_hex(arguments, "aad")?;
            state
                .runtime
                .ha_wrap_decrypt(&wrapped, &aad)
                .map(|plaintext| Value::String(hex::encode(plaintext.as_slice())))
        }
        "pki_wrap_encrypt" => {
            if sealed {
                return Err("vault sealed".to_string());
            }
            let plaintext = decode_hex(arguments, "plaintext")?;
            let aad = decode_hex(arguments, "aad")?;
            state
                .runtime
                .pki_wrap_encrypt(&plaintext, &aad)
                .map(hex::encode)
                .map(Value::String)
        }
        "pki_wrap_decrypt" => {
            if sealed {
                return Err("vault sealed".to_string());
            }
            let wrapped = decode_hex(arguments, "wrapped")?;
            let aad = decode_hex(arguments, "aad")?;
            state
                .runtime
                .pki_wrap_decrypt(&wrapped, &aad)
                .map(|plaintext| Value::String(hex::encode(plaintext.as_slice())))
        }
        "secret_encrypt" => {
            if sealed {
                return Err("vault sealed".to_string());
            }
            let plaintext = decode_hex(arguments, "plaintext")?;
            let dek_aad = decode_hex(arguments, "dek_aad")?;
            let secret_aad = decode_hex(arguments, "secret_aad")?;
            state
                .runtime
                .chained_secret_encrypt(&plaintext, &dek_aad, &secret_aad)
                .map(encode_chained_secret)
        }
        "secret_decrypt" => {
            if sealed {
                return Err("vault sealed".to_string());
            }
            let wrapped_dek = wrapped_dek_from_args(arguments, "encrypted_dek", "dek_nonce")?;
            let dek_aad = decode_hex(arguments, "dek_aad")?;
            let ciphertext = decode_hex(arguments, "ciphertext")?;
            let secret_nonce = decode_hex(arguments, "secret_nonce")?;
            let secret_aad = decode_hex(arguments, "secret_aad")?;
            state
                .runtime
                .chained_secret_decrypt(
                    &wrapped_dek,
                    &dek_aad,
                    &ciphertext,
                    &secret_nonce,
                    &secret_aad,
                )
                .map(|plaintext| Value::String(hex::encode(plaintext.as_slice())))
        }
        "secret_reencrypt" => {
            if sealed {
                return Err("vault sealed".to_string());
            }
            let old_wrapped_dek =
                wrapped_dek_from_args(arguments, "old_encrypted_dek", "old_dek_nonce")?;
            let old_dek_aad = decode_hex(arguments, "old_dek_aad")?;
            let old_ciphertext = decode_hex(arguments, "old_ciphertext")?;
            let old_secret_nonce = decode_hex(arguments, "old_secret_nonce")?;
            let old_secret_aad = decode_hex(arguments, "old_secret_aad")?;
            let new_dek_aad = decode_hex(arguments, "new_dek_aad")?;
            let new_secret_aad = decode_hex(arguments, "new_secret_aad")?;
            state
                .runtime
                .chained_secret_reencrypt(ChainedSecretReencryptInput {
                    old_wrapped_dek: &old_wrapped_dek,
                    old_dek_aad: &old_dek_aad,
                    old_ciphertext: &old_ciphertext,
                    old_secret_nonce: &old_secret_nonce,
                    old_secret_aad: &old_secret_aad,
                    new_dek_aad: &new_dek_aad,
                    new_secret_aad: &new_secret_aad,
                })
                .map(encode_chained_secret)
        }
        operation => Err(format!("unknown op: {operation}")),
    }
}

fn serve_connection(
    mut stream: UnixStream,
    owner_uid: u32,
    state: &CustodianState,
) -> io::Result<()> {
    stream.set_read_timeout(Some(SOCKET_IO_TIMEOUT))?;
    stream.set_write_timeout(Some(SOCKET_IO_TIMEOUT))?;
    let (peer_uid, _) = read_peer_cred(&stream)?;
    if peer_uid != owner_uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "custodian peer UID does not match socket owner",
        ));
    }
    let frame = read_frame(&mut stream, MAX_RPC_FRAME_BYTES)?;
    let parsed_request = serde_json::from_slice::<Value>(&frame);
    drop(frame);
    let response = match parsed_request {
        Ok(request) => {
            let control_authorized = state
                .control_capability
                .authorizes(request.get("capability").and_then(Value::as_str));
            dispatch_request(request, |operation, arguments| {
                dispatch_operation(state, control_authorized, operation, arguments)
            })
        }
        Err(_) => error_response("invalid JSON request"),
    };
    let response_bytes = response.to_bytes();
    write_frame(&mut stream, &response_bytes, MAX_RPC_FRAME_BYTES)
}

fn run(config: Config) -> io::Result<()> {
    let socket = BoundSocket::bind(&config.socket_path)?;
    let capability = load_control_capability(&config.control_token_file, socket.owner_uid)?;
    let transport_key = load_transport_private_key(&config.transport_key_file, socket.owner_uid)?;
    let local_public_key = transport_key.public_key();
    if config
        .peer_keys
        .iter()
        .any(|(_, peer_key)| *peer_key == local_public_key)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "transport public key is assigned to both local and remote slots",
        ));
    }
    let transport_peers = TransportPeerSet::new(config.topology, config.slot, &config.peer_keys)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let mut state = CustodianState::sealed(
        capability,
        config.topology,
        config.slot,
        transport_key,
        transport_peers,
    )
    .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    if let Some(share_state_file) = config.share_state_file {
        state
            .enable_share_persistence(
                share_state_file,
                config.adopt_share_state_file,
                socket.owner_uid,
            )
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    }
    if config.once {
        let (stream, _) = socket.listener.accept()?;
        let _ = serve_connection(stream, socket.owner_uid, &state);
        return Ok(());
    }

    // Several accept threads share one listener: the kernel hands each
    // connection to exactly one of them, so no queue of our own is needed.
    // The pool is bounded because the socket is reachable by any process
    // running as the socket owner, and thread-per-connection would turn that
    // into a local exhaustion lever.
    let state = Arc::new(state);
    let socket = Arc::new(socket);
    let mut workers = Vec::with_capacity(usize::from(config.threads));
    for _ in 0..config.threads {
        let state = Arc::clone(&state);
        let socket = Arc::clone(&socket);
        workers.push(thread::spawn(move || {
            serve_forever(&socket, &state);
        }));
    }
    for worker in workers {
        // A worker only returns once its listener is unusable, and a panicking
        // worker aborts the process before it can get here (see serve_forever),
        // so a join error still means this custodian must not keep serving.
        if worker.join().is_err() {
            return Err(io::Error::other("custodian accept worker panicked"));
        }
    }
    Err(io::Error::other("custodian listener stopped accepting"))
}

/// Accept and serve until the listener fails. A panic here is fatal to the
/// whole process on purpose: single-threaded, a panic in `serve_connection`
/// unwound out of `main` and the supervisor restarted a clean daemon. Letting
/// one worker die quietly instead would silently shrink the pool AND leave the
/// state mutexes poisoned, so every later request would fail anyway -- a
/// half-dead custodian that still answers is worse than a restarted one.
fn serve_forever(socket: &BoundSocket, state: &CustodianState) {
    loop {
        let accepted = socket.listener.accept();
        let panicked = panic::catch_unwind(AssertUnwindSafe(|| match accepted {
            Ok((stream, _)) => {
                let _ = serve_connection(stream, socket.owner_uid, state);
                true
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => true,
            Err(error) => {
                eprintln!("[rhorizon] custodian accept failed: {error}");
                false
            }
        }));
        match panicked {
            Ok(true) => {}
            Ok(false) => return,
            Err(_) => {
                eprintln!("[rhorizon] custodian worker panicked; terminating daemon");
                process::exit(101);
            }
        }
    }
}

fn main() {
    let arguments: Vec<String> = env::args().collect();
    let offline = OfflineCommand::parse(&arguments).unwrap_or_else(|error| {
        eprintln!("{error}");
        std::process::exit(2);
    });
    if let Some(command) = offline {
        let result = match command {
            OfflineCommand::GenerateControlToken(path) => {
                generate_control_token_file(&path).map(|()| None)
            }
            OfflineCommand::GenerateTransportKey(path) => {
                generate_transport_key_file(&path).map(Some)
            }
            OfflineCommand::PrintTransportPublicKey(path) => {
                print_transport_public_key(&path).map(Some)
            }
        };
        match result {
            Ok(Some(public_key)) => println!("{}", hex::encode(public_key.as_bytes())),
            Ok(None) => {}
            Err(error) => {
                eprintln!("rhorizon-custodian: {error}");
                std::process::exit(1);
            }
        }
        return;
    }
    let config = Config::parse(arguments).unwrap_or_else(|error| {
        eprintln!("{error}");
        std::process::exit(2);
    });
    if let Err(error) = run(config) {
        eprintln!("rhorizon-custodian: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
// The private-file checks (owner, mode, symlink refusal, atomic replacement)
// and the encrypted share-state persistence need real `open`/`stat`/`rename`
// syscalls, which miri refuses under isolation. They are
// `#[cfg_attr(miri, ignore)]` like the socket and mlock tests in the PyO3
// crate; miri still covers this crate's pure-logic and unsafe paths (framing,
// state machine, reshare, zeroizing buffers) under `cargo +nightly miri test`.
mod tests {
    use super::*;
    use rhorizon_custody_core::shamir;
    use rhorizon_custody_core::transport::{open_share_contribution, CUSTODY_SHARE_ENVELOPE_BYTES};
    use std::io::{Cursor, Write};

    const TEST_CAPABILITY: &str = "0123456789abcdef0123456789abcdef";

    fn test_transport_key(slot: u8) -> TransportPrivateKey {
        TransportPrivateKey::from_slice(&[0x10 + slot; CUSTODY_TRANSPORT_KEY_BYTES])
            .expect("test transport key")
    }

    fn test_peer_keys(local_slot: u8) -> Vec<(u8, TransportPublicKey)> {
        (1..=3)
            .filter(|slot| *slot != local_slot)
            .map(|slot| (slot, test_transport_key(slot).public_key()))
            .collect()
    }

    fn test_peer_set(local_slot: u8) -> TransportPeerSet {
        TransportPeerSet::new(
            CustodyTopology::new(2, 3).expect("test topology"),
            local_slot,
            &test_peer_keys(local_slot),
        )
        .expect("test peer set")
    }

    fn sealed_state_in(topology: CustodyTopology, slot: u8) -> CustodianState {
        let peers: Vec<(u8, TransportPublicKey)> = (1..=topology.slots())
            .filter(|candidate| *candidate != slot)
            .map(|candidate| (candidate, test_transport_key(candidate).public_key()))
            .collect();
        CustodianState::sealed(
            ControlCapability::new(TEST_CAPABILITY.as_bytes()).expect("test capability"),
            topology,
            slot,
            test_transport_key(slot),
            TransportPeerSet::new(topology, slot, &peers).expect("test peer set"),
        )
        .expect("test state")
    }

    fn sealed_state_for(slot: u8) -> CustodianState {
        sealed_state_in(CustodyTopology::new(2, 3).expect("test topology"), slot)
    }

    fn sealed_state() -> CustodianState {
        sealed_state_for(2)
    }

    fn private_test_dir(label: &str) -> PathBuf {
        let mut random = [0u8; 8];
        getrandom::getrandom(&mut random).expect("test random suffix");
        let path = env::temp_dir().join(format!(
            "rhorizon-custodian-{label}-{}-{}",
            std::process::id(),
            hex::encode(random)
        ));
        fs::create_dir(&path).expect("create private test directory");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .expect("protect test directory");
        path
    }

    fn persistent_state_for(slot: u8, path: &Path) -> CustodianState {
        let mut state = sealed_state_for(slot);
        state
            .enable_share_persistence(path.to_path_buf(), None, current_uid())
            .expect("enable share persistence");
        state
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn control_token_loader_rejects_public_mode_and_symlinks() {
        let path = env::temp_dir().join(format!(
            "rhorizon-custodian-token-test-{}.token",
            std::process::id()
        ));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .expect("create private token");
        file.write_all(TEST_CAPABILITY.as_bytes())
            .expect("write token");
        file.sync_all().expect("sync token");
        let owner_uid = file.metadata().expect("token metadata").uid();
        drop(file);

        let capability = load_control_capability(&path, owner_uid).expect("load private token");
        assert!(capability.authorizes(Some(TEST_CAPABILITY)));

        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("make token public");
        let error = match load_control_capability(&path, owner_uid) {
            Ok(_) => panic!("public token must fail"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        fs::remove_file(&path).expect("remove token");

        std::os::unix::fs::symlink("/dev/null", &path).expect("create token symlink");
        assert!(load_control_capability(&path, owner_uid).is_err());
        fs::remove_file(path).expect("remove token symlink");
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn transport_key_loader_requires_private_regular_hex_file() {
        let path = env::temp_dir().join(format!(
            "rhorizon-custodian-transport-key-test-{}.key",
            std::process::id()
        ));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .expect("create private transport key");
        file.write_all(hex::encode([0x12; CUSTODY_TRANSPORT_KEY_BYTES]).as_bytes())
            .expect("write transport key");
        file.write_all(b"\n").expect("write trailing newline");
        file.sync_all().expect("sync transport key");
        let owner_uid = file.metadata().expect("transport key metadata").uid();
        drop(file);

        let key = load_transport_private_key(&path, owner_uid).expect("load transport key");
        assert_eq!(key.public_key(), test_transport_key(2).public_key());

        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))
            .expect("make transport key public");
        let error = match load_transport_private_key(&path, owner_uid) {
            Ok(_) => panic!("public transport key file must fail"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        fs::remove_file(&path).expect("remove transport key");

        std::os::unix::fs::symlink("/dev/null", &path).expect("create key symlink");
        assert!(load_transport_private_key(&path, owner_uid).is_err());
        fs::remove_file(path).expect("remove key symlink");
    }

    #[test]
    fn offline_transport_key_commands_are_explicit() {
        assert_eq!(
            OfflineCommand::parse(&[
                "custodian".to_string(),
                "generate-control-token".to_string(),
                "--output".to_string(),
                "/tmp/custodian.token".to_string(),
            ]),
            Ok(Some(OfflineCommand::GenerateControlToken(PathBuf::from(
                "/tmp/custodian.token"
            ))))
        );
        assert_eq!(
            OfflineCommand::parse(&[
                "custodian".to_string(),
                "generate-transport-key".to_string(),
                "--output".to_string(),
                "/tmp/custodian.key".to_string(),
            ]),
            Ok(Some(OfflineCommand::GenerateTransportKey(PathBuf::from(
                "/tmp/custodian.key"
            ))))
        );
        assert_eq!(
            OfflineCommand::parse(&[
                "custodian".to_string(),
                "print-transport-public-key".to_string(),
                "--transport-key-file".to_string(),
                "/tmp/custodian.key".to_string(),
            ]),
            Ok(Some(OfflineCommand::PrintTransportPublicKey(
                PathBuf::from("/tmp/custodian.key")
            )))
        );
        assert!(OfflineCommand::parse(&[
            "custodian".to_string(),
            "generate-transport-key".to_string(),
        ])
        .is_err());
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn generated_control_token_is_private_valid_and_never_replaced() {
        let path = env::temp_dir().join(format!(
            "rhorizon-custodian-generated-control-token-test-{}.token",
            std::process::id()
        ));
        generate_control_token_file(&path).expect("generate control token");
        let metadata = fs::metadata(&path).expect("generated token metadata");
        assert!(metadata.file_type().is_file());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        assert_eq!(metadata.len(), 65);

        let original = fs::read(&path).expect("read generated token");
        let capability = load_control_capability(&path, metadata.uid()).expect("load token");
        assert!(capability.authorizes(std::str::from_utf8(original.trim_ascii()).ok()));
        let error = generate_control_token_file(&path).expect_err("existing token must be refused");
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&path).expect("read preserved token"), original);
        fs::remove_file(path).expect("remove generated token");
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn failed_bootstrap_generation_removes_partial_file_and_allows_retry() {
        let path = env::temp_dir().join(format!(
            "rhorizon-custodian-failed-bootstrap-test-{}.token",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);
        let error =
            match generate_private_random_hex_file_with(&path, 32, "failed bootstrap test", |_| {
                Err(io::Error::other("injected entropy failure"))
            }) {
                Ok(_) => panic!("injected bootstrap failure must be returned"),
                Err(error) => error,
            };
        assert_eq!(error.to_string(), "injected entropy failure");
        assert!(!path.exists(), "partial bootstrap file must be removed");

        generate_private_random_hex_file_with(&path, 32, "bootstrap retry test", |output| {
            output.fill(0x5a);
            Ok(())
        })
        .expect("retry bootstrap generation");
        assert_eq!(fs::metadata(&path).expect("retry metadata").len(), 65);
        fs::remove_file(path).expect("remove retry token");
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn generated_transport_key_is_private_and_never_replaced() {
        let path = env::temp_dir().join(format!(
            "rhorizon-custodian-generated-transport-key-test-{}.key",
            std::process::id()
        ));
        let public = generate_transport_key_file(&path).expect("generate transport key");
        let metadata = fs::metadata(&path).expect("generated key metadata");
        assert!(metadata.file_type().is_file());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        assert_eq!(metadata.len(), (CUSTODY_TRANSPORT_KEY_BYTES * 2 + 1) as u64);
        assert_eq!(
            print_transport_public_key(&path).expect("derive public key"),
            public
        );

        let original = fs::read(&path).expect("read generated key");
        let error = generate_transport_key_file(&path).expect_err("existing key must be refused");
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&path).expect("read preserved key"), original);
        fs::remove_file(path).expect("remove generated key");
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn transactional_share_state_survives_full_state_reconstruction() {
        let directory = private_test_dir("share-state");
        let path = directory.join("slot-2.share-state");
        let topology = CustodyTopology::new(2, 3).expect("test topology");
        let mut old_share = vec![0x51; CUSTODY_V1_SHARE_BYTES];
        old_share[0] = 2;
        let mut new_share = vec![0x62; CUSTODY_V1_SHARE_BYTES];
        new_share[0] = 2;
        let args = |generation: u64, share: &[u8]| {
            json!({
                "generation": generation,
                "threshold": topology.threshold(),
                "slots": topology.slots(),
                "slot": 2,
                "share": hex::encode(share),
            })
        };

        {
            let state = persistent_state_for(2, &path);
            install_share(&state, &args(41, &old_share)).expect("persist active share");
            prepare_share(&state, &args(42, &new_share)).expect("persist prepared share");
            commit_share(&state, &json!({"generation": 42})).expect("persist commit");
        }

        let persisted = fs::read(&path).expect("read encrypted share state");
        assert_eq!(persisted.len(), SHARE_STATE_FILE_BYTES);
        assert_eq!(
            fs::metadata(&path)
                .expect("share-state metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert!(!persisted
            .windows(old_share.len())
            .any(|window| window == old_share));
        assert!(!persisted
            .windows(new_share.len())
            .any(|window| window == new_share));

        let restarted = persistent_state_for(2, &path);
        let identities = restarted.share.identities().expect("restored identities");
        assert_eq!(
            identities.active().map(CustodyShareId::generation),
            Some(42)
        );
        assert_eq!(
            identities.previous().map(CustodyShareId::generation),
            Some(41)
        );
        assert_eq!(identities.prepared(), None);
        rollback_share(&restarted, &json!({"generation": 42})).expect("persist rollback");
        drop(restarted);

        let rolled_back = persistent_state_for(2, &path);
        assert_eq!(
            rolled_back
                .share
                .identity()
                .expect("restored active identity")
                .map(CustodyShareId::generation),
            Some(41)
        );
        fs::remove_dir_all(directory).expect("remove test directory");
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn legacy_share_state_is_adopted_once_under_its_own_topology() {
        let directory = private_test_dir("share-state-adopt");
        let legacy = directory.join("slot-2.share-state");
        let scoped = directory.join("slot-2.2-of-3.share-state");
        let written = persistent_state_for(2, &legacy);
        let mut share = vec![0x5A; CUSTODY_V1_SHARE_BYTES];
        share[0] = 2;
        written
            .share
            .install(
                CustodyTopology::new(2, 3).expect("test topology"),
                CustodyShareId::new(77, 2, CustodyTopology::new(2, 3).expect("test topology"))
                    .expect("identity"),
                &share,
            )
            .expect("install legacy generation");
        written.persist_share_state().expect("persist legacy state");
        drop(written);

        let mut adopted = sealed_state_for(2);
        adopted
            .enable_share_persistence(scoped.clone(), Some(legacy.clone()), current_uid())
            .expect("adopt legacy share state");
        assert_eq!(
            adopted
                .share
                .identity()
                .expect("adopted identity")
                .map(CustodyShareId::generation),
            Some(77)
        );
        // Exactly one owner of the state: the topology-scoped copy.
        assert!(scoped.exists());
        assert!(!legacy.exists());

        // A pool relaunched under the reshare target must not swallow the
        // shape it may still revert to.
        let legacy_again = directory.join("slot-2.share-state");
        fs::copy(&scoped, &legacy_again).expect("restore a legacy file");
        let target = CustodyTopology::new(3, 5).expect("target topology");
        let mut relaunched = sealed_state_in(target, 2);
        let error = relaunched
            .enable_share_persistence(
                directory.join("slot-2.3-of-5.share-state"),
                Some(legacy_again.clone()),
                current_uid(),
            )
            .expect_err("a 2-of-3 state is not a 3-of-5 state");
        assert!(error.contains("as a 3-of-5 share state"), "{error}");
        assert!(legacy_again.exists(), "a refused adoption destroys nothing");
        fs::remove_dir_all(directory).expect("remove test directory");
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn persisted_share_tamper_and_public_mode_fail_startup() {
        let directory = private_test_dir("share-state-tamper");
        let path = directory.join("slot-2.share-state");
        drop(persistent_state_for(2, &path));
        let mut envelope = fs::read(&path).expect("read share state");
        let last = envelope.len() - 1;
        envelope[last] ^= 1;
        fs::write(&path, envelope).expect("tamper share state");
        let mut tampered = sealed_state_for(2);
        assert!(tampered
            .enable_share_persistence(path.clone(), None, current_uid())
            .is_err());

        drop(persistent_state_for(
            2,
            &directory.join("public.share-state"),
        ));
        let public = directory.join("public.share-state");
        fs::set_permissions(&public, fs::Permissions::from_mode(0o644))
            .expect("make share state public");
        let mut exposed = sealed_state_for(2);
        assert!(exposed
            .enable_share_persistence(public, None, current_uid())
            .is_err());
        fs::remove_dir_all(directory).expect("remove test directory");
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn transport_key_generation_refuses_symlink_target() {
        let path = env::temp_dir().join(format!(
            "rhorizon-custodian-generated-transport-key-symlink-test-{}.key",
            std::process::id()
        ));
        std::os::unix::fs::symlink("/dev/null", &path).expect("create key symlink");
        assert!(generate_transport_key_file(&path).is_err());
        assert!(fs::symlink_metadata(&path)
            .expect("preserved key symlink")
            .file_type()
            .is_symlink());
        fs::remove_file(path).expect("remove key symlink");
    }

    #[test]
    fn config_requires_explicit_socket() {
        assert_eq!(Config::parse(["custodian".to_string()]), Err(usage()));
        let peer_keys = test_peer_keys(2);
        let peer_one = format!("1:{}", hex::encode(peer_keys[0].1.as_bytes()));
        let peer_three = format!("3:{}", hex::encode(peer_keys[1].1.as_bytes()));
        assert_eq!(
            Config::parse(vec![
                "custodian".to_string(),
                "--socket".to_string(),
                "/tmp/custodian.sock".to_string(),
                "--control-token-file".to_string(),
                "/tmp/custodian.token".to_string(),
                "--transport-key-file".to_string(),
                "/tmp/custodian.transport-key".to_string(),
                "--share-state-file".to_string(),
                "/tmp/custodian.2-of-3.share-state".to_string(),
                "--adopt-share-state-file".to_string(),
                "/tmp/custodian.share-state".to_string(),
                "--peer-key".to_string(),
                peer_one,
                "--peer-key".to_string(),
                peer_three,
                "--threshold".to_string(),
                "2".to_string(),
                "--slots".to_string(),
                "3".to_string(),
                "--slot".to_string(),
                "2".to_string(),
                "--once".to_string(),
            ]),
            Ok(Config {
                socket_path: PathBuf::from("/tmp/custodian.sock"),
                control_token_file: PathBuf::from("/tmp/custodian.token"),
                transport_key_file: PathBuf::from("/tmp/custodian.transport-key"),
                share_state_file: Some(PathBuf::from("/tmp/custodian.2-of-3.share-state")),
                adopt_share_state_file: Some(PathBuf::from("/tmp/custodian.share-state")),
                peer_keys,
                topology: CustodyTopology::new(2, 3).expect("test topology"),
                slot: 2,
                once: true,
                threads: DEFAULT_SERVE_THREADS,
            })
        );
    }

    fn config_without_share_state(extra: &[&str]) -> Result<Config, String> {
        let peer_keys = test_peer_keys(2);
        let mut argv = vec![
            "custodian".to_string(),
            "--socket".to_string(),
            "/tmp/custodian.sock".to_string(),
            "--control-token-file".to_string(),
            "/tmp/custodian.token".to_string(),
            "--transport-key-file".to_string(),
            "/tmp/custodian.transport-key".to_string(),
        ];
        for (slot, key) in &peer_keys {
            argv.push("--peer-key".to_string());
            argv.push(format!("{slot}:{}", hex::encode(key.as_bytes())));
        }
        argv.extend([
            "--threshold".to_string(),
            "2".to_string(),
            "--slots".to_string(),
            "3".to_string(),
            "--slot".to_string(),
            "2".to_string(),
        ]);
        argv.extend(extra.iter().map(|value| value.to_string()));
        Config::parse(argv)
    }

    #[test]
    fn a_custodian_runs_without_persisting_its_share() {
        // THE default. Persisting puts sub-key material on disk that is
        // decryptable with the transport key stored beside it; a surviving
        // quorum already refills an empty slot, so the file buys only the
        // below-threshold case and costs the whole at-rest guarantee.
        let config = config_without_share_state(&[]).expect("parses without a state file");
        assert_eq!(config.share_state_file, None);
        assert_eq!(config.adopt_share_state_file, None);
    }

    #[test]
    fn adopting_a_legacy_state_file_requires_opting_into_persistence() {
        // Adoption WRITES the adopted state back out. Accepting it alone would
        // persist share material after the operator asked for none.
        let error =
            config_without_share_state(&["--adopt-share-state-file", "/tmp/custodian.share-state"])
                .expect_err("adoption without persistence must be refused");
        assert!(error.contains("requires --share-state-file"), "{error}");
    }

    fn config_with_threads(threads: &str) -> Result<Config, String> {
        let peer_keys = test_peer_keys(2);
        Config::parse(vec![
            "custodian".to_string(),
            "--socket".to_string(),
            "/tmp/custodian.sock".to_string(),
            "--control-token-file".to_string(),
            "/tmp/custodian.token".to_string(),
            "--transport-key-file".to_string(),
            "/tmp/custodian.transport-key".to_string(),
            "--share-state-file".to_string(),
            "/tmp/custodian.share-state".to_string(),
            "--peer-key".to_string(),
            format!("1:{}", hex::encode(peer_keys[0].1.as_bytes())),
            "--peer-key".to_string(),
            format!("3:{}", hex::encode(peer_keys[1].1.as_bytes())),
            "--threshold".to_string(),
            "2".to_string(),
            "--slots".to_string(),
            "3".to_string(),
            "--slot".to_string(),
            "2".to_string(),
            "--threads".to_string(),
            threads.to_string(),
        ])
    }

    #[test]
    fn serve_thread_count_is_bounded_and_defaults() {
        assert_eq!(
            config_with_threads("1")
                .expect("one thread is valid")
                .threads,
            1
        );
        assert_eq!(
            config_with_threads(&MAX_SERVE_THREADS.to_string())
                .expect("the maximum is valid")
                .threads,
            MAX_SERVE_THREADS
        );
        // Zero would leave the socket bound with nothing accepting on it: the
        // launcher's readiness probe would pass and every call would hang.
        assert!(config_with_threads("0").is_err());
        assert!(config_with_threads(&(u16::from(MAX_SERVE_THREADS) + 1).to_string()).is_err());
        assert!(config_with_threads("not-a-number").is_err());
    }

    #[test]
    fn starts_sealed_and_rejects_unknown_operations() {
        let state = sealed_state();
        assert_eq!(
            dispatch_operation(&state, false, "status", &json!({})),
            Ok(json!({
                "audit_identity_loaded": false,
                "generation": null,
                "ha_password_loaded": false,
                "previous_hmac_loaded": false,
                "protocol_version": CUSTODY_PROTOCOL_VERSION,
                "state": "sealed"
            }))
        );
        assert_eq!(
            dispatch_operation(&state, false, "decrypt", &json!({})),
            Err("unknown op: decrypt".to_string())
        );
        assert_eq!(
            dispatch_operation(&state, false, "has_ha_password", &json!({})),
            Err("vault sealed".to_string())
        );
        assert_eq!(
            dispatch_operation(&state, true, "clear_ha_password", &json!({})),
            Err("vault sealed".to_string())
        );
        assert_eq!(
            dispatch_operation(&state, false, "clear_ha_password", &json!({})),
            Err("invalid control capability".to_string())
        );
    }

    #[test]
    fn share_install_requires_capability_and_keeps_daemon_sealed() {
        let state = sealed_state();
        let mut share = vec![0xA5u8; CUSTODY_V1_SHARE_BYTES];
        share[0] = 2;
        let arguments = json!({
            "generation": 7,
            "threshold": 2,
            "slots": 3,
            "slot": 2,
            "share": hex::encode(&share),
        });
        assert_eq!(
            dispatch_operation(&state, false, "install_share", &arguments),
            Err("invalid control capability".to_string())
        );
        assert_eq!(state.share.identity().expect("share state"), None);
        assert_eq!(
            dispatch_operation(&state, true, "install_share", &arguments),
            Ok(Value::String("installed".to_string()))
        );
        assert_eq!(
            dispatch_operation(&state, true, "install_share", &arguments),
            Ok(Value::String("already-installed".to_string()))
        );
        let status =
            dispatch_operation(&state, false, "share_status", &json!({})).expect("share status");
        assert_eq!(status["generation"], 7);
        assert_eq!(status["prepared_generation"], Value::Null);
        assert_eq!(status["previous_generation"], Value::Null);
        assert_eq!(status["slot"], 2);
        assert_eq!(
            status["transport_public_key"],
            hex::encode(test_transport_key(2).public_key().as_bytes())
        );
        assert!(state.is_sealed().expect("seal state"));

        assert_eq!(
            dispatch_operation(
                &state,
                false,
                "share_contribution",
                &json!({"recipient_slot": 1})
            ),
            Err("invalid control capability".to_string())
        );
        let contribution = dispatch_operation(
            &state,
            true,
            "share_contribution",
            &json!({"recipient_slot": 1}),
        )
        .expect("encrypted contribution")
        .as_str()
        .expect("hex contribution")
        .to_string();
        assert_eq!(contribution.len(), CUSTODY_SHARE_ENVELOPE_BYTES * 2);
        let contribution = hex::decode(contribution).expect("decode contribution");
        let (identity, opened_share) =
            open_share_contribution(&test_transport_key(1), &test_peer_set(1), 7, &contribution)
                .expect("recipient authenticates contribution");
        assert_eq!(identity.slot(), 2);
        assert_eq!(identity.generation(), 7);
        assert_eq!(opened_share.as_slice(), share.as_slice());

        assert_eq!(
            dispatch_operation(&state, true, "clear_share", &json!({})),
            Ok(Value::String(String::new()))
        );
        assert_eq!(state.share.identity().expect("share state"), None);
    }

    #[test]
    fn share_reshare_transitions_keep_both_generations_until_finalize() {
        let state = sealed_state();
        let mut old_share = vec![0x11u8; CUSTODY_V1_SHARE_BYTES];
        old_share[0] = 2;
        let mut new_share = vec![0x22u8; CUSTODY_V1_SHARE_BYTES];
        new_share[0] = 2;
        let share_args = |generation: u64, share: &[u8]| {
            json!({
                "generation": generation,
                "threshold": 2,
                "slots": 3,
                "slot": 2,
                "share": hex::encode(share),
            })
        };
        dispatch_operation(&state, true, "install_share", &share_args(7, &old_share))
            .expect("install active share");

        assert_eq!(
            dispatch_operation(&state, false, "prepare_share", &share_args(8, &new_share)),
            Err("invalid control capability".to_string())
        );
        assert_eq!(
            dispatch_operation(&state, true, "prepare_share", &share_args(8, &new_share)),
            Ok(Value::String("prepared".to_string()))
        );
        assert_eq!(
            dispatch_operation(&state, true, "prepare_share", &share_args(8, &new_share)),
            Ok(Value::String("already-prepared".to_string()))
        );
        let prepared_status =
            dispatch_operation(&state, false, "share_status", &json!({})).expect("share status");
        assert_eq!(prepared_status["generation"], 7);
        assert_eq!(prepared_status["prepared_generation"], 8);
        assert_eq!(prepared_status["previous_generation"], Value::Null);

        let prepared_envelope = dispatch_operation(
            &state,
            true,
            "share_contribution",
            &json!({"recipient_slot": 1, "generation": 8}),
        )
        .expect("prepared share contribution");
        let prepared_envelope = hex::decode(
            prepared_envelope
                .as_str()
                .expect("hex prepared contribution"),
        )
        .expect("decode prepared contribution");
        let (identity, opened) = open_share_contribution(
            &test_transport_key(1),
            &test_peer_set(1),
            8,
            &prepared_envelope,
        )
        .expect("recipient authenticates prepared contribution");
        assert_eq!(identity.generation(), 8);
        assert_eq!(opened.as_slice(), new_share.as_slice());

        assert_eq!(
            dispatch_operation(&state, true, "commit_share", &json!({"generation": 8})),
            Ok(Value::String("committed".to_string()))
        );
        let committed_status =
            dispatch_operation(&state, false, "share_status", &json!({})).expect("share status");
        assert_eq!(committed_status["generation"], 8);
        assert_eq!(committed_status["prepared_generation"], Value::Null);
        assert_eq!(committed_status["previous_generation"], 7);
        assert!(dispatch_operation(
            &state,
            true,
            "share_contribution",
            &json!({"recipient_slot": 1, "generation": 7}),
        )
        .is_ok());

        assert_eq!(
            dispatch_operation(&state, true, "rollback_share", &json!({"generation": 8}),),
            Ok(Value::String("rolled-back".to_string()))
        );
        assert_eq!(
            state.share.identity().expect("share state"),
            Some(CustodyShareId::new(7, 2, state.share.topology()).expect("identity"))
        );

        dispatch_operation(&state, true, "prepare_share", &share_args(8, &new_share))
            .expect("prepare again");
        dispatch_operation(&state, true, "commit_share", &json!({"generation": 8}))
            .expect("commit again");
        assert_eq!(
            dispatch_operation(&state, true, "finalize_share", &json!({"generation": 8}),),
            Ok(Value::String("finalized".to_string()))
        );
        assert!(dispatch_operation(
            &state,
            true,
            "share_contribution",
            &json!({"recipient_slot": 1, "generation": 7}),
        )
        .is_err());
    }

    #[test]
    fn encrypted_remote_contribution_unseals_atomically_and_seal_wipes_runtime() {
        let topology = CustodyTopology::new(2, 3).expect("test topology");
        let runtime: Vec<u8> = (0..CUSTODY_V1_SHARE_BYTES - 1)
            .map(|index| index as u8)
            .collect();
        let mut next = 1u8;
        let shares = shamir::split_with_fill(&runtime, 2, 3, |buffer| {
            for byte in buffer {
                *byte = next;
                next = next.wrapping_add(1);
            }
            Ok(())
        })
        .expect("split runtime bundle");
        let donor = sealed_state_for(1);
        let coordinator = sealed_state_for(2);
        for (state, slot, share) in [(&donor, 1u8, &shares[0]), (&coordinator, 2, &shares[1])] {
            assert_eq!(
                dispatch_operation(
                    state,
                    true,
                    "install_share",
                    &json!({
                        "generation": 11,
                        "threshold": topology.threshold(),
                        "slots": topology.slots(),
                        "slot": slot,
                        "share": hex::encode(share),
                    }),
                ),
                Ok(Value::String("installed".to_string()))
            );
        }

        let envelope = dispatch_operation(
            &donor,
            true,
            "share_contribution",
            &json!({"recipient_slot": 2}),
        )
        .expect("donor contribution")
        .as_str()
        .expect("hex envelope")
        .to_string();
        let arguments = json!({"contributions": [envelope]});
        assert_eq!(
            dispatch_operation(&coordinator, false, "unseal", &arguments),
            Err("invalid control capability".to_string())
        );
        assert!(coordinator.is_sealed().expect("failed unseal stays sealed"));
        assert_eq!(
            dispatch_operation(&coordinator, true, "unseal", &arguments),
            Ok(json!({"generation": 11, "state": "unsealed"}))
        );
        assert!(!coordinator.is_sealed().expect("runtime loaded"));
        let (generation, loaded) = coordinator
            .runtime
            .snapshot()
            .expect("runtime state")
            .expect("runtime loaded");
        assert_eq!(generation, 11);
        assert_eq!(loaded.as_slice(), runtime.as_slice());
        assert_eq!(
            dispatch_operation(
                &coordinator,
                false,
                "hmac_sha512",
                &json!({"message": hex::encode(b"runtime parity")})
            ),
            Ok(Value::String(hex::encode(
                rhorizon_custody_core::operations::hmac_sha512(&runtime[..32], b"runtime parity")
                    .expect("reference HMAC")
            )))
        );
        assert_eq!(
            dispatch_operation(
                &coordinator,
                false,
                "hmac_sha512_prev",
                &json!({"message": hex::encode(b"old token")})
            ),
            Ok(Value::String(String::new()))
        );
        let previous_hmac_key = [0x29; 32];
        let wrapped_previous_hmac = rhorizon_custody_core::operations::aes256_gcm_encrypt(
            &runtime[32..64],
            &previous_hmac_key,
            &[],
        )
        .expect("wrap previous HMAC key");
        let previous_hmac_arguments = json!({"wrapped_key": hex::encode(&wrapped_previous_hmac)});
        assert_eq!(
            dispatch_operation(
                &coordinator,
                false,
                "install_prev_hmac",
                &previous_hmac_arguments
            ),
            Err("invalid control capability".to_string())
        );
        assert_eq!(
            dispatch_operation(
                &coordinator,
                true,
                "install_prev_hmac",
                &previous_hmac_arguments
            ),
            Ok(Value::String("installed".to_string()))
        );
        assert_eq!(
            dispatch_operation(
                &coordinator,
                false,
                "hmac_sha512_prev",
                &json!({"message": hex::encode(b"old token")})
            ),
            Ok(Value::String(hex::encode(
                rhorizon_custody_core::operations::hmac_sha512(&previous_hmac_key, b"old token")
                    .expect("reference previous HMAC")
            )))
        );
        assert_eq!(
            dispatch_operation(&coordinator, false, "clear_prev_hmac", &json!({})),
            Err("invalid control capability".to_string())
        );
        assert_eq!(
            dispatch_operation(
                &coordinator,
                false,
                "clear_prev_hmac_if_envelope",
                &previous_hmac_arguments
            ),
            Err("invalid control capability".to_string())
        );
        assert_eq!(
            dispatch_operation(
                &coordinator,
                true,
                "clear_prev_hmac_if_envelope",
                &json!({"wrapped_key": "00"})
            ),
            Ok(Value::String("stale".to_string()))
        );
        assert_eq!(
            dispatch_operation(
                &coordinator,
                true,
                "clear_prev_hmac_if_envelope",
                &previous_hmac_arguments
            ),
            Ok(Value::String("cleared".to_string()))
        );
        assert_eq!(
            dispatch_operation(
                &coordinator,
                false,
                "hmac_sha512_prev",
                &json!({"message": hex::encode(b"old token")})
            ),
            Ok(Value::String(String::new()))
        );
        assert_eq!(
            dispatch_operation(
                &coordinator,
                true,
                "install_prev_hmac",
                &previous_hmac_arguments
            ),
            Ok(Value::String("installed".to_string()))
        );
        let audit_seed =
            hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .expect("RFC audit seed");
        let wrapped_audit_seed = rhorizon_custody_core::operations::aes256_gcm_encrypt(
            &runtime[32..64],
            &audit_seed,
            &[],
        )
        .expect("wrap audit seed");
        let expected_audit_public_key =
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
        let audit_identity_arguments = json!({
            "wrapped_seed": hex::encode(wrapped_audit_seed),
            "expected_public_key": expected_audit_public_key,
        });
        assert_eq!(
            dispatch_operation(&coordinator, false, "generate_audit_identity", &json!({})),
            Err("invalid control capability".to_string())
        );
        let generated_identity =
            dispatch_operation(&coordinator, true, "generate_audit_identity", &json!({}))
                .expect("generate audit identity envelope");
        assert_eq!(
            generated_identity["public_key"]
                .as_str()
                .expect("generated public key")
                .len(),
            64
        );
        assert_eq!(
            generated_identity["wrapped_seed"]
                .as_str()
                .expect("generated wrapped seed")
                .len(),
            120
        );
        assert!(!coordinator
            .runtime
            .audit_identity_loaded()
            .expect("generation does not install"));
        assert_eq!(
            dispatch_operation(
                &coordinator,
                false,
                "install_audit_identity",
                &audit_identity_arguments
            ),
            Err("invalid control capability".to_string())
        );
        assert_eq!(
            dispatch_operation(
                &coordinator,
                true,
                "install_audit_identity",
                &audit_identity_arguments
            ),
            Ok(json!({
                "public_key": "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                "state": "installed"
            }))
        );
        assert_eq!(
            dispatch_operation(
                &coordinator,
                true,
                "install_audit_identity",
                &audit_identity_arguments
            ),
            Ok(json!({
                "public_key": "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                "state": "already-installed"
            }))
        );
        assert_eq!(
            dispatch_operation(&coordinator, false, "status", &json!({})).expect("unsealed status")
                ["audit_identity_loaded"],
            true
        );
        assert_eq!(
            dispatch_operation(
                &coordinator,
                false,
                "audit_sign_identity",
                &json!({"payload": "", "prev_signature": ""})
            ),
            Ok(Value::String(
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555\
                 fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
                    .replace(char::is_whitespace, "")
            ))
        );
        assert_eq!(
            dispatch_operation(
                &coordinator,
                false,
                "audit_sign_raw",
                &json!({"message": ""})
            ),
            dispatch_operation(
                &coordinator,
                false,
                "audit_sign_identity",
                &json!({"payload": "", "prev_signature": ""})
            )
        );
        assert_eq!(
            dispatch_operation(
                &coordinator,
                false,
                "audit_sign",
                &json!({"payload": "row|café|漢字", "prev_signature": "ab".repeat(64)})
            ),
            Ok(Value::String(hex::encode(
                rhorizon_custody_core::operations::audit_hmac_sha512(
                    &runtime[64..96],
                    "row|café|漢字",
                    &"ab".repeat(64),
                )
                .expect("reference audit")
            )))
        );
        let encrypted = dispatch_operation(
            &coordinator,
            false,
            "aesgcm_encrypt",
            &json!({
                "plaintext": hex::encode(b"custodian secret"),
                "aad": hex::encode(b"namespace:name")
            }),
        )
        .expect("runtime AES encrypt")
        .as_str()
        .expect("hex ciphertext")
        .to_string();
        let nonce_hex_bytes = AES_GCM_NONCE_BYTES * 2;
        assert_eq!(
            dispatch_operation(
                &coordinator,
                false,
                "aesgcm_decrypt",
                &json!({
                    "ciphertext": &encrypted[nonce_hex_bytes..],
                    "nonce": &encrypted[..nonce_hex_bytes],
                    "aad": hex::encode(b"namespace:name")
                })
            ),
            Ok(Value::String(hex::encode(b"custodian secret")))
        );
        assert!(dispatch_operation(
            &coordinator,
            false,
            "aesgcm_decrypt",
            &json!({
                "ciphertext": &encrypted[nonce_hex_bytes..],
                "nonce": &encrypted[..nonce_hex_bytes],
                "aad": hex::encode(b"wrong")
            })
        )
        .is_err());
        for (encrypt_op, decrypt_op, plaintext, aad) in [
            (
                "ha_wrap_encrypt",
                "ha_wrap_decrypt",
                b"HA wrapped value".as_slice(),
                b"vault-cluster:ha_password".as_slice(),
            ),
            (
                "pki_wrap_encrypt",
                "pki_wrap_decrypt",
                b"PKI wrapped value".as_slice(),
                b"pki-ca:root".as_slice(),
            ),
        ] {
            let wrapped = dispatch_operation(
                &coordinator,
                false,
                encrypt_op,
                &json!({"plaintext": hex::encode(plaintext), "aad": hex::encode(aad)}),
            )
            .expect("typed wrap")
            .as_str()
            .expect("wrapped hex")
            .to_string();
            assert_eq!(
                dispatch_operation(
                    &coordinator,
                    false,
                    decrypt_op,
                    &json!({"wrapped": wrapped, "aad": hex::encode(aad)})
                ),
                Ok(Value::String(hex::encode(plaintext)))
            );
            assert!(dispatch_operation(
                &coordinator,
                false,
                decrypt_op,
                &json!({"wrapped": wrapped, "aad": hex::encode(b"wrong")})
            )
            .is_err());
        }
        let ha_password = [0x91; 32];
        let wrapped_password = rhorizon_custody_core::operations::aes256_gcm_encrypt(
            &runtime[96..128],
            &ha_password,
            b"vault-cluster:ha_password",
        )
        .expect("database HA-password envelope");
        let install_arguments = json!({"wrapped": hex::encode(&wrapped_password)});
        assert_eq!(
            dispatch_operation(
                &coordinator,
                false,
                "install_ha_password",
                &install_arguments
            ),
            Err("invalid control capability".to_string())
        );
        assert_eq!(
            dispatch_operation(
                &coordinator,
                true,
                "install_ha_password",
                &install_arguments
            ),
            Ok(Value::String("installed".to_string()))
        );
        assert_eq!(
            dispatch_operation(
                &coordinator,
                true,
                "install_ha_password",
                &install_arguments
            ),
            Ok(Value::String("already-installed".to_string()))
        );
        assert_eq!(
            dispatch_operation(&coordinator, false, "has_ha_password", &json!({})),
            Ok(Value::String("1".to_string()))
        );
        assert_eq!(
            dispatch_operation(
                &coordinator,
                false,
                "ha_password_hmac",
                &json!({"message": hex::encode(b"join proof")})
            ),
            Ok(Value::String(hex::encode(
                rhorizon_custody_core::operations::hmac_sha512(&ha_password, b"join proof")
                    .expect("reference HA HMAC")
            )))
        );
        let node_wrapped = dispatch_operation(
            &coordinator,
            false,
            "wrap_node_key_for_joiner",
            &json!({"node_key_pem": hex::encode(b"node key"), "node_uuid": "node-a"}),
        )
        .expect("node-key wrap");
        let server_wrapped = dispatch_operation(
            &coordinator,
            false,
            "wrap_server_key_for_joiner",
            &json!({"server_key_pem": hex::encode(b"server key"), "node_uuid": "node-a"}),
        )
        .expect("server-key wrap");
        assert_ne!(node_wrapped, server_wrapped);
        let rotated_password = [0x92; 32];
        assert_eq!(
            dispatch_operation(
                &coordinator,
                false,
                "set_ha_password_from_plain",
                &json!({"plain": hex::encode(rotated_password)})
            ),
            Err("invalid control capability".to_string())
        );
        assert_eq!(
            dispatch_operation(
                &coordinator,
                true,
                "set_ha_password_from_plain",
                &json!({"plain": hex::encode(rotated_password)})
            ),
            Ok(Value::String(String::new()))
        );
        assert_eq!(
            dispatch_operation(
                &coordinator,
                false,
                "ha_password_hmac",
                &json!({"message": hex::encode(b"join proof")})
            ),
            Ok(Value::String(hex::encode(
                rhorizon_custody_core::operations::hmac_sha512(&rotated_password, b"join proof")
                    .expect("rotated HA HMAC")
            )))
        );
        let envelope_password = [0x93; 32];
        let replacement = rhorizon_custody_core::operations::aes256_gcm_encrypt(
            &runtime[96..128],
            &envelope_password,
            b"vault-cluster:ha_password",
        )
        .expect("replacement HA-password envelope");
        let replacement_arguments = json!({"wrapped": hex::encode(&replacement)});
        assert_eq!(
            dispatch_operation(
                &coordinator,
                false,
                "replace_ha_password",
                &replacement_arguments
            ),
            Err("invalid control capability".to_string())
        );
        assert_eq!(
            dispatch_operation(
                &coordinator,
                true,
                "replace_ha_password",
                &replacement_arguments
            ),
            Ok(Value::String(String::new()))
        );
        assert_eq!(
            dispatch_operation(
                &coordinator,
                false,
                "ha_password_hmac",
                &json!({"message": hex::encode(b"join proof")})
            ),
            Ok(Value::String(hex::encode(
                rhorizon_custody_core::operations::hmac_sha512(&envelope_password, b"join proof")
                    .expect("envelope-rotated HA HMAC")
            )))
        );
        let chained = dispatch_operation(
            &coordinator,
            false,
            "secret_encrypt",
            &json!({
                "plaintext": hex::encode(b"chained custodian secret"),
                "dek_aad": hex::encode(b"dek:old"),
                "secret_aad": hex::encode(b"secret:old")
            }),
        )
        .expect("chained encrypt")
        .as_str()
        .expect("chained wire hex")
        .to_string();
        let chained = hex::decode(chained).expect("decode chained wire");
        assert!(chained.len() >= DEK_WRAPPED_BYTES + XCHACHA_NONCE_BYTES + XCHACHA_TAG_BYTES);
        let dek_nonce = &chained[..AES_GCM_NONCE_BYTES];
        let encrypted_dek = &chained[AES_GCM_NONCE_BYTES..DEK_WRAPPED_BYTES];
        let secret_nonce = &chained[DEK_WRAPPED_BYTES..DEK_WRAPPED_BYTES + XCHACHA_NONCE_BYTES];
        let ciphertext = &chained[DEK_WRAPPED_BYTES + XCHACHA_NONCE_BYTES..];
        assert_eq!(
            dispatch_operation(
                &coordinator,
                false,
                "secret_decrypt",
                &json!({
                    "encrypted_dek": hex::encode(encrypted_dek),
                    "dek_nonce": hex::encode(dek_nonce),
                    "dek_aad": hex::encode(b"dek:old"),
                    "ciphertext": hex::encode(ciphertext),
                    "secret_nonce": hex::encode(secret_nonce),
                    "secret_aad": hex::encode(b"secret:old")
                })
            ),
            Ok(Value::String(hex::encode(b"chained custodian secret")))
        );
        assert!(dispatch_operation(
            &coordinator,
            false,
            "secret_decrypt",
            &json!({
                "encrypted_dek": hex::encode(encrypted_dek),
                "dek_nonce": hex::encode(dek_nonce),
                "dek_aad": hex::encode(b"dek:old"),
                "ciphertext": hex::encode(ciphertext),
                "secret_nonce": hex::encode(secret_nonce),
                "secret_aad": hex::encode(b"secret:wrong")
            })
        )
        .is_err());
        let rotated = dispatch_operation(
            &coordinator,
            false,
            "secret_reencrypt",
            &json!({
                "old_encrypted_dek": hex::encode(encrypted_dek),
                "old_dek_nonce": hex::encode(dek_nonce),
                "old_dek_aad": hex::encode(b"dek:old"),
                "old_ciphertext": hex::encode(ciphertext),
                "old_secret_nonce": hex::encode(secret_nonce),
                "old_secret_aad": hex::encode(b"secret:old"),
                "new_dek_aad": hex::encode(b"dek:new"),
                "new_secret_aad": hex::encode(b"secret:new")
            }),
        )
        .expect("chained reencrypt")
        .as_str()
        .expect("rotated wire hex")
        .to_string();
        let rotated = hex::decode(rotated).expect("decode rotated wire");
        assert_ne!(&rotated[..DEK_WRAPPED_BYTES], &chained[..DEK_WRAPPED_BYTES]);
        assert_eq!(
            dispatch_operation(
                &coordinator,
                false,
                "secret_decrypt",
                &json!({
                    "encrypted_dek": hex::encode(
                        &rotated[AES_GCM_NONCE_BYTES..DEK_WRAPPED_BYTES]
                    ),
                    "dek_nonce": hex::encode(&rotated[..AES_GCM_NONCE_BYTES]),
                    "dek_aad": hex::encode(b"dek:new"),
                    "ciphertext": hex::encode(
                        &rotated[DEK_WRAPPED_BYTES + XCHACHA_NONCE_BYTES..]
                    ),
                    "secret_nonce": hex::encode(
                        &rotated[
                            DEK_WRAPPED_BYTES..DEK_WRAPPED_BYTES + XCHACHA_NONCE_BYTES
                        ]
                    ),
                    "secret_aad": hex::encode(b"secret:new")
                })
            ),
            Ok(Value::String(hex::encode(b"chained custodian secret")))
        );
        assert_eq!(
            dispatch_operation(&coordinator, true, "unseal", &arguments),
            Ok(json!({"generation": 11, "state": "already-unsealed"}))
        );
        assert_eq!(
            dispatch_operation(&coordinator, true, "clear_share", &json!({})),
            Err("vault must be sealed to clear a custody share".to_string())
        );
        assert_eq!(
            dispatch_operation(
                &coordinator,
                true,
                "share_contribution",
                &json!({"recipient_slot": 1})
            ),
            Err("vault must be sealed to contribute a custody share".to_string())
        );
        assert_eq!(
            dispatch_operation(&coordinator, false, "seal", &json!({})),
            Err("invalid control capability".to_string())
        );
        assert_eq!(
            dispatch_operation(&coordinator, true, "seal", &json!({})),
            Ok(Value::String(String::new()))
        );
        assert!(coordinator.is_sealed().expect("runtime cleared"));
        assert_eq!(
            dispatch_operation(&coordinator, false, "hmac_sha512", &json!({"message": ""})),
            Err("vault sealed".to_string())
        );
        assert_eq!(
            dispatch_operation(
                &coordinator,
                false,
                "hmac_sha512_prev",
                &json!({"message": ""})
            ),
            Err("vault sealed".to_string())
        );
        assert_eq!(
            dispatch_operation(
                &coordinator,
                false,
                "ha_password_hmac",
                &json!({"message": ""})
            ),
            Err("vault sealed".to_string())
        );
        assert_eq!(
            dispatch_operation(
                &coordinator,
                false,
                "ha_wrap_encrypt",
                &json!({"plaintext": "", "aad": ""})
            ),
            Err("vault sealed".to_string())
        );
        assert_eq!(
            dispatch_operation(
                &coordinator,
                false,
                "pki_wrap_encrypt",
                &json!({"plaintext": "", "aad": ""})
            ),
            Err("vault sealed".to_string())
        );
        assert_eq!(
            dispatch_operation(
                &coordinator,
                false,
                "audit_sign_identity",
                &json!({"payload": "", "prev_signature": ""})
            ),
            Err("vault sealed".to_string())
        );
        assert_eq!(
            dispatch_operation(
                &coordinator,
                false,
                "audit_sign",
                &json!({"payload": "", "prev_signature": ""})
            ),
            Err("vault sealed".to_string())
        );
        assert_eq!(
            dispatch_operation(
                &coordinator,
                false,
                "secret_encrypt",
                &json!({"plaintext": "", "dek_aad": "", "secret_aad": ""})
            ),
            Err("vault sealed".to_string())
        );
        assert_eq!(
            dispatch_operation(
                &coordinator,
                false,
                "aesgcm_encrypt",
                &json!({"plaintext": "", "aad": ""})
            ),
            Err("vault sealed".to_string())
        );
        assert_eq!(
            coordinator.runtime.generation().expect("runtime state"),
            None
        );
        assert_eq!(
            coordinator
                .share
                .identity()
                .expect("share remains")
                .map(|id| id.slot()),
            Some(2)
        );
    }

    #[test]
    fn native_reshare_roundtrip_never_returns_plaintext_shares() {
        let topology = CustodyTopology::new(2, 3).expect("test topology");
        let runtime: Vec<u8> = (0..CUSTODY_V1_SHARE_BYTES - 1)
            .map(|index| 0x80u8.wrapping_add(index as u8))
            .collect();
        let mut next = 1u8;
        let old_shares = shamir::split_with_fill(&runtime, 2, 3, |buffer| {
            for byte in buffer {
                *byte = next;
                next = next.wrapping_add(1);
            }
            Ok(())
        })
        .expect("split old runtime bundle");
        let first = sealed_state_for(1);
        let coordinator = sealed_state_for(2);
        let third = sealed_state_for(3);
        let states = [&first, &coordinator, &third];
        for (index, state) in states.iter().enumerate() {
            dispatch_operation(
                state,
                true,
                "install_share",
                &json!({
                    "generation": 11,
                    "threshold": topology.threshold(),
                    "slots": topology.slots(),
                    "slot": index + 1,
                    "share": hex::encode(&old_shares[index]),
                }),
            )
            .expect("install old generation");
        }

        let old_contribution = dispatch_operation(
            &first,
            true,
            "share_contribution",
            &json!({"recipient_slot": 2, "generation": 11}),
        )
        .expect("old contribution");
        dispatch_operation(
            &coordinator,
            true,
            "unseal",
            &json!({
                "contributions": [old_contribution],
                "generation": 11,
            }),
        )
        .expect("unseal old generation");

        assert_eq!(
            dispatch_operation(
                &coordinator,
                false,
                "generate_reshare",
                &json!({"generation": 12}),
            ),
            Err("invalid control capability".to_string())
        );
        let deliveries = dispatch_operation(
            &coordinator,
            true,
            "generate_reshare",
            &json!({"generation": 12}),
        )
        .expect("generate native reshare");
        assert_eq!(
            dispatch_operation(
                &coordinator,
                true,
                "generate_reshare",
                &json!({"generation": 12}),
            ),
            Ok(deliveries.clone())
        );
        assert_eq!(deliveries["generation"], 12);
        let remote = deliveries["deliveries"]
            .as_array()
            .expect("encrypted delivery array");
        assert_eq!(remote.len(), 2);
        for delivery in remote {
            let slot = delivery["slot"].as_u64().expect("recipient slot") as usize;
            let recipient = states[slot - 1];
            let arguments = json!({
                "envelope": delivery["envelope"],
                "generation": 12,
            });
            assert_eq!(
                dispatch_operation(recipient, false, "accept_reshare", &arguments),
                Err("invalid control capability".to_string())
            );
            assert_eq!(
                dispatch_operation(recipient, true, "accept_reshare", &arguments),
                Ok(Value::String("prepared".to_string()))
            );
        }
        for state in states {
            let status = dispatch_operation(state, false, "share_status", &json!({}))
                .expect("prepared status");
            assert_eq!(status["generation"], 11);
            assert_eq!(status["prepared_generation"], 12);
        }
        assert_eq!(
            dispatch_operation(&coordinator, false, "share_status", &json!({}))
                .expect("coordinator status")["reshare_generation"],
            12
        );

        dispatch_operation(&coordinator, true, "seal", &json!({})).expect("seal old runtime");
        for state in states {
            assert!(
                dispatch_operation(state, true, "commit_share", &json!({"generation": 12}),)
                    .is_ok()
            );
        }
        assert_eq!(
            dispatch_operation(&coordinator, false, "share_status", &json!({}))
                .expect("committed status")["reshare_generation"],
            Value::Null
        );

        let new_contribution = dispatch_operation(
            &first,
            true,
            "share_contribution",
            &json!({"recipient_slot": 2, "generation": 12}),
        )
        .expect("new contribution");
        assert_eq!(
            dispatch_operation(
                &coordinator,
                true,
                "unseal",
                &json!({
                    "contributions": [new_contribution],
                    "generation": 12,
                }),
            ),
            Ok(json!({"generation": 12, "state": "unsealed"}))
        );
        let (generation, reconstructed) = coordinator
            .runtime
            .snapshot()
            .expect("runtime state")
            .expect("new runtime loaded");
        assert_eq!(generation, 12);
        assert_eq!(reconstructed.as_slice(), runtime.as_slice());

        dispatch_operation(&coordinator, true, "seal", &json!({})).expect("seal new runtime");
        for state in states {
            assert!(
                dispatch_operation(state, true, "finalize_share", &json!({"generation": 12}),)
                    .is_ok()
            );
            assert_eq!(
                state
                    .share
                    .identities()
                    .expect("finalized identities")
                    .previous(),
                None
            );
        }
    }

    #[test]
    fn topology_reshare_grows_the_pool_across_a_relaunch() {
        let launch = CustodyTopology::new(2, 3).expect("launch topology");
        let target = CustodyTopology::new(3, 5).expect("target topology");
        let runtime: Vec<u8> = (0..CUSTODY_V1_SHARE_BYTES - 1)
            .map(|index| 0x40u8.wrapping_add(index as u8))
            .collect();
        let mut next = 1u8;
        let old_shares = shamir::split_with_fill(&runtime, 2, 3, |buffer| {
            for byte in buffer {
                *byte = next;
                next = next.wrapping_add(1);
            }
            Ok(())
        })
        .expect("split old runtime bundle");
        let first = sealed_state_for(1);
        let coordinator = sealed_state_for(2);
        let third = sealed_state_for(3);
        for (index, state) in [&first, &coordinator, &third].iter().enumerate() {
            dispatch_operation(
                state,
                true,
                "install_share",
                &json!({
                    "generation": 11,
                    "threshold": launch.threshold(),
                    "slots": launch.slots(),
                    "slot": index + 1,
                    "share": hex::encode(&old_shares[index]),
                }),
            )
            .expect("install launch generation");
        }
        let contribution = dispatch_operation(
            &first,
            true,
            "share_contribution",
            &json!({"recipient_slot": 2, "generation": 11}),
        )
        .expect("launch contribution");
        dispatch_operation(
            &coordinator,
            true,
            "unseal",
            &json!({"contributions": [contribution], "generation": 11}),
        )
        .expect("unseal launch generation");

        let peer_keys: Vec<Value> = (1..=target.slots())
            .map(|slot| {
                json!({
                    "slot": slot,
                    "key": hex::encode(test_transport_key(slot).public_key().as_bytes()),
                })
            })
            .collect();
        let request = json!({
            "generation": 12,
            "threshold": target.threshold(),
            "slots": target.slots(),
            "peer_keys": peer_keys,
        });
        assert_eq!(
            dispatch_operation(&coordinator, false, "generate_topology_reshare", &request),
            Err("invalid control capability".to_string())
        );
        // A surviving slot cannot be re-pointed at a caller-supplied key.
        let mut redirected = peer_keys.clone();
        redirected[0] = json!({
            "slot": 1,
            "key": hex::encode(test_transport_key(9).public_key().as_bytes()),
        });
        assert_eq!(
            dispatch_operation(
                &coordinator,
                true,
                "generate_topology_reshare",
                &json!({
                    "generation": 12,
                    "threshold": target.threshold(),
                    "slots": target.slots(),
                    "peer_keys": redirected,
                }),
            ),
            Err("topology reshare target must keep a surviving slot's transport key".to_string())
        );

        let deliveries =
            dispatch_operation(&coordinator, true, "generate_topology_reshare", &request)
                .expect("generate topology reshare");
        assert_eq!(
            dispatch_operation(&coordinator, true, "generate_topology_reshare", &request),
            Ok(deliveries.clone()),
            "a retry must return the same polynomial, not a fresh split"
        );
        assert_eq!(deliveries["threshold"], 3);
        assert_eq!(deliveries["slots"], 5);
        let envelopes = deliveries["deliveries"]
            .as_array()
            .expect("encrypted delivery array");
        assert_eq!(
            envelopes.len(),
            5,
            "every target slot including the coordinator"
        );
        for envelope in envelopes {
            let encoded = envelope["envelope"].as_str().expect("hex envelope");
            assert!(!old_shares
                .iter()
                .any(|share| encoded.contains(&hex::encode(share))));
        }
        // The ceremony leaves the running pool exactly as it was, so reverting
        // the environment and restarting is still a complete rollback.
        let status = dispatch_operation(&coordinator, false, "share_status", &json!({}))
            .expect("coordinator status");
        assert_eq!(status["generation"], 11);
        assert_eq!(status["prepared_generation"], Value::Null);
        assert_eq!(status["reshare_generation"], 12);
        assert_eq!(status["reshare_slots"], 5);
        assert_eq!(status["reshare_threshold"], 3);
        // Nothing installs while the daemons still run the launch topology.
        let own = envelopes
            .iter()
            .find(|envelope| envelope["slot"] == 2)
            .expect("coordinator delivery");
        dispatch_operation(&coordinator, true, "seal", &json!({})).expect("seal coordinator");
        assert_eq!(
            dispatch_operation(
                &coordinator,
                true,
                "accept_topology_reshare",
                &json!({"envelope": own["envelope"], "generation": 12}),
            ),
            Err("custody topology reshare metadata mismatch".to_string())
        );

        // The operator relaunches the pool under the target topology.
        let relaunched: Vec<CustodianState> = (1..=target.slots())
            .map(|slot| sealed_state_in(target, slot))
            .collect();
        for envelope in envelopes {
            let slot = envelope["slot"].as_u64().expect("recipient slot") as usize;
            let arguments = json!({"envelope": envelope["envelope"], "generation": 12});
            assert_eq!(
                dispatch_operation(
                    &relaunched[slot - 1],
                    false,
                    "accept_topology_reshare",
                    &arguments
                ),
                Err("invalid control capability".to_string())
            );
            assert_eq!(
                dispatch_operation(
                    &relaunched[slot - 1],
                    true,
                    "accept_topology_reshare",
                    &arguments
                ),
                Ok(Value::String("installed".to_string()))
            );
            assert_eq!(
                dispatch_operation(
                    &relaunched[slot - 1],
                    true,
                    "accept_topology_reshare",
                    &arguments
                ),
                Ok(Value::String("already-installed".to_string()))
            );
            // A delivery only opens for the slot it was addressed to.
            let other = usize::from(slot as u8 % target.slots());
            assert_eq!(
                dispatch_operation(
                    &relaunched[other],
                    true,
                    "accept_topology_reshare",
                    &arguments,
                ),
                Err("custody topology reshare authentication failed".to_string())
            );
        }

        // The new shape reconstructs the same runtime bundle from its own
        // threshold, which the launch topology could not have satisfied.
        let contributions: Vec<Value> = [1u8, 3]
            .iter()
            .map(|slot| {
                dispatch_operation(
                    &relaunched[usize::from(*slot) - 1],
                    true,
                    "share_contribution",
                    &json!({"recipient_slot": 5, "generation": 12}),
                )
                .expect("target contribution")
            })
            .collect();
        assert_eq!(
            dispatch_operation(
                &relaunched[4],
                true,
                "unseal",
                &json!({"contributions": contributions[..1], "generation": 12}),
            ),
            Err("unseal requires exactly 2 remote contributions".to_string())
        );
        assert_eq!(
            dispatch_operation(
                &relaunched[4],
                true,
                "unseal",
                &json!({"contributions": contributions, "generation": 12}),
            ),
            Ok(json!({"generation": 12, "state": "unsealed"}))
        );
        let (generation, reconstructed) = relaunched[4]
            .runtime
            .snapshot()
            .expect("runtime state")
            .expect("target runtime loaded");
        assert_eq!(generation, 12);
        assert_eq!(reconstructed.as_slice(), runtime.as_slice());
    }

    #[test]
    fn status_response_uses_shared_framing() {
        let state = sealed_state();
        let response = dispatch_request(json!({"op": "status"}), |operation, arguments| {
            dispatch_operation(&state, false, operation, arguments)
        });
        let mut wire = Vec::new();
        write_frame(&mut wire, &response.to_bytes(), MAX_RPC_FRAME_BYTES).expect("write frame");
        let decoded = read_frame(&mut Cursor::new(wire), MAX_RPC_FRAME_BYTES).expect("read frame");
        assert!(decoded.windows(6).any(|window| window == b"sealed"));
    }
}
